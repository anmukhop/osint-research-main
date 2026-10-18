"""
Browsing context summarization and OSINT query suggestion service.

Uses claude-haiku-4-5-20251001 (lowest cost) to:
1. Aggregate and summarize team browsing events into a structured summary
   with common/unique site and search breakdowns annotated by username.
2. Generate one high-confidence OSINT query grounded in the tool registry,
   then notify team members via the Notification model.

Called from the workspace view when the cached BrowsingTeamSummary is stale.
"""

import json
import logging
import os
from datetime import timedelta

from anthropic import Anthropic
from django.utils import timezone as django_tz
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

HAIKU_MODEL = "claude-haiku-4-5-20251001"
SUMMARY_TTL_MINUTES = 3
EVENT_WINDOW_MINUTES = 10

_client = None

OSINT_PLATFORM_CONTEXT = """Platform background:
- The Railway app at https://osint-research-production.up.railway.app/ is the AI agent/workbench for a team of 2 participants collaborating on CTF-style challenges that exercise OSINT skills.
- The research target is always an external entity discovered from the team's browsing/search activity. Do not treat or investigate the Railway app itself as the target; it is only the tool used to coordinate and run OSINT tasks.
- The platform gathers intelligence through an MCP architecture: the available tools in the registry are the allowed way to fetch WHOIS, DNS, subdomain, IP, Shodan, BuiltWith, and related OSINT data.
- Use browsing events and search queries made across websites to infer the team's current external target, shared investigation themes, and what tool-backed query would move the investigation forward.
- Treat OSINT research app queries and relevant browsing/search events as evidence of work already done. AI suggestions should not repeat those actions; they should propose the next best tool-backed step."""


def _get_client() -> Anthropic:
    global _client
    if _client is None:
        _client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    return _client


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def _event_cutoff():
    """Return the lower bound for browsing events included in Team Context."""
    return django_tz.now() - timedelta(minutes=EVENT_WINDOW_MINUTES)


def _latest_team_event_at(team):
    """Return the newest in-window browsing event timestamp for this team."""
    from researcher.models import BrowsingEvent

    return (
        BrowsingEvent.objects
        .filter(team=team, created_at__gte=_event_cutoff())
        .order_by("-created_at")
        .values_list("created_at", flat=True)
        .first()
    )


def _has_new_team_events_since(team, since) -> bool:
    """Return True when the team has in-window browsing events newer than since."""
    latest = _latest_team_event_at(team)
    return bool(latest and (since is None or latest > since))


def _collect_team_events(team) -> dict:
    """Return team browsing events from the last EVENT_WINDOW_MINUTES.

    Returns a dict keyed by username with lists of visit/search events.
    """
    from researcher.models import BrowsingEvent

    events = (
        BrowsingEvent.objects
        .filter(team=team, created_at__gte=_event_cutoff())
        .select_related("user")
        .order_by("user", "-created_at")
    )

    by_user: dict = {}
    for e in events:
        uname = e.user.username
        if uname not in by_user:
            by_user[uname] = {"visits": [], "searches": []}
        if e.event_type == BrowsingEvent.EVENT_SEARCH and e.search_query:
            by_user[uname]["searches"].append({
                "site": e.site_name,
                "query": e.search_query,
            })
        else:
            entry = {"site": e.site_name}
            if e.top_heading:
                entry["heading"] = e.top_heading
            elif e.page_title:
                entry["heading"] = e.page_title
            by_user[uname]["visits"].append(entry)

    return by_user


def _format_events_for_prompt(by_user: dict) -> str:
    """Turn the by-user event dict into a compact text block for the LLM."""
    lines = []
    for uname, data in by_user.items():
        lines.append(f"User: {uname}")
        seen_sites = set()
        if data["visits"]:
            for v in data["visits"][:15]:
                site = v["site"]
                if site in seen_sites:
                    continue
                seen_sites.add(site)
                heading = v.get("heading", "")
                lines.append(f"  visited: {site}" + (f' ("{heading}")' if heading else ""))
        if data["searches"]:
            for s in data["searches"][:10]:
                lines.append(f'  searched: "{s["query"]}" on {s["site"]}')
        lines.append("")
    return "\n".join(lines)


def _build_summary_prompt(team_name: str, events_text: str) -> str:
    """Build the summary prompt used for team browsing context."""
    return f"""You are an OSINT research analyst assistant.

{OSINT_PLATFORM_CONTEXT}

Team: {team_name}
Time window: last {EVENT_WINDOW_MINUTES} minutes

Browsing activity:
{events_text}

Summarize the external OSINT target(s), investigation themes, and each participant's activity. Preserve search queries made across websites as evidence of context. Do not summarize the Railway app as a target.

Produce a JSON object with EXACTLY these keys (no markdown, raw JSON only):
{{
  "overview": "2-3 sentence description of what the team is collectively researching",
  "common_sites": ["hostname only, sites visited by 2+ users"],
  "common_search_themes": ["keyword theme appearing across multiple users' searches"],
  "per_user": {{
    "<username>": {{
      "sites": ["hostname1", "hostname2"],
      "searches": ["search term 1", "search term 2"],
      "focus": "one sentence about this user's apparent research focus"
    }}
  }},
  "unique_sites": {{"<username>": ["site only they visited"]}},
  "unique_searches": {{"<username>": ["search only they made"]}}
}}

Return only the JSON, nothing else."""


def _strip_json_fence(raw: str) -> str:
    """Return raw JSON text, tolerating accidental markdown fences."""
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return raw.strip()


# ---------------------------------------------------------------------------
# Claude Haiku: summarize
# ---------------------------------------------------------------------------

def _call_summary(team_name: str, events_text: str) -> dict:
    """Ask Haiku to produce a structured JSON summary of team browsing."""
    prompt = _build_summary_prompt(team_name, events_text)
    try:
        resp = _get_client().messages.create(
            model=HAIKU_MODEL,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return json.loads(_strip_json_fence(resp.content[0].text))
    except Exception:
        logger.exception("browsing summary LLM call failed")
        return {}


# ---------------------------------------------------------------------------
# Claude Haiku: generate OSINT queries
# ---------------------------------------------------------------------------

_TOOL_DESCRIPTIONS = None


def _get_tool_descriptions() -> str:
    global _TOOL_DESCRIPTIONS
    if _TOOL_DESCRIPTIONS is None:
        from researcher.services.tool_registry import get_tools_for_prompt
        _TOOL_DESCRIPTIONS = get_tools_for_prompt()
    return _TOOL_DESCRIPTIONS


def _build_suggestions_prompt(summary: dict) -> str:
    """Build the OSINT query suggestion prompt from a browsing summary."""
    overview = summary.get("overview", "")
    common_sites = summary.get("common_sites", [])
    per_user = summary.get("per_user", {})

    all_searches = []
    all_sites = list(common_sites)
    for uname, data in per_user.items():
        all_searches.extend(data.get("searches", []))
        all_sites.extend(data.get("sites", []))

    # Deduplicate
    all_sites = list(dict.fromkeys(all_sites))[:20]
    all_searches = list(dict.fromkeys(all_searches))[:15]

    tool_desc = _get_tool_descriptions()

    return f"""You are an OSINT research assistant helping a team of analysts.

{OSINT_PLATFORM_CONTEXT}

Team research overview: {overview}

Sites being visited: {", ".join(all_sites) if all_sites else "none"}
Searches being made: {", ".join(all_searches) if all_searches else "none"}

Available OSINT tools:
{tool_desc}

Based on what this team is researching, generate AT MOST 1 high-confidence OSINT query that:
1. Are directly and specifically relevant to the sites/searches above
2. Can be answered by one of the listed tools (use specific domains or usernames from the browsing data)
3. Would provide genuinely useful intelligence for their research
4. Mark the query as "recommended": true only if it is strongly grounded in common points across multiple users' browsing/searches AND would move the investigation forward.
5. Include a succinct, lucid "relevance_analysis" with 2-3 short sentences, maximum 40 words. Focus only on how the query follows from team member activity and how the result can help the investigation.
6. Focus on how the MCP tool registry can be leveraged in this browsing context. Do not generate a query about the Railway app itself unless it appears as an external target in the browsing data, which it normally should not.
7. Do NOT suggest investigating team members, participants, or their usernames/personas. A team member's name or username is not an external OSINT target.
8. Do NOT repeat a query, lookup, or browsing action that the team appears to have already performed in the OSINT research app or browser. The suggestion must be forward looking: choose the closest related AI-agent/tool capability that can add new, more relevant information.
9. If there is no clear external target or the browsing context is too thin/conflicting, return an empty JSON array [] instead of a low-confidence query.

Return a JSON array with either one object or no objects (no markdown, raw JSON only):
[
  {{
    "query": "natural language query text (specific, actionable, e.g. 'What are the DNS records for shodan.io?')",
    "tool": "tool_name from the registry",
    "reason": "one sentence explaining why this is relevant to the team's work",
    "recommended": true,
    "relevance_analysis": "2-3 short sentences, maximum 40 words, explaining how this follows from team member activity and how the result can help the investigation"
  }}
]

Return only the JSON array, nothing else."""


def _call_suggestions(summary: dict) -> list[dict]:
    """Ask Haiku for one confident OSINT query grounded in the tool registry."""
    prompt = _build_suggestions_prompt(summary)
    try:
        resp = _get_client().messages.create(
            model=HAIKU_MODEL,
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        suggestions = json.loads(_strip_json_fence(resp.content[0].text))
        if isinstance(suggestions, list):
            return suggestions[:1]
        return []
    except Exception:
        logger.exception("browsing suggestions LLM call failed")
        return []


# ---------------------------------------------------------------------------
# Prompt simulation helpers
# ---------------------------------------------------------------------------

def _default_simulated_events() -> dict:
    """Realistic two-member browsing dataset for Team Context prompt tests."""
    return {
        "maya": {
            "visits": [
                {
                    "site": "virginiatech.edu",
                    "heading": "Information Technology Security Office",
                },
                {
                    "site": "security.vt.edu",
                    "heading": "Alerts and Advisories",
                },
                {
                    "site": "shodan.io",
                    "heading": "128.173.236.101",
                },
                {
                    "site": "crt.sh",
                    "heading": "Certificate Search: vt.edu",
                },
                {
                    "site": "github.com",
                    "heading": "VirginiaTech open source repositories",
                },
            ],
            "searches": [
                {"site": "google.com", "query": "Virginia Tech public IP exposure Shodan"},
                {"site": "shodan.io", "query": "ssl.cert.subject.cn:*.vt.edu"},
                {"site": "crt.sh", "query": "%.vt.edu"},
                {"site": "github.com", "query": "org:VirginiaTech secrets vt.edu"},
            ],
        },
        "leo": {
            "visits": [
                {
                    "site": "virginiatech.edu",
                    "heading": "Network Infrastructure and Services",
                },
                {
                    "site": "security.vt.edu",
                    "heading": "Vulnerability Management",
                },
                {
                    "site": "cvedetails.com",
                    "heading": "Apache HTTP Server Vulnerabilities",
                },
                {
                    "site": "builtwith.com",
                    "heading": "Technology Profile for vt.edu",
                },
                {
                    "site": "dnsdumpster.com",
                    "heading": "DNS recon for vt.edu",
                },
            ],
            "searches": [
                {"site": "google.com", "query": "site:vt.edu VPN portal"},
                {"site": "cvedetails.com", "query": "Apache httpd recent CVEs"},
                {"site": "builtwith.com", "query": "vt.edu technology stack"},
                {"site": "dnsdumpster.com", "query": "vt.edu subdomains"},
            ],
        },
    }


def _collect_simulation_seed_events(team=None) -> dict:
    """Return recent real browsing events when they are useful for simulation."""
    if team is None:
        return {}

    by_user = _collect_team_events(team)
    useful = {
        username: data
        for username, data in by_user.items()
        if data.get("visits") or data.get("searches")
    }
    if len(useful) < 2:
        return {}

    return dict(list(useful.items())[:2])


def run_team_context_prompt_simulation(team=None) -> dict:
    """Run both Team Context prompts against a two-member browsing scenario.

    This is intentionally separate from refresh_team_context: it does not write
    BrowsingEvent, BrowsingTeamSummary, or Notification rows. It exercises the
    same prompt builders and LLM calls used by the production Team Context pane.
    """
    team_name = getattr(team, "name", None) or "Team Context Simulation"
    seeded_events = _collect_simulation_seed_events(team)
    by_user = seeded_events or _default_simulated_events()
    events_text = _format_events_for_prompt(by_user)
    summary_prompt = _build_summary_prompt(team_name, events_text)

    summary = {}
    suggestions = []
    summary_error = ""
    suggestions_error = ""

    if not os.getenv("ANTHROPIC_API_KEY"):
        summary_error = "ANTHROPIC_API_KEY is not set, so the live Haiku prompt was not executed."
    else:
        try:
            summary = _call_summary(team_name, events_text)
        except Exception as exc:
            logger.exception("team context simulation summary failed")
            summary_error = str(exc)

    suggestions_prompt = _build_suggestions_prompt(summary) if summary else ""
    if summary:
        try:
            suggestions = _call_suggestions(summary)
        except Exception as exc:
            logger.exception("team context simulation suggestions failed")
            suggestions_error = str(exc)

    return {
        "team_name": team_name,
        "source": "recent team browsing events" if seeded_events else "built-in realistic sample",
        "events_by_user": by_user,
        "events_text": events_text,
        "summary_prompt": summary_prompt,
        "summary": summary,
        "summary_error": summary_error,
        "suggestions_prompt": suggestions_prompt,
        "suggestions": suggestions,
        "suggestions_error": suggestions_error,
        "model": HAIKU_MODEL,
    }


# ---------------------------------------------------------------------------
# Notification dispatch
# ---------------------------------------------------------------------------

def _select_recommended_suggestion(suggestions: list[dict]) -> dict | None:
    """Return the single AI-recommended suggestion, if present."""
    if not suggestions:
        return None

    for suggestion in suggestions:
        if suggestion.get("recommended") is True:
            return suggestion
    return None


def _notify_team_of_ai_query_result(team, query, suggestion: dict, requesting_user=None):
    """Notify team members after an AI-generated query result is added.

    De-duplicates by checking if an identical suggestion was already sent
    in the active browsing-event window.
    """
    from researcher.models import Notification, TeamMembership

    if not query or not suggestion:
        return

    cutoff = _event_cutoff()
    members = TeamMembership.objects.filter(team=team).select_related("user")

    text = suggestion.get("query", "").strip() or query.user_query
    analysis = suggestion.get("relevance_analysis") or suggestion.get("reason", "")
    full_text = f"[AI Research Result] {text}"
    if analysis:
        full_text += f" — {analysis}"

    for membership in members:
        user = membership.user
        # Skip the user who triggered the refresh
        if requesting_user and user.id == requesting_user.id:
            continue
        already_sent = Notification.objects.filter(
            recipient=user,
            query=query,
            suggestion_text=full_text,
            created_at__gte=cutoff,
        ).exists()
        if already_sent:
            continue
        Notification.objects.create(
            recipient=user,
            query=query,
            suggestion_text=full_text,
            is_read=False,
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_summary_stale(team) -> bool:
    """Return True if the team summary needs regeneration.

    A refresh is allowed only when:
    - there are team browsing events in the last EVENT_WINDOW_MINUTES, and
    - either no summary exists yet, or the cached summary is older than
      SUMMARY_TTL_MINUTES and at least one newer event has arrived.
    """
    from researcher.models import BrowsingTeamSummary
    latest_event_at = _latest_team_event_at(team)

    try:
        s = BrowsingTeamSummary.objects.get(team=team)
        if latest_event_at is None:
            return not s.data.get("no_events", False)
        cutoff = django_tz.now() - timedelta(minutes=SUMMARY_TTL_MINUTES)
        return s.generated_at < cutoff and latest_event_at > s.generated_at
    except BrowsingTeamSummary.DoesNotExist:
        return latest_event_at is not None


def get_cached_summary(team) -> dict:
    """Return the cached summary data dict, or empty dict if none exists."""
    from researcher.models import BrowsingTeamSummary
    try:
        return BrowsingTeamSummary.objects.get(team=team).data
    except BrowsingTeamSummary.DoesNotExist:
        return {}


def refresh_team_context(team, requesting_user=None, auto_run_callback=None) -> dict:
    """Regenerate the team browsing summary and OSINT suggestions.

    1. Collect browsing events for all team members (last 10 minutes)
    2. Call Haiku to summarize
    3. Call Haiku to generate one suggested query
    4. Auto-run the single recommended AI query, when one is present
    5. Store in BrowsingTeamSummary
    6. Notify team members after the AI-generated output is added
    7. Return the full summary+suggestions dict
    """
    from researcher.models import BrowsingTeamSummary

    previous_summary = None
    try:
        previous_summary = BrowsingTeamSummary.objects.get(team=team)
    except BrowsingTeamSummary.DoesNotExist:
        previous_summary = None

    latest_event_at = _latest_team_event_at(team)
    if latest_event_at is None:
        empty = {"no_events": True, "suggestions": []}
        BrowsingTeamSummary.objects.update_or_create(
            team=team, defaults={"data": empty}
        )
        return empty

    if previous_summary and not _has_new_team_events_since(team, previous_summary.generated_at):
        return previous_summary.data

    by_user = _collect_team_events(team)
    if not by_user:
        empty = {"no_events": True, "suggestions": []}
        BrowsingTeamSummary.objects.update_or_create(
            team=team, defaults={"data": empty}
        )
        return empty

    events_text = _format_events_for_prompt(by_user)
    summary = _call_summary(team.name, events_text)

    suggestions = []
    auto_run_query = None
    auto_run_error = ""
    if summary:
        suggestions = _call_suggestions(summary)
        recommended = _select_recommended_suggestion(suggestions)
        if recommended and auto_run_callback:
            try:
                auto_run_query = auto_run_callback(recommended)
                if auto_run_query:
                    _notify_team_of_ai_query_result(
                        team,
                        auto_run_query,
                        recommended,
                        requesting_user=requesting_user,
                    )
            except Exception as exc:
                logger.exception("AI recommended query auto-run failed")
                auto_run_error = str(exc)

    data = {
        **summary,
        "suggestions": suggestions,
        "auto_run_query_id": getattr(auto_run_query, "id", None),
        "auto_run_error": auto_run_error,
    }
    BrowsingTeamSummary.objects.update_or_create(
        team=team, defaults={"data": data}
    )
    return data
