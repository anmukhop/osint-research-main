"""
Follow-up suggestion generation.

Called from the view layer after a query completes. Takes the user's
original query, the summary, and the tool calls, and asks Claude Haiku
to propose 2-3 natural-language follow-up questions the user might want
to ask next.

Kept as a separate module from mcp_client so that:
- Failures here don't break the main query path
- The model and prompt can be tuned independently
- Cost is obvious (one extra Haiku call per query)
"""

import json
import logging
import os
from typing import Optional

from .llm_provider import get_provider

logger = logging.getLogger(__name__)

# Runs on the provider's "fast" tier (Haiku on Anthropic, LLM_FAST_MODEL
# otherwise): plenty smart enough for "generate 3 related questions" tasks.
_MAX_TOKENS = 400
_NUM_SUGGESTIONS = 3

_SYSTEM_PROMPT = f"""You are a follow-up query suggester for an OSINT research tool.

Given a user's query and the results they just received, propose exactly {_NUM_SUGGESTIONS} natural-language follow-up queries that a researcher might logically want to ask next.

RULES:
- Each suggestion must be a single question or command, phrased as a user would type it
- Suggestions must be ACTIONABLE with the available OSINT tools: WHOIS/DNS/subdomain/IP geolocation/threat intelligence/SSL cert/username search/technology detection/Shodan host lookups/CVE lookups
- Do NOT suggest things outside those categories (no "check news articles", no "search LinkedIn directly", no "call the company")
- Each suggestion should build on or complement what was just found — not repeat it
- Reference specific targets from the prior results (domain names, IPs, usernames) rather than generic placeholders
- Output as a JSON array of exactly {_NUM_SUGGESTIONS} strings, nothing else
- No markdown, no explanation, no preamble — just the JSON array

Example output format:
["What are the DNS records for example.com?", "Check threat intelligence for example.com", "Find subdomains of example.com"]
"""


def generate_followups(
    user_query: str,
    summary: Optional[str],
    tool_calls: list[dict],
) -> list[str]:
    """
    Generate follow-up query suggestions for a completed search.

    Returns a list of suggestion strings (may be empty on failure — caller
    should treat empty as "no suggestions available" and render nothing).
    Never raises — all errors are logged and swallowed.
    """
    if not user_query:
        return []

    provider = get_provider()
    if not provider.is_configured():
        logger.warning("generate_followups: LLM provider %s not configured", provider.name)
        return []

    # Build a compact context summary. We deliberately don't pass the full
    # raw tool results — that would balloon the prompt for no benefit. The
    # LLM's summary is already a distilled view of what was found.
    tools_used = [c.get("tool", "unknown") for c in tool_calls if c]
    context_lines = [
        f"Original query: {user_query}",
    ]
    if tools_used:
        context_lines.append(f"Tools used: {', '.join(tools_used)}")
    if summary:
        # Cap the summary at ~1500 chars to keep the prompt small
        context_lines.append(f"Summary of findings:\n{summary[:1500]}")
    else:
        context_lines.append("No summary available (no tools were used).")

    user_message = "\n\n".join(context_lines)

    try:
        response = provider.create(
            tier="fast",
            max_tokens=_MAX_TOKENS,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )

        # Extract the text response
        text = ""
        for block in response.content:
            if block.type == "text":
                text = block.text
                break

        if not text:
            logger.warning("generate_followups: empty response from model")
            return []

        # Parse the JSON array. Be lenient about stray whitespace or the
        # model occasionally wrapping the array in a code fence despite
        # instructions.
        text = text.strip()
        if text.startswith("```"):
            # Strip code fence if present
            lines = text.split("\n")
            text = "\n".join(
                line for line in lines if not line.startswith("```")
            ).strip()

        suggestions = json.loads(text)

        if not isinstance(suggestions, list):
            logger.warning(
                "generate_followups: parsed response is not a list: %r", suggestions
            )
            return []

        # Filter to strings only and cap the count
        cleaned = [
            s.strip() for s in suggestions
            if isinstance(s, str) and s.strip()
        ][:_NUM_SUGGESTIONS]

        return cleaned

    except json.JSONDecodeError as e:
        logger.warning("generate_followups: failed to parse JSON: %s", e)
        return []
    except Exception:
        logger.exception("generate_followups: unexpected error")
        return []