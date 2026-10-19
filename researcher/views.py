"""
Views for OSINT Research Platform

Changes from previous version:
- Uses the per-worker MCPRuntime singleton instead of building a fresh
  OSINTMCPClient per request. No more reconnect-per-request; the stall
  under concurrent load is fixed here.
- Every /search/stream/ request writes a Query row and a ToolCall row to
  the database, tied to the anonymous session from AnonymousSessionMiddleware.
- Legacy non-streaming /search/ endpoint removed (nothing in urls.py uses it).
"""

import json
import os
import queue
import threading
import time
import logging

from django.db import close_old_connections
from django.shortcuts import render
from django.http import JsonResponse, StreamingHttpResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import get_object_or_404
from .models import Team, TeamMembership, Notification, BrowsingEvent

from .services.mcp_runtime import get_runtime
from .services.mcp_client import ProgressUpdate
from .services.llm_provider import get_provider
from .services.tool_registry import (
    get_claude_tool_definitions,
    get_confirmation_message,
    get_tool,
    get_tools_for_prompt,
)
from .models import Query, ToolCall

from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger(__name__)

ACTIVE_TEAM_SESSION_KEY = "active_team_id"
CONTEXT_AWARE_SESSION_KEY = "context_aware_enabled"

BENCHMARK_QUERIES = [
    {
        "id": "ST-01",
        "query": "Who is the registrant and registrar for vt.edu, and when was it created?",
    },
    {
        "id": "ST-02",
        "query": "Who owns the domain behind crowd.cs.vt.edu?",
    },
    {
        "id": "ST-03",
        "query": "Show the historical WHOIS records for crowd.cs.vt.edu and note any registrar changes.",
    },
    {
        "id": "ST-04",
        "query": "Find all domains registered to the same organization as the registrant of vt.edu.",
    },
    {
        "id": "ST-05",
        "query": "What are the current DNS records (A, MX, NS, TXT) for crowd.cs.vt.edu?",
    },
    {
        "id": "ST-06",
        "query": "Resolve the A and CNAME records for crowd.cs.vt.edu.",
    },
    {
        "id": "ST-07",
        "query": "Show the historical DNS record changes for crowd.cs.vt.edu.",
    },
]


def _build_confirmation_plan(tool_uses) -> list[dict]:
    """Summarize planned tool calls for the confirmation UI."""
    plan: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for block in tool_uses:
        tool_name = getattr(block, "name", None)
        if not tool_name:
            continue
        params = getattr(block, "input", None) or {}
        key = (tool_name, json.dumps(params, sort_keys=True, default=str))
        if key in seen:
            continue
        seen.add(key)

        tool = get_tool(tool_name) or {}
        plan.append({
            "tool": tool_name,
            "server": tool.get("server") or "unknown",
            "description": tool.get("description") or tool_name,
            "params": params,
        })

    return plan


def _handle_query_stream_disconnect(query_id: int, result_holder: dict, persist_callback) -> None:
    """Persist completed searches; leave in-flight searches for the worker.

    Navigating away closes the SSE stream, but it should not cancel or fail the
    query. The background worker owns final persistence once runtime returns.
    """
    if result_holder.get("result") is not None or result_holder.get("error"):
        persist_callback()


def _serialize_workspace_query(query: Query) -> dict:
    """Return query data for the in-page workspace detail pane."""
    tool_calls = []
    for call in query.tool_calls.all().order_by("created_at"):
        tool_calls.append({
            "tool_name": call.tool_name,
            "tool": call.tool_name,
            "server_name": call.server_name,
            "server": call.server_name,
            "arguments": call.arguments,
            "args": call.arguments,
            "result": call.result,
            "success": call.success,
            "error": call.error,
        })

    return {
        "id": query.id,
        "query_id": query.id,
        "user_query": query.user_query,
        "summary": query.summary,
        "success": query.success,
        "error": query.error,
        "interpreted_action": query.interpreted_action,
        "action": query.interpreted_action,
        "interpreted_params": query.interpreted_params,
        "params": query.interpreted_params,
        "server_used": query.server_used,
        "server": query.server_used,
        "raw_results": query.raw_results,
        "tool_calls": tool_calls,
        "author": query.user.username if query.user_id else "AI Research Assistant",
        "created_at": query.created_at.isoformat(),
        "duration_ms": query.duration_ms,
        "is_running": (not query.success and not query.error and not query.duration_ms),
        "answer_source": (query.raw_results or {}).get("answer_source") if query.raw_results else None,
        "execution_steps": (query.raw_results or {}).get("execution_steps", []) if query.raw_results else [],
    }


def _setup_extension_request(request) -> bool:
    """Authenticate an extension API request using the X-Session-Id header.

    The browser's fetch() API treats `Cookie` as a forbidden header and silently
    drops it, so we cannot rely on Django's normal session-cookie flow for
    cross-origin requests from the browser extension.  Instead the extension
    reads the sessionid cookie via chrome.cookies (allowed for permitted origins)
    and forwards it in the custom X-Session-Id header.  We load the matching
    session here and patch request.user / request.session so all downstream
    helpers (_get_active_team, etc.) work transparently.

    Falls through to normal Django auth if the request is already authenticated
    (e.g. same-origin AJAX calls from the web app).

    Returns True if the request is authenticated after setup.
    """
    if request.user.is_authenticated:
        return True

    session_key = request.META.get("HTTP_X_SESSION_ID", "").strip()
    if not session_key:
        return False

    try:
        from django.contrib.sessions.backends.db import SessionStore
        from django.contrib.auth import SESSION_KEY, get_user_model

        session = SessionStore(session_key)
        # Validate the session exists and hasn't expired
        if not session.exists(session_key):
            return False

        user_id = session.get(SESSION_KEY)
        if not user_id:
            return False

        User = get_user_model()
        user = User.objects.get(pk=user_id, is_active=True)

        # Patch the request so all existing view helpers work as-is
        request.user = user
        request.session = session
        return True
    except Exception:
        logger.debug("X-Session-Id auth failed", exc_info=True)
        return False


def _extension_cors(response, request):
    """Add CORS headers to allow browser extension origins to read the response."""
    origin = request.META.get("HTTP_ORIGIN", "")
    if origin.startswith(("chrome-extension://", "moz-extension://")):
        response["Access-Control-Allow-Origin"] = origin
        response["Access-Control-Allow-Credentials"] = "true"
        response["Access-Control-Allow-Headers"] = "Content-Type, X-Session-Id, X-CSRFToken"
        response["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


def index(request):
    """Main page with the search form."""
    return render(request, "researcher/index.html", {
        "context_aware_enabled": request.session.get(CONTEXT_AWARE_SESSION_KEY, False),
    })

def signup(request):
    """Create a new user account.

    Uses Django's built-in UserCreationForm (username + password + confirm).
    On success, auto-logs-in the new user and redirects to the search page.
    """
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect("index")
    else:
        form = UserCreationForm()
    return render(request, "registration/signup.html", {"form": form})

def active_team_context(request):
    """Template context processor: expose `active_team` on every request.

    Registered in settings.TEMPLATES[0]['OPTIONS']['context_processors'].
    """
    return {"active_team": _get_active_team(request)}


def _set_active_team(request, team: Team) -> None:
    """Stash the user's active team ID in their session."""
    request.session[ACTIVE_TEAM_SESSION_KEY] = team.id


def _get_active_team(request) -> Team | None:
    """Fetch the currently-active team for this request, or None.

    Silently drops a stale/invalid session value (e.g. if the team was
    deleted, or the user was removed from it — not implemented yet but
    cheap to defend against now).
    """
    if not request.user.is_authenticated:
        return None
    team_id = request.session.get(ACTIVE_TEAM_SESSION_KEY)
    if not team_id:
        return None
    team = Team.objects.filter(
        id=team_id,
        memberships__user=request.user,
    ).first()
    if team is None:
        request.session.pop(ACTIVE_TEAM_SESSION_KEY, None)
    return team


def _get_extension_team(request) -> Team | None:
    """Return the team context the browser extension should display.

    The web UI requires an explicitly active team, but the extension can be
    opened after a login/session change where no active team has been selected
    yet. If the user has exactly one team membership, use that as the obvious
    context and persist it to the session.
    """
    active_team = _get_active_team(request)
    if active_team is not None:
        return active_team

    teams = list(
        Team.objects
        .filter(memberships__user=request.user)
        .order_by("-created_at")[:2]
    )
    if len(teams) == 1:
        _set_active_team(request, teams[0])
        return teams[0]
    return None


def _build_history_from_parent(parent_query) -> list[dict]:
    """Walk up the parent chain and build a Claude-format message history.

    Returns a list of {"role", "content"} dicts in oldest-first order,
    capped at MAX_HISTORY_TURNS ancestors so long threads don't blow up
    the prompt. Used by both /parse/ and /search/stream/ so that follow-up
    queries see the same conversational context at every stage.
    """
    history: list[dict] = []
    if parent_query is None:
        return history

    chain: list = []
    cursor = parent_query
    MAX_HISTORY_TURNS = 3
    for _ in range(MAX_HISTORY_TURNS):
        if cursor is None:
            break
        chain.append(cursor)
        cursor = cursor.parent_query

    chain.reverse()  # oldest first
    for prior in chain:
        history.append({"role": "user", "content": prior.user_query})
        assistant_text = prior.summary or "(no response recorded)"
        history.append({"role": "assistant", "content": assistant_text})
    return history


def _resolve_parent_query(request, session, parent_id_raw):
    """Look up a parent Query, scoped to what the requester is allowed to see.

    Same access rules as search_stream's parent lookup: the requester's
    own session, or any query on their active team. Returns None if
    parent_id_raw is missing, malformed, or refers to a query the user
    can't see.
    """
    if not parent_id_raw:
        return None
    try:
        pid = int(parent_id_raw)
    except (ValueError, TypeError):
        return None

    qs = Query.objects.filter(id=pid)
    active_team_for_parent = _get_active_team(request)
    if active_team_for_parent is not None:
        from django.db.models import Q as DjQ
        qs = qs.filter(DjQ(session=session) | DjQ(team=active_team_for_parent))
    else:
        qs = qs.filter(session=session)
    return qs.first()


def _persist_runtime_result(query_row, result, duration_ms: int) -> None:
    """Persist an MCP runtime result and its tool calls onto an existing Query."""
    if result is None:
        Query.objects.filter(id=query_row.id).update(
            success=False,
            error="No result returned from runtime",
            duration_ms=duration_ms,
        )
        return

    Query.objects.filter(id=query_row.id).update(
        success=result.success,
        error=result.error,
        interpreted_action=result.action,
        interpreted_params=result.params,
        server_used=result.server_used,
        summary=result.formatted_response,
        raw_results=result.raw_results,
        duration_ms=duration_ms,
    )

    for call in result.tool_calls_made:
        try:
            ToolCall.objects.create(
                query_id=query_row.id,
                tool_name=call.get("tool", "unknown"),
                server_name=call.get("server") or "unknown",
                arguments=call.get("args"),
                result=call.get("result"),
                success=call.get("success", False),
                error=call.get("error"),
            )
        except Exception:
            logger.exception("Failed to write ToolCall row")


def _auto_run_context_suggestion(request, team, suggestion: dict):
    """Run one AI-recommended Team Context query and add its output to the team view."""
    query_text = (suggestion or {}).get("query", "").strip()
    if not query_text:
        return None

    session = getattr(request, "osint_session", None)
    if session is None:
        logger.warning("context auto-run skipped: request has no osint_session")
        return None

    from datetime import timedelta
    from django.utils import timezone as django_tz

    cutoff = django_tz.now() - timedelta(hours=24)
    existing = (
        Query.objects
        .filter(team=team, user_query=query_text, created_at__gte=cutoff)
        .order_by("-created_at")
        .first()
    )
    if existing:
        return existing

    query_row = Query.objects.create(
        session=session,
        user=None,
        team=team,
        user_query=query_text,
    )

    start_time = time.time()
    try:
        runtime = get_runtime()
        result = runtime.process_query_sync(
            user_query=query_text,
            timeout=300.0,
            history=[],
        )
        _persist_runtime_result(
            query_row,
            result,
            int((time.time() - start_time) * 1000),
        )
    except Exception as exc:
        logger.exception("context auto-run query failed")
        Query.objects.filter(id=query_row.id).update(
            success=False,
            error=str(exc),
            duration_ms=int((time.time() - start_time) * 1000),
        )

    return Query.objects.get(id=query_row.id)


@login_required
def teams_list(request):
    """Show all teams the user belongs to, with the active one marked."""
    memberships = (
        TeamMembership.objects
        .filter(user=request.user)
        .select_related('team')
        .order_by('-team__created_at')
    )
    active_team = _get_active_team(request)
    return render(request, "researcher/teams_list.html", {
        "memberships": memberships,
        "active_team": active_team,
    })


@login_required
def team_create(request):
    """Create a new team. Creator is auto-added as owner and becomes active."""
    if request.method == "POST":
        name = (request.POST.get("name") or "").strip()
        if not name:
            messages.error(request, "Team name can't be empty.")
            return render(request, "researcher/team_create.html")
        if len(name) > 120:
            messages.error(request, "Team name is too long (max 120 characters).")
            return render(request, "researcher/team_create.html")

        team = Team.objects.create(name=name, created_by=request.user)
        TeamMembership.objects.create(
            user=request.user,
            team=team,
            role=TeamMembership.ROLE_OWNER,
        )
        _set_active_team(request, team)
        messages.success(request, f"Team '{team.name}' created. Invite code: {team.invite_code}")
        return redirect("teams_list")

    return render(request, "researcher/team_create.html")


@login_required
def team_join(request):
    """Join an existing team by invite code.

    Accepts the code via:
      - POST form field 'invite_code'
      - GET query param 'code' (for shareable URLs; form is pre-filled)
    """
    prefill = (request.GET.get("code") or "").strip().upper()

    if request.method == "POST":
        code = (request.POST.get("invite_code") or "").strip().upper()
        if not code:
            messages.error(request, "Please enter an invite code.")
            return render(request, "researcher/team_join.html", {"prefill": prefill})

        team = Team.objects.filter(invite_code=code).first()
        if team is None:
            messages.error(request, f"No team found with invite code '{code}'.")
            return render(request, "researcher/team_join.html", {"prefill": code})

        membership, created = TeamMembership.objects.get_or_create(
            user=request.user,
            team=team,
            defaults={"role": TeamMembership.ROLE_MEMBER},
        )
        if created:
            messages.success(request, f"Joined '{team.name}'.")
        else:
            messages.info(request, f"You're already in '{team.name}'.")
        _set_active_team(request, team)
        return redirect("teams_list")

    return render(request, "researcher/team_join.html", {"prefill": prefill})


@login_required
def team_switch(request, team_id: int):
    """Set a team as the user's active team. POST only.

    Returns 404 if the user isn't a member of that team — we don't leak
    existence of teams the user doesn't belong to.
    """
    if request.method != "POST":
        return redirect("teams_list")

    team = get_object_or_404(
        Team,
        id=team_id,
        memberships__user=request.user,
    )
    _set_active_team(request, team)
    messages.success(request, f"Switched to '{team.name}'.")
    return redirect("teams_list")


@csrf_exempt
@require_http_methods(["POST"])
def parse_query(request):
    """
    Parse a query and return the interpreted action for user confirmation.
    Unchanged from previous version — this doesn't hit MCP, just Anthropic.
    """
    try:
        data = json.loads(request.body)
        user_query = data.get("query", "").strip()

        if not user_query:
            return JsonResponse({"error": "Please enter a query"}, status=400)

        # If this is a follow-up, load prior turns so the parser can resolve
        # references like "that domain" or "its DNS records". Without this
        # the parser sees only the bare follow-up text and asks for clarification,
        # killing the thread before it ever reaches search_stream.
        session = getattr(request, "osint_session", None)
        parent_id_raw = data.get("parent_id")
        parent_query = _resolve_parent_query(request, session, parent_id_raw) if session else None
        history = _build_history_from_parent(parent_query)

        tools = get_claude_tool_definitions()
        system_prompt = f"""You are an OSINT query parser. Determine which tool to use for the user's query.

{get_tools_for_prompt()}

Choose the most appropriate tool or tools. If the query requires several lookups, emit the likely tool calls in the order they should run so the user can approve the brief plan. If the query is unclear or doesn't match any tool, respond with text asking for clarification.

If the user's query refers to something from prior turns ("that domain", "its DNS records", "the registrar"), resolve the reference using the conversation history before picking a tool. The tool's argument should be the concrete value (e.g. "google.com"), not the pronoun."""

        # Build messages: prior turns first, then the new user query.
        parse_messages = list(history)
        parse_messages.append({"role": "user", "content": user_query})

        response = get_provider().create(
            tier="main",
            max_tokens=512,
            system=system_prompt,
            tools=tools,
            messages=parse_messages,
        )

        tool_uses = [block for block in response.content if block.type == "tool_use"]
        if tool_uses:
            first_tool = tool_uses[0]
            action = first_tool.name
            params = first_tool.input
            msg, _est_time, server = get_confirmation_message(action, params)
            tool_plan = _build_confirmation_plan(tool_uses)
            if len(tool_plan) > 1:
                tool_names = ", ".join(item["tool"] for item in tool_plan)
                msg = (
                    f"{msg} The agent's current plan may also use these tools "
                    f"as part of the execution: {tool_names}."
                )
            return JsonResponse({
                "success": True,
                    "interpreted_action": action,
                    "interpreted_params": params,
                    "confirmation_message": msg,
                    "source": server,
                    "tool_plan": tool_plan,
                })

        for block in response.content:
            if block.type == "text":
                return JsonResponse({"success": False, "error": block.text})

        return JsonResponse({"success": False, "error": "Could not understand query"})

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        logger.exception("parse_query failed")
        return JsonResponse({"error": str(e)}, status=500)

@require_http_methods(["GET"])
def thread_history(request, parent_id: int):
    """Return the ancestor chain for a Query as JSON, oldest-first.

    Used by the index page on follow-up handoff: when a user lands at
    /?parent_id=N, the page fetches this endpoint to render prior turns
    as visible cards in the thread before running the new query.

    Access control mirrors search_stream: requester must own the chain
    (same anonymous session) or be on the team that owns it.
    """
    session = getattr(request, "osint_session", None)
    if session is None:
        return JsonResponse({"error": "Session not initialized"}, status=400)

    root = _resolve_parent_query(request, session, str(parent_id))
    if root is None:
        # Don't leak the existence of queries the requester can't see.
        return JsonResponse({"error": "Not found"}, status=404)

    # Walk the chain. Same cap as the LLM-context history (3 turns) so the
    # UI matches what Claude actually sees.
    MAX_THREAD_TURNS = 3
    chain = []
    cursor = root
    for _ in range(MAX_THREAD_TURNS):
        if cursor is None:
            break
        chain.append(cursor)
        cursor = cursor.parent_query
    chain.reverse()  # oldest first

    turns = []
    for q in chain:
        # Pull tool calls per query for the collapsed details view.
        tool_calls = list(
            q.tool_calls.values(
                "tool_name", "server_name", "success", "error"
            ).order_by("created_at")
        )
        turns.append({
            "id": q.id,
            "user_query": q.user_query,
            "summary": q.summary,
            "success": q.success,
            "error": q.error,
            "interpreted_action": q.interpreted_action,
            "server_used": q.server_used,
            "raw_results": q.raw_results,
            "tool_calls": tool_calls,
            "author": (q.user.username if q.user_id else None),
            "created_at": q.created_at.isoformat(),
        })

    return JsonResponse({"turns": turns})

@csrf_exempt
@require_http_methods(["GET"])
def search_stream(request):
    """
    Execute a search with real-time progress updates via Server-Sent Events.

    Uses the shared MCPRuntime singleton — no per-request reconnect.
    Writes Query + ToolCall rows to the database on every call.
    """
    user_query = request.GET.get("query", "").strip()

    if not user_query:
        def error_stream():
            yield f"event: error\ndata: {json.dumps({'error': 'Please enter a query'})}\n\n"
        return StreamingHttpResponse(error_stream(), content_type="text/event-stream")

    # Create the Query row immediately, before any work starts. This way even
    # if the search errors out mid-flight we still have a record of what was
    # attempted. Tied to the anonymous session set by middleware.
    session = getattr(request, "osint_session", None)
    if session is None:
        # Shouldn't happen if middleware is installed, but don't crash if it isn't.
        logger.warning("search_stream: request has no osint_session")
        def error_stream():
            yield f"event: error\ndata: {json.dumps({'error': 'Session not initialized'})}\n\n"
        return StreamingHttpResponse(error_stream(), content_type="text/event-stream")

    parent_query = _resolve_parent_query(
        request, session, request.GET.get("parent_id")
    )

    
    # Build history from the parent chain so Claude has conversational context.
    history = _build_history_from_parent(parent_query)

    active_team = _get_active_team(request)
    query_user = request.user if request.user.is_authenticated else None

    query_row = Query.objects.create(
        session=session,
        user=query_user,
        team=active_team,
        user_query=user_query,
        parent_query=parent_query,
    )
    query_id = query_row.id
    start_time = time.time()

    # Queue for progress updates from the runtime thread to the SSE thread.
    progress_queue = queue.Queue()
    result_holder = {"result": None, "error": None, "persisted": False}
    persist_lock = threading.Lock()

    def progress_callback(update: ProgressUpdate):
        """Called by MCPRuntime's background loop with progress updates."""
        progress_queue.put({
            "type": "progress",
            "stage": update.stage,
            "message": update.message,
            "details": update.details,
            "progress_percent": update.progress_percent,
        })

    def persist_query_result():
        """Write final result back to the Query row, create ToolCall rows,
        and generate follow-up suggestions via a separate Haiku call."""
        from .services.followups import generate_followups

        with persist_lock:
            if result_holder["persisted"]:
                return
            result_holder["persisted"] = True

        duration_ms = int((time.time() - start_time) * 1000)

        if result_holder["error"]:
            Query.objects.filter(id=query_id).update(
                success=False,
                error=result_holder["error"],
                duration_ms=duration_ms,
            )
            return

        result = result_holder["result"]
        if result is None:
            Query.objects.filter(id=query_id).update(
                success=False,
                error="No result returned from runtime",
                duration_ms=duration_ms,
            )
            return

        # Generate follow-up suggestions. This is a best-effort call that
        # never raises — empty list on any failure. We only bother if the
        # main query actually succeeded, since suggesting follow-ups for
        # a failed search doesn't make sense.
        suggestions: list[str] = []
        if result.success:
            try:
                suggestions = generate_followups(
                    user_query=user_query,
                    summary=result.formatted_response,
                    tool_calls=result.tool_calls_made or [],
                )
            except Exception:
                logger.exception("generate_followups call blew up unexpectedly")

        Query.objects.filter(id=query_id).update(
            success=result.success,
            error=result.error,
            interpreted_action=result.action,
            interpreted_params=result.params,
            server_used=result.server_used,
            summary=result.formatted_response,
            raw_results=result.raw_results,
            duration_ms=duration_ms,
            suggested_queries=suggestions if suggestions else None,
        )

        # Stash suggestions on the result holder so the SSE event stream
        # can include them in the final `result` payload.
        result_holder["suggestions"] = suggestions

        # Tool call rows (unchanged from 2a)
        for call in result.tool_calls_made:
            try:
                ToolCall.objects.create(
                    query_id=query_id,
                    tool_name=call.get("tool", "unknown"),
                    server_name=call.get("server") or "unknown",
                    arguments=call.get("args"),
                    result=call.get("result"),
                    success=call.get("success", False),
                    error=call.get("error"),
                )
            except Exception:
                logger.exception("Failed to write ToolCall row")

    def run_search():
        """Run the search and persist final results in a worker thread."""
        try:
            close_old_connections()
            runtime = get_runtime()
            result = runtime.process_query_sync(
                user_query=user_query,
                progress_callback=progress_callback,
                timeout=300.0,
                history=history,
            )
            result_holder["result"] = result
        except Exception as e:
            logger.exception("search_stream: runtime call failed")
            result_holder["error"] = str(e)
        finally:
            try:
                persist_query_result()
            except Exception:
                logger.exception("persist_query_result failed in background worker")
            progress_queue.put({"type": "done"})
            close_old_connections()

    search_thread = threading.Thread(target=run_search, daemon=True)
    search_thread.start()

    def event_stream():
        """Generate SSE events while the background worker runs."""
        try:
            while True:
                try:
                    item = progress_queue.get(timeout=1)
                except queue.Empty:
                    yield f": keepalive\n\n"
                    continue

                if item["type"] == "done":
                    if result_holder["error"]:
                        yield f"event: error\ndata: {json.dumps({'error': result_holder['error']})}\n\n"
                    elif result_holder["result"]:
                        result = result_holder["result"]
                        response_data = {
                            "success": result.success,
                            "error": result.error,
                            "action": result.action,
                            "server": result.server_used,
                            "params": result.params,
                            "total_found": (
                                result.raw_results.get("total_found", 0)
                                if result.raw_results else 0
                            ),
                            "turns": (
                                result.raw_results.get("turns", 1)
                                if result.raw_results else 1
                            ),
                            "summary": result.formatted_response,
                            "tool_calls": result.tool_calls_made,
                            "raw_results": result.raw_results,
                            "execution_steps": (
                                result.raw_results.get("execution_steps", [])
                                if result.raw_results else []
                            ),
                            "suggested_queries": result_holder.get("suggestions") or [],
                            "query_id": query_id,
                            "answer_source": result.answer_source,
                        }
                        yield f"event: result\ndata: {json.dumps(response_data)}\n\n"
                    break

                elif item["type"] == "progress":
                    yield f"event: progress\ndata: {json.dumps(item)}\n\n"
        except GeneratorExit:
            # If the user cancels while the runtime is still processing, do not
            # write an artificial failure such as "No result returned". If the
            # runtime already completed, persist the actual outcome.
            try:
                _handle_query_stream_disconnect(query_id, result_holder, persist_query_result)
            except Exception:
                logger.exception("persist_query_result failed on disconnect")
            raise

    response = StreamingHttpResponse(event_stream(), content_type="text/event-stream")
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return response


@csrf_exempt
@require_http_methods(["GET"])
def capabilities(request):
    """
    Get available tools and capabilities from the shared runtime.
    No per-request connection — reads from the already-connected singleton.
    """
    try:
        runtime = get_runtime()
        if not runtime.wait_ready(timeout=10):
            return JsonResponse(
                {"error": "Runtime not ready", "detail": runtime.startup_error},
                status=503,
            )

        # Submit to the background loop via the runtime's shared client.
        future = runtime.submit(runtime._client.get_server_capabilities())
        caps = future.result(timeout=30)

        if "error" in caps:
            return JsonResponse(caps, status=500)

        response = {
            "servers": {},
            "total_tools": caps.get("total_tools", 0),
            "examples": [
                "Find all social media accounts for john_doe",
                "Who owns google.com?",
                "What are the DNS records for github.com?",
                "What is the IP geolocation for 8.8.8.8?",
                "Find subdomains of example.com",
                "Check threat intelligence for suspicious-domain.com",
            ],
        }

        for server_name, server_caps in caps.get("servers", {}).items():
            response["servers"][server_name] = {
                "tool_count": server_caps.get("tool_count", 0),
                "tools": [
                    {
                        "name": t["name"],
                        "description": (
                            t["description"][:100] + "..."
                            if len(t["description"]) > 100 else t["description"]
                        ),
                    }
                    for t in server_caps.get("tools", [])
                ],
            }

        return JsonResponse(response)

    except Exception as e:
        logger.exception("capabilities failed")
        return JsonResponse({"error": str(e)}, status=500)


@login_required
def benchmark(request):
    """Render a benchmark table whose rows run through the backend agent."""
    return render(request, "researcher/benchmark.html", {
        "benchmark_queries": BENCHMARK_QUERIES,
    })


@login_required
@require_http_methods(["POST"])
def benchmark_run(request):
    """Run one benchmark query through the shared MCP runtime."""
    try:
        data = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    benchmark_id = (data.get("id") or "").strip()
    row = next((item for item in BENCHMARK_QUERIES if item["id"] == benchmark_id), None)
    if row is None:
        return JsonResponse({"error": "Unknown benchmark ID"}, status=404)

    start = time.time()
    try:
        result = get_runtime().process_query_sync(
            user_query=row["query"],
            timeout=300.0,
            history=None,
        )
    except Exception as exc:
        logger.exception("benchmark_run failed")
        return JsonResponse({
            "id": benchmark_id,
            "query": row["query"],
            "success": False,
            "error": str(exc),
            "duration_ms": int((time.time() - start) * 1000),
        })

    raw_results = result.raw_results or {}
    tool_calls = result.tool_calls_made or raw_results.get("tool_calls") or []
    return JsonResponse({
        "id": benchmark_id,
        "query": row["query"],
        "success": result.success,
        "error": result.error,
        "summary": result.formatted_response,
        "action": result.action,
        "server": result.server_used,
        "params": result.params,
        "tool_calls": tool_calls,
        "raw_results": raw_results,
        "answer_source": result.answer_source or raw_results.get("answer_source"),
        "duration_ms": int((time.time() - start) * 1000),
    })
    
@login_required
def workspace(request):
    """Shared team workspace with search history and team browsing context panel."""
    active_team = _get_active_team(request)
    if active_team is None:
        messages.info(request, "Pick or create a team to use the shared workspace.")
        return redirect("teams_list")

    member_count = TeamMembership.objects.filter(team=active_team).count()

    context_aware_enabled = request.session.get(CONTEXT_AWARE_SESSION_KEY, False)

    # Only load / refresh the browsing summary when context mode is ON.
    browsing_summary = {}
    if context_aware_enabled:
        from .services.browsing_summary import is_summary_stale, get_cached_summary, refresh_team_context
        try:
            if is_summary_stale(active_team):
                browsing_summary = refresh_team_context(
                    active_team,
                    requesting_user=request.user,
                    auto_run_callback=lambda suggestion: _auto_run_context_suggestion(
                        request,
                        active_team,
                        suggestion,
                    ),
                )
            else:
                browsing_summary = get_cached_summary(active_team)
        except Exception:
            logger.exception("browsing context refresh failed, using cached or empty")
            browsing_summary = get_cached_summary(active_team)

    queries = (
        Query.objects
        .filter(team=active_team)
        .select_related('user')
        .prefetch_related('tool_calls')
        .order_by('-created_at')[:50]
    )
    query_list = list(queries)
    query_payloads = [_serialize_workspace_query(q) for q in query_list]

    selected_query_id = request.GET.get("query_id")
    if selected_query_id:
        try:
            selected_query_id = int(selected_query_id)
        except (TypeError, ValueError):
            selected_query_id = None
    if selected_query_id and not any(q["id"] == selected_query_id for q in query_payloads):
        selected = (
            Query.objects
            .filter(team=active_team, id=selected_query_id)
            .select_related("user")
            .prefetch_related("tool_calls")
            .first()
        )
        if selected:
            query_payloads.insert(0, _serialize_workspace_query(selected))

    return render(request, "researcher/workspace.html", {
        "active_team": active_team,
        "queries": query_list,
        "query_payloads": query_payloads,
        "selected_query_id": selected_query_id,
        "member_count": member_count,
        "browsing_summary": browsing_summary,
        "context_aware_enabled": context_aware_enabled,
    })


@login_required
@require_http_methods(["POST"])
def workspace_refresh_context(request):
    """Force-regenerate the team browsing context summary and suggestions.

    Called by the workspace Refresh button. Returns JSON so the page
    can update the right panel without a full reload.
    """
    active_team = _get_active_team(request)
    if active_team is None:
        return JsonResponse({"error": "No active team"}, status=400)

    from .services.browsing_summary import refresh_team_context
    try:
        data = refresh_team_context(
            active_team,
            requesting_user=request.user,
            auto_run_callback=lambda suggestion: _auto_run_context_suggestion(
                request,
                active_team,
                suggestion,
            ),
        )
        return JsonResponse({"ok": True, "data": data})
    except Exception as exc:
        logger.exception("workspace_refresh_context failed")
        return JsonResponse({"error": str(exc)}, status=500)


@login_required
def workspace_context_simulation(request):
    """Render a live Team Context prompt simulation page.

    The page exercises the same summary and suggestion prompts used by the
    workspace Team Context pane, using either two recent real team members'
    browsing events or a built-in realistic two-member dataset.
    """
    from .services.browsing_summary import run_team_context_prompt_simulation

    active_team = _get_active_team(request)
    result = run_team_context_prompt_simulation(active_team)
    return render(request, "researcher/context_simulation.html", {
        "active_team": active_team,
        "simulation": result,
    })


@login_required
def workspace_query_detail(request, query_id: int):
    """Detail view for a single query in the team workspace.

    Access control: the requester must either be on the team this query
    belongs to, or be the user who ran it (covers the case of a query
    that was run before the user's active team was set).
    """
    query = get_object_or_404(Query, id=query_id)

    user_is_member = False
    if query.team_id is not None:
        user_is_member = TeamMembership.objects.filter(
            team_id=query.team_id, user=request.user
        ).exists()

    user_is_author = (query.user_id == request.user.id)

    if not (user_is_member or user_is_author):
        # Don't leak the existence of queries the user can't see.
        from django.http import Http404
        raise Http404("Query not found")

    tool_calls = query.tool_calls.all().order_by('created_at')

    return render(request, "researcher/workspace_detail.html", {
        "query": query,
        "tool_calls": tool_calls,
        "active_team": _get_active_team(request),
    })

@login_required
@require_http_methods(["GET"])
def notifications_list(request):
    """Return the current user's unread notifications as JSON.

    Used by the workspace bell-icon poller. Caps at 20 items — if a user
    really has more than 20 unread, they can clear them by clicking through.
    """
    notifs = (
        Notification.objects
        .filter(recipient=request.user, is_read=False)
        .exclude(suggestion_text="")
        .select_related('query', 'query__user')
        .order_by('-created_at')[:20]
    )

    items = []
    for n in notifs:
        if n.suggestion_text:
            author = "AI Research Assistant"
            text = n.suggestion_text
            notif_type = "suggestion"
        elif n.query_id:
            # Legacy unread query notifications may still exist, but new team
            # member queries no longer create notifications.
            author = n.query.user.username if n.query.user_id else "anonymous"
            text = n.query.user_query
            notif_type = "query"
        else:
            author = "AI Research Assistant"
            text = ""
            notif_type = "suggestion"

        if len(text) > 80:
            text = text[:77] + "…"
        items.append({
            "id": n.id,
            "query_id": n.query_id,
            "query_text": text,
            "author": author,
            "type": notif_type,
            "created_at": n.created_at.isoformat(),
        })

    return JsonResponse({
        "unread_count": len(items),
        "notifications": items,
    })


@login_required
@require_http_methods(["POST"])
def notification_mark_read(request, notif_id: int):
    """Mark a single notification as read. Returns JSON ack.

    Only the recipient can mark their own. We update by filter so a 404
    silently no-ops rather than 500ing — the user clicked something, the
    server's job is to not block them.
    """
    Notification.objects.filter(
        id=notif_id, recipient=request.user
    ).update(is_read=True)
    return JsonResponse({"ok": True})


# ===================== BROWSER EXTENSION API =====================


@csrf_exempt
def extension_status(request):
    """Return auth status and context-aware mode flag for the browser extension.

    Accepts authentication via the normal Django session cookie (same-origin)
    OR via the X-Session-Id custom header sent by the browser extension.
    """
    # Handle CORS preflight from extension origin
    if request.method == "OPTIONS":
        resp = JsonResponse({})
        return _extension_cors(resp, request)

    _setup_extension_request(request)

    if not request.user.is_authenticated:
        resp = JsonResponse({"authenticated": False, "context_aware_enabled": False})
        return _extension_cors(resp, request)

    active_team = _get_extension_team(request)
    resp = JsonResponse({
        "authenticated": True,
        "username": request.user.username,
        "team_name": active_team.name if active_team else None,
        "team_id": active_team.id if active_team else None,
        "context_aware_enabled": request.session.get(CONTEXT_AWARE_SESSION_KEY, False),
    })
    return _extension_cors(resp, request)


@csrf_exempt
@require_http_methods(["POST"])
def extension_toggle(request):
    """Toggle context-aware mode on/off. Called by the landing page toggle button.

    This is always called same-origin from the web app, so normal Django auth applies.
    """
    if not request.user.is_authenticated:
        return JsonResponse({"error": "Not authenticated"}, status=401)
    current = request.session.get(CONTEXT_AWARE_SESSION_KEY, False)
    request.session[CONTEXT_AWARE_SESSION_KEY] = not current
    return JsonResponse({"context_aware_enabled": request.session[CONTEXT_AWARE_SESSION_KEY]})


@csrf_exempt
def extension_events_create(request):
    """Accept a browsing event from the browser extension and persist it."""
    # Handle CORS preflight from extension origin
    if request.method == "OPTIONS":
        resp = JsonResponse({})
        return _extension_cors(resp, request)

    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    _setup_extension_request(request)

    if not request.user.is_authenticated:
        resp = JsonResponse({"error": "Not authenticated"}, status=401)
        return _extension_cors(resp, request)

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    active_team = _get_active_team(request)

    allowed_types = {BrowsingEvent.EVENT_VISIT, BrowsingEvent.EVENT_SEARCH}
    event_type = data.get("event_type", BrowsingEvent.EVENT_VISIT)
    if event_type not in allowed_types:
        event_type = BrowsingEvent.EVENT_VISIT

    event = BrowsingEvent.objects.create(
        user=request.user,
        team=active_team,
        event_type=event_type,
        url=data.get("url", "")[:2000],
        site_name=data.get("site_name", "")[:255],
        page_title=data.get("page_title", "")[:500],
        top_heading=data.get("top_heading", "")[:500],
        search_query=data.get("search_query", "")[:1000],
    )
    resp = JsonResponse({"id": event.id, "created": True})
    return _extension_cors(resp, request)


@csrf_exempt
def extension_events_list(request):
    """Return recent browsing events for the current user (last 50).

    Used by the extension side panel to populate the event feed.
    """
    if request.method == "OPTIONS":
        resp = JsonResponse({})
        return _extension_cors(resp, request)

    _setup_extension_request(request)

    if not request.user.is_authenticated:
        resp = JsonResponse({"authenticated": False, "events": []})
        return _extension_cors(resp, request)

    events = BrowsingEvent.objects.filter(
        user=request.user
    ).select_related("team").order_by("-created_at")[:50]

    resp = JsonResponse({
        "events": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "url": e.url,
                "site_name": e.site_name,
                "page_title": e.page_title,
                "top_heading": e.top_heading,
                "search_query": e.search_query,
                "team_name": e.team.name if e.team_id else None,
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ]
    })
    return _extension_cors(resp, request)
