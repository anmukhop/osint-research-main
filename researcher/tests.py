from unittest.mock import patch
from datetime import timedelta
import asyncio
import json
import time
from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone as django_tz

from researcher.models import (
    BrowsingEvent,
    BrowsingTeamSummary,
    Notification,
    Query,
    Session,
    Team,
    TeamMembership,
)
from researcher import views
from researcher.services import browsing_summary
from researcher.services.mcp_client import OSINTMCPClient, QueryResult
from researcher.services.llm_provider import AnthropicProvider, OpenAICompatProvider, get_provider
from researcher.services.tool_registry import (
    TOOLS,
    get_confirmation_message,
    get_confirmation_placeholders,
)


class TeamContextSimulationTests(TestCase):
    def test_team_events_are_team_scoped_and_limited_to_last_10_minutes(self):
        User = get_user_model()
        user = User.objects.create_user(username="analyst", password="pass12345")
        other_user = User.objects.create_user(username="other", password="pass12345")
        team = Team.objects.create(name="Recent Team", created_by=user)
        other_team = Team.objects.create(name="Other Team", created_by=other_user)
        TeamMembership.objects.create(user=user, team=team)
        TeamMembership.objects.create(user=other_user, team=other_team)

        recent = BrowsingEvent.objects.create(
            user=user,
            team=team,
            event_type=BrowsingEvent.EVENT_VISIT,
            url="https://security.vt.edu",
            site_name="security.vt.edu",
            top_heading="Alerts",
        )
        old = BrowsingEvent.objects.create(
            user=user,
            team=team,
            event_type=BrowsingEvent.EVENT_VISIT,
            url="https://old.example.com",
            site_name="old.example.com",
        )
        BrowsingEvent.objects.filter(id=old.id).update(
            created_at=django_tz.now() - timedelta(minutes=11)
        )
        BrowsingEvent.objects.create(
            user=other_user,
            team=other_team,
            event_type=BrowsingEvent.EVENT_VISIT,
            url="https://other.example.com",
            site_name="other.example.com",
        )

        by_user = browsing_summary._collect_team_events(team)

        self.assertEqual(list(by_user.keys()), ["analyst"])
        self.assertEqual(by_user["analyst"]["visits"][0]["site"], recent.site_name)
        self.assertNotIn("old.example.com", str(by_user))
        self.assertNotIn("other.example.com", str(by_user))

    def test_summary_stale_requires_three_minutes_and_new_team_event(self):
        User = get_user_model()
        user = User.objects.create_user(username="analyst", password="pass12345")
        team = Team.objects.create(name="TTL Team", created_by=user)
        TeamMembership.objects.create(user=user, team=team)
        summary = BrowsingTeamSummary.objects.create(team=team, data={"overview": "old"})
        event = BrowsingEvent.objects.create(
            user=user,
            team=team,
            event_type=BrowsingEvent.EVENT_SEARCH,
            url="https://google.com/search?q=old",
            site_name="google.com",
            search_query="old",
        )
        BrowsingEvent.objects.filter(id=event.id).update(
            created_at=django_tz.now() - timedelta(minutes=5)
        )
        BrowsingTeamSummary.objects.filter(team=team).update(
            generated_at=django_tz.now() - timedelta(minutes=4)
        )

        self.assertFalse(browsing_summary.is_summary_stale(team))

        BrowsingEvent.objects.create(
            user=user,
            team=team,
            event_type=BrowsingEvent.EVENT_SEARCH,
            url="https://google.com/search?q=vt.edu",
            site_name="google.com",
            search_query="vt.edu",
        )

        self.assertTrue(browsing_summary.is_summary_stale(team))

    def test_refresh_returns_cached_summary_without_auto_run_when_no_new_events(self):
        User = get_user_model()
        user = User.objects.create_user(username="analyst", password="pass12345")
        team = Team.objects.create(name="No New Events Team", created_by=user)
        TeamMembership.objects.create(user=user, team=team)
        event = BrowsingEvent.objects.create(
            user=user,
            team=team,
            event_type=BrowsingEvent.EVENT_VISIT,
            url="https://security.vt.edu",
            site_name="security.vt.edu",
        )
        BrowsingEvent.objects.filter(id=event.id).update(
            created_at=django_tz.now() - timedelta(minutes=5)
        )
        cached = {"overview": "cached", "suggestions": []}
        BrowsingTeamSummary.objects.create(team=team, data=cached)
        BrowsingTeamSummary.objects.filter(team=team).update(
            generated_at=django_tz.now() - timedelta(minutes=4)
        )

        with (
            patch.object(browsing_summary, "_call_summary") as call_summary,
            patch.object(browsing_summary, "_call_suggestions") as call_suggestions,
        ):
            data = browsing_summary.refresh_team_context(
                team,
                requesting_user=user,
                auto_run_callback=lambda suggestion: self.fail("auto-run should not happen"),
            )

        self.assertEqual(data, cached)
        call_summary.assert_not_called()
        call_suggestions.assert_not_called()

    def test_refresh_clears_context_when_no_events_remain_in_window(self):
        User = get_user_model()
        user = User.objects.create_user(username="analyst", password="pass12345")
        team = Team.objects.create(name="Expired Events Team", created_by=user)
        TeamMembership.objects.create(user=user, team=team)
        old_event = BrowsingEvent.objects.create(
            user=user,
            team=team,
            event_type=BrowsingEvent.EVENT_VISIT,
            url="https://expired.example.com",
            site_name="expired.example.com",
        )
        BrowsingEvent.objects.filter(id=old_event.id).update(
            created_at=django_tz.now() - timedelta(minutes=11)
        )
        BrowsingTeamSummary.objects.create(
            team=team,
            data={"overview": "expired", "suggestions": [{"query": "old"}]},
        )

        data = browsing_summary.refresh_team_context(team, requesting_user=user)

        self.assertEqual(data, {"no_events": True, "suggestions": []})

    def test_simulation_runs_summary_and_suggestions_for_two_members(self):
        summary = {
            "overview": "The team is investigating Virginia Tech public infrastructure exposure.",
            "common_sites": ["virginiatech.edu", "security.vt.edu"],
            "common_search_themes": ["public IP exposure", "vt.edu infrastructure"],
            "per_user": {
                "maya": {
                    "sites": ["virginiatech.edu", "shodan.io"],
                    "searches": ["Virginia Tech public IP exposure Shodan"],
                    "focus": "Maya is focused on exposed services and certificates.",
                },
                "leo": {
                    "sites": ["virginiatech.edu", "builtwith.com"],
                    "searches": ["vt.edu technology stack"],
                    "focus": "Leo is focused on web stack and subdomain discovery.",
                },
            },
            "unique_sites": {"maya": ["shodan.io"], "leo": ["builtwith.com"]},
            "unique_searches": {
                "maya": ["Virginia Tech public IP exposure Shodan"],
                "leo": ["vt.edu technology stack"],
            },
        }
        suggestions = [
            {
                "query": "What DNS records exist for vt.edu?",
                "tool": "dns_lookup",
                "reason": "The team is reviewing vt.edu infrastructure.",
                "recommended": True,
                "relevance_analysis": (
                    "Both members are researching vt.edu infrastructure, and DNS records "
                    "would identify assets to investigate next."
                ),
            },
        ]

        with (
            patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key", "LLM_PROVIDER": "anthropic"}),
            patch.object(browsing_summary, "_call_summary", return_value=summary) as call_summary,
            patch.object(browsing_summary, "_call_suggestions", return_value=suggestions) as call_suggestions,
        ):
            result = browsing_summary.run_team_context_prompt_simulation()

        self.assertEqual(set(result["events_by_user"].keys()), {"maya", "leo"})
        self.assertIn("User: maya", result["events_text"])
        self.assertIn("User: leo", result["events_text"])
        self.assertIn("Produce a JSON object", result["summary_prompt"])
        self.assertIn("CTF-style challenges", result["summary_prompt"])
        self.assertIn("Do not treat or investigate the Railway app itself", result["summary_prompt"])
        self.assertEqual(result["summary"], summary)
        self.assertEqual(result["suggestions"], suggestions)
        self.assertIn("generate AT MOST 1", result["suggestions_prompt"])
        self.assertIn("MCP architecture", result["suggestions_prompt"])
        self.assertIn("Do not generate a query about the Railway app itself", result["suggestions_prompt"])
        self.assertIn("Do NOT suggest investigating team members", result["suggestions_prompt"])
        self.assertIn("Do NOT repeat a query", result["suggestions_prompt"])
        self.assertIn("forward looking", result["suggestions_prompt"])
        self.assertIn("closest related AI-agent/tool capability", result["suggestions_prompt"])
        self.assertIn("2-3 short sentences", result["suggestions_prompt"])
        self.assertIn("maximum 40 words", result["suggestions_prompt"])
        self.assertIn("team member activity", result["suggestions_prompt"])
        call_summary.assert_called_once()
        call_suggestions.assert_called_once_with(summary)

    def test_refresh_context_auto_runs_recommended_query_and_notifies_after_result(self):
        User = get_user_model()
        requester = User.objects.create_user(username="owner", password="pass12345")
        teammate = User.objects.create_user(username="teammate", password="pass12345")
        team = Team.objects.create(name="Context Team", created_by=requester)
        TeamMembership.objects.create(user=requester, team=team, role=TeamMembership.ROLE_OWNER)
        TeamMembership.objects.create(user=teammate, team=team, role=TeamMembership.ROLE_MEMBER)
        session = Session.objects.create()
        BrowsingEvent.objects.create(
            user=requester,
            team=team,
            event_type=BrowsingEvent.EVENT_VISIT,
            url="https://virginiatech.edu/security",
            site_name="virginiatech.edu",
        )
        ai_query = Query.objects.create(
            session=session,
            team=team,
            user_query="What DNS records exist for vt.edu?",
            success=True,
            summary="DNS records found.",
        )

        summary = {"overview": "The team is researching vt.edu.", "per_user": {}}
        suggestions = [
            {
                "query": "What DNS records exist for vt.edu?",
                "tool": "dns_lookup",
                "reason": "The team is reviewing vt.edu infrastructure.",
                "recommended": True,
                "relevance_analysis": "Both members focused on vt.edu; DNS records identify next assets.",
            },
        ]

        with (
            patch.object(browsing_summary, "_collect_team_events", return_value={
                "owner": {"visits": [{"site": "virginiatech.edu"}], "searches": []},
                "teammate": {"visits": [{"site": "virginiatech.edu"}], "searches": []},
            }),
            patch.object(browsing_summary, "_call_summary", return_value=summary),
            patch.object(browsing_summary, "_call_suggestions", return_value=suggestions),
        ):
            data = browsing_summary.refresh_team_context(
                team,
                requesting_user=requester,
                auto_run_callback=lambda suggestion: ai_query,
            )

        self.assertEqual(data["auto_run_query_id"], ai_query.id)
        notif = Notification.objects.get(recipient=teammate)
        self.assertEqual(notif.query_id, ai_query.id)
        self.assertIn("[AI Research Result]", notif.suggestion_text)
        self.assertFalse(Notification.objects.filter(recipient=requester).exists())

    def test_notifications_endpoint_shows_only_ai_generated_query_notifications(self):
        User = get_user_model()
        recipient = User.objects.create_user(username="recipient", password="pass12345")
        teammate = User.objects.create_user(username="human", password="pass12345")
        session = Session.objects.create()
        human_query = Query.objects.create(
            session=session,
            user=teammate,
            user_query="Who owns example.com?",
            success=True,
        )
        ai_query = Query.objects.create(
            session=session,
            user=None,
            user_query="What DNS records exist for vt.edu?",
            success=True,
        )
        Notification.objects.create(recipient=recipient, query=human_query)
        Notification.objects.create(
            recipient=recipient,
            query=ai_query,
            suggestion_text="[AI Research Result] What DNS records exist for vt.edu?",
        )

        self.client.force_login(recipient)
        response = self.client.get(reverse("notifications_list"))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["unread_count"], 1)
        self.assertEqual(payload["notifications"][0]["type"], "suggestion")
        self.assertEqual(payload["notifications"][0]["query_id"], ai_query.id)
        self.assertIn("AI Research Result", payload["notifications"][0]["query_text"])

    @override_settings(ALLOWED_HOSTS=["testserver"])
    def test_context_simulation_page_renders_prompt_results(self):
        User = get_user_model()
        user = User.objects.create_user(username="sim_viewer", password="pass12345")

        payload = {
            "team_name": "Simulation Team",
            "source": "built-in realistic sample",
            "model": "claude-haiku-4-5-20251001",
            "events_by_user": {
                "maya": {
                    "visits": [{"site": "shodan.io", "heading": "128.173.236.101"}],
                    "searches": [{"site": "google.com", "query": "Virginia Tech public IP exposure"}],
                },
                "leo": {
                    "visits": [{"site": "builtwith.com", "heading": "Technology Profile"}],
                    "searches": [{"site": "builtwith.com", "query": "vt.edu technology stack"}],
                },
            },
            "events_text": "User: maya\n  visited: shodan.io\n\nUser: leo\n  visited: builtwith.com",
            "summary_prompt": "summary prompt",
            "summary": {"overview": "The team is researching vt.edu exposure."},
            "summary_error": "",
            "suggestions_prompt": "suggestions prompt",
            "suggestions": [
                {
                    "query": "What DNS records exist for vt.edu?",
                    "tool": "dns_lookup",
                    "reason": "Relevant to the infrastructure research.",
                    "recommended": True,
                    "relevance_analysis": "Both users are browsing vt.edu infrastructure, so DNS records advance asset discovery.",
                },
            ],
            "suggestions_error": "",
            "auto_run_query_id": None,
            "auto_run_error": "",
        }

        with patch(
            "researcher.services.browsing_summary.run_team_context_prompt_simulation",
            return_value=payload,
        ):
            self.client.force_login(user)
            response = self.client.get(reverse("workspace_context_simulation"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Team Context Prompt Simulation")
        self.assertContains(response, "maya")
        self.assertContains(response, "leo")
        self.assertContains(response, "The team is researching vt.edu exposure.")
        self.assertContains(response, "What DNS records exist for vt.edu?")


class MCPClientConcurrencyTests(TestCase):
    def test_concurrent_queries_do_not_block_or_share_progress_callbacks(self):
        client = OSINTMCPClient.__new__(OSINTMCPClient)
        client._connected = True
        client.progress_callback = None
        client.get_tools_for_claude = lambda: []

        class FakeMessages:
            def create(self, **kwargs):
                time.sleep(0.2)
                query = kwargs["messages"][-1]["content"]
                return SimpleNamespace(content=[
                    SimpleNamespace(type="text", text=f"done: {query}")
                ])

        client.llm = AnthropicProvider(client=SimpleNamespace(messages=FakeMessages()))

        events = {"a": [], "b": []}

        async def run_two():
            start = time.perf_counter()
            result_a, result_b = await asyncio.gather(
                client.process_query("query-a", progress_callback=lambda update: events["a"].append(update)),
                client.process_query("query-b", progress_callback=lambda update: events["b"].append(update)),
            )
            return result_a, result_b, time.perf_counter() - start

        result_a, result_b, elapsed = asyncio.run(run_two())

        self.assertTrue(result_a.success)
        self.assertTrue(result_b.success)
        self.assertEqual(result_a.formatted_response, "done: query-a")
        self.assertEqual(result_b.formatted_response, "done: query-b")
        self.assertLess(elapsed, 0.35)
        self.assertGreaterEqual(len(events["a"]), 2)
        self.assertGreaterEqual(len(events["b"]), 2)
        self.assertTrue(all(e.message for e in events["a"]))
        self.assertTrue(all(e.message for e in events["b"]))

    def test_failed_tool_with_final_text_is_agent_only_success(self):
        client = OSINTMCPClient.__new__(OSINTMCPClient)
        client._connected = True
        client.progress_callback = None
        client.MAX_AGENT_TURNS = 3
        client._whoisxml_backup_attempted = True
        client.get_tools_for_claude = lambda: [{"name": "breach_lookup"}]
        client.get_server_for_tool = lambda tool_name: "local"

        calls = {"count": 0}

        class FakeMessages:
            def create(self, **kwargs):
                calls["count"] += 1
                if calls["count"] == 1:
                    return SimpleNamespace(content=[
                        SimpleNamespace(
                            type="tool_use",
                            id="toolu_1",
                            name="breach_lookup",
                            input={"email": "person@example.com"},
                        )
                    ])
                return SimpleNamespace(content=[
                    SimpleNamespace(
                        type="text",
                        text="Yes, the email appears in the provided breach data.",
                    )
                ])

        client.llm = AnthropicProvider(client=SimpleNamespace(messages=FakeMessages()))

        async def fake_call_tool(tool_name, arguments):
            raise RuntimeError("lookup unavailable")

        client.call_tool = fake_call_tool

        result = asyncio.run(client.process_query("Was the email breached?"))

        self.assertTrue(result.success)
        self.assertIsNone(result.error)
        self.assertEqual(result.answer_source, "agent_only")
        self.assertEqual(result.raw_results["answer_source"], "agent_only")
        self.assertEqual(
            result.formatted_response,
            "Yes, the email appears in the provided breach data.",
        )

    def test_tool_call_executes_directly_and_records_steps(self):
        client = OSINTMCPClient.__new__(OSINTMCPClient)
        client._connected = True
        client.progress_callback = None
        client.MAX_AGENT_TURNS = 3
        client._whoisxml_backup_attempted = True
        client.get_tools_for_claude = lambda: [{"name": "dns_lookup"}]
        client.get_server_for_tool = lambda tool_name: "whoisxml"

        calls = {"model": 0, "tool": 0}
        class FakeMessages:
            def create(self, **kwargs):
                calls["model"] += 1
                if calls["model"] == 1:
                    return SimpleNamespace(content=[
                        SimpleNamespace(
                            type="tool_use",
                            id="toolu_1",
                            name="dns_lookup",
                            input={"domain": "vt.edu"},
                        )
                    ])
                return SimpleNamespace(content=[
                    SimpleNamespace(type="text", text="DNS records found.")
                ])

        client.llm = AnthropicProvider(client=SimpleNamespace(messages=FakeMessages()))

        async def fake_call_tool(tool_name, arguments):
            calls["tool"] += 1
            return SimpleNamespace(
                isError=False,
                content=[SimpleNamespace(text=json.dumps({"records": ["A 1.2.3.4"]}))],
            )

        client.call_tool = fake_call_tool

        result = asyncio.run(client.process_query("DNS for vt.edu"))

        self.assertTrue(result.success)
        self.assertEqual(calls["tool"], 1)
        self.assertEqual(result.tool_calls_made[0]["tool"], "dns_lookup")
        self.assertEqual(result.tool_calls_made[0]["args"], {"domain": "vt.edu"})
        self.assertEqual(result.raw_results["execution_steps"], ["dns_lookup"])

    def test_turn_cap_returns_summary_of_partial_findings(self):
        client = OSINTMCPClient.__new__(OSINTMCPClient)
        client._connected = True
        client.progress_callback = None
        client.MAX_AGENT_TURNS = 2
        client._whoisxml_backup_attempted = True
        client.get_tools_for_claude = lambda: [{"name": "dns_lookup"}]
        client.get_server_for_tool = lambda tool_name: "whoisxml"

        calls = {"model": 0, "tool": 0}

        class FakeMessages:
            def create(self, **kwargs):
                calls["model"] += 1
                if "tools" not in kwargs:
                    return SimpleNamespace(content=[
                        SimpleNamespace(
                            type="text",
                            text=(
                                "Reached the turn limit. Steps taken: "
                                "dns_lookup -> dns_lookup. Found DNS records so far."
                            ),
                        )
                    ])
                return SimpleNamespace(content=[
                    SimpleNamespace(
                        type="tool_use",
                        id=f"toolu_{calls['model']}",
                        name="dns_lookup",
                        input={"domainName": "vt.edu"},
                    )
                ])

        client.llm = AnthropicProvider(client=SimpleNamespace(messages=FakeMessages()))

        async def fake_call_tool(tool_name, arguments):
            calls["tool"] += 1
            return SimpleNamespace(
                isError=False,
                content=[SimpleNamespace(text=json.dumps({"records": [f"A 1.2.3.{calls['tool']}"]}))],
            )

        client.call_tool = fake_call_tool

        result = asyncio.run(client.process_query("Keep investigating DNS for vt.edu"))

        self.assertTrue(result.success)
        self.assertIsNone(result.error)
        self.assertEqual(calls["tool"], 2)
        self.assertEqual(calls["model"], 3)
        self.assertTrue(result.raw_results["hit_cap"])
        self.assertTrue(result.raw_results["partial_due_to_turn_limit"])
        self.assertEqual(result.raw_results["execution_steps"], ["dns_lookup", "dns_lookup"])
        self.assertIn("Steps taken", result.formatted_response)


class QueryApprovalAndCancellationTests(TestCase):
    @override_settings(ALLOWED_HOSTS=["testserver"])
    def test_benchmark_page_renders_query_table(self):
        User = get_user_model()
        user = User.objects.create_user(username="benchmark_user", password="pass12345")
        self.client.force_login(user)

        response = self.client.get(reverse("benchmark"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "OSINT Agent Benchmark")
        self.assertContains(response, "ST-01")
        self.assertContains(response, "Who is the registrant and registrar for vt.edu")
        self.assertContains(response, "benchmark-query-data")

    @override_settings(ALLOWED_HOSTS=["testserver"])
    def test_benchmark_run_calls_backend_agent_for_one_query(self):
        User = get_user_model()
        user = User.objects.create_user(username="benchmark_runner", password="pass12345")
        self.client.force_login(user)

        fake_result = QueryResult(
            success=True,
            action="whois",
            params={"domain": "vt.edu"},
            raw_results={"tool_calls": [{"tool": "whois", "server": "whoisxml", "success": True}]},
            formatted_response="Registrar and registrant details.",
            tool_calls_made=[{"tool": "whois", "server": "whoisxml", "success": True}],
            server_used="whoisxml",
        )
        fake_runtime = SimpleNamespace(process_query_sync=lambda **kwargs: fake_result)

        with patch("researcher.views.get_runtime", return_value=fake_runtime):
            response = self.client.post(
                reverse("benchmark_run"),
                data=json.dumps({"id": "ST-01"}),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["id"], "ST-01")
        self.assertTrue(payload["success"])
        self.assertEqual(payload["action"], "whois")
        self.assertEqual(payload["tool_calls"][0]["tool"], "whois")
        self.assertIn("Registrar and registrant", payload["summary"])

    @override_settings(ALLOWED_HOSTS=["testserver"])
    def test_workspace_renders_three_pane_query_shell(self):
        User = get_user_model()
        user = User.objects.create_user(username="workspace_user", password="pass12345")
        team = Team.objects.create(name="Workspace Team", created_by=user)
        TeamMembership.objects.create(user=user, team=team)
        session_row = Session.objects.create()
        Query.objects.create(
            session=session_row,
            user=user,
            team=team,
            user_query="What DNS records exist for vt.edu?",
            success=True,
            summary="DNS records found.",
            duration_ms=100,
        )

        self.client.force_login(user)
        session = self.client.session
        session[views.ACTIVE_TEAM_SESSION_KEY] = team.id
        session[views.CONTEXT_AWARE_SESSION_KEY] = True
        session.save()

        response = self.client.get(reverse("workspace"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Run a new query")
        self.assertContains(response, "https://osint-research-production.up.railway.app/")
        self.assertContains(response, "detailPane")
        self.assertContains(response, "workspace-query-data")
        self.assertContains(response, "Team Context")

    def test_parse_query_returns_brief_multi_tool_plan(self):
        class FakeMessages:
            def create(self, **kwargs):
                return SimpleNamespace(content=[
                    SimpleNamespace(
                        type="tool_use",
                        name="whois",
                        input={"domain": "vt.edu"},
                    ),
                    SimpleNamespace(
                        type="tool_use",
                        name="dns_lookup",
                        input={"domain": "vt.edu"},
                    ),
                ])

        class FakeAnthropic:
            def __init__(self, **kwargs):
                self.messages = FakeMessages()

        with patch("researcher.views.get_provider", lambda: AnthropicProvider(client=FakeAnthropic())):
            response = self.client.post(
                reverse("parse_query"),
                data=json.dumps({"query": "Investigate vt.edu ownership and DNS"}),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["interpreted_action"], "whois")
        self.assertEqual([item["tool"] for item in payload["tool_plan"]], ["whois", "dns_lookup"])
        self.assertIn("whois", payload["confirmation_message"])
        self.assertIn("dns_lookup", payload["confirmation_message"])

    def test_disconnected_in_flight_query_stays_pending_for_background_worker(self):
        session = Session.objects.create()
        query = Query.objects.create(session=session, user_query="Investigate vt.edu")
        persisted = []

        views._handle_query_stream_disconnect(
            query.id,
            {"result": None, "error": None},
            lambda: persisted.append(True),
        )

        query.refresh_from_db()
        self.assertFalse(query.success)
        self.assertIsNone(query.error)
        self.assertIsNone(query.duration_ms)
        self.assertEqual(persisted, [])


class OpenAICompatProviderTests(TestCase):
    """The VT ARC / OpenAI-compatible backend, exercised against a fake HTTP server."""

    def _provider(self, handler):
        import httpx
        return OpenAICompatProvider(
            base_url="https://llm.example/api/v1",
            api_key="test-key",
            model="main-model",
            fast_model="fast-model",
            http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

    def test_get_provider_selects_backend_from_env(self):
        with patch.dict("os.environ", {"LLM_PROVIDER": "anthropic"}):
            self.assertIsInstance(get_provider(), AnthropicProvider)
        with patch.dict("os.environ", {"LLM_PROVIDER": "openai_compat"}):
            self.assertIsInstance(get_provider(), OpenAICompatProvider)

    def test_tool_round_trip_translates_both_directions(self):
        sent = []

        def handler(request):
            body = json.loads(request.content)
            sent.append(body)
            if len(sent) == 1:
                return httpx.Response(200, json={"choices": [{"message": {
                    "content": None,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "dns_lookup", "arguments": "{\"domain\": \"vt.edu\"}"},
                    }],
                }}]})
            return httpx.Response(200, json={"choices": [{"message": {"content": "DNS records found."}}]})

        import httpx
        client = OSINTMCPClient.__new__(OSINTMCPClient)
        client._connected = True
        client.progress_callback = None
        client.MAX_AGENT_TURNS = 3
        client._whoisxml_backup_attempted = True
        client.get_tools_for_claude = lambda: [{
            "name": "dns_lookup",
            "description": "DNS records",
            "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}},
        }]
        client.get_server_for_tool = lambda tool_name: "whoisxml"
        client.llm = self._provider(handler)

        async def fake_call_tool(tool_name, arguments):
            return SimpleNamespace(
                isError=False,
                content=[SimpleNamespace(text=json.dumps({"records": ["A 1.2.3.4"]}))],
            )

        client.call_tool = fake_call_tool

        result = asyncio.run(client.process_query("DNS for vt.edu"))

        self.assertTrue(result.success)
        self.assertEqual(result.formatted_response, "DNS records found.")
        self.assertEqual(result.tool_calls_made[0]["args"], {"domain": "vt.edu"})

        first = sent[0]
        self.assertEqual(first["model"], "main-model")
        self.assertEqual(first["messages"][0]["role"], "system")
        self.assertEqual(first["tools"][0]["function"]["name"], "dns_lookup")
        self.assertEqual(first["tools"][0]["function"]["parameters"]["properties"]["domain"]["type"], "string")

        second = sent[1]["messages"]
        self.assertEqual(second[-2]["role"], "assistant")
        self.assertEqual(second[-2]["tool_calls"][0]["id"], "call_1")
        self.assertEqual(second[-1]["role"], "tool")
        self.assertEqual(second[-1]["tool_call_id"], "call_1")
        self.assertIn("1.2.3.4", second[-1]["content"])

    def test_fast_tier_uses_fast_model_and_omits_tools(self):
        import httpx
        sent = []

        def handler(request):
            sent.append(json.loads(request.content))
            return httpx.Response(200, json={"choices": [{"message": {"content": "[\"a\"]"}}]})

        resp = self._provider(handler).create(
            tier="fast", max_tokens=50, messages=[{"role": "user", "content": "hi"}],
        )
        self.assertEqual(resp.content[0].text, '["a"]')
        self.assertEqual(sent[0]["model"], "fast-model")
        self.assertNotIn("tools", sent[0])

    def test_bad_tool_arguments_become_empty_dict(self):
        resp = OpenAICompatProvider.convert_response({"choices": [{"message": {
            "tool_calls": [{"function": {"name": "whois", "arguments": "{not json"}}],
        }}]})
        self.assertEqual(resp.content[0].type, "tool_use")
        self.assertEqual(resp.content[0].input, {})
        self.assertTrue(resp.content[0].id)

    def test_http_error_raises_with_status(self):
        import httpx
        provider = self._provider(lambda request: httpx.Response(401, json={"detail": "401 Unauthorized"}))
        with self.assertRaisesRegex(RuntimeError, "401"):
            provider.create(messages=[{"role": "user", "content": "hi"}], max_tokens=10)

    def test_reasoning_headroom_is_added_to_max_tokens(self):
        import httpx
        sent = []

        def handler(request):
            sent.append(json.loads(request.content))
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

        provider = self._provider(handler)
        provider.reasoning_headroom = 1000
        provider.create(messages=[{"role": "user", "content": "hi"}], max_tokens=400)
        self.assertEqual(sent[0]["max_tokens"], 1400)

    def test_empty_reply_raises_instead_of_returning_nothing(self):
        # DeepSeek spent the whole budget on hidden reasoning.
        with self.assertRaisesRegex(RuntimeError, "finish_reason=length"):
            OpenAICompatProvider.convert_response({"choices": [{
                "message": {"content": "", "reasoning": "thinking..."},
                "finish_reason": "length",
            }]})

    def test_vpn_403_gives_clear_message(self):
        import httpx
        provider = self._provider(lambda request: httpx.Response(
            403, text="API access is restricted to the VT Campus VPN. Please connect to the VPN and retry.",
        ))
        with self.assertRaisesRegex(RuntimeError, "Connect to the VT Campus VPN"):
            provider.create(messages=[{"role": "user", "content": "hi"}], max_tokens=10)


class ConfirmationMessageTests(TestCase):
    """The "I'll ..." sentence shown in the Confirm Search box."""

    def test_every_tool_has_a_confirmation_phrase(self):
        missing = [name for name, tool in TOOLS.items() if not tool.get("confirmation")]
        self.assertEqual(missing, [])

    def test_every_placeholder_matches_a_tool_argument(self):
        for name, tool in TOOLS.items():
            with self.subTest(tool=name):
                placeholders = get_confirmation_placeholders(tool["confirmation"])
                self.assertTrue(placeholders, "phrase should mention what is being searched")
                for placeholder in placeholders:
                    self.assertIn(placeholder, tool["arguments"])

    def test_every_phrase_renders_with_its_required_arguments(self):
        for name, tool in TOOLS.items():
            with self.subTest(tool=name):
                params = {
                    arg: "example"
                    for arg, info in tool["arguments"].items()
                    if info.get("required")
                }
                msg, _, _ = get_confirmation_message(name, params)
                self.assertEqual(msg, f"I'll {tool['confirmation'].format(**{a: repr('example') for a in params})}.")

    def test_dns_lookup_reads_naturally(self):
        msg, _, server = get_confirmation_message("dns_lookup", {"domainName": "google.com", "type": "_all"})
        self.assertEqual(msg, "I'll look up the DNS records for 'google.com'.")
        self.assertEqual(server, "whoisxml")

    def test_username_search_reads_naturally(self):
        msg, _, _ = get_confirmation_message("username_search", {"username": "test_user"})
        self.assertEqual(msg, "I'll search 600+ sites for profiles matching the username 'test_user'.")

    def test_missing_argument_falls_back_to_generic_message(self):
        msg, _, _ = get_confirmation_message("dns_lookup", {"type": "MX"})
        self.assertEqual(msg, "I'll run the dns_lookup tool with the provided parameters.")

    def test_phrase_with_unknown_placeholder_falls_back_instead_of_erroring(self):
        with patch.dict(TOOLS["dns_lookup"], {"confirmation": "look up {notAnArgument}"}):
            msg, _, _ = get_confirmation_message("dns_lookup", {"domainName": "google.com"})
        self.assertEqual(msg, "I'll run the dns_lookup tool for 'google.com'.")

    def test_unknown_tool_falls_back_to_generic_message(self):
        msg, est_time, server = get_confirmation_message("not_a_tool", {"x": "y"})
        self.assertEqual(msg, "I'll run the not_a_tool tool with the provided parameters.")
        self.assertEqual((est_time, server), ("Unknown", "unknown"))
