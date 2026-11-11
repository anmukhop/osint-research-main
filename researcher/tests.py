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


class TeamPersistenceTests(TestCase):
    def test_login_restores_last_active_team_after_logout(self):
        User = get_user_model()
        user = User.objects.create_user(username="team_user", password="test-password")
        first_team = Team.objects.create(name="First Team", created_by=user)
        second_team = Team.objects.create(name="Second Team", created_by=user)
        first_membership = TeamMembership.objects.create(user=user, team=first_team)
        second_membership = TeamMembership.objects.create(user=user, team=second_team)
        TeamMembership.objects.filter(id=first_membership.id).update(
            joined_at=django_tz.now() - timedelta(days=2)
        )
        TeamMembership.objects.filter(id=second_membership.id).update(
            joined_at=django_tz.now() - timedelta(days=1)
        )

        self.client.post(
            reverse("login"),
            {"username": user.username, "password": "test-password"},
        )
        self.assertEqual(
            self.client.session[views.ACTIVE_TEAM_SESSION_KEY],
            second_team.id,
        )

        self.client.post(reverse("team_switch", args=[first_team.id]))
        self.assertIsNotNone(
            TeamMembership.objects.get(id=first_membership.id).last_active_at
        )
        self.client.post(reverse("logout"))
        self.client.post(
            reverse("login"),
            {"username": user.username, "password": "test-password"},
        )

        self.assertEqual(
            self.client.session[views.ACTIVE_TEAM_SESSION_KEY],
            first_team.id,
        )
        response = self.client.get(reverse("index"))
        self.assertEqual(response.context["active_team"], first_team)

    def test_login_without_team_membership_does_not_set_active_team(self):
        User = get_user_model()
        user = User.objects.create_user(username="solo_user", password="test-password")

        self.client.post(
            reverse("login"),
            {"username": user.username, "password": "test-password"},
        )

        self.assertNotIn(views.ACTIVE_TEAM_SESSION_KEY, self.client.session)


class PasswordVisibilityTests(TestCase):
    def test_login_password_has_visibility_toggle(self):
        response = self.client.get(reverse("login"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'aria-label="Show password"')
        self.assertContains(response, 'class="password-toggle"')
        self.assertContains(response, 'name="password"')

    def test_signup_password_fields_each_have_visibility_toggle(self):
        response = self.client.get(reverse("signup"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.count(b'class="password-toggle"'), 2)
        self.assertContains(response, 'name="password1"')
        self.assertContains(response, 'name="password2"')


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


class AgentToolListTests(TestCase):
    """Name clashes keep both tools, and the planner prompt lists only callable tools."""

    def _client(self):
        client = OSINTMCPClient.__new__(OSINTMCPClient)
        client._tool_to_server = {}
        client._upstream_name = {}
        client._all_tools = []
        return client

    def _tool(self, name, server):
        return {"name": name, "description": f"{server} {name}", "input_schema": {}, "server": server}

    def _register_like_connect(self, client):
        for server, names in [
            ("local", ["username_search"]),
            ("whoisxml", ["whois", "dns_lookup", "domain_info", "subdomain_lookup"]),
            ("shodan", ["ip_lookup", "dns_lookup", "domain_info"]),
        ]:
            for name in names:
                client._register_tool(self._tool(name, server), server)

    def test_shodan_clashing_tools_are_prefixed_not_dropped(self):
        client = self._client()
        self._register_like_connect(client)
        self.assertEqual(client._tool_to_server["domain_info"], "whoisxml")
        self.assertEqual(client._tool_to_server["dns_lookup"], "whoisxml")
        self.assertEqual(client._tool_to_server["shodan_domain_info"], "shodan")
        self.assertEqual(client._tool_to_server["shodan_dns_lookup"], "shodan")
        self.assertEqual(client._tool_to_server["ip_lookup"], "shodan")
        names = [t["name"] for t in client._all_tools]
        self.assertEqual(len(names), len(set(names)))

    def test_shodan_names_do_not_depend_on_connection_order(self):
        # e.g. after the WhoisXML backup-key reconnect, WhoisXML registers last.
        client = self._client()
        for name in ["dns_lookup", "domain_info"]:
            client._register_tool(self._tool(name, "shodan"), "shodan")
        for name in ["dns_lookup", "domain_info"]:
            client._register_tool(self._tool(name, "whoisxml"), "whoisxml")
        self.assertEqual(client._tool_to_server["domain_info"], "whoisxml")
        self.assertEqual(client._tool_to_server["shodan_domain_info"], "shodan")

    def test_other_clashes_keep_the_second_tool_under_a_prefix(self):
        client = self._client()
        client._register_tool(self._tool("lookup", "whoisxml"), "whoisxml")
        client._register_tool(self._tool("lookup", "builtwith"), "builtwith")
        self.assertEqual(client._tool_to_server["builtwith_lookup"], "builtwith")
        self.assertEqual(client._upstream_name["builtwith_lookup"], "lookup")

    def test_prefixed_tool_is_called_by_its_real_name_on_its_server(self):
        client = self._client()
        self._register_like_connect(client)
        seen = {}

        class FakeConnection:
            def __init__(self, server):
                self.server = server

            async def call_tool(self, name, arguments):
                seen["call"] = (self.server, name, arguments)
                return "ok"

        client._connections = {s: FakeConnection(s) for s in ["local", "whoisxml", "shodan"]}
        asyncio.run(client.call_tool("shodan_domain_info", {"domain": "vt.edu"}))
        self.assertEqual(seen["call"], ("shodan", "domain_info", {"domain": "vt.edu"}))
        asyncio.run(client.call_tool("whois", {"domainName": "vt.edu"}))
        self.assertEqual(seen["call"], ("whoisxml", "whois", {"domainName": "vt.edu"}))

    def test_planner_prompt_lists_exactly_the_callable_tools(self):
        import re
        from researcher.services.mcp_client import AGENT_ALLOWED_TOOLS
        client = self._client()
        self._register_like_connect(client)
        tools = [
            {"name": t["name"], "description": t["description"], "input_schema": {}}
            for t in client._all_tools if t["name"] in AGENT_ALLOWED_TOOLS
        ]
        prompt = client._planner_system_prompt(tools)
        section = prompt.split("AVAILABLE TOOLS")[1].split("RULES FOR TOOL USE")[0]
        listed = {
            name.strip()
            for line in section.splitlines() if line.startswith("- ")
            for name in line.split(": ", 1)[1].split(",")
        }
        self.assertEqual(listed, {t["name"] for t in tools})
        self.assertIn("shodan_domain_info", listed)
        self.assertNotIn("subdomain_lookup", prompt)  # hidden (0 WhoisXML credits)
        self.assertNotIn("{tool_list}", prompt)
        # Every tool named in the rules is one the agent can call.
        rules = prompt.split("RULES FOR TOOL USE")[1].split("RULES FOR WHEN")[0]
        for named in re.findall(r"'([a-z_-]+)'", rules):
            self.assertIn(named, AGENT_ALLOWED_TOOLS)

    def test_planner_prompt_with_no_tools_says_so(self):
        prompt = self._client()._planner_system_prompt([])
        self.assertIn("no tool servers are connected", prompt)


class AgentToolReviewTests(TestCase):
    """The reviewed allowlist (docs/agent-tool-list.md), stealth mode, live-tool labels."""

    def _reload(self, stealth):
        import importlib
        import os
        from unittest import mock
        import researcher.services.mcp_client as mod
        env = {"OSINT_STEALTH_MODE": "true"} if stealth else {}
        with mock.patch.dict(os.environ, env):
            if not stealth:
                os.environ.pop("OSINT_STEALTH_MODE", None)
            return importlib.reload(mod)

    def tearDown(self):
        self._reload(stealth=False)

    def _prompt(self, mod, names):
        client = mod.OSINTMCPClient.__new__(mod.OSINTMCPClient)
        client._tool_to_server = {}
        tools = [{"name": n, "description": "", "input_schema": {}}
                 for n in names if n in mod.AGENT_ALLOWED_TOOLS]
        return client._planner_system_prompt(tools)

    def test_reviewed_tools_are_allowed_by_default(self):
        mod = self._reload(stealth=False)
        for name in ["ssl_certificates", "email_verification", "categorization",
                     "domain_reputation", "disposable_email_check", "trends-api",
                     "username_search", "free-api"]:
            self.assertIn(name, mod.AGENT_ALLOWED_TOOLS)

    def test_hidden_and_banned_tools_stay_off(self):
        mod = self._reload(stealth=False)
        for name in ["subdomain_lookup", "reverse_whois", "whois_history", "reverse_ip",
                     "website_screenshot", "domain-api", "bulk_whois",
                     "bulk_email_verification", "payment-purchase",
                     "x402-credit-purchase", "mpp-purchase"]:
            self.assertNotIn(name, mod.AGENT_ALLOWED_TOOLS)

    def test_stealth_mode_removes_live_contact_tools(self):
        mod = self._reload(stealth=True)
        for name in mod.LIVE_CONTACT_TOOLS:
            self.assertNotIn(name, mod.AGENT_ALLOWED_TOOLS)
        self.assertIn("username_search", mod.LIVE_CONTACT_TOOLS)
        self.assertIn("whois", mod.AGENT_ALLOWED_TOOLS)
        prompt = self._prompt(mod, ["whois", "email_verification"])
        self.assertNotIn("email_verification", prompt)
        self.assertIn("switched off", prompt)

    def test_prompt_labels_live_tools_only_when_present(self):
        mod = self._reload(stealth=False)
        prompt = self._prompt(mod, ["whois", "ssl_certificates", "username_search"])
        rule = [l for l in prompt.splitlines() if "passive-only" in l]
        self.assertEqual(len(rule), 1)
        self.assertIn("ssl_certificates, username_search", rule[0])
        self.assertNotIn("whois", rule[0])
        self.assertNotIn("switched off", prompt)
        self.assertNotIn("{live_tools_rule}", prompt)
        self.assertNotIn("passive-only", self._prompt(mod, ["whois"]))

    def test_domain_reputation_is_forced_to_fast_mode(self):
        mod = self._reload(stealth=False)
        client = mod.OSINTMCPClient.__new__(mod.OSINTMCPClient)
        client._tool_to_server = {"domain_reputation": "whoisxml"}
        client._upstream_name = {}
        seen = {}

        class FakeConnection:
            async def call_tool(self, name, arguments):
                seen["args"] = arguments

        client._connections = {"whoisxml": FakeConnection()}
        asyncio.run(client.call_tool("domain_reputation", {"domain_name": "x.org", "mode": "full"}))
        self.assertEqual(seen["args"], {"domain_name": "x.org", "mode": "fast"})


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


@override_settings(ALLOWED_HOSTS=["testserver"])
class RequireLoginTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="searcher", password="pw-12345-test")

    @override_settings(REQUIRE_LOGIN=True)
    def test_anonymous_visitor_is_sent_to_login(self):
        response = self.client.get(reverse("index"))
        self.assertRedirects(response, f"{reverse('login')}?next=/", fetch_redirect_response=False)

    @override_settings(REQUIRE_LOGIN=True)
    def test_anonymous_search_is_refused_without_running(self):
        with patch.object(views, "Query") as query_model:
            response = self.client.get(reverse("search_stream"), {"query": "whois example.com"})
            body = b"".join(response.streaming_content)
        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Please log in to search.", body)
        query_model.objects.create.assert_not_called()

    @override_settings(REQUIRE_LOGIN=True)
    def test_anonymous_parse_is_refused(self):
        response = self.client.post(reverse("parse_query"), data=json.dumps({"query": "whois example.com"}),
                                    content_type="application/json")
        self.assertEqual(response.status_code, 401)

    @override_settings(REQUIRE_LOGIN=True)
    def test_login_page_hides_continue_without_login_link(self):
        response = self.client.get(reverse("login"))
        self.assertNotContains(response, "Continue without logging in")

    @override_settings(REQUIRE_LOGIN=True)
    def test_logged_in_user_can_open_search_page(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("index")).status_code, 200)

    @override_settings(REQUIRE_LOGIN=False)
    def test_default_allows_anonymous_use(self):
        self.assertEqual(self.client.get(reverse("index")).status_code, 200)
        self.assertContains(self.client.get(reverse("login")), "Continue without logging in")


class EmailBreachCheckTests(TestCase):
    """XposedOrNot email_breach_check tool. The API is faked; no network calls."""

    def _breach(self, name, year, added, records=100, leaked="Email addresses;Passwords"):
        return {
            "breach": name, "details": "long text", "domain": f"{name.lower()}.com",
            "industry": "Tech", "logo": "https://x/logo.png", "password_risk": "plaintext",
            "verified": "Yes", "xposed_data": leaked, "xposed_date": year,
            "xposed_records": records, "added": added,
        }

    def _fake_response(self, status=200, payload=None):
        response = SimpleNamespace(status_code=status)
        response.json = lambda: payload
        return response

    def _run(self, email="test@example.com", status=200, payload=None, **kwargs):
        from researcher.services.agents.xposedornot import XposedOrNotAgent
        with patch("researcher.services.agents.xposedornot.requests.get",
                   return_value=self._fake_response(status, payload)) as get:
            result = XposedOrNotAgent().run(email=email, **kwargs)
        return result, get

    def test_normal_result_is_tidy_and_newest_first(self):
        payload = {
            "ExposedBreaches": {"breaches_details": [
                self._breach("Old", "2012", "2019-01-01T00:00:00+00:00"),
                self._breach("Newest", "2026", "2026-11-05T00:00:00+00:00", records=445899,
                             leaked="Email addresses;Names;Phone numbers"),
                self._breach("Middle", "2020", "2021-01-01T00:00:00+00:00"),
            ]},
            "BreachMetrics": {"risk": [{"risk_label": "Critical", "risk_score": 100}]},
            "ExposedPastes": None,
        }
        result, get = self._run(email="  Test@Example.com ", payload=payload, max_breaches=2)

        self.assertIsNone(result["error"])
        self.assertEqual(result["email"], "test@example.com")
        self.assertEqual(result["breach_count"], 3)
        self.assertEqual((result["risk_label"], result["risk_score"]), ("Critical", 100))
        self.assertEqual([b["name"] for b in result["breaches"]], ["Newest", "Middle"])
        self.assertEqual(result["breaches"][0], {
            "name": "Newest", "domain": "newest.com", "year": "2026", "records": 445899,
            "leaked": ["Email addresses", "Names", "Phone numbers"],
        })
        self.assertEqual(get.call_args.kwargs["params"], {"email": "test@example.com"})
        self.assertIn("User-Agent", get.call_args.kwargs["headers"])

    def test_breach_without_a_domain_gives_none(self):
        breach = self._breach("NoSite", "2024", "2024-01-01T00:00:00+00:00")
        breach["domain"] = ""
        payload = {"ExposedBreaches": {"breaches_details": [breach]}, "BreachMetrics": None}
        result, _ = self._run(payload=payload)
        self.assertIsNone(result["breaches"][0]["domain"])

    def test_no_breaches_is_a_clean_empty_result(self):
        payload = {"BreachMetrics": None, "ExposedBreaches": None, "ExposedPastes": None}
        result, _ = self._run(payload=payload)
        self.assertIsNone(result["error"])
        self.assertEqual(result["breach_count"], 0)
        self.assertEqual(result["breaches"], [])
        self.assertIsNone(result["risk_label"])

    def test_rate_limit_and_other_error_statuses_return_an_error(self):
        result, _ = self._run(status=429, payload={})
        self.assertIn("429", result["error"])
        result, _ = self._run(status=500, payload={})
        self.assertIn("500", result["error"])
        self.assertEqual(result["breaches"], [])

    def test_timeout_returns_an_error_instead_of_raising(self):
        import requests
        from researcher.services.agents.xposedornot import XposedOrNotAgent
        with patch("researcher.services.agents.xposedornot.requests.get",
                   side_effect=requests.Timeout()):
            result = XposedOrNotAgent().run(email="test@example.com")
        self.assertIn("did not respond", result["error"])

    def test_bad_input_is_rejected_without_calling_the_api(self):
        for bad in ["", "   ", "not-an-email", "a@b", "two@@example.com", None, 42]:
            with self.subTest(email=bad):
                result, get = self._run(email=bad, payload={})
                self.assertIsNotNone(result["error"])
                get.assert_not_called()

    def test_email_is_not_written_to_the_logs(self):
        import io
        from contextlib import redirect_stderr
        payload = {"ExposedBreaches": None, "BreachMetrics": None}
        captured = io.StringIO()
        with redirect_stderr(captured):
            self._run(email="secret-person@example.com", payload=payload)
        self.assertNotIn("secret-person", captured.getvalue())

    def test_tool_is_registered_visible_to_agent_and_confirms_naturally(self):
        from researcher.services.mcp_client import AGENT_ALLOWED_TOOLS
        from researcher.services.tool_registry import get_server_for_tool
        self.assertIn("email_breach_check", AGENT_ALLOWED_TOOLS)
        self.assertEqual(get_server_for_tool("email_breach_check"), "local")
        msg, _, _ = get_confirmation_message("email_breach_check", {"email": "test@example.com"})
        self.assertEqual(msg, "I'll check known data breaches for the email address 'test@example.com'.")
