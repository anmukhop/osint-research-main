"""
Offline tests for the free-API tools (free-apis branch). Every HTTP call is
faked: patch requests.request (all agents go through free_api_common), or the
websocket connect for AISStream. No network, no keys needed.
"""

import json
import os
from types import SimpleNamespace
from unittest.mock import patch

import requests
from django.test import SimpleTestCase

from researcher.services.agents import (
    aisstream, cisa_kev, crtsh, opensky, osv, ransomware_live, reddit, sec_edgar, wigle,
)
from researcher.services.free_api_registry import FREE_API_TOOLS, FREE_API_TOOL_NAMES
from researcher.services.tool_registry import (
    SERVERS, TOOLS, get_claude_tool_definitions, get_confirmation_message,
    get_confirmation_placeholders, get_server_for_tool,
)

HTTP = "researcher.services.agents.free_api_common.requests.request"
ALL_KEYS = {
    "SEC_USER_AGENT": "test-lab test@example.com",
    "OPENSKY_CLIENT_ID": "id", "OPENSKY_CLIENT_SECRET": "secret",
    "AISSTREAM_API_KEY": "ais-key",
    "WIGLE_API_NAME": "AIDname", "WIGLE_API_TOKEN": "token",
    "REDDIT_CLIENT_ID": "rid", "REDDIT_CLIENT_SECRET": "rsecret",
}


def fake(status=200, payload=None, not_json=False):
    response = SimpleNamespace(status_code=status, headers={})

    def as_json():
        if not_json:
            raise ValueError("not json")
        return payload
    response.json = as_json
    return response


class FreeApiTestCase(SimpleTestCase):
    def setUp(self):
        for module in (cisa_kev, sec_edgar, opensky, reddit):
            module.clear_cache()
        env = patch.dict(os.environ, ALL_KEYS)
        env.start()
        self.addCleanup(env.stop)
        sleep = patch("researcher.services.agents.sec_edgar.time.sleep")
        sleep.start()
        self.addCleanup(sleep.stop)

    def without(self, *names):
        """Context: remove env vars for one check."""
        cleared = {n: "" for n in names}
        return patch.dict(os.environ, cleared)


# ---------------------------------------------------------------------------
class CommonBehaviourTests(FreeApiTestCase):
    def test_network_failures_never_raise(self):
        calls = [
            lambda: crtsh.CrtShAgent().run(domain="example.com"),
            lambda: osv.OSVAgent().run(package="jquery", version="1.12.4"),
            lambda: cisa_kev.CisaKevAgent().run(query="CVE-2021-44228"),
            lambda: sec_edgar.SecEdgarAgent().company_filings(company="320193"),
            lambda: sec_edgar.SecEdgarAgent().full_text_search(query="x"),
            lambda: ransomware_live.RansomwareLiveAgent().run(query="example"),
            lambda: opensky.OpenSkyAgent().airport_flights(airport="KILG", start="2025-12-12"),
            lambda: wigle.WigleAgent().run(latitude=38.9, longitude=-77.0),
            lambda: reddit.RedditAgent().search(query="example"),
        ]
        for error in (requests.Timeout(), requests.ConnectionError()):
            for call in calls:
                with self.subTest(error=type(error).__name__, call=call), \
                        patch(HTTP, side_effect=error):
                    result = call()
                    self.assertIsInstance(result["error"], str)

    def test_server_errors_and_bad_json_give_an_error(self):
        with patch(HTTP, return_value=fake(500, {})):
            self.assertIn("500", osv.OSVAgent().run(package="jquery")["error"])
        with patch(HTTP, return_value=fake(200, not_json=True)):
            self.assertIn("isn't JSON", osv.OSVAgent().run(package="jquery")["error"])

    def test_missing_keys_say_which_env_var_to_set_and_make_no_call(self):
        cases = [
            ("SEC_USER_AGENT", lambda: sec_edgar.SecEdgarAgent().company_filings(company="MSFT")),
            ("SEC_USER_AGENT", lambda: sec_edgar.SecEdgarAgent().full_text_search(query="x")),
            ("OPENSKY_CLIENT_SECRET",
             lambda: opensky.OpenSkyAgent().airport_flights(airport="KILG", start="2025-12-12")),
            ("AISSTREAM_API_KEY", lambda: aisstream.AISStreamAgent().run(latitude=1, longitude=1)),
            ("WIGLE_API_TOKEN", lambda: wigle.WigleAgent().run(latitude=1, longitude=1)),
            ("REDDIT_CLIENT_ID", lambda: reddit.RedditAgent().search(query="x")),
        ]
        for name, call in cases:
            with self.subTest(env=name), self.without(name), patch(HTTP) as http:
                result = call()
                self.assertIn(f"set {name}", result["error"])
                self.assertIn(".env", result["error"])
                http.assert_not_called()


# ---------------------------------------------------------------------------
class CrtShTests(FreeApiTestCase):
    CERTS = [
        {"issuer_name": "C=US, O=Let's Encrypt, CN=R3", "common_name": "www.example.com",
         "name_value": "www.example.com\nexample.com", "not_before": "2024-01-01T00:00:00",
         "not_after": "2024-04-01T00:00:00"},
        {"issuer_name": "C=US, O=DigiCert Inc, CN=X", "common_name": "*.example.com",
         "name_value": "*.example.com\nvpn.example.com\nevil.com", "not_before": "2025-06-01T00:00:00",
         "not_after": "2026-06-01T00:00:00"},
        {"issuer_name": "C=US, O=Let's Encrypt, CN=R3", "common_name": "www.example.com",
         "name_value": "WWW.example.com", "not_before": "2025-01-01T00:00:00",
         "not_after": "2025-04-01T00:00:00"},
    ]

    def test_names_are_grouped_filtered_and_newest_first(self):
        with patch(HTTP, return_value=fake(200, self.CERTS)) as http:
            result = crtsh.CrtShAgent().run(domain="https://Example.com/path", max_results=10)
        self.assertIsNone(result["error"])
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(http.call_args.kwargs["params"]["q"], "%.example.com")
        names = [s["name"] for s in result["subdomains"]]
        self.assertNotIn("evil.com", names)
        self.assertEqual(names[:2], ["vpn.example.com", "*.example.com"])
        www = next(s for s in result["subdomains"] if s["name"] == "www.example.com")
        self.assertEqual((www["first_seen"], www["last_seen"], www["certificates"]),
                         ("2024-01-01", "2025-04-01", 2))
        self.assertEqual(www["issuers"], ["Let's Encrypt"])
        self.assertTrue(next(s for s in result["subdomains"] if s["name"] == "*.example.com")["wildcard"])

    def test_cap_and_expired_flag(self):
        with patch(HTTP, return_value=fake(200, self.CERTS)) as http:
            result = crtsh.CrtShAgent().run(domain="example.com", max_results=1, include_expired=False)
        self.assertEqual(len(result["subdomains"]), 1)
        self.assertTrue(result["truncated"])
        self.assertEqual(http.call_args.kwargs["params"]["exclude"], "expired")

    def test_bad_domain_and_overload(self):
        with patch(HTTP) as http:
            self.assertIsNotNone(crtsh.CrtShAgent().run(domain="not a domain")["error"])
            http.assert_not_called()
        with patch(HTTP, return_value=fake(503)):
            self.assertIn("overloaded", crtsh.CrtShAgent().run(domain="example.com")["error"])


# ---------------------------------------------------------------------------
class OSVTests(FreeApiTestCase):
    VULN = {
        "id": "GHSA-xxxx", "aliases": ["CVE-2020-11022"], "summary": "XSS in htmlPrefilter",
        "published": "2020-04-29T00:00:00Z", "database_specific": {"severity": "MODERATE"},
        "affected": [{"package": {"name": "jquery", "ecosystem": "npm"},
                      "ranges": [{"events": [{"introduced": "1.2"}, {"fixed": "3.5.0"}]}]}],
    }

    def test_query_body_and_tidy_output(self):
        older = dict(self.VULN, id="OLD", aliases=[], published="2015-01-01T00:00:00Z")
        with patch(HTTP, return_value=fake(200, {"vulns": [older, self.VULN]})) as http:
            result = osv.OSVAgent().run(package="jquery", version="1.12.4", ecosystem="JavaScript")
        self.assertEqual(http.call_args.kwargs["json"],
                         {"package": {"name": "jquery", "ecosystem": "npm"}, "version": "1.12.4"})
        self.assertEqual(result["vuln_count"], 2)
        first = result["vulns"][0]
        self.assertEqual((first["id"], first["cves"], first["severity"], first["fixed_in"]),
                         ("GHSA-xxxx", ["CVE-2020-11022"], "MODERATE", ["3.5.0"]))

    def test_follows_page_tokens_and_handles_empty(self):
        pages = [fake(200, {"vulns": [self.VULN], "next_page_token": "t"}),
                 fake(200, {"vulns": [dict(self.VULN, id="B")]})]
        with patch(HTTP, side_effect=pages) as http:
            result = osv.OSVAgent().run(package="jquery")
        self.assertEqual(result["vuln_count"], 2)
        self.assertEqual(http.call_args.kwargs["json"]["page_token"], "t")
        with patch(HTTP, return_value=fake(200, {})):
            result = osv.OSVAgent().run(package="jquery", version="3.7.1")
        self.assertEqual(result["vulns"], [])
        self.assertIn("No known", result["note"])

    def test_pypi_spelling_and_empty_package(self):
        self.assertEqual(osv.normalize_ecosystem("pypi"), "PyPI")
        with patch(HTTP) as http:
            self.assertIsNotNone(osv.OSVAgent().run(package="  ")["error"])
            http.assert_not_called()


# ---------------------------------------------------------------------------
class CisaKevTests(FreeApiTestCase):
    CATALOG = {"catalogVersion": "2026.11.10", "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
         "vulnerabilityName": "Apache Log4j2 RCE", "dateAdded": "2021-12-10",
         "knownRansomwareCampaignUse": "Known", "shortDescription": "JNDI", "cwes": ["CWE-917"]},
        {"cveID": "CVE-2023-4966", "vendorProject": "Citrix", "product": "NetScaler",
         "vulnerabilityName": "Citrix Bleed", "dateAdded": "2023-10-18",
         "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2019-19781", "vendorProject": "Citrix", "product": "ADC",
         "vulnerabilityName": "Citrix ADC traversal", "dateAdded": "2021-11-03"},
    ]}

    def test_check_cves_and_cache(self):
        with patch(HTTP, return_value=fake(200, self.CATALOG)) as http:
            result = cisa_kev.CisaKevAgent().run(query="cve-2021-44228; CVE-2099-0001")
            cisa_kev.CisaKevAgent().run(query="citrix")
        self.assertEqual(http.call_count, 1)  # second call used the cache
        self.assertEqual([m["cve"] for m in result["matches"]], ["CVE-2021-44228"])
        self.assertEqual(result["matches"][0]["ransomware_use"], "Known")
        self.assertEqual(result["not_in_kev"], ["CVE-2099-0001"])
        self.assertEqual(result["catalog_count"], 3)

    def test_keyword_search_newest_first(self):
        with patch(HTTP, return_value=fake(200, self.CATALOG)):
            result = cisa_kev.CisaKevAgent().run(query="Citrix", max_results=1)
        self.assertEqual([m["cve"] for m in result["matches"]], ["CVE-2023-4966"])
        self.assertTrue(result["truncated"])

    def test_falls_back_to_github_copy_when_cisa_refuses(self):
        with patch(HTTP, side_effect=[fake(403), fake(200, self.CATALOG)]) as http:
            result = cisa_kev.CisaKevAgent().run(query="CVE-2023-4966")
        self.assertIsNone(result["error"])
        self.assertIn("githubusercontent", http.call_args.args[1])

    def test_needs_input(self):
        with patch(HTTP) as http:
            self.assertIsNotNone(cisa_kev.CisaKevAgent().run(query=" ")["error"])
            http.assert_not_called()


# ---------------------------------------------------------------------------
class SecEdgarTests(FreeApiTestCase):
    TICKERS = {"0": {"cik_str": 789019, "ticker": "MSFT", "title": "MICROSOFT CORP"},
               "1": {"cik_str": 1, "ticker": "AAA", "title": "ACME HOLDINGS"},
               "2": {"cik_str": 2, "ticker": "AAB", "title": "ACME PARTNERS"}}
    SUBMISSIONS = {
        "name": "MICROSOFT CORP", "tickers": ["MSFT"], "sicDescription": "Services-Prepackaged Software",
        "phone": "425-882-8080", "stateOfIncorporation": "WA",
        "addresses": {"business": {"street1": "ONE MICROSOFT WAY", "city": "REDMOND",
                                   "stateOrCountry": "WA", "zipCode": "98052"}},
        "formerNames": [],
        "filings": {"recent": {
            "accessionNumber": ["0000950170-24-000001", "0000950170-24-000002"],
            "filingDate": ["2024-07-30", "2024-07-01"], "reportDate": ["2024-06-30", ""],
            "form": ["10-K", "8-K"], "primaryDocument": ["msft-10k.htm", "8k.htm"],
            "primaryDocDescription": ["10-K", "8-K"]}},
    }

    def test_ticker_lookup_profile_and_filtered_filings(self):
        with patch(HTTP, side_effect=[fake(200, self.TICKERS), fake(200, self.SUBMISSIONS)]) as http:
            result = sec_edgar.SecEdgarAgent().company_filings(company="msft", forms="10-K")
        self.assertIsNone(result["error"])
        self.assertEqual(result["cik"], 789019)
        self.assertIn("CIK0000789019.json", http.call_args.args[1])
        self.assertEqual(http.call_args.kwargs["headers"]["User-Agent"], "test-lab test@example.com")
        self.assertEqual(result["addresses"]["business"], "ONE MICROSOFT WAY, REDMOND, WA, 98052")
        self.assertEqual([f["form"] for f in result["filings"]], ["10-K"])
        self.assertEqual(result["filings"][0]["url"],
                         "https://www.sec.gov/Archives/edgar/data/789019/000095017024000001/msft-10k.htm")

    def test_cik_skips_name_list_and_ambiguous_names_list_candidates(self):
        with patch(HTTP, return_value=fake(200, self.SUBMISSIONS)) as http:
            sec_edgar.SecEdgarAgent().company_filings(company="CIK789019")
        self.assertEqual(http.call_count, 1)
        with patch(HTTP, return_value=fake(200, self.TICKERS)):
            result = sec_edgar.SecEdgarAgent().company_filings(company="Acme")
        self.assertEqual(len(result["candidates"]), 2)
        self.assertIn("Several", result["error"])

    def test_full_text_search(self):
        payload = {"hits": {"total": {"value": 1}, "hits": [{
            "_id": "0001234567-24-000010:ex21.htm",
            "_source": {"ciks": ["0001234567"], "display_names": ["Example Corp (EXC) (CIK 0001234567)"],
                        "form": "10-K", "file_date": "2024-03-01", "biz_locations": ["Reston, VA"]}}]}}
        with patch(HTTP, return_value=fake(200, payload)) as http:
            result = sec_edgar.SecEdgarAgent().full_text_search(
                query='"Example Corp"', forms="10-K", start_date="2023-01-01")
        params = http.call_args.kwargs["params"]
        self.assertEqual((params["forms"], params["startdt"], params["dateRange"]),
                         ("10-K", "2023-01-01", "custom"))
        hit = result["results"][0]
        self.assertEqual((hit["cik"], hit["form"], hit["url"]), (
            1234567, "10-K",
            "https://www.sec.gov/Archives/edgar/data/1234567/000123456724000010/ex21.htm"))

    def test_bad_dates_and_403_wording(self):
        self.assertIn("YYYY-MM-DD", sec_edgar.SecEdgarAgent().full_text_search(
            query="x", start_date="March 2024")["error"])
        with patch(HTTP, return_value=fake(403)):
            error = sec_edgar.SecEdgarAgent().company_filings(company="789019")["error"]
        self.assertIn("SEC_USER_AGENT", error)


# ---------------------------------------------------------------------------
class RansomwareLiveTests(FreeApiTestCase):
    V2 = [{"victim": "Example Corp", "group": "akira", "attackdate": "2025-02-03 10:00:00",
           "country": "US", "activity": "Manufacturing"},
          {"victim": "Example Ltd", "group": "lockbit3", "attackdate": "2024-01-01", "country": "GB"}]

    def test_free_v2_without_key_filters_locally_and_notes_terms(self):
        with self.without("RANSOMWARE_LIVE_API_KEY"), patch(HTTP, return_value=fake(200, self.V2)) as http:
            result = ransomware_live.RansomwareLiveAgent().run(query="Example Corp", country="us")
        self.assertIn("/v2/searchvictims/Example%20Corp", http.call_args.args[1])
        self.assertEqual(result["source"], "free v2")
        self.assertEqual([v["victim"] for v in result["victims"]], ["Example Corp"])
        self.assertEqual(result["victims"][0]["attack_date"], "2025-02-03")
        self.assertIn("personal use", result["note"])

    def test_pro_key_uses_header_and_server_filters(self):
        with patch.dict(os.environ, {"RANSOMWARE_LIVE_API_KEY": "pro"}), \
                patch(HTTP, return_value=fake(200, {"victims": self.V2})) as http:
            result = ransomware_live.RansomwareLiveAgent().run(query="example", group="Akira")
        self.assertEqual(http.call_args.kwargs["headers"]["X-API-KEY"], "pro")
        self.assertEqual(http.call_args.kwargs["params"]["group"], "akira")
        self.assertEqual(result["source"], "pro")
        self.assertEqual(result["victim_count"], 2)

    def test_v2_rate_limit_and_not_found(self):
        with self.without("RANSOMWARE_LIVE_API_KEY"):
            with patch(HTTP, return_value=fake(429)):
                self.assertIn("1 request per minute", ransomware_live.RansomwareLiveAgent().run(query="abc")["error"])
            with patch(HTTP, return_value=fake(404)):
                result = ransomware_live.RansomwareLiveAgent().run(query="nobody-here")
        self.assertIsNone(result["error"])
        self.assertEqual(result["victims"], [])


# ---------------------------------------------------------------------------
class OpenSkyTests(FreeApiTestCase):
    FLIGHT = {"icao24": "a0b1c2", "firstSeen": 1765562400, "lastSeen": 1765569600,
              "estDepartureAirport": "KTEB", "estArrivalAirport": "KILG", "callsign": "N123AB  "}

    def test_token_then_arrivals_with_unix_window(self):
        token = fake(200, {"access_token": "tok", "expires_in": 1800})
        with patch(HTTP, side_effect=[token, fake(200, [self.FLIGHT])]) as http:
            result = opensky.OpenSkyAgent().airport_flights(airport="kilg", start="2025-12-12")
        token_call, flights_call = http.call_args_list
        self.assertEqual(token_call.kwargs["data"]["grant_type"], "client_credentials")
        self.assertEqual(flights_call.kwargs["headers"]["Authorization"], "Bearer tok")
        self.assertEqual(flights_call.kwargs["params"],
                         {"airport": "KILG", "begin": 1765497600, "end": 1765584000})
        self.assertTrue(flights_call.args[1].endswith("/flights/arrival"))
        flight = result["flights"][0]
        self.assertEqual((flight["callsign"], flight["from_airport"], flight["last_seen"]),
                         ("N123AB", "KTEB", "2025-12-12 20:00 UTC"))

    def test_token_reused_and_refreshed_on_401(self):
        token = fake(200, {"access_token": "tok"})
        with patch(HTTP, side_effect=[token, fake(404), fake(401), fake(200, {"access_token": "t2"}),
                                      fake(200, [])]) as http:
            first = opensky.OpenSkyAgent().aircraft_flights(icao24="A0B1C2", start="2025-12-12")
            second = opensky.OpenSkyAgent().aircraft_flights(icao24="a0b1c2", start="2025-12-12")
        self.assertEqual(http.call_count, 5)
        self.assertIsNone(first["error"])
        self.assertIn("nightly", first["note"])
        self.assertIsNone(second["error"])

    def test_input_checks_make_no_call(self):
        agent = opensky.OpenSkyAgent()
        with patch(HTTP) as http:
            self.assertIn("ICAO", agent.airport_flights(airport="ILG", start="2025-12-12")["error"])
            self.assertIn("2 days", agent.airport_flights(airport="KILG", start="2025-12-01",
                                                          end="2025-12-05")["error"])
            self.assertIn("6-hex", agent.aircraft_flights(icao24="N123AB", start="2025-12-12")["error"])
            self.assertIn("start", agent.airport_flights(airport="KILG", start="yesterday")["error"])
            http.assert_not_called()


# ---------------------------------------------------------------------------
class FakeSocket:
    def __init__(self, messages):
        self.messages = list(messages)
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def send(self, text):
        self.sent.append(json.loads(text))

    def recv(self, timeout=None):
        if not self.messages:
            raise TimeoutError()
        return json.dumps(self.messages.pop(0))


class AISStreamTests(FreeApiTestCase):
    def test_subscribes_with_box_and_merges_messages_per_ship(self):
        messages = [
            {"MessageType": "PositionReport",
             "MetaData": {"MMSI": 366999999, "ShipName": "EXAMPLE STAR  ", "latitude": 39.27,
                          "longitude": -76.58, "time_utc": "2026-11-13 12:00:00.1 +0000 UTC"},
             "Message": {"PositionReport": {"Sog": 0.1, "TrueHeading": 511}}},
            {"MessageType": "ShipStaticData", "MetaData": {"MMSI": 366999999},
             "Message": {"ShipStaticData": {"ImoNumber": 9000001, "CallSign": "WXYZ",
                                            "Type": 70, "Destination": "BALTIMORE"}}},
            {"MessageType": "ShipStaticData", "MetaData": {"MMSI": 1},  # never gave a position
             "Message": {"ShipStaticData": {"Destination": "X"}}},
        ]
        socket = FakeSocket(messages)
        with patch("researcher.services.agents.aisstream._connect", return_value=socket):
            result = aisstream.AISStreamAgent().run(latitude=39.27, longitude=-76.58, listen_seconds=5)
        subscription = socket.sent[0]
        self.assertEqual(subscription["APIKey"], "ais-key")
        (low, high), = subscription["BoundingBoxes"]
        self.assertLess(low[0], 39.27)
        self.assertGreater(high[1], -76.58)
        self.assertEqual(result["ship_count"], 1)
        ship = result["ships"][0]
        self.assertEqual((ship["name"], ship["imo"], ship["destination"], ship["heading"]),
                         ("EXAMPLE STAR", 9000001, "BALTIMORE", None))
        self.assertEqual(result["messages"], 3)

    def test_bad_key_and_connection_failure(self):
        with patch("researcher.services.agents.aisstream._connect",
                   return_value=FakeSocket([{"error": "Api Key Is Not Valid"}])):
            self.assertIn("AISSTREAM_API_KEY", aisstream.AISStreamAgent().run(latitude=1, longitude=1)["error"])
        with patch("researcher.services.agents.aisstream._connect", side_effect=OSError("down")):
            self.assertIn("Could not reach", aisstream.AISStreamAgent().run(latitude=1, longitude=1)["error"])
        with patch("researcher.services.agents.aisstream._connect") as connect:
            self.assertIsNotNone(aisstream.AISStreamAgent().run(latitude=91, longitude=1)["error"])
            connect.assert_not_called()


# ---------------------------------------------------------------------------
class WigleTests(FreeApiTestCase):
    PAYLOAD = {"success": True, "totalResults": 3, "results": [
        {"ssid": "Acme-Guest", "netid": "AA:BB:CC:00:11:22", "encryption": "wpa2", "channel": 6,
         "trilat": 38.88, "trilong": -77.03, "firsttime": "2023-01-02T00:00:00.000Z",
         "lasttime": "2025-02-10T00:00:00.000Z", "road": "Main St", "city": "Arlington"}]}

    def test_point_search_builds_box_auth_and_date(self):
        with patch(HTTP, return_value=fake(200, self.PAYLOAD)) as http:
            result = wigle.WigleAgent().run(latitude=38.88, longitude=-77.03, radius_m=100,
                                            ssid="Acme%", seen_since="2025-02-01", max_results=1)
        kwargs = http.call_args.kwargs
        self.assertEqual(kwargs["auth"], ("AIDname", "token"))
        params = kwargs["params"]
        self.assertLess(params["latrange1"], 38.88)
        self.assertGreater(params["latrange2"], 38.88)
        self.assertEqual((params["ssidlike"], params["lasttime"], params["resultsPerPage"]),
                         ("Acme%", "20250201", 1))
        network = result["networks"][0]
        self.assertEqual((network["bssid"], network["last_seen"], network["address"]),
                         ("AA:BB:CC:00:11:22", "2025-02-10", "Main St, Arlington"))
        self.assertTrue(result["truncated"])

    def test_needs_a_place_or_name_and_reports_daily_limit(self):
        with patch(HTTP) as http:
            self.assertIn("location", wigle.WigleAgent().run()["error"])
            http.assert_not_called()
        with patch(HTTP, return_value=fake(429)):
            self.assertIn("daily", wigle.WigleAgent().run(latitude=1, longitude=1)["error"])


# ---------------------------------------------------------------------------
class RedditTests(FreeApiTestCase):
    TOKEN = {"access_token": "rt", "expires_in": 86400}
    POST = {"kind": "t3", "data": {"id": "1abc23d", "title": "Example Corp outage", "subreddit": "sysadmin",
                                   "author": "someone", "created_utc": 1731456000, "score": 42,
                                   "num_comments": 2, "permalink": "/r/sysadmin/comments/1abc23d/x/",
                                   "is_self": True, "selftext": "Their VPN is down"}}

    def listing(self, *children):
        return {"kind": "Listing", "data": {"children": list(children)}}

    def test_search_in_subreddit_uses_app_token(self):
        with patch(HTTP, side_effect=[fake(200, self.TOKEN), fake(200, self.listing(self.POST))]) as http:
            result = reddit.RedditAgent().search(query="Example Corp", subreddit="r/sysadmin", sort="new")
        token_call, search_call = http.call_args_list
        self.assertEqual(token_call.kwargs["auth"], ("rid", "rsecret"))
        self.assertTrue(search_call.args[1].endswith("/r/sysadmin/search"))
        self.assertEqual(search_call.kwargs["params"]["restrict_sr"], "on")
        self.assertEqual(search_call.kwargs["headers"]["Authorization"], "bearer rt")
        post = result["posts"][0]
        self.assertEqual((post["title"], post["url"]), (
            "Example Corp outage", "https://www.reddit.com/r/sysadmin/comments/1abc23d/x/"))

    def test_thread_walks_nested_replies(self):
        reply = {"kind": "t1", "data": {"id": "c2", "author": "b", "body": "agreed", "replies": ""}}
        top = {"kind": "t1", "data": {"id": "c1", "author": "a", "body": "same here",
                                      "replies": self.listing(reply)}}
        more = {"kind": "more", "data": {}}
        thread = [self.listing(self.POST), self.listing(top, more)]
        with patch(HTTP, side_effect=[fake(200, self.TOKEN), fake(200, thread)]) as http:
            result = reddit.RedditAgent().post_comments(
                post="https://www.reddit.com/r/sysadmin/comments/1abc23d/example_corp_outage/")
        self.assertTrue(http.call_args.args[1].endswith("/comments/1abc23d"))
        self.assertEqual(result["post"]["text"], "Their VPN is down")
        self.assertEqual([(c["id"], c["depth"]) for c in result["comments"]], [("c1", 0), ("c2", 1)])

    def test_user_activity_and_missing_user(self):
        about = {"kind": "t2", "data": {"name": "someone", "created_utc": 1500000000,
                                        "link_karma": 10, "comment_karma": 20}}
        comment = {"kind": "t1", "data": {"id": "c9", "body": "I work at Example Corp",
                                          "subreddit": "jobs"}}
        with patch(HTTP, side_effect=[fake(200, self.TOKEN), fake(200, about),
                                      fake(200, self.listing(self.POST, comment))]):
            result = reddit.RedditAgent().user_activity(username="u/someone")
        self.assertEqual(result["account"]["comment_karma"], 20)
        self.assertEqual([i["type"] for i in result["items"]], ["post", "comment"])
        with patch(HTTP, return_value=fake(404)):
            self.assertIn("No Reddit account", reddit.RedditAgent().user_activity(username="ghost_x")["error"])
        with patch(HTTP) as http:
            self.assertIsNotNone(reddit.RedditAgent().user_activity(username="a b")["error"])
            http.assert_not_called()


# ---------------------------------------------------------------------------
class FreeApiRegistryTests(SimpleTestCase):
    def test_tools_are_registered_local_and_allowed(self):
        from researcher.services.mcp_client import AGENT_ALLOWED_TOOLS, LIVE_CONTACT_TOOLS
        self.assertEqual(len(FREE_API_TOOLS), 13)
        for name in FREE_API_TOOL_NAMES:
            with self.subTest(tool=name):
                self.assertIn(name, TOOLS)
                self.assertEqual(get_server_for_tool(name), "local")
                self.assertIn(name, SERVERS["local"]["tools"])
                self.assertIn(name, AGENT_ALLOWED_TOOLS)
                self.assertNotIn(name, LIVE_CONTACT_TOOLS)  # all passive

    def test_confirmations_use_required_arguments_only(self):
        for name, tool in FREE_API_TOOLS.items():
            for placeholder in get_confirmation_placeholders(tool["confirmation"]):
                with self.subTest(tool=name, placeholder=placeholder):
                    self.assertTrue(tool["arguments"][placeholder]["required"])
        msg, _, server = get_confirmation_message("kev_check", {"query": "CVE-2021-44228"})
        self.assertEqual((msg, server), (
            "I'll check 'CVE-2021-44228' against CISA's Known Exploited Vulnerabilities list.", "local"))
        msg, _, _ = get_confirmation_message("crtsh_subdomains", {"domain": "example.com"})
        self.assertEqual(msg, "I'll search certificate logs (crt.sh) for subdomains of 'example.com'.")

    def test_claude_definitions_include_new_tools(self):
        names = {t["name"] for t in get_claude_tool_definitions()}
        self.assertTrue(FREE_API_TOOL_NAMES <= names)

    def test_mcp_server_registers_matching_tools(self):
        import asyncio
        import sys
        from pathlib import Path
        services = str(Path(__file__).resolve().parent / "services")
        sys.path.insert(0, services)
        try:
            from mcp.server.fastmcp import FastMCP
            from free_api_tools import register_free_api_tools
            server = FastMCP(name="test")
            register_free_api_tools(server)
            tools = {t.name: t for t in asyncio.run(server.list_tools())}
        finally:
            sys.path.remove(services)
        self.assertEqual(set(tools), set(FREE_API_TOOL_NAMES))
        for name, tool in tools.items():
            with self.subTest(tool=name):  # registry arguments match the MCP signature
                self.assertEqual(set(tool.inputSchema["properties"]),
                                 set(FREE_API_TOOLS[name]["arguments"]))
