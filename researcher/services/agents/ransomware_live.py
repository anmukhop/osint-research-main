"""
ransomware.live agent for OSINT Research Platform

Has an organization (a vendor, a supplier, the target) been listed on a
ransomware gang's leak site? Searches ransomware.live's victim database by
name or website. Passive: only ransomware.live is contacted.

CVA category: Third-Party Services (Breach Data 2nd: leaked data).

Two ways in, picked automatically:
- PRO API (preferred) when RANSOMWARE_LIVE_API_KEY is set. Free key from
  https://www.ransomware.live/my . 60 requests/minute, 500,000/month.
  Docs: https://api-pro.ransomware.live/docs (header X-API-KEY).
- Free v2 API without a key. 1 request/minute per endpoint, and its terms say
  "Personal use only... not intended for corporate or business use", so it's a
  fallback for trying the tool, not for study use. Docs: https://www.ransomware.live/apidocs
"""

import re
from urllib.parse import quote

from .free_api_common import clamp_int, env, log, request_json


PRO_SEARCH_URL = "https://api-pro.ransomware.live/victims/search"
V2_SEARCH_URL = "https://api.ransomware.live/v2/searchvictims/{keyword}"
PROVIDER = "ransomware.live"
ENV_KEY = "RANSOMWARE_LIVE_API_KEY"
DEFAULT_MAX_RESULTS = 20
MAX_RESULTS_CAP = 100

_COUNTRY_RE = re.compile(r"^[A-Za-z]{2}$")


class RansomwareLiveAgent:
    """Search ransomware leak-site victims by organization name or website."""

    name = "ransomware_live"

    def run(self, query: str, group: str = "", country: str = "",
            max_results: int = DEFAULT_MAX_RESULTS, **kwargs) -> dict:
        """
        Returns: query, source ("pro" or "free v2"), victim_count, victims
        (newest first: victim, website, group, attack_date, discovered, country,
        sector, press, permalink), truncated, note, error. Never raises.
        """
        query = query.strip() if isinstance(query, str) else ""
        group = group.strip().lower() if isinstance(group, str) else ""
        country = country.strip().upper() if isinstance(country, str) else ""
        key = env(ENV_KEY)
        result = {
            "query": query, "source": "pro" if key else "free v2",
            "victim_count": 0, "victims": [], "truncated": False, "note": None, "error": None,
        }
        if len(query) < 3 or len(query) > 100:
            result["error"] = "Give an organization name or website of 3-100 characters."
            return result
        if country and not _COUNTRY_RE.match(country):
            result["error"] = "country must be a 2-letter code such as US."
            return result
        max_results = clamp_int(max_results, DEFAULT_MAX_RESULTS, 1, MAX_RESULTS_CAP)

        log(self.name, f"victim search ({result['source']})")
        if key:
            params = {"q": query, "order": "attacked"}
            if group:
                params["group"] = group
            if country:
                params["country"] = country
            data, error, _ = request_json(
                "GET", PRO_SEARCH_URL, PROVIDER, params=params, timeout=20,
                headers={"X-API-KEY": key, "Accept": "application/json"},
                empty_statuses=(404,),
                status_messages={401: "ransomware.live rejected the key (HTTP 401). "
                                      "Check RANSOMWARE_LIVE_API_KEY in .env."},
            )
        else:
            data, error, _ = request_json(
                "GET", V2_SEARCH_URL.format(keyword=quote(query, safe="")), PROVIDER,
                timeout=20, empty_statuses=(404,),
                status_messages={429: "ransomware.live's free API allows 1 request per minute "
                                      "(HTTP 429). Wait a minute, or set RANSOMWARE_LIVE_API_KEY "
                                      "in .env for the PRO API."},
            )
            result["note"] = ("Used the free v2 API (personal use only, 1 request/minute). "
                              "Set RANSOMWARE_LIVE_API_KEY in .env to use the PRO API.")
        if error:
            result["error"] = error
            return result

        rows = data
        if isinstance(data, dict):
            rows = data.get("victims") or data.get("results") or data.get("data") or []
        if data is not None and not isinstance(rows, list):
            result["error"] = "ransomware.live returned an unexpected response."
            return result

        victims = [self._tidy(v) for v in rows or [] if isinstance(v, dict)]
        if not key:  # v2 has no filters; apply them here
            victims = [v for v in victims
                       if (not group or str(v["group"] or "").lower() == group)
                       and (not country or str(v["country"] or "").upper() == country)]
        victims.sort(key=lambda v: v["attack_date"] or "", reverse=True)
        result["victim_count"] = len(victims)
        result["victims"] = victims[:max_results]
        result["truncated"] = len(victims) > max_results
        log(self.name, f"{len(victims)} victims")
        return result

    @staticmethod
    def _tidy(v: dict) -> dict:
        def day(value):
            return str(value)[:10] if value else None
        return {
            "victim": v.get("victim") or v.get("post_title"),
            "website": v.get("website") or None,
            "group": v.get("group") or v.get("group_name"),
            "attack_date": day(v.get("attackdate") or v.get("published")),
            "discovered": day(v.get("discovered")),
            "country": v.get("country") or None,
            "sector": v.get("activity") or None,
            "description": (v.get("description") or "")[:300] or None,
            "press": v.get("press") or None,
            "permalink": v.get("permalink") or None,
        }
