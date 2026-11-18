"""
WiGLE agent for OSINT Research Platform

WiFi networks that volunteers have recorded at a place (around a point, or by
network name): network name (SSID), router address (BSSID), encryption, and
when it was first and last seen. Passive: reads WiGLE's database.

CVA category: Physical Assets (Network Discovery 2nd).
Research use only: WiGLE says "commercial licensing operations are
suspended", so never use it for a Peraton deliverable.
Account: free account at https://wigle.net -> Account -> "Show my token".
Set WIGLE_API_NAME and WIGLE_API_TOKEN in .env (the "API Name" and "API Token").
Limits (docs): "Number of daily queries allowed per user are throttled based
on history and participation", so a new account gets only a few searches a
day; over the limit -> HTTP 429. At most 100 results per page.
Docs: https://api.wigle.net/swagger (search: /api/v2/network/search)
"""

import math
import re

from .free_api_common import clamp_int, env, log, missing_env_error, request_json


SEARCH_URL = "https://api.wigle.net/api/v2/network/search"
PROVIDER = "WiGLE"
ENV_NAMES = ["WIGLE_API_NAME", "WIGLE_API_TOKEN"]
ENV_HELP = "free account at wigle.net -> Account -> Show my token"
DEFAULT_RADIUS_M = 150
MAX_RADIUS_M = 2000
DEFAULT_MAX_RESULTS = 50
MAX_RESULTS_CAP = 100      # one page; each page is one of the few daily queries

_DATE_RE = re.compile(r"^(\d{4})-?(\d{2})-?(\d{2})$")


class WigleAgent:
    """Search WiGLE for WiFi networks near a point and/or by network name."""

    name = "wigle"

    def run(self, latitude=None, longitude=None, radius_m: int = DEFAULT_RADIUS_M,
            ssid: str = "", seen_since: str = "", max_results: int = DEFAULT_MAX_RESULTS,
            **kwargs) -> dict:
        """
        Give a point (latitude + longitude), an ssid, or both. ssid may use %
        as a wildcard ('Acme%'). seen_since: YYYY-MM-DD, keeps networks with
        data submitted after that date. Returns: total_results, networks
        (closest first when a point is given), error.
        """
        ssid = ssid.strip() if isinstance(ssid, str) else ""
        result = {"center": None, "radius_m": None, "ssid": ssid or None,
                  "total_results": 0, "networks": [], "truncated": False,
                  "note": "WiGLE data is research use only (no commercial licensing).",
                  "error": None}
        problem = missing_env_error(PROVIDER, ENV_NAMES, ENV_HELP)
        if problem:
            result["error"] = problem
            return result

        params = {}
        has_point = latitude not in (None, "") and longitude not in (None, "")
        if has_point:
            try:
                lat, lon = float(latitude), float(longitude)
            except (TypeError, ValueError):
                result["error"] = "latitude and longitude must be numbers (decimal degrees)."
                return result
            if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                result["error"] = "latitude must be -90..90 and longitude -180..180."
                return result
            radius = clamp_int(radius_m, DEFAULT_RADIUS_M, 10, MAX_RADIUS_M)
            dlat = radius / 111_000
            dlon = radius / (111_000 * max(math.cos(math.radians(lat)), 0.01))
            params.update(latrange1=round(lat - dlat, 6), latrange2=round(lat + dlat, 6),
                          longrange1=round(lon - dlon, 6), longrange2=round(lon + dlon, 6),
                          closestLat=lat, closestLong=lon)
            result.update(center=[lat, lon], radius_m=radius)
        if ssid:
            if len(ssid) > 64:
                result["error"] = "ssid is at most 32 characters (64 with wildcards)."
                return result
            params["ssidlike" if ("%" in ssid or "_" in ssid) else "ssid"] = ssid
        if not params:
            result["error"] = "Give a location (latitude and longitude), an ssid, or both."
            return result
        if seen_since:
            match = _DATE_RE.match(seen_since.strip()) if isinstance(seen_since, str) else None
            if not match:
                result["error"] = "seen_since must be YYYY-MM-DD."
                return result
            params["lasttime"] = "".join(match.groups())
        max_results = clamp_int(max_results, DEFAULT_MAX_RESULTS, 1, MAX_RESULTS_CAP)
        params["resultsPerPage"] = max_results

        log(self.name, "network search")
        data, error, _ = request_json(
            "GET", SEARCH_URL, PROVIDER, params=params, timeout=30,
            auth=(env("WIGLE_API_NAME"), env("WIGLE_API_TOKEN")),
            status_messages={
                401: "WiGLE rejected the login (HTTP 401). Check WIGLE_API_NAME and "
                     "WIGLE_API_TOKEN in .env (the API Name, not your username).",
                429: "WiGLE's daily search limit for this account is used up (HTTP 429). "
                     "It resets tomorrow; new accounts get only a few searches a day.",
            },
        )
        if error:
            result["error"] = error
            return result
        if not isinstance(data, dict) or data.get("success") is False:
            message = data.get("message") if isinstance(data, dict) else None
            result["error"] = f"WiGLE refused the search: {message or 'unexpected response'}."
            return result

        rows = [r for r in data.get("results") or [] if isinstance(r, dict)]
        result["total_results"] = data.get("totalResults") or len(rows)
        result["networks"] = [self._tidy(r) for r in rows[:max_results]]
        result["truncated"] = result["total_results"] > len(result["networks"])
        log(self.name, f"{len(rows)} networks returned of {result['total_results']}")
        return result

    @staticmethod
    def _tidy(r: dict) -> dict:
        address = ", ".join(str(p) for p in (r.get("housenumber"), r.get("road"), r.get("city"),
                                              r.get("region"), r.get("country")) if p)
        return {
            "ssid": r.get("ssid") or None,
            "bssid": r.get("netid"),
            "encryption": r.get("encryption"),
            "channel": r.get("channel"),
            "latitude": r.get("trilat"),
            "longitude": r.get("trilong"),
            "first_seen": (r.get("firsttime") or "")[:10] or None,
            "last_seen": (r.get("lasttime") or "")[:10] or None,
            "address": address or None,
        }
