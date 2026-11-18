"""
OpenSky Network agent for OSINT Research Platform

Flights in and out of an airport, or the flights of one aircraft, from the
OpenSky Network's history. Passive: only OpenSky is contacted.

CVA category: Physical Assets.
Account: free OpenSky account -> Account page -> create an API client.
Set OPENSKY_CLIENT_ID and OPENSKY_CLIENT_SECRET in .env. OpenSky accepts only
OAuth2 client credentials now (basic auth was retired); tokens last 30 min.
Limits (docs): each query covers at most 2 days; flights are filled in by a
nightly batch, so yesterday is the newest data. A query of one day costs 30
credits (under 24 h: 4); a free account gets 4,000 credits a day. Out of
credits -> HTTP 429. No published maximum lookback for flights.
Private jets can be hidden from public tracking (FAA LADD/PIA programs).
Docs: https://openskynetwork.github.io/opensky-api/rest.html
"""

import re
import threading
import time
from datetime import datetime, timedelta, timezone

from .free_api_common import clamp_int, env, log, missing_env_error, request_json


TOKEN_URL = ("https://auth.opensky-network.org/auth/realms/opensky-network/"
             "protocol/openid-connect/token")
API_URL = "https://opensky-network.org/api"
PROVIDER = "OpenSky"
ENV_NAMES = ["OPENSKY_CLIENT_ID", "OPENSKY_CLIENT_SECRET"]
ENV_HELP = "free account at opensky-network.org, then Account -> API client"
MAX_WINDOW = timedelta(days=2)
DEFAULT_MAX_RESULTS = 50
MAX_RESULTS_CAP = 300

_AIRPORT_RE = re.compile(r"^[A-Z0-9]{4}$")
_ICAO24_RE = re.compile(r"^[0-9a-f]{6}$")
_token = {"value": None, "expires": 0.0}
_lock = threading.Lock()


def clear_cache() -> None:
    with _lock:
        _token.update(value=None, expires=0.0)


def parse_time(value) -> datetime | None:
    """'2025-12-12', '2025-12-12T20:00' or '2025-12-12 20:00:00' (UTC) -> datetime."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace(" ", "T").rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _iso(seconds) -> str | None:
    if not isinstance(seconds, (int, float)):
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


class OpenSkyAgent:
    """Historical flights by airport or by aircraft (OpenSky REST API)."""

    name = "opensky"

    def _bearer(self, force_new: bool = False):
        with _lock:
            if not force_new and _token["value"] and time.time() < _token["expires"]:
                return _token["value"], None
        data, error, _ = request_json(
            "POST", TOKEN_URL, PROVIDER, timeout=15,
            data={"grant_type": "client_credentials",
                  "client_id": env("OPENSKY_CLIENT_ID"),
                  "client_secret": env("OPENSKY_CLIENT_SECRET")},
            status_messages={401: "OpenSky rejected the API client (HTTP 401). Check "
                                  "OPENSKY_CLIENT_ID and OPENSKY_CLIENT_SECRET in .env.",
                             400: "OpenSky rejected the API client (HTTP 400). Check "
                                  "OPENSKY_CLIENT_ID and OPENSKY_CLIENT_SECRET in .env."},
        )
        if error:
            return None, error
        token = (data or {}).get("access_token") if isinstance(data, dict) else None
        if not token:
            return None, "OpenSky's login returned no token."
        lifetime = clamp_int((data or {}).get("expires_in"), 1800, 60, 3600)
        with _lock:
            _token.update(value=token, expires=time.time() + lifetime - 60)
        return token, None

    def _window(self, start, end):
        begin = parse_time(start)
        if begin is None:
            return None, None, "start must be a UTC date or time, e.g. 2025-12-12 or 2025-12-12T18:00."
        finish = parse_time(end) if end else begin + timedelta(days=1)
        if finish is None:
            return None, None, "end must be a UTC date or time, e.g. 2025-12-13."
        if finish <= begin:
            return None, None, "end must be after start."
        if finish - begin > MAX_WINDOW:
            return None, None, "OpenSky allows at most 2 days per query; split the period."
        return begin, finish, None

    def _flights(self, path, params, result, max_results):
        problem = missing_env_error(PROVIDER, ENV_NAMES, ENV_HELP)
        if problem:
            result["error"] = problem
            return result
        for attempt in (1, 2):
            token, error = self._bearer(force_new=attempt == 2)
            if error:
                result["error"] = error
                return result
            data, error, status = request_json(
                "GET", f"{API_URL}{path}", PROVIDER, params=params, timeout=30,
                headers={"Authorization": f"Bearer {token}"}, empty_statuses=(404,),
                status_messages={
                    401: "OpenSky login expired.",
                    429: "OpenSky daily credits used up (HTTP 429). They reset daily.",
                    400: "OpenSky didn't accept that query (HTTP 400).",
                },
            )
            if status != 401:
                break
        if error:
            result["error"] = error
            return result
        if data is not None and not isinstance(data, list):
            result["error"] = "OpenSky returned an unexpected response."
            return result
        flights = [self._tidy(f) for f in data or [] if isinstance(f, dict)]
        flights.sort(key=lambda f: f["_sort"])
        for f in flights:
            f.pop("_sort")
        result["flight_count"] = len(flights)
        result["flights"] = flights[:max_results]
        result["truncated"] = len(flights) > max_results
        if not flights:
            result["note"] = ("No flights found. Data is filled in nightly (yesterday is the "
                              "newest), and some private aircraft are hidden from public tracking.")
        log(self.name, f"{len(flights)} flights")
        return result

    def airport_flights(self, airport: str, direction: str = "arrival", start: str = "",
                        end: str = "", max_results: int = DEFAULT_MAX_RESULTS, **kwargs) -> dict:
        """
        airport: 4-letter ICAO code (KILG, not ILG). direction: arrival or
        departure. start/end: UTC; end defaults to start + 1 day; max 2 days.
        """
        airport = airport.strip().upper() if isinstance(airport, str) else ""
        direction = (direction or "arrival").strip().lower() if isinstance(direction, str) else "arrival"
        direction = {"arrivals": "arrival", "departures": "departure"}.get(direction, direction)
        result = {"airport": airport, "direction": direction, "start": None, "end": None,
                  "flight_count": 0, "flights": [], "truncated": False, "note": None, "error": None}
        if not _AIRPORT_RE.match(airport):
            result["error"] = ("airport must be a 4-letter ICAO code (US airports add a K: "
                               "Wilmington DE is KILG).")
            return result
        if direction not in ("arrival", "departure"):
            result["error"] = "direction must be arrival or departure."
            return result
        begin, finish, error = self._window(start, end)
        if error:
            result["error"] = error
            return result
        result["start"], result["end"] = _iso(begin.timestamp()), _iso(finish.timestamp())
        max_results = clamp_int(max_results, DEFAULT_MAX_RESULTS, 1, MAX_RESULTS_CAP)
        log(self.name, f"{direction}s at {airport}")
        return self._flights(f"/flights/{direction}",
                             {"airport": airport, "begin": int(begin.timestamp()),
                              "end": int(finish.timestamp())}, result, max_results)

    def aircraft_flights(self, icao24: str, start: str = "", end: str = "",
                         max_results: int = DEFAULT_MAX_RESULTS, **kwargs) -> dict:
        """icao24: the aircraft's 6-hex-digit transponder address (e.g. a0b1c2)."""
        icao24 = icao24.strip().lower() if isinstance(icao24, str) else ""
        result = {"icao24": icao24, "start": None, "end": None, "flight_count": 0,
                  "flights": [], "truncated": False, "note": None, "error": None}
        if not _ICAO24_RE.match(icao24):
            result["error"] = ("icao24 must be the 6-hex-digit transponder address (e.g. a0b1c2), "
                               "not the tail number.")
            return result
        begin, finish, error = self._window(start, end)
        if error:
            result["error"] = error
            return result
        result["start"], result["end"] = _iso(begin.timestamp()), _iso(finish.timestamp())
        max_results = clamp_int(max_results, DEFAULT_MAX_RESULTS, 1, MAX_RESULTS_CAP)
        log(self.name, f"flights of {icao24}")
        return self._flights("/flights/aircraft",
                             {"icao24": icao24, "begin": int(begin.timestamp()),
                              "end": int(finish.timestamp())}, result, max_results)

    @staticmethod
    def _tidy(f: dict) -> dict:
        return {
            "icao24": f.get("icao24"),
            "callsign": (f.get("callsign") or "").strip() or None,
            "from_airport": f.get("estDepartureAirport"),
            "to_airport": f.get("estArrivalAirport"),
            "first_seen": _iso(f.get("firstSeen")),   # about departure time
            "last_seen": _iso(f.get("lastSeen")),     # about arrival time
            "_sort": f.get("lastSeen") or f.get("firstSeen") or 0,
        }
