"""
AISStream agent for OSINT Research Platform

Which ships are near a place right now: listens to AISStream's live feed of
ship transponder (AIS) broadcasts inside a box around a point for a few
seconds, then lists each ship once with its latest position. Passive: ships
broadcast AIS publicly; only aisstream.io is contacted.

CVA category: Physical Assets (port-side or waterfront sites).
Key: free account at https://aisstream.io (sign in with GitHub) -> API Keys.
Set AISSTREAM_API_KEY in .env.
Limits (docs): live only, no history ("events are not durably replayed");
3 open connections per account and per IP; the subscription must be sent
within 3 seconds of connecting. No SLA.
Docs: https://aisstream.io/documentation
"""

import json
import math
import time

from .free_api_common import clamp_int, env, log, missing_env_error


STREAM_URL = "wss://stream.aisstream.io/v0/stream"
PROVIDER = "AISStream"
ENV_KEY = "AISSTREAM_API_KEY"
ENV_HELP = "free account at aisstream.io -> API Keys"
MESSAGE_TYPES = ["PositionReport", "StandardClassBPositionReport",
                 "ExtendedClassBPositionReport", "ShipStaticData"]
DEFAULT_LISTEN = 30
MAX_LISTEN = 90
DEFAULT_RADIUS_KM = 5.0
MAX_RADIUS_KM = 50.0
DEFAULT_MAX_SHIPS = 50
MAX_SHIPS_CAP = 200
MAX_MESSAGES = 20000


def bounding_box(lat: float, lon: float, radius_km: float) -> list:
    """[[lat_min, lon_min], [lat_max, lon_max]] around a point."""
    dlat = radius_km / 111.0
    dlon = radius_km / (111.0 * max(math.cos(math.radians(lat)), 0.01))
    return [[max(lat - dlat, -90.0), max(lon - dlon, -180.0)],
            [min(lat + dlat, 90.0), min(lon + dlon, 180.0)]]


def _connect(url, timeout):
    """Open the websocket. Separate so tests can replace it."""
    from websockets.sync.client import connect
    return connect(url, open_timeout=timeout, close_timeout=2)


class AISStreamAgent:
    """List ships broadcasting near a point during a short listening window."""

    name = "aisstream"

    def run(self, latitude, longitude, radius_km: float = DEFAULT_RADIUS_KM,
            listen_seconds: int = DEFAULT_LISTEN, max_ships: int = DEFAULT_MAX_SHIPS,
            **kwargs) -> dict:
        """
        Returns: center, radius_km, listened_seconds, messages, ship_count,
        ships (name, mmsi, imo, call_sign, type, destination, latitude,
        longitude, speed_knots, heading, last_seen_utc), note, error.
        """
        result = {"center": None, "radius_km": None, "listened_seconds": 0, "messages": 0,
                  "ship_count": 0, "ships": [], "truncated": False,
                  "note": "Live only: ships that didn't broadcast while listening aren't listed.",
                  "error": None}
        problem = missing_env_error(PROVIDER, [ENV_KEY], ENV_HELP)
        if problem:
            result["error"] = problem
            return result
        try:
            lat, lon = float(latitude), float(longitude)
        except (TypeError, ValueError):
            result["error"] = "latitude and longitude must be numbers (decimal degrees)."
            return result
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            result["error"] = "latitude must be -90..90 and longitude -180..180."
            return result
        try:
            radius = float(radius_km)
        except (TypeError, ValueError):
            radius = DEFAULT_RADIUS_KM
        radius = max(0.5, min(radius, MAX_RADIUS_KM))
        listen = clamp_int(listen_seconds, DEFAULT_LISTEN, 5, MAX_LISTEN)
        max_ships = clamp_int(max_ships, DEFAULT_MAX_SHIPS, 1, MAX_SHIPS_CAP)
        result.update(center=[lat, lon], radius_km=radius)

        subscription = {
            "APIKey": env(ENV_KEY),
            "BoundingBoxes": [bounding_box(lat, lon, radius)],
            "FilterMessageTypes": MESSAGE_TYPES,
        }
        ships: dict[str, dict] = {}
        started = time.monotonic()
        log(self.name, f"listening {listen}s, radius {radius} km")
        try:
            ws = _connect(STREAM_URL, timeout=10)
        except ImportError:
            result["error"] = "The websockets package isn't installed (pip install -r requirements.txt)."
            return result
        except Exception as e:  # network, TLS, handshake
            result["error"] = f"Could not reach AISStream ({type(e).__name__})."
            return result
        try:
            with ws:
                ws.send(json.dumps(subscription))
                while result["messages"] < MAX_MESSAGES:
                    remaining = listen - (time.monotonic() - started)
                    if remaining <= 0:
                        break
                    try:
                        raw = ws.recv(timeout=remaining)
                    except TimeoutError:
                        break
                    result["messages"] += 1
                    try:
                        message = json.loads(raw)
                    except (TypeError, ValueError):
                        continue
                    if isinstance(message, dict) and message.get("error"):
                        result["error"] = f"AISStream: {message['error']}. Check AISSTREAM_API_KEY in .env."
                        return result
                    self._absorb(ships, message)
        except Exception as e:  # connection closed by the server, etc.
            if not ships and not result["messages"]:
                result["error"] = (f"AISStream closed the connection ({type(e).__name__}). "
                                   "Check AISSTREAM_API_KEY in .env.")
                return result

        result["listened_seconds"] = round(time.monotonic() - started, 1)
        listed = [s for s in ships.values() if s.get("latitude") is not None]
        listed.sort(key=lambda s: s.get("last_seen_utc") or "", reverse=True)
        result["ship_count"] = len(listed)
        result["ships"] = listed[:max_ships]
        result["truncated"] = len(listed) > max_ships
        log(self.name, f"{result['messages']} messages, {len(listed)} ships")
        return result

    @staticmethod
    def _absorb(ships: dict, message) -> None:
        if not isinstance(message, dict):
            return
        meta = message.get("MetaData") or {}
        kind = message.get("MessageType")
        body = (message.get("Message") or {}).get(kind) or {}
        mmsi = str(meta.get("MMSI") or body.get("UserID") or "").strip()
        if not mmsi:
            return
        ship = ships.setdefault(mmsi, {"mmsi": mmsi, "name": None, "imo": None, "call_sign": None,
                                       "type": None, "destination": None, "latitude": None,
                                       "longitude": None, "speed_knots": None, "heading": None,
                                       "last_seen_utc": None})
        name = (meta.get("ShipName") or body.get("Name") or "").strip()
        if name:
            ship["name"] = name
        if kind == "ShipStaticData":
            ship["imo"] = body.get("ImoNumber") or ship["imo"]
            ship["call_sign"] = (body.get("CallSign") or "").strip() or ship["call_sign"]
            ship["type"] = body.get("Type", ship["type"])
            ship["destination"] = (body.get("Destination") or "").strip() or ship["destination"]
            return
        lat = meta.get("latitude", meta.get("Latitude", body.get("Latitude")))
        lon = meta.get("longitude", meta.get("Longitude", body.get("Longitude")))
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            ship["latitude"], ship["longitude"] = round(lat, 5), round(lon, 5)
        speed, heading = body.get("Sog"), body.get("TrueHeading")
        ship["speed_knots"] = speed if isinstance(speed, (int, float)) else ship["speed_knots"]
        if isinstance(heading, int) and heading != 511:   # 511 = not available
            ship["heading"] = heading
        seen = meta.get("time_utc")
        ship["last_seen_utc"] = str(seen)[:19] if seen else ship["last_seen_utc"]
