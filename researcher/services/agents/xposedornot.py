"""
XposedOrNot Agent for OSINT Research Platform

Checks whether an email address appears in known data breaches, using
XposedOrNot's free breach-analytics API (no API key). Passive: it reads
XposedOrNot's database and never contacts the address's owner.

CVA category: Breach Data.
API docs: https://xposedornot.com/api_doc
"""

import re
import sys

import requests


API_URL = "https://api.xposedornot.com/v1/breach-analytics"
USER_AGENT = "osint-research-platform"
DEFAULT_MAX_BREACHES = 10
MAX_BREACHES_CAP = 50

# Deliberately loose: one "@", no spaces, a dot in the domain part.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(email) -> str | None:
    """Trim and lowercase an email; return None if it doesn't look like one."""
    if not isinstance(email, str):
        return None
    cleaned = email.strip().lower()
    if len(cleaned) > 254 or not _EMAIL_RE.match(cleaned):
        return None
    return cleaned


class XposedOrNotAgent:
    """Look up the breaches an email address appeared in."""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    @property
    def name(self) -> str:
        return "xposedornot"

    def run(self, email: str, max_breaches: int = DEFAULT_MAX_BREACHES, **kwargs) -> dict:
        """
        Returns a dict with: email, breach_count, risk_label, risk_score,
        breaches (newest first, at most max_breaches), error (None if OK).
        Never raises.
        """
        cleaned = normalize_email(email)
        result = {
            "email": cleaned or email,
            "breach_count": 0,
            "risk_label": None,
            "risk_score": None,
            "breaches": [],
            "error": None,
        }

        if cleaned is None:
            result["error"] = "That doesn't look like an email address."
            return result

        try:
            max_breaches = int(max_breaches)
        except (TypeError, ValueError):
            max_breaches = DEFAULT_MAX_BREACHES
        max_breaches = max(1, min(max_breaches, MAX_BREACHES_CAP))

        # Don't log the address itself.
        print(f"[{self.name}] breach lookup started", file=sys.stderr)

        try:
            response = requests.get(
                API_URL,
                params={"email": cleaned},
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
            )
        except requests.Timeout:
            result["error"] = "XposedOrNot did not respond in time. Try again shortly."
            return result
        except requests.RequestException as e:
            result["error"] = f"Could not reach XposedOrNot ({type(e).__name__})."
            return result

        if response.status_code == 429:
            result["error"] = "XposedOrNot rate limit reached (HTTP 429). Wait a minute and try again."
            return result
        if response.status_code != 200:
            result["error"] = f"XposedOrNot returned HTTP {response.status_code}."
            return result

        try:
            data = response.json()
        except ValueError:
            result["error"] = "XposedOrNot returned a response that isn't JSON."
            return result
        if not isinstance(data, dict):
            result["error"] = "XposedOrNot returned an unexpected response."
            return result

        details = (data.get("ExposedBreaches") or {}).get("breaches_details") or []
        risk = ((data.get("BreachMetrics") or {}).get("risk") or [{}])[0] or {}

        breaches = [self._tidy(b) for b in details if isinstance(b, dict)]
        breaches.sort(key=lambda b: (b["year"] or "", b["_added"] or ""), reverse=True)
        for b in breaches:
            b.pop("_added")

        result["breach_count"] = len(breaches)
        result["risk_label"] = risk.get("risk_label")
        result["risk_score"] = risk.get("risk_score")
        result["breaches"] = breaches[:max_breaches]
        print(f"[{self.name}] breach lookup finished: {len(breaches)} breaches", file=sys.stderr)
        return result

    @staticmethod
    def _tidy(breach: dict) -> dict:
        leaked = breach.get("xposed_data") or ""
        return {
            "name": breach.get("breach"),
            "domain": breach.get("domain") or None,
            "year": str(breach.get("xposed_date") or "") or None,
            "records": breach.get("xposed_records"),
            "leaked": [item.strip() for item in leaked.split(";") if item.strip()],
            "_added": breach.get("added"),
        }
