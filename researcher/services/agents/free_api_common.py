"""
Shared plumbing for the free-API tools (crt.sh, OSV.dev, CISA KEV, SEC EDGAR,
ransomware.live, OpenSky, AISStream, WiGLE, Reddit).

Every tool follows the XposedOrNot pattern: it never raises, returns a dict
with an "error" key (None when OK), caps how much it returns, and runs in a
background thread (the MCP server wraps it in run_in_executor).

Keys and account names come from environment variables (.env). A missing
key gives a plain "set X in .env" error instead of a call.
"""

import os
import sys

import requests


USER_AGENT = "osint-research-platform"


def clamp_int(value, default: int, low: int, high: int) -> int:
    """Turn value into an int between low and high; use default if it isn't a number."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(low, min(number, high))


def env(name: str) -> str | None:
    """Read an environment variable, trimmed; None when unset or blank."""
    value = os.getenv(name, "")
    value = value.strip() if isinstance(value, str) else ""
    return value or None


def missing_env_error(provider: str, names: list[str], where: str) -> str | None:
    """None if every variable is set; otherwise a plain 'set X in .env' message."""
    missing = [n for n in names if not env(n)]
    if not missing:
        return None
    return (f"{provider} isn't set up: set {' and '.join(missing)} in .env "
            f"({where}), then restart the server.")


def log(tool: str, message: str) -> None:
    """One line to stderr (the MCP server's log). Never log keys."""
    print(f"[{tool}] {message}", file=sys.stderr)


def request_json(method: str, url: str, provider: str, *, timeout=15,
                 empty_statuses=(), status_messages=None, **kwargs):
    """
    Make one HTTP request and parse JSON. Returns (data, error, status).

    - Never raises. On failure data is None and error is a plain sentence.
    - empty_statuses: statuses that mean "nothing found" (data None, error None).
    - status_messages: {status: message} to override the default wording.
    """
    headers = {"User-Agent": USER_AGENT}
    headers.update(kwargs.pop("headers", None) or {})
    try:
        response = requests.request(method, url, headers=headers, timeout=timeout, **kwargs)
    except requests.Timeout:
        return None, f"{provider} did not respond in time. Try again shortly.", None
    except requests.RequestException as e:
        return None, f"Could not reach {provider} ({type(e).__name__}).", None

    status = response.status_code
    if status in empty_statuses:
        return None, None, status
    if status != 200:
        custom = (status_messages or {}).get(status)
        if custom:
            return None, custom, status
        if status == 429:
            return None, f"{provider} rate limit reached (HTTP 429). Wait a minute and try again.", status
        if status in (401, 403):
            return None, (f"{provider} refused the request (HTTP {status}). "
                          "Check the key or account settings in .env."), status
        return None, f"{provider} returned HTTP {status}.", status

    try:
        return response.json(), None, status
    except ValueError:
        return None, f"{provider} returned a response that isn't JSON.", status
