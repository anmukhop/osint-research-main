"""Hudson Rock Cavalier domain-level infostealer exposure lookup."""

import ipaddress
import re
from urllib.parse import urlsplit

import requests


API_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
USER_AGENT = "osint-research-platform"
DEFAULT_LIMIT = 5
MAX_LIMIT = 20
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(value) -> str | None:
    """Extract and validate a domain from a domain string or URL."""
    if not isinstance(value, str):
        return None

    value = value.strip()
    if not value or len(value) > 2048:
        return None

    try:
        parsed = urlsplit(value)
        if parsed.scheme:
            if parsed.scheme.lower() not in ("http", "https"):
                return None
        else:
            parsed = urlsplit(f"//{value}")
        if parsed.username or parsed.password or parsed.port is not None:
            return None
        host = parsed.hostname
    except ValueError:
        return None

    if not host:
        return None
    try:
        domain = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None

    if domain.startswith("www."):
        domain = domain[4:]
    if len(domain) > 253 or "." not in domain:
        return None
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass
    if any(not _DOMAIN_LABEL_RE.fullmatch(label) for label in domain.split(".")):
        return None
    return domain


class InfostealerDomainSearchAgent:
    """Look up aggregate Hudson Rock infostealer exposure for a domain."""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    @property
    def name(self) -> str:
        return "infostealer_domain_search"

    def run(self, domain: str, limit: int = DEFAULT_LIMIT) -> dict:
        """Return aggregate counts and top employee/user login URLs; never raises."""
        cleaned = normalize_domain(domain)
        result = {
            "domain": cleaned or domain,
            "total": 0,
            "employees": 0,
            "users": 0,
            "third_parties": 0,
            "total_urls": 0,
            "employee_urls": [],
            "user_urls": [],
            "error": None,
        }
        if cleaned is None:
            result["error"] = "Enter a valid company domain or URL."
            return result
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            result["error"] = "The URL limit must be a positive whole number."
            return result
        limit = min(limit, MAX_LIMIT)

        try:
            response = requests.get(
                API_URL,
                params={"domain": cleaned},
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
            )
        except requests.Timeout:
            result["error"] = "Hudson Rock did not respond in time. Try again shortly."
            return result
        except requests.RequestException as exc:
            result["error"] = f"Could not reach Hudson Rock ({type(exc).__name__})."
            return result

        if response.status_code != 200:
            if response.status_code == 429:
                result["error"] = "Hudson Rock rate limit reached (HTTP 429). Try again later."
            else:
                result["error"] = f"Hudson Rock returned HTTP {response.status_code}."
            return result

        try:
            data = response.json()
        except ValueError:
            result["error"] = "Hudson Rock returned a response that isn't JSON."
            return result

        if not isinstance(data, dict):
            result["error"] = "Hudson Rock returned an unexpected response."
            return result

        counts = {
            "total": data.get("total"),
            "employees": data.get("employees"),
            "users": data.get("users"),
            "third_parties": data.get("third_parties"),
            "total_urls": data.get("totalUrls"),
        }
        if any(type(value) is not int or value < 0 for value in counts.values()):
            result["error"] = "Hudson Rock returned unexpected count data."
            return result

        url_data = data.get("data")
        if not isinstance(url_data, dict):
            result["error"] = "Hudson Rock returned unexpected login URL data."
            return result
        employee_urls = self._top_urls(url_data.get("employees_urls"), limit)
        user_urls = self._top_urls(url_data.get("clients_urls"), limit)
        if employee_urls is None or user_urls is None:
            result["error"] = "Hudson Rock returned unexpected login URL data."
            return result

        result.update(counts)
        result["employee_urls"] = employee_urls
        result["user_urls"] = user_urls
        return result

    @staticmethod
    def _top_urls(entries, limit: int) -> list[dict] | None:
        if not isinstance(entries, list):
            return None

        urls = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            occurrence = entry.get("occurrence")
            url = entry.get("url")
            if type(occurrence) is not int or occurrence < 0 or not isinstance(url, str):
                continue
            try:
                parsed = urlsplit(url)
                hostname = parsed.hostname
            except ValueError:
                continue
            if parsed.scheme not in ("http", "https") or not hostname or parsed.username or parsed.password:
                continue
            urls.append({"url": url, "occurrence": occurrence})

        urls.sort(key=lambda item: item["occurrence"], reverse=True)
        return urls[:limit]
