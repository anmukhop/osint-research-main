"""
crt.sh certificate-transparency search for OSINT Research Platform

Finds a domain's subdomains from public certificate logs: every TLS
certificate a public CA issues is logged, and crt.sh indexes the logs.
Passive: only crt.sh is contacted, never the target. Free, no key.

CVA category: Network Discovery.
Rate limit: none published; crt.sh is a shared, often slow service (a big
domain can take 30-60 s or time out). Be gentle: one query per question.
API: https://crt.sh/?q=%25.example.com&output=json (no formal docs page)
"""

import re

from .free_api_common import clamp_int, log, request_json


API_URL = "https://crt.sh/"
PROVIDER = "crt.sh"
TIMEOUT = (10, 90)   # (connect, read) seconds: crt.sh is slow on big domains
DEFAULT_MAX_RESULTS = 200
MAX_RESULTS_CAP = 1000

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_domain(domain) -> str | None:
    """Lowercase a domain, dropping any scheme, path or port; None if invalid."""
    if not isinstance(domain, str):
        return None
    cleaned = domain.strip().lower()
    cleaned = re.sub(r"^[a-z]+://", "", cleaned).split("/")[0].split(":")[0].strip(".")
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    return cleaned if _DOMAIN_RE.match(cleaned) else None


class CrtShAgent:
    """List the subdomains named in certificates issued for a domain."""

    name = "crtsh"

    def run(self, domain: str, include_expired: bool = True,
            max_results: int = DEFAULT_MAX_RESULTS, **kwargs) -> dict:
        """
        Returns: domain, certificates_seen, subdomain_count, subdomains (newest
        last_seen first: name, wildcard, first_seen, last_seen, certificates,
        issuers), truncated, error. Never raises.
        """
        cleaned = normalize_domain(domain)
        result = {
            "domain": cleaned or domain,
            "certificates_seen": 0,
            "subdomain_count": 0,
            "subdomains": [],
            "truncated": False,
            "error": None,
        }
        if cleaned is None:
            result["error"] = "That doesn't look like a domain name (e.g. example.com)."
            return result
        max_results = clamp_int(max_results, DEFAULT_MAX_RESULTS, 1, MAX_RESULTS_CAP)

        params = {"q": f"%.{cleaned}", "output": "json", "deduplicate": "Y"}
        if not include_expired:
            params["exclude"] = "expired"

        log(self.name, f"certificate search for {cleaned}")
        data, error, _ = request_json(
            "GET", API_URL, PROVIDER, params=params, timeout=TIMEOUT,
            status_messages={
                502: "crt.sh is overloaded (HTTP 502). It often is; try again in a minute.",
                503: "crt.sh is overloaded (HTTP 503). It often is; try again in a minute.",
            },
        )
        if error:
            result["error"] = error
            return result
        if not isinstance(data, list):
            result["error"] = "crt.sh returned an unexpected response."
            return result

        names: dict[str, dict] = {}
        for cert in data:
            if not isinstance(cert, dict):
                continue
            seen = (cert.get("not_before") or "")[:10] or None
            until = (cert.get("not_after") or "")[:10] or None
            issuer = _issuer_org(cert.get("issuer_name"))
            raw = f"{cert.get('common_name') or ''}\n{cert.get('name_value') or ''}"
            for name in {n.strip().lower() for n in raw.split("\n") if n.strip()}:
                wildcard = name.startswith("*.")
                bare = name[2:] if wildcard else name
                if bare != cleaned and not bare.endswith("." + cleaned):
                    continue
                entry = names.setdefault(name, {
                    "name": name, "wildcard": wildcard, "first_seen": seen,
                    "last_seen": until, "certificates": 0, "issuers": set(),
                })
                entry["certificates"] += 1
                if seen and (not entry["first_seen"] or seen < entry["first_seen"]):
                    entry["first_seen"] = seen
                if until and (not entry["last_seen"] or until > entry["last_seen"]):
                    entry["last_seen"] = until
                if issuer:
                    entry["issuers"].add(issuer)

        subdomains = sorted(names.values(), key=lambda e: (e["last_seen"] or "", e["name"]), reverse=True)
        for entry in subdomains:
            entry["issuers"] = sorted(entry["issuers"])[:5]
        result["certificates_seen"] = len(data)
        result["subdomain_count"] = len(subdomains)
        result["subdomains"] = subdomains[:max_results]
        result["truncated"] = len(subdomains) > max_results
        log(self.name, f"found {len(subdomains)} names in {len(data)} certificates")
        return result


def _issuer_org(issuer_name) -> str | None:
    """'C=US, O=Let's Encrypt, CN=R3' -> "Let's Encrypt"."""
    if not isinstance(issuer_name, str):
        return None
    match = re.search(r"(?:^|,\s*)O=(\"[^\"]*\"|[^,]*)", issuer_name)
    return match.group(1).strip('" ') if match else issuer_name.strip() or None
