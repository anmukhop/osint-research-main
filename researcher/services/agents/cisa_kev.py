"""
CISA Known Exploited Vulnerabilities (KEV) agent for OSINT Research Platform

Answers "is this CVE being exploited in the wild?" from CISA's KEV catalogue,
and searches it by vendor or product. Pairs with cve_lookup / cves_by_product.
Passive: downloads CISA's public JSON feed (about 2 MB), cached in memory for
6 hours. Free, no key. Licence: CC0 ("use this data in any legal manner").

CVA category: Website Vulnerabilities.
Rate limit: none published; the cache means about 4 downloads a day at most.
Feed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import re
import threading
import time

from .free_api_common import clamp_int, log, request_json


FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# CISA's own GitHub copy of the same feed, used if cisa.gov refuses or fails.
MIRROR_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
PROVIDER = "CISA KEV"
CACHE_SECONDS = 6 * 3600
DEFAULT_MAX_RESULTS = 20
MAX_RESULTS_CAP = 100
MAX_CVES = 50

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_cache = {"at": 0.0, "data": None}
_lock = threading.Lock()


def clear_cache() -> None:
    with _lock:
        _cache.update(at=0.0, data=None)


def load_catalog() -> tuple[dict | None, str | None]:
    """Return (catalogue, error), downloading at most once per CACHE_SECONDS."""
    with _lock:
        if _cache["data"] and time.time() - _cache["at"] < CACHE_SECONDS:
            return _cache["data"], None
        data, error, _ = request_json("GET", FEED_URL, PROVIDER, timeout=30)
        if error or not isinstance(data, dict):
            log("cisa_kev", f"cisa.gov failed ({error}); trying the GitHub copy")
            data, error, _ = request_json("GET", MIRROR_URL, PROVIDER, timeout=30)
        if error:
            return None, error
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            return None, "The CISA KEV feed returned an unexpected response."
        _cache.update(at=time.time(), data=data)
        return data, None


class CisaKevAgent:
    """Check CVEs against, or search, CISA's Known Exploited Vulnerabilities catalogue."""

    name = "cisa_kev"

    def run(self, query: str, max_results: int = DEFAULT_MAX_RESULTS, **kwargs) -> dict:
        """
        query: one or more CVE IDs (any separator) to check, or else a word
        matched against vendor, product and vulnerability name ('Citrix').
        Returns: mode, catalog_version, catalog_count, matches (newest first),
        not_in_kev, truncated, error. Never raises.
        """
        text = query.strip() if isinstance(query, str) else ""
        wanted = []
        for cve in _CVE_RE.findall(text):
            if cve.upper() not in wanted:
                wanted.append(cve.upper())
        keyword = "" if wanted else text.lower()
        result = {
            "mode": "check CVEs" if wanted else "keyword search",
            "catalog_version": None, "catalog_count": 0, "matches": [],
            "not_in_kev": [], "truncated": False, "error": None,
        }
        if not wanted and not 2 <= len(keyword) <= 100:
            result["error"] = "Give CVE IDs (e.g. CVE-2021-44228) or a vendor/product word."
            return result
        if len(wanted) > MAX_CVES:
            result["error"] = f"Too many CVEs at once; give at most {MAX_CVES}."
            return result
        max_results = clamp_int(max_results, DEFAULT_MAX_RESULTS, 1, MAX_RESULTS_CAP)

        catalog, error = load_catalog()
        if error:
            result["error"] = error
            return result
        entries = [v for v in catalog["vulnerabilities"] if isinstance(v, dict)]
        result["catalog_version"] = catalog.get("catalogVersion")
        result["catalog_count"] = len(entries)

        matches = []
        if wanted:
            by_id = {str(v.get("cveID", "")).upper(): v for v in entries}
            matches = [by_id[c] for c in wanted if c in by_id]
            result["not_in_kev"] = [c for c in wanted if c not in by_id]
        else:
            matches = [v for v in entries if keyword in " ".join(
                str(v.get(k) or "") for k in ("vendorProject", "product", "vulnerabilityName")
            ).lower()]

        matches = sorted((self._tidy(v) for v in matches),
                         key=lambda v: v["date_added"] or "", reverse=True)
        result["matches"] = matches[:max_results]
        result["truncated"] = len(matches) > max_results
        log(self.name, f"{len(matches)} KEV matches")
        return result

    @staticmethod
    def _tidy(v: dict) -> dict:
        return {
            "cve": v.get("cveID"),
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "name": v.get("vulnerabilityName"),
            "date_added": v.get("dateAdded"),
            "due_date": v.get("dueDate"),
            "ransomware_use": v.get("knownRansomwareCampaignUse"),
            "description": v.get("shortDescription"),
            "cwes": v.get("cwes") or [],
        }
