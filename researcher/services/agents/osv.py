"""
OSV.dev agent for OSINT Research Platform

Known vulnerabilities for a software package and version (e.g. jQuery
1.12.4, the kind of version seen in an archived page's script tags).
Passive: only api.osv.dev is contacted. Free, no key.

CVA category: Website Vulnerabilities.
Rate limit: none ("no limits on the API", per the OSV docs; #47).
API docs: https://google.github.io/osv.dev/api/
"""

from .free_api_common import clamp_int, log, request_json


QUERY_URL = "https://api.osv.dev/v1/query"
PROVIDER = "OSV.dev"
DEFAULT_MAX_RESULTS = 20
MAX_RESULTS_CAP = 100
MAX_PAGES = 5

# OSV ecosystem names are case-sensitive; accept common spellings.
ECOSYSTEMS = {
    "npm": "npm", "javascript": "npm", "js": "npm",
    "pypi": "PyPI", "python": "PyPI", "pip": "PyPI",
    "maven": "Maven", "java": "Maven",
    "go": "Go", "golang": "Go",
    "crates.io": "crates.io", "cargo": "crates.io", "rust": "crates.io",
    "nuget": "NuGet", ".net": "NuGet",
    "packagist": "Packagist", "php": "Packagist", "composer": "Packagist",
    "rubygems": "RubyGems", "ruby": "RubyGems", "gem": "RubyGems",
    "hex": "Hex", "pub": "Pub", "cran": "CRAN", "swifturl": "SwiftURL",
    "debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine",
    "wordpress": "WordPress",
}


def normalize_ecosystem(ecosystem) -> str | None:
    if not isinstance(ecosystem, str) or not ecosystem.strip():
        return "npm"
    cleaned = ecosystem.strip()
    return ECOSYSTEMS.get(cleaned.lower(), cleaned)


class OSVAgent:
    """Look up known vulnerabilities for a package (optionally one version)."""

    name = "osv"

    def run(self, package: str, version: str = "", ecosystem: str = "npm",
            max_results: int = DEFAULT_MAX_RESULTS, **kwargs) -> dict:
        """
        Returns: package, ecosystem, version, vuln_count, vulns (newest first:
        id, cves, summary, severity, published, fixed_in, url), truncated,
        error. Never raises.
        """
        package = package.strip() if isinstance(package, str) else ""
        version = version.strip() if isinstance(version, str) else ""
        ecosystem = normalize_ecosystem(ecosystem)
        result = {
            "package": package, "ecosystem": ecosystem, "version": version or None,
            "vuln_count": 0, "vulns": [], "truncated": False, "error": None,
        }
        if not package or len(package) > 214:
            result["error"] = "Give a package name, e.g. 'jquery' (ecosystem npm)."
            return result
        max_results = clamp_int(max_results, DEFAULT_MAX_RESULTS, 1, MAX_RESULTS_CAP)

        body = {"package": {"name": package, "ecosystem": ecosystem}}
        if version:
            body["version"] = version

        log(self.name, f"query {ecosystem}/{package} {version or '(all versions)'}")
        raw = []
        for _ in range(MAX_PAGES):
            data, error, _ = request_json(
                "POST", QUERY_URL, PROVIDER, json=body, timeout=20,
                status_messages={400: f"OSV.dev didn't accept that query (HTTP 400). "
                                      f"Check the ecosystem name ('{ecosystem}')."},
            )
            if error:
                result["error"] = error
                return result
            if not isinstance(data, dict):
                result["error"] = "OSV.dev returned an unexpected response."
                return result
            raw.extend(v for v in data.get("vulns") or [] if isinstance(v, dict))
            token = data.get("next_page_token")
            if not token:
                break
            body["page_token"] = token

        vulns = [self._tidy(v, package) for v in raw]
        vulns.sort(key=lambda v: v["published"] or "", reverse=True)
        result["vuln_count"] = len(vulns)
        result["vulns"] = vulns[:max_results]
        result["truncated"] = len(vulns) > max_results
        if not vulns:
            result["note"] = ("No known vulnerabilities. If that's unexpected, check the "
                              "package name and ecosystem spelling.")
        log(self.name, f"found {len(vulns)} vulnerabilities")
        return result

    @staticmethod
    def _tidy(vuln: dict, package: str) -> dict:
        ids = [vuln.get("id")] + list(vuln.get("aliases") or [])
        severity = (vuln.get("database_specific") or {}).get("severity")
        if not severity:
            scores = [s.get("score") for s in vuln.get("severity") or [] if isinstance(s, dict)]
            severity = scores[0] if scores else None
        fixed = []
        for affected in vuln.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            name = (affected.get("package") or {}).get("name")
            if name and name.lower() != package.lower():
                continue
            for rng in affected.get("ranges") or []:
                for event in (rng or {}).get("events") or []:
                    if isinstance(event, dict) and event.get("fixed") and event["fixed"] not in fixed:
                        fixed.append(event["fixed"])
        summary = vuln.get("summary") or (vuln.get("details") or "")[:300] or None
        return {
            "id": vuln.get("id"),
            "cves": sorted({i for i in ids if isinstance(i, str) and i.startswith("CVE-")}),
            "summary": summary,
            "severity": severity,
            "published": (vuln.get("published") or "")[:10] or None,
            "fixed_in": fixed[:10],
            "url": f"https://osv.dev/vulnerability/{vuln.get('id')}",
        }
