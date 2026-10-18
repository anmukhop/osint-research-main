"""
WhatsMyName Agent for OSINT Research Platform

Fast HTTP-based username search using the WhatsMyName project's data file.
Checks usernames across 600+ platforms in parallel.

Data source: https://github.com/WebBreacher/WhatsMyName
"""

import json
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import requests


# Cache settings
CACHE_DIR = Path("/tmp/wmn-cache")
CACHE_FILE = CACHE_DIR / "wmn-data.json"
CACHE_MAX_AGE = 86400  # 24 hours

# Data source
WMN_DATA_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"


class WhatsMyNameAgent:
    """
    Agent for searching usernames across 600+ platforms.
    Uses direct HTTP requests instead of browser automation.
    """

    def __init__(self, headless: bool = True, timeout: int = 5, max_workers: int = 30):
        """
        Args:
            headless: Ignored (kept for interface compatibility)
            timeout: Request timeout per site in seconds
            max_workers: Maximum concurrent requests
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = None
        self._sites_data = []

    @property
    def name(self) -> str:
        return "whatsmyname"

    def run(self, username: str, max_results: int = 100, **kwargs) -> dict:
        """
        Search for a username across platforms.
        
        Args:
            username: The username to search for
            max_results: Maximum results to return
            
        Returns:
            dict with username, found_sites, total_found, error
        """
        results = {
            "username": username,
            "found_sites": [],
            "total_found": 0,
            "error": None
        }

        try:
            # Setup session
            self.session = requests.Session()
            self.session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })

            # Load site data
            print(f"[{self.name}] Loading site data...", file=sys.stderr)
            self._load_sites_data()

            if not self._sites_data:
                results["error"] = "Failed to load site data"
                return results

            print(f"[{self.name}] Checking {len(self._sites_data)} sites for: {username}", file=sys.stderr)

            # Check sites in parallel
            found = []
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {
                    executor.submit(self._check_site, site, username): site
                    for site in self._sites_data
                }

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        found.append(result)
                        # Progress update
                        if len(found) % 10 == 0:
                            print(f"[{self.name}] Found {len(found)} so far...", file=sys.stderr)

            # Sort and limit
            found.sort(key=lambda x: x["platform"].lower())
            results["found_sites"] = found[:max_results]
            results["total_found"] = len(found)

            print(f"[{self.name}] Done. Found {len(found)} sites.", file=sys.stderr)

        except Exception as e:
            results["error"] = str(e)
            print(f"[{self.name}] Error: {e}", file=sys.stderr)

        finally:
            if self.session:
                self.session.close()

        return results

    def _load_sites_data(self) -> None:
        """Load WhatsMyName data, using cache if fresh."""
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

        # Use cache if exists and fresh
        if CACHE_FILE.exists():
            age = time.time() - CACHE_FILE.stat().st_mtime
            if age < CACHE_MAX_AGE:
                print(f"[{self.name}] Using cached data", file=sys.stderr)
                with open(CACHE_FILE, "r") as f:
                    data = json.load(f)
                    self._sites_data = data.get("sites", [])
                    return

        # Download fresh
        print(f"[{self.name}] Downloading from GitHub...", file=sys.stderr)
        try:
            resp = requests.get(WMN_DATA_URL, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            self._sites_data = data.get("sites", [])

            # Cache it
            with open(CACHE_FILE, "w") as f:
                json.dump(data, f)

            print(f"[{self.name}] Cached {len(self._sites_data)} sites", file=sys.stderr)

        except Exception as e:
            print(f"[{self.name}] Download failed: {e}", file=sys.stderr)
            # Try stale cache
            if CACHE_FILE.exists():
                with open(CACHE_FILE, "r") as f:
                    self._sites_data = json.load(f).get("sites", [])

    def _check_site(self, site: dict, username: str) -> dict | None:
        """Check if username exists on a site. Returns result dict or None."""
        if not site.get("valid", True):
            return None

        uri_check = site.get("uri_check", "")
        if not uri_check or "{account}" not in uri_check:
            return None

        check_url = uri_check.replace("{account}", username)
        e_code = site.get("e_code", 200)
        e_string = site.get("e_string", "")

        try:
            if site.get("post_body"):
                # POST request
                body = site["post_body"].replace("{account}", username)
                headers = {"Content-Type": "application/json"}
                if site.get("headers"):
                    headers.update(site["headers"])
                resp = self.session.post(check_url, data=body, headers=headers, timeout=self.timeout)
            else:
                # GET request
                headers = site.get("headers", {})
                resp = self.session.get(check_url, headers=headers, timeout=self.timeout)

            # Check if user exists
            if resp.status_code == e_code:
                if e_string:
                    if e_string in resp.text:
                        return self._build_result(site, username)
                else:
                    return self._build_result(site, username)

        except requests.RequestException:
            pass

        return None

    def _build_result(self, site: dict, username: str) -> dict:
        """Build result dict for a found site."""
        uri_pretty = site.get("uri_pretty", site.get("uri_check", ""))
        profile_url = uri_pretty.replace("{account}", username)

        domain = "Unknown"
        try:
            domain = urlparse(profile_url).netloc
        except:
            pass

        return {
            "platform": site.get("name", "Unknown"),
            "category": site.get("cat", "unknown"),
            "domain": domain,
            "profile_url": profile_url,
        }


# Convenience function for backwards compatibility
def search_username(username: str, headless: bool = True, max_results: int = 100) -> dict:
    """Search for a username across platforms."""
    agent = WhatsMyNameAgent(headless=headless)
    return agent.run(username=username, max_results=max_results)


if __name__ == "__main__":
    print("Testing WhatsMyName Agent")
    print("=" * 50)

    start = time.time()
    results = search_username("test_user", max_results=50)
    elapsed = time.time() - start

    if results["error"]:
        print(f"Error: {results['error']}")
    else:
        print(f"\nFound {results['total_found']} sites in {elapsed:.1f}s")
        for site in results["found_sites"][:10]:
            print(f"  - {site['platform']}: {site['profile_url']}")