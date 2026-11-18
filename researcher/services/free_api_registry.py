"""
Free-API tools (free-apis branch): registry entries, kept in their own module
so they merge cleanly with other branches. tool_registry.py adds FREE_API_TOOLS
to TOOLS and SERVERS["local"]; mcp_client.py adds FREE_API_TOOL_NAMES to the
agent allowlist. The MCP tools themselves are in free_api_tools.py.

All are Passive (they read someone else's database or a public broadcast
feed; none contacts the target), so none is in LIVE_CONTACT_TOOLS and stealth
mode keeps them. Keys come from .env; see docs/agent-tool-list.md.
"""


def _arg(type_, required, description):
    return {"type": type_, "required": required, "description": description}


FREE_API_TOOLS = {
    # --- Network Discovery ---------------------------------------------------
    "crtsh_subdomains": {
        "name": "crtsh_subdomains",
        "description": "Find a domain's subdomains in public certificate-transparency logs (crt.sh), with first and last dates seen. Passive; can be slow on big domains.",
        "confirmation": "search certificate logs (crt.sh) for subdomains of {domain}",
        "server": "local",
        "arguments": {
            "domain": _arg("string", True, "The domain (e.g., 'example.com')"),
            "include_expired": _arg("boolean", False, "Include names only on expired certificates (default: true)"),
            "max_results": _arg("integer", False, "Most names to list, most recently seen first (default: 200)"),
        },
        "examples": ["What subdomains of example.com appear in certificate logs?",
                     "Find hidden subdomains of example.com"],
        "estimated_time": "5-60 seconds",
        "category": "discovery",
    },

    # --- Website Vulnerabilities --------------------------------------------
    "osv_package_vulns": {
        "name": "osv_package_vulns",
        "description": "List known vulnerabilities (with CVE IDs and fixed versions) for a software package and version from OSV.dev, e.g. jquery 1.12.4 on npm.",
        "confirmation": "look up known vulnerabilities for {package} in OSV.dev",
        "server": "local",
        "arguments": {
            "package": _arg("string", True, "Package name (e.g., 'jquery', 'django', 'log4j-core' as 'org.apache.logging.log4j:log4j-core')"),
            "version": _arg("string", False, "Exact version (e.g., '1.12.4'); empty = all versions"),
            "ecosystem": _arg("string", False, "npm, PyPI, Maven, Go, NuGet, RubyGems, Packagist, crates.io, WordPress... (default: npm)"),
            "max_results": _arg("integer", False, "Most vulnerabilities to list, newest first (default: 20)"),
        },
        "examples": ["Does jQuery 1.12.4 have known vulnerabilities?",
                     "Known CVEs for lodash 4.17.15"],
        "estimated_time": "1-5 seconds",
        "category": "vulnerability",
    },

    "kev_check": {
        "name": "kev_check",
        "description": "Check whether CVEs are on CISA's Known Exploited Vulnerabilities list (exploited in the wild, incl. ransomware use), or search that list by vendor or product.",
        "confirmation": "check {query} against CISA's Known Exploited Vulnerabilities list",
        "server": "local",
        "arguments": {
            "query": _arg("string", True, "CVE IDs to check (e.g., 'CVE-2021-44228, CVE-2023-4966'), or a vendor/product word to search (e.g., 'Citrix')"),
            "max_results": _arg("integer", False, "Most entries to list, newest first (default: 20)"),
        },
        "examples": ["Is CVE-2021-44228 being exploited in the wild?",
                     "Which Citrix vulnerabilities are known to be exploited?"],
        "estimated_time": "1-10 seconds",
        "category": "vulnerability",
    },

    # --- Third-Party Services -----------------------------------------------
    "sec_company_filings": {
        "name": "sec_company_filings",
        "description": "Look up a US public company in SEC EDGAR by ticker, CIK or name: industry, business and mailing addresses, phone, former names, and recent filings (10-K, 8-K...) with links.",
        "confirmation": "look up {company} in SEC EDGAR",
        "server": "local",
        "arguments": {
            "company": _arg("string", True, "Ticker (e.g., 'MSFT'), CIK number, or company name"),
            "forms": _arg("string", False, "Only these form types, comma-separated (e.g., '10-K, 8-K')"),
            "max_filings": _arg("integer", False, "Most filings to list, newest first (default: 20)"),
        },
        "examples": ["What has Microsoft filed with the SEC recently?",
                     "Where is CACI's business address according to SEC filings?"],
        "estimated_time": "1-5 seconds",
        "category": "third_party",
    },

    "sec_filing_search": {
        "name": "sec_filing_search",
        "description": "Full-text search of SEC EDGAR filings since 2001: which companies' filings mention a name or phrase (e.g., a vendor or customer), with form, date and link.",
        "confirmation": "search SEC filings for {query}",
        "server": "local",
        "arguments": {
            "query": _arg("string", True, "Words, or a phrase in double quotes (e.g., '\"Example Corp\"')"),
            "forms": _arg("string", False, "Only these form types, comma-separated (e.g., '10-K, 8-K')"),
            "start_date": _arg("string", False, "Earliest filing date, YYYY-MM-DD"),
            "end_date": _arg("string", False, "Latest filing date, YYYY-MM-DD"),
            "max_results": _arg("integer", False, "Most filings to list (default: 20)"),
        },
        "examples": ["Which SEC filings mention \"Example Corp\" as a supplier?",
                     "Find 8-K filings that mention a ransomware attack in 2024"],
        "estimated_time": "2-8 seconds",
        "category": "third_party",
    },

    "ransomware_victims": {
        "name": "ransomware_victims",
        "description": "Check whether an organization (e.g., a vendor or supplier) was listed as a victim on a ransomware gang's leak site (ransomware.live), with group, date and sector.",
        "confirmation": "check ransomware leak-site victims for {query}",
        "server": "local",
        "arguments": {
            "query": _arg("string", True, "Organization name or website (e.g., 'example.com')"),
            "group": _arg("string", False, "Only this ransomware group (e.g., 'lockbit3')"),
            "country": _arg("string", False, "Only this 2-letter country code (e.g., 'US')"),
            "max_results": _arg("integer", False, "Most victims to list, newest first (default: 20)"),
        },
        "examples": ["Has Example Corp been hit by ransomware?",
                     "Was example.com listed on a ransomware leak site?"],
        "estimated_time": "2-5 seconds",
        "category": "third_party",
    },

    # --- Physical Assets ----------------------------------------------------
    "opensky_airport_flights": {
        "name": "opensky_airport_flights",
        "description": "List flights arriving at or departing from an airport in a past window of up to 2 days (OpenSky Network), with aircraft, callsign and the other airport. Yesterday is the newest data.",
        "confirmation": "list flights in and out of {airport} from OpenSky starting {start}",
        "server": "local",
        "arguments": {
            "airport": _arg("string", True, "4-letter ICAO code (e.g., 'KILG' for Wilmington, DE)"),
            "start": _arg("string", True, "Start, UTC: 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM'"),
            "end": _arg("string", False, "End, UTC (default: start + 1 day; at most 2 days after start)"),
            "direction": _arg("string", False, "arrival or departure (default: arrival)"),
            "max_results": _arg("integer", False, "Most flights to list (default: 50)"),
        },
        "examples": ["Which flights arrived at KILG on 2025-12-12?",
                     "What departed from KIAD between 2025-12-12T18:00 and 2025-12-13T02:00?"],
        "estimated_time": "2-10 seconds",
        "category": "physical",
    },

    "opensky_aircraft_flights": {
        "name": "opensky_aircraft_flights",
        "description": "List one aircraft's flights in a past window of up to 2 days (OpenSky Network), by its 6-hex-digit ICAO24 transponder address.",
        "confirmation": "list OpenSky flights of aircraft {icao24} starting {start}",
        "server": "local",
        "arguments": {
            "icao24": _arg("string", True, "ICAO24 transponder address, 6 hex digits (e.g., 'a0b1c2')"),
            "start": _arg("string", True, "Start, UTC: 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM'"),
            "end": _arg("string", False, "End, UTC (default: start + 1 day; at most 2 days after start)"),
            "max_results": _arg("integer", False, "Most flights to list (default: 50)"),
        },
        "examples": ["Where did aircraft a0b1c2 fly on 2025-12-12?"],
        "estimated_time": "2-10 seconds",
        "category": "physical",
    },

    "ships_near": {
        "name": "ships_near",
        "description": "List ships broadcasting their position (AIS) near a point right now (AISStream): name, MMSI, type, destination, position, speed. Listens live for a few seconds; no history.",
        "confirmation": "listen for ships near {latitude}, {longitude} (AISStream, live feed)",
        "server": "local",
        "arguments": {
            "latitude": _arg("number", True, "Latitude, decimal degrees"),
            "longitude": _arg("number", True, "Longitude, decimal degrees"),
            "radius_km": _arg("number", False, "Search radius in km (default: 5, max 50)"),
            "listen_seconds": _arg("integer", False, "How long to listen (default: 30, max 90)"),
            "max_ships": _arg("integer", False, "Most ships to list (default: 50)"),
        },
        "examples": ["Which ships are near the port at 39.27, -76.58 right now?"],
        "estimated_time": "10-90 seconds",
        "category": "physical",
    },

    "wigle_wifi_search": {
        "name": "wigle_wifi_search",
        "description": "Find WiFi networks recorded near a point, optionally by network name (WiGLE): SSID, router BSSID, encryption, first and last seen. Research use only; few searches per day.",
        "confirmation": "search WiGLE for WiFi networks seen near {latitude}, {longitude}",
        "server": "local",
        "arguments": {
            "latitude": _arg("number", True, "Latitude, decimal degrees"),
            "longitude": _arg("number", True, "Longitude, decimal degrees"),
            "radius_m": _arg("integer", False, "Radius in metres around the point (default: 150, max 2000)"),
            "ssid": _arg("string", False, "Network name; use % as a wildcard (e.g., 'Acme%')"),
            "seen_since": _arg("string", False, "Only networks seen after this date, YYYY-MM-DD"),
            "max_results": _arg("integer", False, "Most networks to list, closest first (default: 50, max 100)"),
        },
        "examples": ["Which WiFi networks were seen near 38.88, -77.03?",
                     "Was a network named 'Acme-Guest' seen near 38.88, -77.03?"],
        "estimated_time": "2-10 seconds",
        "category": "physical",
    },

    # --- Brand Monitoring / Employee Public Information ----------------------
    "reddit_search": {
        "name": "reddit_search",
        "description": "Search Reddit posts (live Reddit API) mentioning a company, product or phrase, site-wide or in one subreddit, with score, comment count and link.",
        "confirmation": "search Reddit posts for {query}",
        "server": "local",
        "arguments": {
            "query": _arg("string", True, "Words or a phrase (e.g., '\"Example Corp\" outage')"),
            "subreddit": _arg("string", False, "Only this subreddit (e.g., 'sysadmin')"),
            "sort": _arg("string", False, "relevance, new, top, hot or comments (default: relevance)"),
            "time_range": _arg("string", False, "hour, day, week, month, year or all (default: all)"),
            "max_results": _arg("integer", False, "Most posts to list (default: 25, max 100)"),
        },
        "examples": ["What are people saying about Example Corp on Reddit?",
                     "Find posts in r/sysadmin about Example Corp's VPN"],
        "estimated_time": "1-5 seconds",
        "category": "brand",
    },

    "reddit_post_comments": {
        "name": "reddit_post_comments",
        "description": "Read a Reddit post and its comments (live Reddit API), by post URL or id.",
        "confirmation": "read the Reddit thread {post}",
        "server": "local",
        "arguments": {
            "post": _arg("string", True, "Post URL or id (e.g., 'https://www.reddit.com/r/x/comments/1abc23d/...')"),
            "max_comments": _arg("integer", False, "Most comments to return, top first (default: 50, max 200)"),
        },
        "examples": ["Read the comments on https://www.reddit.com/r/OSINT/comments/1abc23d/"],
        "estimated_time": "1-5 seconds",
        "category": "brand",
    },

    "reddit_user_activity": {
        "name": "reddit_user_activity",
        "description": "List a Reddit account's recent posts and comments (live Reddit API), with account age and karma.",
        "confirmation": "list recent Reddit posts and comments by u/{username}",
        "server": "local",
        "arguments": {
            "username": _arg("string", True, "Reddit username (with or without u/)"),
            "kind": _arg("string", False, "all, posts or comments (default: all)"),
            "max_results": _arg("integer", False, "Most items to list, newest first (default: 25, max 100)"),
        },
        "examples": ["What else has u/example_user posted on Reddit?"],
        "estimated_time": "2-5 seconds",
        "category": "employee",
    },
}

FREE_API_TOOL_NAMES = frozenset(FREE_API_TOOLS)
