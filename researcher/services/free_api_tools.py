"""
Free-API MCP tools (free-apis branch), registered on the local MCP server by
mcp_server.py with register_free_api_tools(mcp). Kept in their own module so
they merge cleanly with other branches.

Each tool runs its agent in a background thread (run_in_executor), never
raises, and returns a dict with an "error" key. Registry entries (for routing
and confirmations) are in free_api_registry.py. Which CVA category each tool
serves, and its key and rate limit: docs/agent-tool-list.md.
"""

import asyncio


async def _in_thread(call):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, call)


def register_free_api_tools(mcp) -> None:
    """Add the free-API tools to a FastMCP server."""

    @mcp.tool()
    async def crtsh_subdomains(domain: str, include_expired: bool = True,
                               max_results: int = 200) -> dict:
        """
        Find a domain's subdomains in public certificate-transparency logs (crt.sh).
        Passive: only crt.sh is contacted, never the target. Returns each name
        found with first/last dates seen on a certificate, the number of
        certificates and issuers; wildcard names (*.example.com) are flagged.
        Can take up to a minute on big domains; crt.sh is sometimes overloaded.
        """
        from agents.crtsh import CrtShAgent
        return await _in_thread(lambda: CrtShAgent().run(
            domain=domain, include_expired=include_expired, max_results=max_results))

    @mcp.tool()
    async def osv_package_vulns(package: str, version: str = "", ecosystem: str = "npm",
                                max_results: int = 20) -> dict:
        """
        Known vulnerabilities for a software package from OSV.dev (passive).
        Give the package name, the exact version if known (e.g. jquery 1.12.4,
        as seen in a site's script tags), and the ecosystem: npm (default),
        PyPI, Maven, Go, NuGet, RubyGems, Packagist, crates.io, WordPress.
        Returns each vulnerability's OSV id, CVE IDs, summary, severity,
        publish date and the versions that fix it.
        """
        from agents.osv import OSVAgent
        return await _in_thread(lambda: OSVAgent().run(
            package=package, version=version, ecosystem=ecosystem, max_results=max_results))

    @mcp.tool()
    async def kev_check(query: str, max_results: int = 20) -> dict:
        """
        Is a CVE being exploited in the wild? Checks CISA's Known Exploited
        Vulnerabilities (KEV) catalogue (passive, US government, CC0).
        query: one or more CVE IDs; not_in_kev lists the ones CISA hasn't
        listed (that does not mean they are safe). Or a vendor, product or
        vulnerability-name word instead (e.g. 'Citrix'). Each match has
        the date CISA added it, whether ransomware campaigns use it, and a
        short description. Pairs with cve_lookup and cves_by_product.
        """
        from agents.cisa_kev import CisaKevAgent
        return await _in_thread(lambda: CisaKevAgent().run(
            query=query, max_results=max_results))

    @mcp.tool()
    async def sec_company_filings(company: str, forms: str = "", max_filings: int = 20) -> dict:
        """
        Look up a company in SEC EDGAR (passive) by ticker, CIK or name: its
        industry, business and mailing addresses, phone, former names and
        recent filings (form, date, link). forms filters, e.g. "10-K, 8-K".
        Only companies that file with the SEC are covered; names are matched
        against listed (ticker) companies, so for others use sec_filing_search
        to find the CIK first.
        """
        from agents.sec_edgar import SecEdgarAgent
        return await _in_thread(lambda: SecEdgarAgent().company_filings(
            company=company, forms=forms, max_filings=max_filings))

    @mcp.tool()
    async def sec_filing_search(query: str, forms: str = "", start_date: str = "",
                                end_date: str = "", max_results: int = 20) -> dict:
        """
        Full-text search of SEC EDGAR filings since 2001 (passive): which
        companies' filings mention a name or phrase. Put a phrase in double
        quotes for an exact match ("Example Corp"). Useful to find a target's
        customers, suppliers or parent, or 8-K reports of cyber incidents.
        Returns the total match count and each filing's company, CIK, form,
        date, business locations and link.
        """
        from agents.sec_edgar import SecEdgarAgent
        return await _in_thread(lambda: SecEdgarAgent().full_text_search(
            query=query, forms=forms, start_date=start_date, end_date=end_date,
            max_results=max_results))

    @mcp.tool()
    async def ransomware_victims(query: str, group: str = "", country: str = "",
                                 max_results: int = 20) -> dict:
        """
        Was an organization listed as a victim on a ransomware gang's leak
        site? Searches ransomware.live (passive) by organization name or
        website, optionally one group or 2-letter country. Each victim has
        the group, attack date, discovery date, country, sector and a link.
        Use it on a target's vendors and suppliers as well as the target.
        """
        from agents.ransomware_live import RansomwareLiveAgent
        return await _in_thread(lambda: RansomwareLiveAgent().run(
            query=query, group=group, country=country, max_results=max_results))

    @mcp.tool()
    async def opensky_airport_flights(airport: str, start: str, end: str = "",
                                      direction: str = "arrival", max_results: int = 50) -> dict:
        """
        Flights that arrived at (or departed from) an airport in a past window
        (OpenSky Network; passive). airport is the 4-letter ICAO code (US
        airports add K: KILG). start/end are UTC dates or times; end defaults
        to start + 1 day; at most 2 days per query. Yesterday is the newest
        data. Each flight has the aircraft's icao24, callsign, the other
        airport, and first/last seen times. Private jets may be hidden.
        """
        from agents.opensky import OpenSkyAgent
        return await _in_thread(lambda: OpenSkyAgent().airport_flights(
            airport=airport, direction=direction, start=start, end=end, max_results=max_results))

    @mcp.tool()
    async def opensky_aircraft_flights(icao24: str, start: str, end: str = "",
                                       max_results: int = 50) -> dict:
        """
        One aircraft's flights in a past window (OpenSky Network; passive),
        by its 6-hex-digit icao24 transponder address (from
        opensky_airport_flights, not the tail number). start/end are UTC; at
        most 2 days per query.
        """
        from agents.opensky import OpenSkyAgent
        return await _in_thread(lambda: OpenSkyAgent().aircraft_flights(
            icao24=icao24, start=start, end=end, max_results=max_results))

    @mcp.tool()
    async def ships_near(latitude: float, longitude: float, radius_km: float = 5,
                         listen_seconds: int = 30, max_ships: int = 50) -> dict:
        """
        Ships near a point right now, from their public AIS position
        broadcasts (AISStream; passive). Listens for listen_seconds (default
        30, max 90) inside a box of radius_km around the point and lists each
        ship once: name, MMSI, IMO, type, destination, latest position, speed.
        Live only: there is no history, and ships that didn't broadcast while
        listening are missed.
        """
        from agents.aisstream import AISStreamAgent
        return await _in_thread(lambda: AISStreamAgent().run(
            latitude=latitude, longitude=longitude, radius_km=radius_km,
            listen_seconds=listen_seconds, max_ships=max_ships))

    @mcp.tool()
    async def wigle_wifi_search(latitude: float, longitude: float, radius_m: int = 150, ssid: str = "", seen_since: str = "",
                                max_results: int = 50) -> dict:
        """
        WiFi networks volunteers recorded near a point (WiGLE; passive),
        optionally only those named ssid (% is a wildcard). seen_since (YYYY-MM-DD) keeps networks seen after that date.
        Returns SSID, router BSSID, encryption, position, first/last seen.
        Research use only. The account gets few searches a day: search once,
        precisely.
        """
        from agents.wigle import WigleAgent
        return await _in_thread(lambda: WigleAgent().run(
            latitude=latitude, longitude=longitude, radius_m=radius_m, ssid=ssid,
            seen_since=seen_since, max_results=max_results))

    @mcp.tool()
    async def reddit_search(query: str, subreddit: str = "", sort: str = "relevance",
                            time_range: str = "all", max_results: int = 25) -> dict:
        """
        Search Reddit posts (live Reddit API; passive, read-only) that mention
        a company, product or phrase, site-wide or in one subreddit. sort:
        relevance, new, top, hot, comments. time_range: hour, day, week,
        month, year, all. Each post has title, subreddit, author, date,
        score, comment count, link and the start of its text.
        """
        from agents.reddit import RedditAgent
        return await _in_thread(lambda: RedditAgent().search(
            query=query, subreddit=subreddit, sort=sort, time_range=time_range,
            max_results=max_results))

    @mcp.tool()
    async def reddit_post_comments(post: str, max_comments: int = 50) -> dict:
        """
        Read one Reddit post in full and its comments (live Reddit API;
        passive, read-only), by post URL or id. Comments come top first with
        their reply depth.
        """
        from agents.reddit import RedditAgent
        return await _in_thread(lambda: RedditAgent().post_comments(
            post=post, max_comments=max_comments))

    @mcp.tool()
    async def reddit_user_activity(username: str, kind: str = "all", max_results: int = 25) -> dict:
        """
        A Reddit account's recent posts and comments, newest first, with the
        account's creation date and karma (live Reddit API; passive,
        read-only). kind: all, posts or comments. Use on accounts tied to the
        investigation (e.g. the author of a post about the target).
        """
        from agents.reddit import RedditAgent
        return await _in_thread(lambda: RedditAgent().user_activity(
            username=username, kind=kind, max_results=max_results))
