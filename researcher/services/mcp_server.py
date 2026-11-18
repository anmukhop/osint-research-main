"""
OSINT MCP Server

A Model Context Protocol server that exposes OSINT research tools.
This server can be connected to by any MCP client (Claude Desktop, custom clients, etc.)

Tools exposed:
- username_search: Search for a username across 600+ platforms
- email_breach_check: Check an email address against known data breaches (XposedOrNot)
- read_webpage: DISABLED (live visit to the target); see READ_WEBPAGE_ENABLED in agents/page_reader.py
- read_archived_page: Read the Wayback Machine copy of a page or PDF (passive)
- wayback_snapshots: List Wayback captures of a URL, or archived URLs under a site (passive)
- domain_whois: Look up WHOIS registration info for a domain
- dns_lookup: Look up DNS records for a domain
"""

import asyncio
import argparse
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    name="osint-local-server"
)

# TOOL: Username Search

@mcp.tool()
async def username_search(username: str, max_results: int = 100) -> dict:
    """
    Search for a username across 600+ social media platforms, forums, and websites.
    """
    import sys
    print(f"[mcp_server] username_search called for: {username}", file=sys.stderr)
    
    try:
        from agents.whatsmyname import WhatsMyNameAgent
        print(f"[mcp_server] WhatsMyNameAgent imported", file=sys.stderr)
    except Exception as e:
        print(f"[mcp_server] IMPORT FAILED: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return {"username": username, "found_sites": [], "total_found": 0, "error": f"Import failed: {e}"}
    
    loop = asyncio.get_event_loop()
    agent = WhatsMyNameAgent()
    print(f"[mcp_server] Agent created, calling run_in_executor...", file=sys.stderr)
    
    result = await loop.run_in_executor(
        None,
        lambda: agent.run(username=username, max_results=max_results)
    )
    print(f"[mcp_server] Agent finished. Error: {result.get('error')}, Found: {result.get('total_found')}", file=sys.stderr)
    return result


# TOOL: Email Breach Check (XposedOrNot)

@mcp.tool()
async def email_breach_check(email: str, max_breaches: int = 10) -> dict:
    """
    Check whether an email address appears in known data breaches (XposedOrNot database).
    Returns the breach count, an overall risk label and score (0-100), and the most
    recent breaches with name, the breached company's domain, year, number of records
    and what data leaked.
    Passive lookup: it never contacts the address's owner. Use on an organization's
    public addresses (e.g. info@, sales@), not on private individuals.
    """
    from agents.xposedornot import XposedOrNotAgent

    agent = XposedOrNotAgent()
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: agent.run(email=email, max_breaches=max_breaches)
    )


# TOOLS: Page reader (live page, Wayback copies, Wayback URL listing)

# DISABLED pending a decision: registered only when READ_WEBPAGE_ENABLED is
# True in agents/page_reader.py (it visits the target from the server's IP).
async def read_webpage(url: str, start: int = 0, max_chars: int = 8000, max_links: int = 40,
                       fallback_to_archive: bool = True) -> dict:
    """
    Read one web page or PDF as text. LIVE: makes one ordinary visit (a plain GET)
    to the site, like opening it in a browser without running its JavaScript.
    Returns the title, visible text, meta tags, links, script sources (useful for
    spotting JavaScript library versions), HTML comments, and for PDFs the page
    count and document metadata. Long text is cut at max_chars; call again with
    start set to read further. If the live visit fails (error page, blocked,
    site down) and fallback_to_archive is true, it returns the newest Wayback
    Machine copy instead, with source="wayback" and the capture date.
    Does not submit forms, log in, or follow links.
    """
    from agents.page_reader import PageReaderAgent

    agent = PageReaderAgent()
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: agent.read_live(url=url, start=start, max_chars=max_chars, max_links=max_links,
                                fallback_to_archive=fallback_to_archive)
    )


try:  # run as a script from this folder (how mcp_client starts it)
    from agents.page_reader import READ_WEBPAGE_ENABLED  # noqa: E402
except ImportError:  # imported as researcher.services.mcp_server
    from .agents.page_reader import READ_WEBPAGE_ENABLED  # noqa: E402

if READ_WEBPAGE_ENABLED:
    mcp.tool()(read_webpage)


@mcp.tool()
async def read_archived_page(url: str, date: str = "", start: int = 0, max_chars: int = 8000,
                             max_links: int = 40) -> dict:
    """
    Read the Internet Archive (Wayback Machine) copy of a web page or PDF as text.
    Passive: only archive.org is contacted, never the site itself. date (YYYY,
    YYYY-MM or YYYY-MM-DD) picks the capture closest to that date; empty means
    the newest capture. Returns the capture date (archived_at) and the same
    fields as a live page read (title, text, meta tags, links, script sources,
    HTML comments, PDF text). Use wayback_snapshots first to see which captures
    or URLs exist.
    """
    from agents.page_reader import PageReaderAgent

    agent = PageReaderAgent()
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: agent.read_archived(url=url, timestamp=date or None, start=start,
                                    max_chars=max_chars, max_links=max_links)
    )


@mcp.tool()
async def wayback_snapshots(url: str, match_type: str = "exact", from_date: str = "",
                            to_date: str = "", limit: int = 50, newest_first: bool = False,
                            only_ok: bool = False) -> dict:
    """
    List what the Internet Archive (Wayback Machine) has archived. Passive: only
    archive.org is contacted. match_type "exact" lists the captures of one URL
    over time (identical consecutive captures merged). "prefix" (everything under
    a path, e.g. example.com/blog/), "host" (one host name) or "domain" (the
    domain and all its subdomains) list each distinct archived URL once: good for
    finding old, hidden or unlinked pages. Dates are YYYY, YYYY-MM or YYYY-MM-DD.
    only_ok keeps captures that returned HTTP 200. Each result has an archive_url
    and a timestamp to pass to read_archived_page as date.
    """
    from agents.page_reader import WaybackSnapshotsAgent

    agent = WaybackSnapshotsAgent()
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: agent.run(url=url, match_type=match_type, from_date=from_date or None,
                          to_date=to_date or None, limit=limit, newest_first=newest_first,
                          only_ok=only_ok)
    )


# RESOURCES: Provide context about capabilities
@mcp.resource("osint://capabilities")
def get_capabilities() -> str:
    """
    Returns a description of the OSINT server's capabilities.
    This helps LLMs understand what this server can do.
    """
    
    return """
# OSINT Local Server Capabilities

This MCP server provides tools for Open Source Intelligence (OSINT) research.

## Available Tools

### 1. username_search
Search for a username across 600+ platforms including:
- Social media (Twitter, Instagram, TikTok, etc.)
- Professional networks (LinkedIn, GitHub, etc.)
- Forums and communities (Reddit, Discord, etc.)
- Gaming platforms (Steam, Xbox, PlayStation, etc.)
- Dating sites, blogs, and more

**Example queries:**
- "Find all accounts for username cryptoking123"
- "Search for john_doe on social media"

### 2. email_breach_check
Check an email address against XposedOrNot's database of known data breaches.
Returns the breach count, a risk label and score, and the most recent breaches
(name, year, records, what leaked). Passive; no API key.

**Example queries:**
- "Has test@example.com appeared in any data breaches?"

### 3. read_archived_page / wayback_snapshots
Read a web page or PDF as text from the Internet Archive's Wayback Machine
(read_archived_page; passive: only archive.org is contacted). wayback_snapshots
lists the captures of a URL, or every archived URL under a site (old or hidden
pages). Free; no API key.

**Example queries:**
- "What did example.com/about say in 2015?"
- "List the pages the Wayback Machine has archived for example.com"

## Notes
- Domain/IP intelligence (WHOIS, DNS, geolocation) is handled by the WhoisXML MCP server
- Results are returned in structured JSON format
"""

# PROMPTS: Reusable prompt templates
@mcp.prompt()
def investigate_username(username: str) -> str:
    """
    A prompt template for investigating a username across platforms.
    """
    return f"""Please investigate the username "{username}" using the available OSINT tools.

1. First, use the username_search tool to find all platforms where this username exists.
2. Analyze the results to identify patterns:
   - What types of platforms are they on? (social, gaming, professional, etc.)
   - Are there any notable or high-risk platforms?
3. Provide a summary of findings.

Remember to present findings factually without making assumptions about the person's identity or character."""

def main():
    parser = argparse.ArgumentParser(description="OSINT MCP Server")
    parser.add_argument(
        "--sse",
        action="store_true",
        help="Run with SSE transport (for web clients)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8001,
        help="Port for SSE server (default: 8001)"
    )
    args = parser.parse_args()
    
    if args.sse:
        print(f"Starting OSINT MCP Server with SSE transport on port {args.port}...")
        print(f"Connect to: http://localhost:{args.port}/sse")
        mcp.settings.port = args.port
        mcp.run(transport="sse")
    else:
        import sys
        print("Starting OSINT MCP Server with stdio transport...", file=sys.stderr)
        print("Waiting for client connection...", file=sys.stderr)
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
