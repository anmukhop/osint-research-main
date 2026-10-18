"""
OSINT MCP Server

A Model Context Protocol server that exposes OSINT research tools.
This server can be connected to by any MCP client (Claude Desktop, custom clients, etc.)

Tools exposed:
- username_search: Search for a username across 600+ platforms
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
