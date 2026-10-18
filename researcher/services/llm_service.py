"""
LLM Service for OSINT Research Platform

Handles tool-based query execution and result formatting using Claude.
Uses Claude's native tool_use for MCP-style tool calling.
"""

import os
import json
from anthropic import Anthropic
from dotenv import load_dotenv
from .tool_registry import get_tool, get_all_tools

load_dotenv()

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

def get_claude_tools() -> list[dict]:
    """
    Convert our tool registry to Claude's tool schema format.

    Returns:
        List of tools in Claude's expected format
    """
    claude_tools = []

    for tool_name, tool in get_all_tools().items():
        # Build properties and required fields from our arguments
        properties = {}
        required = []

        for arg_name, arg_info in tool["arguments"].items():
            properties[arg_name] = {
                "type": arg_info["type"],
                "description": arg_info["description"]
            }
            if arg_info.get("required", False):
                required.append(arg_name)
        
        claude_tools.append({
            "name": tool_name,
            "description": tool["description"],
            "input_schema": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        })
    
    return claude_tools

def process_query(user_query: str) -> dict:
    """
    Process a user query using Claude's tool_use.
    
    We give Claude tools and let it call them directly.
    
    Returns:
        dict with 'action', 'params', and 'error' (if any)
        Example: {"action": "username_search", "params": {"username": "john_doe"}, "error": None}
    """
    
    tools = get_claude_tools()
    
    response = client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=256,
        system="""You are an OSINT research assistant. When the user asks you to search for information,
use the appropriate tool to help them. 

- For username/handle searches across social media, use username_search
- For domain registration info (WHOIS), use domain_whois
- For DNS records lookup, use dns_lookup

If the query doesn't match any available tool, respond with a brief explanation of what you can help with.""",
        tools=tools,
        messages=[
            {"role": "user", "content": user_query}
        ]
    )
    
    # Check if Claude used a tool
    for block in response.content:
        if block.type == "tool_use":
            return {
                "action": block.name,
                "params": block.input,
                "error": None
            }
    
    # Claude didn't use a tool - check if it gave a text response
    for block in response.content:
        if block.type == "text":
            return {
                "action": "unsupported",
                "params": {},
                "error": block.text
            }
    
    return {
        "action": "error",
        "params": {},
        "error": "Failed to process query"
    }
    
def format_results(action: str, params: dict, results: dict) -> str:
    """Format the raw search results into a readable response."""

    if results.get("error"):
        return f"An error occurred during the search: {results['error']}"
    
    if action == "username_search":
        return _format_username_results(params.get("username", ""), results)
    elif action == "domain_whois":
        return _format_whois_results(params.get("domain", ""), results)
    elif action == "dns_lookup":
        return _format_dns_results(params.get("domain", ""), results)
    else:
        return f"Search completed. Found {results.get('total_found', 0)} results."
    
def _format_username_results(username: str, results: dict) -> str:
    """Format username search results."""
    
    found_sites = results.get("found_sites", [])
    total = len(found_sites)

    if total == 0:
        return f"No accounts found for username '{username}'."
    
    site_list = "\n".join([
        f"- {site['platform']} ({site.get('category', 'unknown')}): {site.get('profile_url', site['domain'])}" 
        for site in found_sites
    ])
    
    response = client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=1024,
        system="""You are an OSINT research assistant. Provide a brief, factual summary.

RULES:
- Start with a 1-2 sentence overview
- Group the platforms by category (Social Media, Gaming, Professional, Forums, etc.)
- List each platform with its URL
- Do NOT include "Key Insights" or "Recommended Next Steps" sections
- Do NOT give advice or recommendations
- Keep it concise and factual""",
        messages=[
            {"role": "user", "content": f"""Summarize these username search results for '{username}':

Total: {total}

Platforms:
{site_list}"""}
        ]
    )
    
    return response.content[0].text

def _format_whois_results(domain: str, results: dict) -> str:
    """Format WHOIS lookup results."""
    data = results.get("data", {})
    
    if not data or not data.get("domain_name"):
        return f"No WHOIS information found for '{domain}'."
    
    whois_info = f"""
Domain: {data.get('domain_name', 'N/A')}
Registrar: {data.get('registrar', 'N/A')}
Created: {data.get('created_date', 'N/A')}
Updated: {data.get('updated_date', 'N/A')}
Expires: {data.get('expires_date', 'N/A')}
Status: {data.get('status', 'N/A')}
Nameservers: {', '.join(data.get('nameservers', [])[:4]) or 'N/A'}
"""
    
    registrant = data.get('registrant', {})
    if registrant and any(registrant.values()):
        whois_info += f"""
Registrant:
  Organization: {registrant.get('organization', 'N/A')}
  Country: {registrant.get('country', 'N/A')}
"""
    
    response = client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=512,
        system="""You are an OSINT research assistant. Provide a brief, factual summary.

RULES:
- Start with a 1 sentence overview
- Present key registration details clearly
- Do NOT include "Key Insights" or "Recommended Next Steps"
- Keep it concise and factual""",
        messages=[
            {"role": "user", "content": f"""Summarize WHOIS lookup for '{domain}':

{whois_info}"""}
        ]
    )
    
    return response.content[0].text


def _format_dns_results(domain: str, results: dict) -> str:
    """Format DNS lookup results."""
    data = results.get("data", {})
    dns_records = data.get("dns_records", [])
    
    if not dns_records:
        return f"No DNS records found for '{domain}'."
    
    # Group records by type
    records_by_type = {}
    for record in dns_records:
        record_type = record.get("type", "Unknown")
        if record_type not in records_by_type:
            records_by_type[record_type] = []
        records_by_type[record_type].append(record.get("value", "N/A"))
    
    dns_summary = f"DNS Records for {domain}:\n"
    for record_type, values in records_by_type.items():
        dns_summary += f"\n{record_type}:\n"
        for value in values[:5]:
            dns_summary += f"  - {value}\n"
    
    response = client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=512,
        system="""You are an OSINT research assistant. Provide a brief, factual summary.

RULES:
- Start with a 1 sentence overview
- List DNS records by type
- Do NOT include "Key Insights" or "Recommended Next Steps"
- Keep it concise and factual""",
        messages=[
            {"role": "user", "content": f"""Summarize DNS lookup results:

{dns_summary}"""}
        ]
    )
    
    return response.content[0].text


if __name__ == "__main__":
    print("=== Testing Tool-Based Query Processing ===\n")
    
    test_queries = [
        "Find all social media accounts for john_doe",
        "Who owns google.com?",
        "What are the DNS records for github.com?",
    ]
    
    print("Available Claude tools:")
    for tool in get_claude_tools():
        print(f"  - {tool['name']}")
    print()
    
    for query in test_queries:
        print(f"Query: {query}")
        result = process_query(query)
        print(f"Result: {result}\n")
