"""
Tool Registry for OSINT Research Platform

Central registry of ALL available tools across ALL MCP servers.
Used for smart routing: determines which server to connect to
BEFORE opening any MCP connections.

Flow:
1. User query → /parse/ → Claude picks a tool name
2. tool_registry.get_server_for_tool(tool_name) → "whoisxml"
3. Only connect to the whoisxml server, skip local server
4. Execute tool → return results
"""

import string

# =============================================================================
# TOOL DEFINITIONS
# =============================================================================
# Every tool across all servers, with enough metadata for:
# - Smart routing (which server handles this tool)
# - Query parsing (Claude tool definitions for /parse/)
# - Validation (required/optional args)
# - Documentation (examples, descriptions)
# - Confirmation UI ("confirmation" is a phrase that follows "I'll ...",
#   with {arg_name} placeholders filled from the tool call's params)
# =============================================================================

TOOLS = {
    # =========================================================================
    # LOCAL SERVER TOOLS (stdio - your custom agents)
    # =========================================================================
    "username_search": {
        "name": "username_search",
        "description": "Search for a username across 600+ social media platforms, forums, and websites to find matching profiles.",
        "confirmation": "search 600+ sites for profiles matching the username {username}",
        "server": "local",
        "arguments": {
            "username": {
                "type": "string",
                "required": True,
                "description": "The username to search for across platforms"
            },
            "max_results": {
                "type": "integer",
                "required": False,
                "description": "Maximum number of results to return (default: 100)"
            }
        },
        "examples": [
            "Find all social media accounts for john_doe",
            "Search for username cryptoking123",
            "Where does the username darknight exist online?"
        ],
        "estimated_time": "30-60 seconds",
        "category": "username"
    },

    # =========================================================================
    # WHOISXML API TOOLS (HTTP - hosted MCP server)
    # =========================================================================
    
    # --- Domain Intelligence ---
    "whois": {
        "name": "whois",
        "description": "Look up WHOIS registration info for a domain including ownership, registrar, dates, and nameservers.",
        "confirmation": "look up WHOIS registration info for {domainName}",
        "server": "whoisxml",
        "arguments": {
            "domainName": {
                "type": "string",
                "required": True,
                "description": "The domain name to look up (e.g., 'google.com')"
            }
        },
        "examples": [
            "Who owns google.com?",
            "Look up WHOIS info for github.com",
            "When was twitter.com registered?"
        ],
        "estimated_time": "5-10 seconds",
        "category": "domain"
    },

    "whois_history": {
        "name": "whois_history",
        "description": "Get historical WHOIS records for a domain showing ownership changes over time.",
        "confirmation": "look up the WHOIS history for {domainName}",
        "server": "whoisxml",
        "arguments": {
            "domainName": {
                "type": "string",
                "required": True,
                "description": "The domain name to look up history for"
            }
        },
        "examples": [
            "Show me historical WHOIS records for twitter.com",
            "Who previously owned example.com?",
            "WHOIS history for facebook.com"
        ],
        "estimated_time": "5-10 seconds",
        "category": "domain"
    },

    "reverse_whois": {
        "name": "reverse_whois",
        "description": "Find all domains registered by a specific person or organization.",
        "confirmation": "find domains registered by {searchTerm}",
        "server": "whoisxml",
        "arguments": {
            "searchTerm": {
                "type": "string",
                "required": True,
                "description": "Person name, organization, or email to search for as registrant"
            }
        },
        "examples": [
            "Find all domains registered by Google LLC",
            "What domains does John Smith own?",
            "Reverse WHOIS for admin@example.com"
        ],
        "estimated_time": "5-10 seconds",
        "category": "domain"
    },

    # --- DNS & Network ---
    "dns_lookup": {
        "name": "dns_lookup",
        "description": "Look up DNS records for a domain (A, MX, NS, TXT, CNAME, SOA records).",
        "confirmation": "look up the DNS records for {domainName}",
        "server": "whoisxml",
        "arguments": {
            "domainName": {
                "type": "string",
                "required": True,
                "description": "The domain name to look up DNS records for"
            },
            "type": {
                "type": "string",
                "required": False,
                "description": "Record type: A, AAAA, MX, NS, TXT, CNAME, SOA, or _all (default: _all)"
            }
        },
        "examples": [
            "What are the DNS records for netflix.com?",
            "Show me MX records for gmail.com",
            "DNS lookup for github.com"
        ],
        "estimated_time": "5-10 seconds",
        "category": "dns"
    },

    "dns_history": {
        "name": "dns_history",
        "description": "Get historical DNS records for a domain showing changes over time.",
        "confirmation": "look up the DNS history for {domainName}",
        "server": "whoisxml",
        "arguments": {
            "domainName": {
                "type": "string",
                "required": True,
                "description": "The domain name to look up DNS history for"
            }
        },
        "examples": [
            "Show DNS history for reddit.com",
            "How have DNS records changed for example.com?",
            "Historical DNS for twitter.com"
        ],
        "estimated_time": "5-10 seconds",
        "category": "dns"
    },

    "reverse_dns": {
        "name": "reverse_dns",
        "description": "Find domains that have DNS records pointing to a specific target (reverse DNS/CNAME lookup).",
        "confirmation": "find domains with DNS records pointing to {target}",
        "server": "whoisxml",
        "arguments": {
            "target": {
                "type": "string",
                "required": True,
                "description": "The target hostname or IP to do a reverse DNS lookup for"
            }
        },
        "examples": [
            "Find domains with CNAME records pointing to amazonaws.com",
            "Reverse DNS for cloudflare.com",
            "What domains point to this IP?"
        ],
        "estimated_time": "5-10 seconds",
        "category": "dns"
    },

    "reverse_ip": {
        "name": "reverse_ip",
        "description": "Find all domains hosted on a specific IP address.",
        "confirmation": "find domains hosted on {ip}",
        "server": "whoisxml",
        "arguments": {
            "ip": {
                "type": "string",
                "required": True,
                "description": "The IP address to look up"
            }
        },
        "examples": [
            "What domains are hosted on IP 142.250.80.46?",
            "Reverse IP lookup for 8.8.8.8",
            "Find all sites on this IP address"
        ],
        "estimated_time": "5-10 seconds",
        "category": "dns"
    },

    "reverse_mx": {
        "name": "reverse_mx",
        "description": "Find domains that use a specific mail server (MX record).",
        "confirmation": "find domains that use the mail server {target}",
        "server": "whoisxml",
        "arguments": {
            "target": {
                "type": "string",
                "required": True,
                "description": "The mail server hostname to search for"
            }
        },
        "examples": [
            "Find domains using mail server alt1.gmail-smtp-in.l.google.com",
            "What domains use this MX server?",
            "Reverse MX lookup for outlook-com.olc.protection.outlook.com"
        ],
        "estimated_time": "5-10 seconds",
        "category": "dns"
    },

    "reverse_ns": {
        "name": "reverse_ns",
        "description": "Find domains that use a specific nameserver.",
        "confirmation": "find domains that use the nameserver {target}",
        "server": "whoisxml",
        "arguments": {
            "target": {
                "type": "string",
                "required": True,
                "description": "The nameserver hostname to search for"
            }
        },
        "examples": [
            "Find domains using nameserver ns1.google.com",
            "What domains use Cloudflare nameservers?",
            "Reverse NS for ns1.example.com"
        ],
        "estimated_time": "5-10 seconds",
        "category": "dns"
    },

    # --- Discovery ---
    "subdomain_lookup": {
        "name": "subdomain_lookup",
        "description": "Enumerate subdomains for a domain.",
        "confirmation": "find subdomains of {domainName}",
        "server": "whoisxml",
        "arguments": {
            "domainName": {
                "type": "string",
                "required": True,
                "description": "The domain to enumerate subdomains for"
            }
        },
        "examples": [
            "Find subdomains of microsoft.com",
            "Enumerate subdomains for github.com",
            "What subdomains does google.com have?"
        ],
        "estimated_time": "10-20 seconds",
        "category": "discovery"
    },

    "domain_and_subdomain_discovery": {
        "name": "domain_and_subdomain_discovery",
        "description": "Discover domains and subdomains containing a specific keyword.",
        "confirmation": "find domains and subdomains containing {searchTerm}",
        "server": "whoisxml",
        "arguments": {
            "searchTerm": {
                "type": "string",
                "required": True,
                "description": "Keyword to search for in domain names"
            }
        },
        "examples": [
            "Discover domains containing 'shopify' in the name",
            "Find domains with 'crypto' in them",
            "Domain discovery for 'openai'"
        ],
        "estimated_time": "10-20 seconds",
        "category": "discovery"
    },

    # --- IP Intelligence ---
    "ipgeolocation": {
        "name": "ipgeolocation",
        "description": "Get geolocation and network information for an IP address including country, city, ASN, and ISP.",
        "confirmation": "look up the location and network info for {ip}",
        "server": "whoisxml",
        "arguments": {
            "ip": {
                "type": "string",
                "required": True,
                "description": "The IP address to geolocate"
            }
        },
        "examples": [
            "Where is IP address 8.8.8.8 located?",
            "IP geolocation for 1.1.1.1",
            "What is the location of this IP?"
        ],
        "estimated_time": "5-10 seconds",
        "category": "ip"
    },

    "ip_netblocks": {
        "name": "ip_netblocks",
        "description": "Get network block ownership information for an IP address or range.",
        "confirmation": "look up network block ownership for {ip}",
        "server": "whoisxml",
        "arguments": {
            "ip": {
                "type": "string",
                "required": True,
                "description": "The IP address or CIDR range to look up"
            }
        },
        "examples": [
            "What network block owns 8.8.8.0?",
            "IP netblock info for 142.250.0.0",
            "Who owns this IP range?"
        ],
        "estimated_time": "5-10 seconds",
        "category": "ip"
    },

    # --- Security & Verification ---
    "threat_intelligence": {
        "name": "threat_intelligence",
        "description": "Get threat intelligence data for a domain or IP address including malware, phishing, and spam reports.",
        "confirmation": "check {target} for malware, phishing, and spam reports",
        "server": "whoisxml",
        "arguments": {
            "target": {
                "type": "string",
                "required": True,
                "description": "Domain or IP to check for threats"
            }
        },
        "examples": [
            "Check threat intelligence for suspicious-domain.com",
            "Is this domain a security threat?",
            "Threat data for 192.168.1.1"
        ],
        "estimated_time": "5-10 seconds",
        "category": "security"
    },

    "ssl_certificates": {
        "name": "ssl_certificates",
        "description": "Get SSL/TLS certificate information for a domain.",
        "confirmation": "look up SSL/TLS certificates for {domainName}",
        "server": "whoisxml",
        "arguments": {
            "domainName": {
                "type": "string",
                "required": True,
                "description": "The domain to check SSL certificates for"
            }
        },
        "examples": [
            "Show SSL certificates for github.com",
            "What SSL cert does amazon.com use?",
            "Check TLS certificate for example.com"
        ],
        "estimated_time": "5-10 seconds",
        "category": "security"
    },

    "email_verification": {
        "name": "email_verification",
        "description": "Verify if an email address is valid and deliverable.",
        "confirmation": "check whether {email} is a valid, deliverable address",
        "server": "whoisxml",
        "arguments": {
            "email": {
                "type": "string",
                "required": True,
                "description": "The email address to verify"
            }
        },
        "examples": [
            "Verify the email address test@gmail.com",
            "Is admin@example.com a valid email?",
            "Check if this email exists"
        ],
        "estimated_time": "5-10 seconds",
        "category": "security"
    },

    "categorization": {
        "name": "categorization",
        "description": "Get the category/classification of a website (e.g., news, shopping, social media).",
        "confirmation": "find out what kind of website {domainName} is",
        "server": "whoisxml",
        "arguments": {
            "domainName": {
                "type": "string",
                "required": True,
                "description": "The domain to categorize"
            }
        },
        "examples": [
            "What category is reddit.com?",
            "Categorize wikipedia.org",
            "What type of website is shopify.com?"
        ],
        "estimated_time": "5-10 seconds",
        "category": "security"
    },

    # =========================================================================
    # SHODAN TOOLS (stdio - npm package)
    # =========================================================================
    "shodan_host_lookup": {
        "name": "host",
        "description": "Get information about a host from Shodan including open ports, services, vulnerabilities, and banners.",
        "confirmation": "look up open ports, services, and vulnerabilities for {ip} on Shodan",
        "server": "shodan",
        "arguments": {
            "ip": {
                "type": "string",
                "required": True,
                "description": "The IP address to look up on Shodan"
            }
        },
        "examples": [
            "What services are running on IP 8.8.8.8?",
            "Shodan lookup for 1.1.1.1",
            "What ports are open on this IP?"
        ],
        "estimated_time": "5-10 seconds",
        "category": "ip"
    },

    "shodan_dns_lookup": {
        "name": "dns-lookup",
        "description": "Resolve a hostname to its IP address(es) using Shodan.",
        "confirmation": "resolve {hostnames} to IP addresses using Shodan",
        "server": "shodan",
        "arguments": {
            "hostnames": {
                "type": "string",
                "required": True,
                "description": "Comma-separated hostnames to resolve"
            }
        },
        "examples": [
            "Resolve google.com to its IP using Shodan",
            "What IP does github.com resolve to?"
        ],
        "estimated_time": "3-5 seconds",
        "category": "dns"
    },

    "shodan_reverse_dns": {
        "name": "reverse-dns",
        "description": "Find hostnames for given IP addresses using Shodan.",
        "confirmation": "find hostnames for {ips} using Shodan",
        "server": "shodan",
        "arguments": {
            "ips": {
                "type": "string",
                "required": True,
                "description": "Comma-separated IP addresses"
            }
        },
        "examples": [
            "Reverse DNS for 8.8.8.8 using Shodan",
            "What hostname does this IP resolve to?"
        ],
        "estimated_time": "3-5 seconds",
        "category": "dns"
    },

    "shodan_cve_lookup": {
        "name": "cve-lookup",
        "description": "Look up details about a specific CVE vulnerability including severity, description, and affected products.",
        "confirmation": "look up details for {cve_id}",
        "server": "shodan",
        "arguments": {
            "cve_id": {
                "type": "string",
                "required": True,
                "description": "The CVE ID to look up (e.g., 'CVE-2021-44228')"
            }
        },
        "examples": [
            "Look up CVE-2021-44228",
            "What is CVE-2024-3400?",
            "Details on this vulnerability"
        ],
        "estimated_time": "3-5 seconds",
        "category": "security"
    },

    # =========================================================================
    # BUILTWITH TOOLS (hosted MCP server - free tier)
    # =========================================================================
    "builtwith": {
        "name": "free-api",
        "description": "Get a technology summary for a website including counts of technologies by category (analytics, CMS, hosting, frameworks, etc.) and when it was first/last indexed.",
        "confirmation": "look up the technologies used by {domain}",
        "server": "builtwith",
        "arguments": {
            "domain": {
                "type": "string",
                "required": True,
                "description": "The domain to look up (e.g., 'shopify.com')"
            }
        },
        "examples": [
            "What technologies does shopify.com use?",
            "What is cnn.com built with?",
            "Technology stack summary for github.com"
        ],
        "estimated_time": "3-5 seconds",
        "category": "discovery"
    },

    "builtwith_trends": {
        "name": "trends-api",
        "description": "Get technology adoption trends showing how many sites use a specific technology, with breakdowns by site ranking tiers.",
        "confirmation": "look up adoption trends for {technology}",
        "server": "builtwith",
        "arguments": {
            "technology": {
                "type": "string",
                "required": True,
                "description": "The technology name to look up trends for (e.g., 'Shopify', 'WordPress', 'React')"
            }
        },
        "examples": [
            "How popular is Shopify?",
            "Show me WordPress adoption trends",
            "How many sites use React?"
        ],
        "estimated_time": "3-5 seconds",
        "category": "discovery"
    },
}


# =============================================================================
# SERVER REGISTRY
# =============================================================================
# Maps server names to their configuration metadata.
# Used by the router to know HOW to connect to each server.
# =============================================================================

SERVERS = {
    "local": {
        "name": "local",
        "type": "stdio",
        "description": "Local OSINT tools (username search)",
        "tools": ["username_search"],
    },
    "whoisxml": {
        "name": "whoisxml",
        "type": "http",
        "description": "WhoisXML API (WHOIS, DNS, IP, threat intelligence)",
        "tools": [
            "whois", "whois_history", "reverse_whois",
            "dns_lookup", "dns_history", "reverse_dns", "reverse_ip",
            "reverse_mx", "reverse_ns",
            "subdomain_lookup", "domain_and_subdomain_discovery",
            "ipgeolocation", "ip_netblocks",
            "threat_intelligence", "ssl_certificates",
            "email_verification", "categorization",
        ],
    },
    "shodan": {
        "name": "shodan",
        "type": "stdio",
        "description": "Shodan (host recon, CVE lookups, DNS)",
        "tools": [
            "shodan_host_lookup", "shodan_dns_lookup",
            "shodan_reverse_dns", "shodan_cve_lookup",
        ],
    },
    "builtwith": {
        "name": "builtwith",
        "type": "http",
        "description": "BuiltWith (technology detection, trends)",
        "tools": [
            "builtwith", "builtwith_trends",
        ],
    },
}


# =============================================================================
# ROUTING FUNCTIONS
# =============================================================================

def get_server_for_tool(tool_name: str) -> str | None:
    """
    Given a tool name, return which server handles it.
    This is the core of smart routing — no MCP connection needed.
    
    Returns:
        Server name string (e.g., "local", "whoisxml", "shodan") or None
    """
    tool = TOOLS.get(tool_name)
    if tool:
        return tool["server"]
    return None


def get_servers_needed(tool_names: list[str]) -> list[str]:
    """
    Given a list of tool names, return the unique servers needed.
    
    Args:
        tool_names: List of tool names that might be called
        
    Returns:
        List of unique server names needed
    """
    servers = set()
    for name in tool_names:
        server = get_server_for_tool(name)
        if server:
            servers.add(server)
    return list(servers)


def get_tools_by_server(server_name: str) -> list[dict]:
    """Get all tools belonging to a specific server."""
    return [
        tool for tool in TOOLS.values()
        if tool["server"] == server_name
    ]


def get_tools_by_category(category: str) -> list[dict]:
    """Get all tools in a specific category."""
    return [
        tool for tool in TOOLS.values()
        if tool.get("category") == category
    ]


# =============================================================================
# QUERY PARSING HELPERS
# =============================================================================

def get_tool(tool_name: str) -> dict | None:
    """Get a tool definition by name."""
    return TOOLS.get(tool_name)


def get_all_tools() -> dict:
    """Get all available tools."""
    return TOOLS


def get_tool_names() -> list[str]:
    """Get list of all tool names."""
    return list(TOOLS.keys())


def get_all_servers() -> dict:
    """Get all server definitions."""
    return SERVERS


def get_claude_tool_definitions() -> list[dict]:
    """
    Generate tool definitions in Claude's format for the /parse/ endpoint.
    This replaces the hardcoded tool list in views.py.
    
    Returns:
        List of tool dicts in Claude's tool_use format
    """
    claude_tools = []
    
    for tool_name, tool in TOOLS.items():
        # Build input schema from arguments
        properties = {}
        required = []
        
        for arg_name, arg_info in tool["arguments"].items():
            prop = {
                "type": arg_info["type"],
                "description": arg_info["description"]
            }
            properties[arg_name] = prop
            
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


def get_confirmation_message(tool_name: str, params: dict) -> tuple[str, str, str]:
    """
    Generate a human-readable confirmation message for a tool call.
    
    Returns:
        Tuple of (message, estimated_time, server_name)
    """
    params = params or {}
    tool = TOOLS.get(tool_name)
    if not tool:
        return (
            f"I'll run the {tool_name} tool with the provided parameters.",
            "Unknown",
            "unknown"
        )

    server = tool["server"]
    est_time = tool.get("estimated_time", "5-10 seconds")

    # Preferred: the tool's hand-written confirmation phrase, e.g.
    # "look up the DNS records for {domainName}" -> "I'll look up the DNS records for 'google.com'."
    template = tool.get("confirmation")
    if template:
        placeholders = get_confirmation_placeholders(template)
        if all(params.get(name) not in (None, "") for name in placeholders):
            quoted = {name: f"'{params[name]}'" for name in placeholders}
            return (f"I'll {template.format(**quoted)}.", est_time, server)

    # Fallback (no phrase, or a placeholder's argument is missing): generic message
    # using the first required parameter that was provided
    main_param = None
    for arg_name, arg_info in tool["arguments"].items():
        if arg_info.get("required") and params.get(arg_name) not in (None, ""):
            main_param = params[arg_name]
            break

    if main_param:
        msg = f"I'll run the {tool_name} tool for '{main_param}'."
    else:
        msg = f"I'll run the {tool_name} tool with the provided parameters."

    return (msg, est_time, server)


def get_confirmation_placeholders(template: str) -> list[str]:
    """Return the {arg_name} placeholders used in a confirmation phrase."""
    return [field for _, field, _, _ in string.Formatter().parse(template) if field]


def get_tools_for_prompt() -> str:
    """
    Generate a formatted string describing all tools for use in LLM prompts.
    """
    lines = ["Available tools by server:\n"]
    
    for server_name, server_info in SERVERS.items():
        lines.append(f"## {server_info['description']}")
        
        for tool_name in server_info["tools"]:
            tool = TOOLS.get(tool_name)
            if tool:
                lines.append(f"  - {tool_name}: {tool['description']}")
        
        lines.append("")
    
    return "\n".join(lines)


def validate_tool_arguments(tool_name: str, provided_args: dict) -> tuple[bool, str]:
    """
    Validate that provided arguments match tool requirements.
    """
    tool = get_tool(tool_name)
    if not tool:
        return True, ""  # Unknown tool — might be discovered at runtime
    
    for arg_name, arg_info in tool["arguments"].items():
        if arg_info.get("required") and arg_name not in provided_args:
            return False, f"Missing required argument: {arg_name}"
        
        if arg_name in provided_args:
            value = provided_args[arg_name]
            expected_type = arg_info["type"]
            
            if expected_type == "string" and not isinstance(value, str):
                return False, f"Argument '{arg_name}' must be a string"
            elif expected_type == "integer" and not isinstance(value, int):
                return False, f"Argument '{arg_name}' must be an integer"
            elif expected_type == "boolean" and not isinstance(value, bool):
                return False, f"Argument '{arg_name}' must be a boolean"
    
    return True, ""


# =============================================================================
# TEST
# =============================================================================

if __name__ == "__main__":
    print("=== Tool Registry ===\n")
    print(f"Total tools: {len(TOOLS)}")
    print(f"Total servers: {len(SERVERS)}\n")
    
    for server_name, server_info in SERVERS.items():
        tools = get_tools_by_server(server_name)
        print(f"[{server_name}] {server_info['description']} — {len(tools)} tools")
        for t in tools:
            print(f"  - {t['name']}: {t['description'][:60]}...")
        print()
    
    print("=" * 50)
    print("\nRouting test:")
    test_tools = ["username_search", "whois", "dns_lookup", "shodan_host_lookup", "nonexistent"]
    for t in test_tools:
        server = get_server_for_tool(t)
        print(f"  {t} → {server or 'NOT FOUND'}")
    
    print(f"\nClaude tool definitions: {len(get_claude_tool_definitions())} tools")
