# 🔍 OSINT Research Tool

Search publicly available data across 25+ intelligence tools from a single interface.

## What is this?

A web-based Open Source Intelligence (OSINT) research platform. Type a natural language query, and the system automatically selects the right tool, executes it, and returns formatted results.

No technical knowledge required — just type what you want to find.

---

## Quick Start

Try the deployed app and use any of the example queries below.

---

## Available Tools

### Domain Intelligence
| What you can do | Example query |
|----------------|---------------|
| Look up domain ownership (WHOIS) | `Who owns example.com?` |
| View historical WHOIS records | `Show me historical WHOIS records for twitter.com` |
| Find all domains owned by a person/org | `Find all domains registered by Google LLC` |
| Look up DNS records | `What are the DNS records for netflix.com?` |
| View DNS history | `Show DNS history for reddit.com` |
| Find domains on an IP | `What domains are hosted on IP 142.250.80.46?` |
| Find domains using a mail server | `Find domains using mail server alt1.gmail-smtp-in.l.google.com` |
| Find domains using a nameserver | `Find domains using nameserver ns1.google.com` |
| Enumerate subdomains | `Find subdomains of microsoft.com` |
| Discover domains by keyword | `Discover domains containing 'shopify' in the name` |

### IP Intelligence
| What you can do | Example query |
|----------------|---------------|
| Geolocate an IP address | `Where is IP address 8.8.8.8 located?` |
| Find network block ownership | `What network block owns 8.8.8.0?` |
| Scan for open ports and services (Shodan) | `What services are running on IP 1.1.1.1?` |
| Check what ports are open (Shodan) | `What ports are open on 8.8.8.8?` |

### Security & Verification
| What you can do | Example query |
|----------------|---------------|
| Check threat intelligence | `Check threat intelligence for suspicious-domain.com` |
| View SSL certificates | `Show SSL certificates for github.com` |
| Verify an email address | `Verify the email address test@gmail.com` |
| Categorize a website | `What category is reddit.com?` |
| Look up a CVE vulnerability (Shodan) | `Look up CVE-2021-44228` |

### Technology Detection (BuiltWith)
| What you can do | Example query |
|----------------|---------------|
| Get tech stack summary for a website | `What technologies does shopify.com use?` |
| View technology adoption trends | `How popular is WordPress?` |

### Username Search
| What you can do | Example query |
|----------------|---------------|
| Find social media accounts for a username | `Find all social media accounts for john_doe` |
| Search across 600+ platforms | `Where does the username cryptoking123 exist online?` |

---

## How It Works

1. **You type a query** in plain English
2. **The system parses it** using AI to determine which tool to use
3. **You confirm** the interpreted action before it runs
4. **Smart routing** connects only to the server needed (faster, saves resources)
5. **Results are displayed** with a formatted summary

### Architecture

The platform connects to multiple intelligence servers via MCP:

| Server | Tools | What it provides |
|--------|-------|-----------------|
| **Local** | 1 | Username search (600+ platforms) |
| **WhoisXML API** | 17 | WHOIS, DNS, IP geolocation, threat intel, SSL, email verification |
| **Shodan** | 4 | Port scanning, service detection, CVE lookups |
| **BuiltWith** | 2 | Website technology detection, tech trends |

---

## Tips

- **Be specific**: "Who owns github.com?" works better than "tell me about github"
- **Use natural language**: No need to know tool names — just describe what you want
- **Check the confirmation**: Before execution, verify the system understood your query correctly
- **Watch the progress**: Real-time updates show which server and tool is being used

---

## Limitations

- **People search** is blocked by anti-bot protections on target sites — investigating API-based alternatives
- **The tool will not respond to queries that can't be answered using the tools integrated through the MCP servers
- **BuiltWith free tier** returns technology category counts, not individual technology names
- **Shodan free tier** has limited query credits
- **WhoisXML** tools use trial credits which will eventually expire
- **Rate limits** apply to all external APIs

---

## Built With

- **Django** — Web framework
- **Model Context Protocol (MCP)** — Tool orchestration
- **Claude AI** — Query parsing and result formatting
- **Playwright** — Browser automation for web scraping
- **WhoisXML API** — Domain and IP intelligence
- **Shodan** — Network reconnaissance
- **BuiltWith** — Technology detection
