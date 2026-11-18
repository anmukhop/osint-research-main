# Which tools the platform's AI agent may call

As of Nov 10, 2026. The code list is `AGENT_ALLOWED_TOOLS` in `researcher/services/mcp_client.py` and must match the **Allowed** column. The servers expose 101 tools today (local 4, WhoisXML 35, Shodan 11, BuiltWith 51). The agent can call 29 of them. (Wayback page-reader tools added Nov 13 on the `page-reader` branch; the live `read_webpage` is built but disabled, see below.)

**Passive** = reads a database someone else already built. The target is not contacted in any way.
**Live** = something contacts the target or another live site now. For WhoisXML tools that contact comes from WhoisXML's servers, never the analyst's computer, and it's one ordinary visit or check, not a scan. Live recon is allowed by default. Evidence backing this up is that OSINT Clinic (CHI '25) Table 1 lists port scanning as a normal Website Vulnerabilities technique.

CVA categories are the seven from OSINT Clinic Table 1. "(2nd)" = a second category the tool also covers. It counts toward the 2+ per category goal, but it isn't the tool's main job.

Credits are as of Nov 10, 2026 (WhoisXML `account_balance`, BuiltWith `whoami-api`/`usage-api`, Shodan `api_info` on Nov 9).

## Allowed (29)

| Tool | Server | Passive / Live | Cost per call | CVA category | Why |
|---|---|---|---|---|---|
| `username_search` | local | Live (checks profile pages on social sites, not the target) | free | Employee Public Information | Finds an employee's accounts across sites |
| `email_breach_check` | local (XposedOrNot) | Passive | free | Breach Data | Which breaches an email appears in |
| `read_archived_page` | local (Wayback Machine) | Passive (only archive.org is contacted) | free | Website Vulnerabilities; Brand Monitoring (2nd) | Reads a page or PDF as archived on a date |
| `wayback_snapshots` | local (Wayback CDX) | Passive | free | Website Vulnerabilities | Lists captures of a URL, or every archived URL under a site (old, hidden or unlinked pages) |
| `whois` | WhoisXML | Passive | 1 WHOIS credit (378 left) | Network Discovery; Physical Assets (2nd) | Registration record; lists the company address unless a privacy service hides it |
| `dns_lookup` | WhoisXML | Passive | 1 DNS credit (374) | Network Discovery; Third-Party Services (2nd) | DNS records; mail and TXT records name vendors (e.g. Mailgun) |
| `ipgeolocation` | WhoisXML | Passive | 1 credit (958) | Physical Assets | Where an IP is located (often a data center, not an office) |
| `ip_netblocks` | WhoisXML | Passive | 1 credit (975) | Network Discovery | Who owns an IP range |
| `vpn_proxy_detection` | WhoisXML | Passive | 1 credit (7) | Network Discovery | Is an IP a VPN or proxy; few credits left |
| `threat_intelligence` | WhoisXML | Passive | 1 credit (67) | Website Vulnerabilities | Known-bad listings for a domain or IP |
| `disposable_email_check` | WhoisXML | Passive | 1 Email Verification credit (93) | Employee Public Information | Is an email a throwaway address |
| `ssl_certificates` | WhoisXML | Live only if `use_fresh_data` (default: stored copy) | 1 credit (90) | Network Discovery | Certificate details; other names on the cert lead to related sites |
| `email_verification` | WhoisXML | Live (SMTP check with the address's mail server; nothing is sent) | 1 Email Verification credit (93) | Employee Public Information | Does a guessed employee address exist |
| `categorization` | WhoisXML | Live (WhoisXML loads the homepage once) | 1 credit (95) | Brand Monitoring | What the site says it is; flags parked or dead sites |
| `domain_reputation` | WhoisXML | Live, mostly database checks; **code forces fast mode** | 1 credit (46) | Website Vulnerabilities | 0–100 trust score with warnings |
| `account_balance` | WhoisXML | Account info | free | none | Credit check |
| `ip_lookup` | Shodan | Passive (Shodan's past scans) | ≤1 query credit (edu plan, 200,000) | Website Vulnerabilities | Open ports, software, known vulns for an IP |
| `shodan_search` | Shodan | Passive | ≤1 query credit | Network Discovery | Search Shodan's index (servers, webcams) |
| `shodan_count` | Shodan | Passive | ≤1 query credit | Network Discovery | Count matches without listing them |
| `reverse_dns_lookup` | Shodan | Passive | free | Network Discovery | IP to hostname |
| `shodan_domain_info` | Shodan | Passive | 1 query credit | Network Discovery | Subdomains of a domain |
| `shodan_dns_lookup` | Shodan | Passive | free | Network Discovery | Hostname to IP |
| `cve_lookup` | Shodan (CVEDB) | Passive | free | Website Vulnerabilities | Details of a CVE |
| `cpe_lookup` | Shodan (CVEDB) | Passive | free | Website Vulnerabilities | Product identifiers |
| `cves_by_product` | Shodan (CVEDB) | Passive | free | Website Vulnerabilities | Known CVEs for a product |
| `api_info` | Shodan | Account info | free | none | Credit check |
| `search_filters` | Shodan | Account info | free | none | Lists Shodan search filters |
| `free-api` | BuiltWith | Passive | free | Third-Party Services | Counts of technology types (e.g. "Analytics: 5"); **no product names** |
| `trends-api` | BuiltWith | Passive | free | Third-Party Services | How widely a named technology is used |

## Allowed: free-API tools (13, added Nov 13, 2026 on the `free-apis` branch)

These are not counted in the totals above. Code: `researcher/services/free_api_registry.py`, which `mcp_client.py` adds to `AGENT_ALLOWED_TOOLS`. All 13 run on the local server and are **Passive**: they read a provider's database or a public broadcast feed, and none contacts the target, so stealth mode keeps them. All are free. Keys go in `.env`; without one, the tool returns a "set X in .env" error and makes no call. "Peraton use" is from `research/free-api-catalogue.md` (phd repo, #48).

| Tool | Provider | Key (`.env`) | Limits | CVA category | Peraton use | Why |
|---|---|---|---|---|---|---|
| `crtsh_subdomains` | crt.sh | none | none published; slow (up to ~60 s) and often overloaded | Network Discovery | OK | Subdomains from certificate logs, with dates first and last seen |
| `osv_package_vulns` | OSV.dev | none | none ("no limits") | Website Vulnerabilities | OK | Known vulns for a package and version (e.g. a JS library seen in an archived page) |
| `kev_check` | CISA KEV | none | feed cached 6 h | Website Vulnerabilities | OK (CC0) | Is a CVE exploited in the wild, or used by ransomware |
| `sec_company_filings` | SEC EDGAR | `SEC_USER_AGENT` (name + contact email, required by SEC) | ≤10 requests/s (code waits 0.15 s between calls) | Third-Party Services; Physical Assets (2nd: business addresses) | OK (US gov) | Company profile, addresses, former names, recent filings |
| `sec_filing_search` | SEC EDGAR full-text search | `SEC_USER_AGENT` | same | Third-Party Services | OK (US gov) | Which filings mention a name: customers, suppliers, 8-K incidents |
| `ransomware_victims` | ransomware.live | `RANSOMWARE_LIVE_API_KEY` (PRO; optional) | PRO: 60/min, 500,000/month. Without a key it uses free v2: 1/min, "personal use only" | Third-Party Services; Breach Data (2nd) | Ask | Was a vendor or the target listed on a leak site |
| `opensky_airport_flights` | OpenSky Network | `OPENSKY_CLIENT_ID`, `OPENSKY_CLIENT_SECRET` | ≤2 days per query; ~30 credits each, 4,000/day; newest data is yesterday | Physical Assets | Ask | Flights in and out of an airport on a date |
| `opensky_aircraft_flights` | OpenSky Network | same | same | Physical Assets | Ask | One aircraft's flights, by ICAO24 address |
| `ships_near` | AISStream | `AISSTREAM_API_KEY` | live only, no history; 3 connections per account | Physical Assets | Unverified | Ships near a waterfront site right now |
| `wigle_wifi_search` | WiGLE | `WIGLE_API_NAME`, `WIGLE_API_TOKEN` | a few searches a day for new accounts | Physical Assets; Network Discovery (2nd) | **No** (research only) | WiFi networks seen at a location |
| `reddit_search` | Reddit Data API | `REDDIT_CLIENT_ID`, `REDDIT_CLIENT_SECRET` (+ `REDDIT_USER_AGENT`) | 100 requests/min | Brand Monitoring | Ask | Posts mentioning the company |
| `reddit_post_comments` | Reddit Data API | same | same | Brand Monitoring | Ask | Read a post and its comments |
| `reddit_user_activity` | Reddit Data API | same | same | Employee Public Information | Ask | An account's recent posts and comments |

## Not allowed yet

| Tool(s) | Server | Cost | Why not | Allow when |
|---|---|---|---|---|
| Domain Research Suite (15): `subdomain_lookup`, `reverse_whois`, `reverse_whois_advanced`, `whois_history`, `dns_history`, `reverse_dns`, `reverse_ip`, `reverse_mx`, `reverse_ns`, `domain_info`, `domain_and_subdomain_discovery`, `brand_alert`, `registrant_alert`, `typosquatting` | WhoisXML | Domain Research Suite credits (main key 0, backup 21) | No credits. Allowing them now would spend the backup key's 21 credits, because the app retries failed WhoisXML calls with the backup key | We have more credits. Core lookups for Network Discovery and Brand Monitoring |
| `domain-api` | BuiltWith | 1 credit (0 left; trial expired Mar 25, 2026) | No credits | BuiltWith credits are bought. It names the actual tech stack, which `free-api` can't |
| `website_screenshot` | WhoisXML | 1 credit (5 left) | Live, unnecessary, and doesn't fit into any of the categories cleanly | Revisit if needed |
| `relationships-api`, `company-to-url`, `redirects-api`, `keywords-api`, `trust-api`, `tags-api`, `recommendations-api`, `product-api`, `vat-api`, `vector-api`, `change-api`, `domain-lookup`, `domain-api-json`, other BuiltWith lookups | BuiltWith | 1 credit or subscription (0 left) | No credits; not reviewed one by one | Credits are bought and each is reviewed |

## Never allowed

| Tool(s) | Why |
|---|---|
| `bulk_*` (WhoisXML: `bulk_whois`, `bulk_dns_lookup`, `bulk_email_verification`, `bulk_ip_geolocation`, `bulk_vpn_proxy_detection`, `bulk_subdomain_lookup`, `bulk_job_status`, `bulk_job_results`) | Up to 10,000 credits per call |
| BuiltWith `payment-*`, `x402-*`, `mpp-*` | They buy things or move money |

## Built but disabled

| Tool | Server | Passive / Live | Why it's off |
|---|---|---|---|
| `read_webpage` | local | Live (one plain GET of the given URL; no forms, no JavaScript, no crawling; Wayback copy if the visit fails) | It visits the target site from the platform server's IP address, so the site can see (and log) the visit. Micah, Nov 13: off until it's discussed with Anirban or Dr. Luther. Re-enable with `READ_WEBPAGE_ENABLED = True` in `researcher/services/agents/page_reader.py`; it stays on the live list, so stealth mode would still hide it. |

## CVA coverage (allowed tools, main + 2nd)

| CVA category | Tools | 2+? |
|---|---|---|
| Network Discovery | whois, dns_lookup, ip_netblocks, vpn_proxy_detection, ssl_certificates, shodan_search, shodan_count, reverse_dns_lookup, shodan_domain_info, shodan_dns_lookup | yes |
| Website Vulnerabilities | ip_lookup, cve_lookup, cpe_lookup, cves_by_product, threat_intelligence, domain_reputation, read_archived_page, wayback_snapshots | yes |
| Physical Assets | ipgeolocation; whois (2nd) | yes, weak |
| Third-Party Services | free-api, trends-api; dns_lookup (2nd) | yes, weak (no product names until `domain-api`) |
| Employee Public Information | username_search, email_verification, disposable_email_check | yes |
| Brand Monitoring | categorization; read_archived_page (2nd) | yes, weak |
| Breach Data | email_breach_check (+ Hudson Rock, from Jeremy) | no, until Hudson Rock |

The agent's instructions name the live tools and tell it to skip them when a user asks for passive-only work. Users don't see this.

### CVA coverage added by the free-API tools

| CVA category | Free-API tools (main + 2nd) |
|---|---|
| Network Discovery | crtsh_subdomains; wigle_wifi_search (2nd) |
| Website Vulnerabilities | osv_package_vulns, kev_check |
| Physical Assets | opensky_airport_flights, opensky_aircraft_flights, ships_near, wigle_wifi_search; sec_company_filings (2nd) |
| Third-Party Services | sec_company_filings, sec_filing_search, ransomware_victims |
| Employee Public Information | reddit_user_activity |
| Brand Monitoring | reddit_search, reddit_post_comments |
| Breach Data | ransomware_victims (2nd) |

With these, every category reaches 2+ tools (Breach Data only by counting `ransomware_victims` as its 2nd), and Physical Assets and Third-Party Services are no longer weak.
