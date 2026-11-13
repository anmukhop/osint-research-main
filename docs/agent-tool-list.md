# Which tools the platform's AI agent may call

As of Nov 10, 2026. The code list is `AGENT_ALLOWED_TOOLS` in `researcher/services/mcp_client.py` and must match the **Allowed** column. The servers expose 99 tools today (local 2, WhoisXML 35, Shodan 11, BuiltWith 51). The agent can call 27 of them.

**Passive** = reads a database someone else already built. The target is not contacted in any way.
**Live** = something contacts the target or another live site now. For WhoisXML tools that contact comes from WhoisXML's servers, never the analyst's computer, and it's one ordinary visit or check, not a scan. Live recon is allowed by default. Evidence backing this up is that OSINT Clinic (CHI '25) Table 1 lists port scanning as a normal Website Vulnerabilities technique.

CVA categories are the seven from OSINT Clinic Table 1. "(2nd)" = a second category the tool also covers. It counts toward the 2+ per category goal, but it isn't the tool's main job.

Credits are as of Nov 10, 2026 (WhoisXML `account_balance`, BuiltWith `whoami-api`/`usage-api`, Shodan `api_info` on Nov 9).

## Allowed (27)

| Tool | Server | Passive / Live | Cost per call | CVA category | Why |
|---|---|---|---|---|---|
| `username_search` | local | Live (checks profile pages on social sites, not the target) | free | Employee Public Information | Finds an employee's accounts across sites |
| `email_breach_check` | local (XposedOrNot) | Passive | free | Breach Data | Which breaches an email appears in |
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

## CVA coverage (allowed tools, main + 2nd)

| CVA category | Tools | 2+? |
|---|---|---|
| Network Discovery | whois, dns_lookup, ip_netblocks, vpn_proxy_detection, ssl_certificates, shodan_search, shodan_count, reverse_dns_lookup, shodan_domain_info, shodan_dns_lookup | yes |
| Website Vulnerabilities | ip_lookup, cve_lookup, cpe_lookup, cves_by_product, threat_intelligence, domain_reputation | yes |
| Physical Assets | ipgeolocation; whois (2nd) | yes, weak |
| Third-Party Services | free-api, trends-api; dns_lookup (2nd) | yes, weak (no product names until `domain-api`) |
| Employee Public Information | username_search, email_verification, disposable_email_check | yes |
| Brand Monitoring | categorization (+ GDELT news-tone tool, to build) | no, until GDELT |
| Breach Data | email_breach_check (+ Hudson Rock, from Jeremy) | no, until Hudson Rock |

The agent's instructions name the live tools and tell it to skip them when a user asks for passive-only work. Users don't see this.
