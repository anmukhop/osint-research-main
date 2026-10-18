# OSINT Agent — Tool Capabilities (Username, Domain, IP, Web Vulnerability)

This document describes the tools the OSINT agent can call for **username/person**, **domain**, **IP**, and **web/security vulnerability** reconnaissance, what each one returns, and how they can be chained together for real vulnerability-assessment workflows.

Source of truth: [`researcher/services/tool_registry.py`](../researcher/services/tool_registry.py) (tool definitions + routing) and [`researcher/services/mcp_client.py`](../researcher/services/mcp_client.py) (agentic tool-calling loop). The agent is Claude, driven by a system prompt that picks one or more of these tools per turn, reads the results, and decides whether to call more (up to 8 turns) before answering — see `_PLANNER_SYSTEM_PROMPT` in `mcp_client.py:645`.

Four backing services provide these tools via MCP: **Local server** (1 tool, stdio), **WhoisXML API** (17 tools, HTTP), **Shodan** (4 tools, stdio/npx), **BuiltWith** (2 tools, HTTP).

---

## 0. Username / Person Search (Local Server)

### `username_search`
Checks a username against 600+ site signatures from the [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) dataset in parallel (`researcher/services/agents/whatsmyname.py`) — social media, professional networks, forums, gaming, dating sites, and more. For each candidate site it sends a GET/POST to a per-site templated URL and checks the response status code / body marker defined in the site's signature to confirm the account exists.
- **Query:** "Find all social media accounts for john_doe"
- **Response (shape):**
```json
{
  "username": "john_doe",
  "found_sites": [
    { "platform": "GitHub", "category": "coding", "domain": "github.com", "profile_url": "https://github.com/john_doe" },
    { "platform": "Reddit", "category": "forum", "domain": "reddit.com", "profile_url": "https://reddit.com/user/john_doe" }
  ],
  "total_found": 2,
  "error": null
}
```
**Assessment value:** maps the human-layer footprint behind a handle. In a vulnerability-assessment context this is used less for "who is this person" and more for **social-engineering surface mapping** — enumerating which platforms an employee/admin/domain-registrant handle is active on (helpful for phishing-pretext research, credential-stuffing target lists, and correlating a breached username to currently-live accounts) and for confirming whether a suspicious actor's handle from one platform (e.g., a phishing kit's Telegram handle) reappears elsewhere.

---

## 1. Domain Intelligence (WhoisXML API)

### `whois`
Registration record for a domain — registrant, registrar, creation/expiry/updated dates, nameservers.
- **Query:** "Who owns google.com?"
- **Response (shape):**
```json
{
  "domainName": "google.com",
  "registrarName": "MarkMonitor Inc.",
  "createdDate": "1997-09-15",
  "expiresDate": "2028-09-13",
  "registrant": { "organization": "Google LLC", "country": "US" },
  "nameServers": ["ns1.google.com", "ns2.google.com"]
}
```
**Assessment value:** confirms who legally controls a domain, how old it is (new domains are a phishing/typosquat signal), and whether it's about to expire (expired-domain hijack risk).

### `whois_history`
All historical WHOIS snapshots for a domain.
- **Query:** "Show historical WHOIS records for twitter.com"
- **Response:** array of past `whois`-shaped records with `changeDate`/`recordDate`, showing prior registrants/registrars.

**Assessment value:** detects ownership changes that may correlate with a compromise, resale to a threat actor, or infrastructure repurposing.

### `reverse_whois`
All domains registered under a given name, org, or email as registrant.
- **Query:** "Find all domains registered by Google LLC"
- **Response:**
```json
{ "domains": ["google.com", "googlemail.com", "abc.xyz", "..."] }
```
**Assessment value:** maps an organization's or an attacker's full domain portfolio — critical for finding shadow IT, look-alike/typosquat domains, or a phishing actor's other properties once one malicious domain is identified.

### `dns_lookup`
Current DNS records (A/AAAA/MX/NS/TXT/CNAME/SOA or all).
- **Query:** "What are the DNS records for netflix.com?"
- **Response:**
```json
{ "A": ["54.237.226.164"], "MX": ["mx.netflix.com"], "TXT": ["v=spf1 ..."], "NS": ["ns1.netflix.com"] }
```
**Assessment value:** baseline map of what's live — mail infra, SPF/DKIM/DMARC posture (via TXT), which nameservers/CDN are authoritative.

### `dns_history`
Historical DNS record changes over time.
- **Query:** "Show DNS history for reddit.com"
- **Response:** timeline of prior A/MX/NS values with change dates.

**Assessment value:** reveals migrations, past hosting providers, or an IP that used to point somewhere sensitive — useful for tracing infrastructure pivots during an incident.

### `reverse_dns`
Domains whose DNS records (typically CNAME) point at a given target.
- **Query:** "Find domains with CNAME records pointing to amazonaws.com"
- **Response:** `{ "domains": ["app.example.com", "cdn.otherexample.com"] }`

**Assessment value:** finds dangling-CNAME / subdomain-takeover candidates when the target service (e.g., an abandoned S3 bucket or SaaS endpoint) is no longer owned by the expected party.

### `reverse_mx`
Domains sharing a given mail server.
- **Query:** "Find domains using mail server alt1.gmail-smtp-in.l.google.com"
- **Response:** `{ "domains": [...] }`

**Assessment value:** clusters organizations by shared mail infrastructure — useful for identifying sibling/subsidiary domains or a common managed-email provider with a known vulnerability.

### `reverse_ns`
Domains sharing a given nameserver.
- **Query:** "Find domains using nameserver ns1.google.com"
- **Response:** `{ "domains": [...] }`

**Assessment value:** clusters domains by DNS provider — relevant when a specific DNS host has a known misconfiguration or the nameserver itself indicates a reseller/bulletproof-hosting pattern.

### `subdomain_lookup`
Enumerates known subdomains of a domain.
- **Query:** "Find subdomains of microsoft.com"
- **Response:** `{ "subdomains": ["login.microsoft.com", "portal.microsoft.com", "dev.microsoft.com", "..."] }`

**Assessment value:** the single highest-value recon step for attack-surface mapping — surfaces forgotten staging/dev/admin hosts that are common initial-access points.

### `domain_and_subdomain_discovery`
Finds domains/subdomains containing a keyword (not restricted to one root domain).
- **Query:** "Discover domains containing 'shopify' in the name"
- **Response:** `{ "domains": ["shopify-support.com", "myshopify-login.net", "..."] }`

**Assessment value:** brand-monitoring and typosquat/phishing-kit discovery — flags look-alike domains impersonating a brand before or during a phishing campaign.

---

## 2. IP Intelligence (WhoisXML API + Shodan)

### `ipgeolocation`
Country/city/ASN/ISP for an IP.
- **Query:** "Where is IP address 8.8.8.8 located?"
- **Response:** `{ "ip": "8.8.8.8", "country": "US", "city": "Mountain View", "asn": "AS15169", "isp": "Google LLC" }`

**Assessment value:** attributes an IP to a hosting provider/geography — useful for jurisdiction, expected-vs-actual hosting checks, and abuse-contact routing.

### `ip_netblocks`
Ownership of the CIDR block containing an IP.
- **Query:** "What network block owns 8.8.8.0?"
- **Response:** `{ "netblock": "8.8.8.0/24", "org": "Google LLC", "asn": "AS15169" }`

**Assessment value:** confirms whether an IP genuinely belongs to the claimed organization's allocated range, or sits in an unrelated/hostile block (evidence of spoofing, compromised infra, or bulletproof hosting).

### `reverse_ip`
All domains hosted on a given IP (shared hosting reveals co-tenants).
- **Query:** "What domains are hosted on IP 142.250.80.46?"
- **Response:** `{ "domains": ["site1.com", "site2.net", "..."] }`

**Assessment value:** on shared hosting, a vulnerability in one co-tenant site (e.g., an outdated CMS) can be a pivot point into others on the same box — this tool identifies the full blast radius.

### `shodan_host_lookup` (`host`)
Open ports, running services/banners, and known CVEs Shodan has fingerprinted for a host.
- **Query:** "What services are running on IP 8.8.8.8?"
- **Response:**
```json
{
  "ip_str": "8.8.8.8",
  "ports": [53, 443],
  "org": "Google LLC",
  "data": [
    { "port": 443, "product": "nginx", "version": "1.18.0", "banner": "..." }
  ],
  "vulns": ["CVE-2021-23017"]
}
```
**Assessment value:** the core exposure scan — directly tells you what's reachable from the internet and whether Shodan has already flagged known CVEs against the fingerprinted service versions.

### `shodan_dns_lookup` (`dns-lookup`) / `shodan_reverse_dns` (`reverse-dns`)
Forward/reverse DNS resolution via Shodan's own resolver.
- **Query:** "Resolve google.com to its IP using Shodan" / "Reverse DNS for 8.8.8.8"
- **Response:** `{ "google.com": "142.250.80.46" }` / `{ "8.8.8.8": ["dns.google"] }`

**Assessment value:** cross-check against WhoisXML's DNS answers — discrepancies between resolvers can indicate split-horizon DNS, geo-based responses, or DNS poisoning.

---

## 3. Web / Security Vulnerability Tools

### `threat_intelligence`
Malware/phishing/spam/blocklist reputation for a domain or IP.
- **Query:** "Check threat intelligence for suspicious-domain.com"
- **Response:** `{ "target": "suspicious-domain.com", "malicious": true, "categories": ["phishing"], "sources": ["..."] }`

**Assessment value:** fastest go/no-go signal — is this asset already known-bad to the security community.

### `ssl_certificates`
Current and historical SSL/TLS certificate details for a domain (issuer, validity window, SANs).
- **Query:** "Show SSL certificates for github.com"
- **Response:** `{ "domain": "github.com", "issuer": "DigiCert Inc", "validFrom": "2025-02-01", "validTo": "2026-02-01", "subjectAltNames": ["github.com","www.github.com"] }`

**Assessment value:** finds expired/self-signed/mismatched certs (MITM and trust-warning risk), and SAN entries are a free subdomain-enumeration source (certs often list internal hostnames).

### `email_verification`
Checks whether an email address is syntactically valid and actually deliverable (mailbox exists).
- **Query:** "Verify the email address test@gmail.com"
- **Response:** `{ "email": "test@gmail.com", "formatValid": true, "smtpCheck": "valid", "disposable": false, "freeProvider": true }`

**Assessment value:** validates registrant/contact emails found via WHOIS, and screens for disposable/throwaway addresses often used in fraudulent domain registrations.

### `categorization`
Content/topic classification of a website (news, shopping, social, etc.).
- **Query:** "What category is reddit.com?"
- **Response:** `{ "domain": "reddit.com", "categories": ["Social Networking", "Forums"] }`

**Assessment value:** sanity-checks whether a domain's declared purpose matches its actual content — mismatches (e.g., a domain categorized as "banking" registered a week ago) are a phishing tell.

### `shodan_cve_lookup` (`cve-lookup`)
Details for a specific CVE — severity/CVSS, description, affected products.
- **Query:** "Look up CVE-2021-44228"
- **Response:** `{ "cve_id": "CVE-2021-44228", "summary": "Apache Log4j2 JNDI features...", "cvss": 10.0, "references": ["..."] }`

**Assessment value:** turns a service/version fingerprint (from `shodan_host_lookup`) into an actionable severity rating and remediation reference.

### `builtwith` (`free-api`)
Technology-stack category summary for a site (CMS, analytics, hosting, frameworks) plus first/last-seen dates.
- **Query:** "What technologies does shopify.com use?"
- **Response:** `{ "domain": "shopify.com", "categories": { "cms": 1, "analytics": 3, "hosting": 2 }, "firstIndexed": "2011-06-01", "lastIndexed": "2026-07-01" }`

**Assessment value:** fingerprints the software stack without touching the target directly — a prerequisite for mapping stack components to known CVEs.

### `builtwith_trends` (`trends-api`)
Market-adoption data for a named technology.
- **Query:** "How popular is WordPress?"
- **Response:** `{ "technology": "WordPress", "totalSites": 45000000, "topTierSites": 120000 }`

**Assessment value:** contextualizes how widely-deployed (and therefore how attractive a target) a technology is — relevant when triaging a newly disclosed CVE's blast radius.

---

## 4. Chaining Tools for Complex Vulnerability-Assessment Scenarios

The agent's value isn't any single lookup — it's that Claude can chain these tool calls across turns, feeding each result into the next decision (`mcp_client.py:747-896`). Representative multi-step investigations:

**A. External attack-surface assessment of an organization**
1. `reverse_whois` (org name) → enumerate every domain the org owns
2. `subdomain_lookup` on each root domain → enumerate hosts
3. `dns_lookup` on each subdomain → resolve to IPs
4. `shodan_host_lookup` on each IP → open ports, service banners, existing Shodan-flagged `vulns`
5. `builtwith` on web hosts → identify CMS/framework versions
6. `shodan_cve_lookup` on any CVE IDs surfaced in steps 4–5 → severity and exploitability context

Result: a ranked list of exposed services with known vulnerabilities, without ever touching the target directly.

**B. Subdomain takeover hunting**
1. `subdomain_lookup` → full subdomain list
2. `reverse_dns` for each subdomain's CNAME target → check whether it points to a third-party service (S3, Heroku, Azure, etc.)
3. `dns_lookup` to confirm the CNAME still resolves but the underlying resource is unclaimed
4. `ssl_certificates` to check whether the site even has a valid cert for that host (often absent on abandoned takeover targets)

Result: identifies dangling DNS entries that can be claimed by an attacker to serve content under the victim's domain.

**C. Phishing / brand-impersonation triage**
1. `domain_and_subdomain_discovery` (brand keyword) → candidate look-alike domains
2. `whois` on each candidate → registration date (very recent = high suspicion) and registrant
3. `threat_intelligence` → check existing blocklist status
4. `categorization` → confirm content mismatch (e.g., claims to be a bank but categorized as "parked/unrated")
5. `ssl_certificates` → confirm whether it's using a free/auto-issued cert typical of throwaway phishing infrastructure

Result: a scored shortlist of active phishing domains impersonating the brand, ready for takedown requests.

**D. Shared-infrastructure / blast-radius analysis after finding one compromised or malicious asset**
1. `reverse_ip` on the malicious host's IP → other domains on the same server (co-tenant exposure)
2. `ip_netblocks` → confirm whether the IP is in a hosting provider's range or a suspicious/bulletproof block
3. `reverse_ns` / `reverse_mx` → other domains sharing the same DNS/mail infrastructure (possible same-actor campaign)
4. `whois_history` / `dns_history` on those related domains → check for coordinated registration/DNS-change timing (campaign infrastructure signature)

Result: maps an entire malicious campaign's infrastructure from a single starting indicator, rather than assessing one domain in isolation.

**E. Pre-disclosure exposure check for a newly announced CVE**
1. `shodan_cve_lookup` → get affected product/version details for the CVE
2. `builtwith_trends` → gauge how widely that technology is deployed (prioritization signal)
3. `shodan_host_lookup` against specific IPs/ranges of interest → check if the fingerprinted service version matches the vulnerable range
4. `ssl_certificates` / `dns_lookup` → confirm the host is still live and identify its operational owner for notification

Result: turns a public CVE advisory into a concrete, targeted exposure list.

**F. Human-layer / social-engineering exposure from a domain**
1. `whois` on the target domain → registrant name/organization and any exposed contact email
2. `email_verification` on that contact email → confirm it's a live, non-disposable mailbox worth targeting in a phishing-resistance test
3. `username_search` on the local-part of the email or any handle found in WHOIS/site content → discover which platforms that person/admin is active on
4. Cross-reference `found_sites` categories (e.g., developer forums, gaming, dating) against the org's threat model to flag high-risk accounts (e.g., a sysadmin active on a breached forum, reused-password risk)

Result: extends infrastructure-only recon into the human attack surface — identifying real people and accounts tied to a domain that a red team or phishing-awareness assessment would target, without needing any credentials or direct contact with the individual.

---

## Notes / Constraints
- Domain/IP/web-vuln lookups are passive (registry/API-sourced or Shodan's pre-existing internet-wide scan data) — none of them actively probe or exploit the target, which keeps this within OSINT/recon scope rather than active penetration testing. `username_search` is the one exception worth flagging: it makes live HTTP requests, but to the 600+ third-party *platforms* being checked, never to the target organization's own infrastructure.
- WhoisXML and BuiltWith run on trial/free-tier credits with rate limits; Shodan free tier has limited query credits (`README.md`). `username_search` results depend on a periodically-refreshed WhatsMyName dataset cached for 24h (`whatsmyname.py:19-22`) and can be affected by target sites' anti-bot protections.
- The agent will refuse to fabricate results or invent URLs/identifiers not present in tool output (`_PLANNER_SYSTEM_PROMPT`, `mcp_client.py:680-686`).
