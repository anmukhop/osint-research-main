# Benchmark v2

A set of plain "do X" requests for the platform's AI agent. It covers every tool the agent may call (`docs/agent-tool-list.md`, 27 tools as of Nov 10, 2026), every pair of tools that can actually chain, and 30 three-tool chains. The goal is to show the system can do each task, not to trick it. It replaces the earlier 30-question Tidegate run (Nov 5, 2026).

| Part | Items | What it checks |
|---|---|---|
| Single | 27 | One test per allowed tool, including the 3 account tools (credit checks, Shodan filters) |
| Pair | 200 | Every ordered pair (A → B) where B can take something A returns |
| Triple | 30 | Realistic three-step analyst paths, at least one in each of the seven CVA categories |
| **Total** | **257** | 13 of them need a one-line code change first (see below) |

The other 352 of the 552 possible ordered pairs (24 investigation tools × 23) are listed in the JSON, each with the reason it doesn't chain.

Files:
- `benchmark-v2.json`: the items. Each has:
  - `query`, `expected_tools` (in order), `steps` (tool, server, expected arguments, and the type of value passed in from the step before), `cva_categories` and `kind`;
  - `links`: for each hand-off, where we saw the first tool return that value;
  - `needs_code_change`, on the 13 items that need one.

  The JSON also lists `excluded_pairs` with the reasons.
- `build_benchmark_v2.py`: generates the JSON. The rules are written out in it: `GIVES` (what each tool returns, with evidence), `TAKES` (what each tool accepts), `EXCLUDE` and `DEAD_END`. Change them there and run `python benchmarks/build_benchmark_v2.py`.

## Targets

All lookups are passive, or one harmless visit by WhoisXML.
- **Tidegate Solutions:** `tidegatesolutions.com`, server `100.48.141.159`, subdomains `www`/`pay` (`pay` points to GoDaddy's payment-link service), registrant `sreyes@tidegatesolutions.com`, username `sreyes`. A fictional CTF company. SecretCorp is left out because it's the pilot study's question.
- **Tidegate's own vendors, as its records name them:** Microsoft (mail), GoDaddy (nameservers, payment page) and Amazon (hosting). Looking up who a company depends on is what the Third-Party Services category is about.
- **`test@example.com`:** a reserved test address, not a person, used for breach chains. XposedOrNot lists it in 216 breaches.
- **Global lookups with no target:** product and CVE databases, and Shodan counts.

## How pairs were chosen

Each tool is listed with the kinds of values it returns and the kinds it accepts: IP, hostname, domain, email, username, company name, organization, ASN, network range, software name, CPE, CVE or link. B follows A when A returns a kind of value B accepts. For example, `reverse_dns_lookup` returns Tidegate's AWS hostname, and `shodan_dns_lookup` takes a hostname.

Every "A returns X" claim carries evidence in `links`:

| Evidence | Pair links |
|---|---|
| Seen in the Nov 5 run | 72 |
| Seen in a free (or 1-credit) probe on Nov 11 | 60 |
| Tool's own description only | 36 |
| Tool's code or XposedOrNot's raw data | 22 |
| Certificate log (crt.sh) | 10 |

Some returns were found on Nov 11 and weren't used in the first draft:
- `shodan_count` breaks results down by organization, ASN, product and domain, and it's free.
- `vpn_proxy_detection` returns an ASN.
- `disposable_email_check` returns the email's domain.
- `email_verification` returns the MX server.
- `ip_netblocks` accepts an ASN or organization name.
- `cve_lookup` names the affected software.
- `trends-api` gives the product's homepage.
- `whois` lists nameservers.

**Why the other 352 pairs don't chain:**
- **92: four tools are dead ends.** `threat_intelligence` returns only the indicator you asked about. `domain_reputation` returns a score and warnings, `categorization` returns content categories, and `free-api` returns category counts with no product names.
- **260: type mismatches.** A returns nothing B accepts. For example, `cves_by_product` returns CVE IDs, and only `cve_lookup` takes a CVE. Vulnerability tools speak software, CPE and CVE; network tools speak IP and hostname; the two meet only through `ip_lookup`, `shodan_search` and `shodan_count`.

**Hostnames and domains.** When a later step asks for "that hostname's domain" (WHOIS, Shodan's subdomain list), the expected argument is the domain, not the full hostname: `ec2-100-48-141-159.compute-1.amazonaws.com` → `amazonaws.com`, the MX host → `outlook.com`, `ns51.domaincontrol.com` → `domaincontrol.com`, `httpd.apache.org` → `apache.org`, `www.tidegatesolutions.com` → `tidegatesolutions.com`.

**`ssl_certificates` hands on `pay`.** The live certificate on `pay.tidegatesolutions.com` (Go Daddy, valid to Dec 4, 2026) names `pay` and `www.pay`. `www.pay` has no DNS record, so pairs take the name the certificate was issued for, `pay.tidegatesolutions.com`, which resolves. Until Nov 13, 2026 the pairs used `www.pay`, which left five items with nothing to find and excluded five others.

## The code change (13 items)

`email_breach_check` drops each breach's `domain` field, which XposedOrNot does return. With that field, a breach becomes a company domain you can investigate. The fix is in `micah-local-development` since Nov 11, 2026 (commit a18b933: one line in `researcher/services/agents/xposedornot.py`, the tool description, and a test). Run the benchmark on a checkout that includes it; on older code, skip the items marked `needs_code_change`.

## Not covered

Tools that aren't built or allowed yet: the GDELT news-tone tool, Hudson Rock, the WhoisXML Domain Research Suite and paid BuiltWith lookups. When one is added to `AGENT_ALLOWED_TOOLS`, add it to `GIVES`/`TAKES`/`SINGLE` and rebuild.

## Before running it

- **Tidegate's domain was renewed on Nov 12, 2026** and now expires Nov 23–24, 2027 (registry and registrar RDAP, checked Nov 13). Item 1's answer is the 2027 date.
- **The `pay` certificate expires Dec 4, 2026.** If the run is later, re-check the `ssl_certificates` items first; a renewed certificate is fine if it still names `pay.tidegatesolutions.com`.
- **Credits.** The JSON gives expected calls per tool. The tight ones:
  - `vpn_proxy_detection` is expected about 10 times and has 7 credits.
  - `email_verification` and `disposable_email_check` are expected about 29 times together and share 93 credits.
  - WHOIS and DNS lookups are expected about 40 times each.
  - `ssl_certificates` is expected 23 times.

  Set per-product limits as the Nov 5 runner did, or run in batches.
- **Scope guard.** The Nov 5 runner allowed only `tidegatesolutions.com` and `100.48.141.159`. This set also needs:
  - the vendors above;
  - `pay.tidegatesolutions.com` (GoDaddy's shared payment-link servers; reputation, category and BuiltWith answers describe that service);
  - `test@example.com` and the breached-company domains it leads to;
  - whatever sites `username_search` finds (for `sreyes` these are unrelated real people, not the fictional registrant; kept on purpose, Nov 13, 2026);
  - global Shodan counts.
- **Live checks.** `email_verification`, `categorization` and `domain_reputation` make one contact with a vendor or social site (an SMTP check or one homepage visit). This is allowed by default (`docs/agent-tool-list.md`).
- Argument values come from earlier runs. `<...>` means the value depends on an earlier step, and third-step values are always "from step 2".

Grading: the main metric is whether the agent called every tool in `expected_tools`. Answer correctness is checked by hand, as in the Nov 5 run.
