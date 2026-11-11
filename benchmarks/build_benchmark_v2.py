"""Build benchmark v2: one test per agent tool, one per chaining pair, ~30 three-tool chains.

The chaining rules live here so they can be reviewed in one place:
  - GIVES: what each tool returns, as typed values (IP, hostname, email, ...),
    with the concrete value and where we saw the tool return it;
  - TAKES: which typed values each tool accepts, and the arguments it gets;
  - tool B can follow tool A when A gives a type that B takes;
  - EXCLUDE lists links that type-match but don't work, with the reason.

Targets (all passive or harmless):
  - Tidegate Solutions (tidegatesolutions.com), the fictional CTF company;
  - Tidegate's own vendors, as its records name them (Microsoft mail, GoDaddy
    nameservers and payments, Amazon hosting): Third-Party Services lookups;
  - test@example.com (reserved test address, not a person) for breach chains;
  - global product / CVE lookups and Shodan counts, which name no target.

    python benchmarks/build_benchmark_v2.py   # writes benchmark-v2.json
"""
import itertools, json, pathlib

HERE = pathlib.Path(__file__).parent

DOMAIN = "tidegatesolutions.com"
IP = "100.48.141.159"
EMAIL = "sreyes@tidegatesolutions.com"
TITLE = "Tidegate Solutions - Purity in Process"
TEST_EMAIL = "test@example.com"

# Evidence that a tool really returns a value of that type.
NOV5 = "seen in the Nov 5, 2026 run"
NOV11 = "seen in a free or 1-credit probe on Nov 11, 2026"
DOCS = "stated in the tool's own description (not yet seen live)"
CODE = "in the tool's code (platform repo)"

# How a later step refers to a value, and how a middle step hands one on.
NOUN = {"IP": "that IP address", "HOST": "that hostname", "DOMAIN": "that domain",
        "EMAIL": "that email address", "USERNAME": "that username", "TITLE": "that name",
        "ORG": "that organization", "ASN": "that ASN", "CIDR": "that network range",
        "PRODUCT": "that software", "CPE": "that CPE identifier", "CVE": "that CVE", "URL": "that link"}
TAKE = {"IP": "note the IP address", "HOST": "note the hostname", "DOMAIN": "note the domain",
        "EMAIL": "note the email address", "USERNAME": "note the username",
        "TITLE": "note the name", "ORG": "note the organization", "ASN": "note the ASN",
        "CIDR": "note the network range", "PRODUCT": "note the software and version",
        "CPE": "note one CPE identifier", "CVE": "pick one CVE", "URL": "pick one link"}
# When several link types fit, prefer the most natural one.
PRIORITY = ["IP", "HOST", "DOMAIN", "EMAIL", "USERNAME", "PRODUCT", "CPE", "CVE",
            "ASN", "TITLE", "ORG", "CIDR", "URL"]

# ---- What each tool returns: type -> (first-step wording, value, evidence) --
GIVES = {
    "whois": {
        "EMAIL": (f"Look up the WHOIS record for {DOMAIN} and find the registrant's email address", EMAIL, NOV5),
        "USERNAME": (f"Look up the WHOIS record for {DOMAIN} and take the username part of the registrant's email address", "sreyes", NOV5),
        "TITLE": (f"Look up the WHOIS record for {DOMAIN} and find the registrant organization's name", "Tidegate Solutions", NOV5),
        "HOST": (f"Look up the WHOIS record for {DOMAIN} and take one of its nameservers", "ns51.domaincontrol.com", NOV5),
    },
    "dns_lookup": {
        "IP": (f"Use WhoisXML's DNS lookup to find the IP address {DOMAIN} points to", IP, NOV5),
        "HOST": (f"Use WhoisXML's DNS lookup to find {DOMAIN}'s mail (MX) server", "tidegatesolutions-com.mail.protection.outlook.com", NOV5),
    },
    "shodan_dns_lookup": {
        "IP": (f"Resolve {DOMAIN} to an IP address with Shodan's DNS lookup", IP, NOV11),
    },
    "shodan_domain_info": {
        "HOST": (f"List the subdomains Shodan knows for {DOMAIN} and pick www.{DOMAIN}", f"www.{DOMAIN}", NOV11),
        "IP": (f"Get the DNS records Shodan has for {DOMAIN} and take the IP address of its A record", IP, NOV11),
    },
    "ssl_certificates": {
        "HOST": (f"Read the SSL certificate for pay.{DOMAIN} and take the other hostname it covers", f"www.pay.{DOMAIN}",
                 "certificate log (crt.sh) on Nov 11, 2026"),
    },
    "ipgeolocation": {
        "ASN": (f"Geolocate {IP} and note its ASN", "AS14618", NOV5),
        "ORG": (f"Geolocate {IP} and note the ISP that runs it", "Amazon", NOV5),
        "IP": (f"Geolocate the domain {DOMAIN} and note the IP address it reports", IP, DOCS),
    },
    "ip_netblocks": {
        "ASN": (f"Find the network block that contains {IP} and note its ASN", "AS14618", NOV5),
        "CIDR": (f"Find the network block that contains {IP} and note its range", "100.48.0.0/12", NOV5),
        "ORG": (f"Find the network block that contains {IP} and note the organization that owns it", "Amazon.com, Inc.", NOV5),
    },
    "vpn_proxy_detection": {
        "ASN": (f"Check whether {IP} is a VPN, proxy or hosting address, and note its ASN", "AS14618", DOCS),
    },
    "trends-api": {
        "HOST": ("Look up Apache on BuiltWith trends and take the hostname of its official website link", "httpd.apache.org", NOV11),
        "URL": ("Look up Apache on BuiltWith trends and take its official website link", "https://httpd.apache.org/", NOV11),
    },
    "ip_lookup": {
        "PRODUCT": (f"Look up {IP} in Shodan and find the web server software and version it runs", "Apache httpd 2.4.65", NOV5),
        "CPE": (f"Look up {IP} in Shodan and note the CPE identifier of its web server", "cpe:2.3:a:apache:http_server:2.4.65", NOV5),
        "CVE": (f"Look up {IP} in Shodan and pick one of the CVEs it lists", "<a CVE from step 1>", NOV5),
        "TITLE": (f"Look up {IP} in Shodan and note the page title of its website", TITLE, NOV5),
        "ASN": (f"Look up {IP} in Shodan and note its ASN", "AS14618", NOV5),
        "ORG": (f"Look up {IP} in Shodan and note the organization it belongs to", "Amazon Data Services Northern Virginia", NOV5),
        "HOST": (f"Look up {IP} in Shodan and note its hostname", "ec2-100-48-141-159.compute-1.amazonaws.com", NOV5),
    },
    "shodan_search": {
        "IP": (f"Search Shodan for hosts whose page title is '{TITLE}' and note the IP address of the result", IP, NOV5),
        "PRODUCT": (f"Search Shodan for hosts whose page title is '{TITLE}' and note the web server software and version", "Apache httpd 2.4.65", NOV5),
        "CVE": (f"Search Shodan for hosts whose page title is '{TITLE}' and pick one CVE listed for the result", "<a CVE from step 1>", NOV5),
        "ASN": (f"Search Shodan for hosts whose page title is '{TITLE}' and note the result's ASN", "AS14618", NOV5),
        "ORG": (f"Search Shodan for hosts whose page title is '{TITLE}' and note the result's organization", "Amazon Data Services Northern Virginia", NOV5),
        "HOST": (f"Search Shodan for hosts whose page title is '{TITLE}' and note the result's hostname", "ec2-100-48-141-159.compute-1.amazonaws.com", NOV5),
    },
    "shodan_count": {
        "ORG": (f"Count the hosts in Shodan whose page title contains 'Tidegate Solutions', broken down by organization, and note the top one", "Amazon Data Services Northern Virginia", NOV11),
        "ASN": (f"Count the hosts in Shodan whose page title contains 'Tidegate Solutions', broken down by ASN, and note the top one", "AS14618", NOV11),
        "PRODUCT": (f"Count the hosts in Shodan whose page title contains 'Tidegate Solutions', broken down by product, and note the top one", "Apache httpd", NOV11),
        "DOMAIN": (f"Count the hosts in Shodan whose page title contains 'Tidegate Solutions', broken down by domain, and note the top one", "amazonaws.com", NOV11),
    },
    "reverse_dns_lookup": {
        "HOST": (f"Find the hostname {IP} reverse-resolves to", "ec2-100-48-141-159.compute-1.amazonaws.com", NOV11),
    },
    "cve_lookup": {
        "CPE": ("Look up CVE-2025-55753 and note one CPE identifier of a product it affects", "<a CPE from step 1>", DOCS),
        "PRODUCT": ("Look up CVE-2025-55753 and note the name of the software it affects", "Apache HTTP Server", DOCS),
    },
    "cpe_lookup": {
        "CPE": ("Find the official CPE identifier for Apache HTTP Server 2.4.65", "cpe:2.3:a:apache:http_server:2.4.65", NOV5),
    },
    "cves_by_product": {
        "CVE": ("List the known CVEs for Apache HTTP Server 2.4.65 and pick the one with the highest EPSS score", "<a CVE from step 1>", NOV5),
    },
    "username_search": {
        "URL": ("Search social media sites for accounts that use the username sreyes and pick one profile link", "<a profile link from step 1>", CODE),
        "HOST": ("Search social media sites for accounts that use the username sreyes and note the website of one match", "<a site's hostname from step 1>", CODE),
    },
    "email_breach_check": {
        "DOMAIN": (f"Check which data breaches {TEST_EMAIL} appears in and note the domain of one breached company", "<a breached company's domain>",
                   "in XposedOrNot's raw data (Nov 11 probe); the tool must return it (see NEEDS_CHANGE)"),
    },
    "email_verification": {
        "HOST": (f"Verify whether the mailbox {EMAIL} exists and note its mail (MX) server", "tidegatesolutions-com.mail.protection.outlook.com", DOCS),
    },
    "disposable_email_check": {
        "DOMAIN": (f"Check whether {EMAIL} is a disposable email address and note the domain it uses", DOMAIN, DOCS),
    },
}

# ---- What each tool takes: type -> (later-step wording, args builder) -------
def h(key, wrap=False):
    return lambda v: {key: [v] if wrap else v}

TAKES = {
    "whois": {"DOMAIN": ("look up the WHOIS record for that domain", h("domain")),
              "HOST": ("look up the WHOIS record for that hostname's domain", h("domain"))},
    "dns_lookup": {t: (f"use WhoisXML's DNS lookup to get {NOUN[t]}'s DNS records", h("domain_name")) for t in ("HOST", "DOMAIN")},
    "shodan_dns_lookup": {t: (f"resolve {NOUN[t]} to an IP address with Shodan's DNS lookup", h("hostnames", True)) for t in ("HOST", "DOMAIN")},
    "shodan_domain_info": {t: (f"list the subdomains Shodan knows for {NOUN[t]}'s domain", h("domain")) for t in ("HOST", "DOMAIN")},
    "ssl_certificates": {t: (f"show {NOUN[t]}'s SSL certificate", h("domain")) for t in ("HOST", "DOMAIN")},
    "ipgeolocation": {"IP": ("find where that IP address is physically located", h("ip_address")),
                      "EMAIL": ("geolocate that email address", h("email_address")),
                      "HOST": ("find where that hostname's server is physically located", h("domain_name")),
                      "DOMAIN": ("find where that domain's server is physically located", h("domain_name"))},
    "ip_netblocks": {"IP": ("find who owns the IP range that contains that IP address", h("ip_address")),
                     "ASN": ("list the network blocks registered to that ASN (first 10)", lambda v: {"asn": v, "limit": 10}),
                     "ORG": ("list the network blocks registered to that organization (first 10)", lambda v: {"organizations": [v], "limit": 10})},
    "vpn_proxy_detection": {"IP": ("check whether that IP address is a VPN, proxy, Tor or hosting address", h("ip_address"))},
    "threat_intelligence": {t: (f"check {NOUN[t]} against malware, phishing and spam feeds", h("search_term"))
                            for t in ("IP", "HOST", "DOMAIN", "URL", "CIDR")},
    "domain_reputation": {t: (f"get {NOUN[t]}'s domain reputation score", h("domain_name")) for t in ("HOST", "DOMAIN")},
    "categorization": {"HOST": ("give the content category of that hostname's website", h("domain")),
                       "DOMAIN": ("give the content category of that domain's website", h("domain")),
                       "URL": ("give the content category of the page at that link", lambda v: {"domain": "<the link's domain>", "url": v})},
    "free-api": {t: (f"use BuiltWith's free lookup to count the technology types on {NOUN[t]}", h("lookup")) for t in ("HOST", "DOMAIN")},
    "trends-api": {"PRODUCT": ("check on BuiltWith trends how widely that software is used", lambda v: {"tech": "Apache"})},
    "ip_lookup": {"IP": ("look that IP address up in Shodan for open ports and software", h("ip"))},
    "shodan_search": {"IP": ("search Shodan for that IP address (net: filter) and list what it shows", lambda v: {"query": f"net:{v}"}),
                      "TITLE": ("search Shodan for hosts with that name in their page title", lambda v: {"query": f'http.title:"{v}"'}),
                      "ASN": ("search Shodan for hosts on that ASN with 'Tidegate Solutions' in their page title",
                              lambda v: {"query": f'asn:{v} http.title:"Tidegate Solutions"'})},
    "shodan_count": {"IP": ("count Shodan's results for that IP address, broken down by port", lambda v: {"query": f"net:{v}", "facets": "port"}),
                     "TITLE": ("count how many hosts in Shodan have that name in their page title", lambda v: {"query": f'http.title:"{v}"'}),
                     "ORG": ("count how many hosts Shodan sees for that organization", lambda v: {"query": f'org:"{v}"'}),
                     "ASN": ("count how many hosts Shodan sees on that ASN", lambda v: {"query": f"asn:{v}"}),
                     "CIDR": ("count how many hosts Shodan sees in that network range", lambda v: {"query": f"net:{v}"}),
                     "PRODUCT": ("count how many hosts on the internet run that same software", lambda v: {"query": 'product:"Apache httpd" version:"2.4.65"'}),
                     "CPE": ("count how many hosts in Shodan match that CPE identifier", lambda v: {"query": f'cpe:"{v}"'}),
                     "HOST": ("count how many hosts in Shodan have that hostname", lambda v: {"query": f"hostname:{v}"}),
                     "DOMAIN": ("count how many hosts in Shodan have a hostname under that domain", lambda v: {"query": f"hostname:{v}"})},
    "reverse_dns_lookup": {"IP": ("find the hostname that IP address reverse-resolves to", h("ips", True))},
    "cve_lookup": {"CVE": ("give that CVE's severity and whether it is on CISA's Known Exploited Vulnerabilities list", h("cve"))},
    "cpe_lookup": {"PRODUCT": ("find the official CPE identifier for that software", lambda v: {"product": "http_server"})},
    "cves_by_product": {"PRODUCT": ("list the known CVEs for that software", lambda v: {"product": v}),
                        "CPE": ("list the known CVEs for that CPE identifier", h("cpe23"))},
    "username_search": {"USERNAME": ("search social media sites for accounts that use that username", h("username"))},
    "email_breach_check": {"EMAIL": ("check whether that email address appears in any known data breaches", h("email"))},
    "email_verification": {"EMAIL": ("verify whether that mailbox actually exists", h("email"))},
    "disposable_email_check": {"EMAIL": ("check whether that email address is a disposable (throwaway) address", h("email"))},
}

# ---- Single tests ------------------------------------------------------------
SINGLE = {
    "whois": (f"Who registered {DOMAIN}, and when does the registration expire?", {"domain": DOMAIN}),
    "dns_lookup": (f"Using WhoisXML's DNS lookup, list the A, MX and TXT records for {DOMAIN}.", {"domain_name": DOMAIN}),
    "shodan_dns_lookup": (f"Use Shodan's DNS lookup to resolve {DOMAIN} to an IP address.", {"hostnames": [DOMAIN]}),
    "shodan_domain_info": (f"List the subdomains Shodan knows for {DOMAIN}.", {"domain": DOMAIN}),
    "ssl_certificates": (f"Show the SSL certificate for pay.{DOMAIN}: issuer, validity dates and the names it covers.", {"domain": f"pay.{DOMAIN}"}),
    "ipgeolocation": (f"Where is the server at {IP} physically located, and which ISP runs it?", {"ip_address": IP}),
    "ip_netblocks": (f"Who owns the IP range that contains {IP}?", {"ip_address": IP}),
    "vpn_proxy_detection": (f"Is {IP} a VPN, proxy, Tor or hosting IP address?", {"ip_address": IP}),
    "threat_intelligence": (f"Is {DOMAIN} listed in any malware, phishing or spam feeds?", {"search_term": DOMAIN}),
    "domain_reputation": (f"What is {DOMAIN}'s domain reputation score, and does it come with any warnings?", {"domain_name": DOMAIN}),
    "categorization": (f"What kind of website is {DOMAIN}? Give its content category.", {"domain": DOMAIN}),
    "free-api": (f"Using BuiltWith's free lookup, how many technologies of each type does {DOMAIN} use?", {"lookup": DOMAIN}),
    "trends-api": ("According to BuiltWith trends, how widely is Apache used on the web?", {"tech": "Apache"}),
    "ip_lookup": (f"What ports and software does Shodan show for {IP}?", {"ip": IP}),
    "shodan_search": (f"Search Shodan for hosts whose page title is '{TITLE}' and list them.", {"query": f'http.title:"{TITLE}"'}),
    "shodan_count": (f"How many hosts does Shodan see with the page title '{TITLE}'?", {"query": f'http.title:"{TITLE}"'}),
    "reverse_dns_lookup": (f"What hostname does {IP} reverse-resolve to?", {"ips": [IP]}),
    "cve_lookup": ("How severe is CVE-2025-55753, and is it on CISA's Known Exploited Vulnerabilities list?", {"cve": "CVE-2025-55753"}),
    "cpe_lookup": ("What is the official CPE identifier for Apache HTTP Server?", {"product": "http_server"}),
    "cves_by_product": ("List the known CVEs for Apache HTTP Server 2.4.65, highest EPSS score first.",
                        {"cpe23": "cpe:2.3:a:apache:http_server:2.4.65", "sort_by_epss": True}),
    "username_search": ("Find social media accounts that use the username sreyes.", {"username": "sreyes"}),
    "email_breach_check": (f"Has {EMAIL} appeared in any known data breaches?", {"email": EMAIL}),
    "email_verification": (f"Does the mailbox {EMAIL} actually exist?", {"email": EMAIL}),
    "disposable_email_check": (f"Is {EMAIL} a disposable (throwaway) email address?", {"email": EMAIL}),
    "account_balance": ("How many WhoisXML API credits do we have left?", {}),
    "api_info": ("How many Shodan query credits are left on our plan?", {}),
    "search_filters": ("Which search filters does Shodan support?", {}),
}
SERVER = {"email_breach_check": "local", "username_search": "local", "free-api": "builtwith", "trends-api": "builtwith",
          **{t: "shodan" for t in ("shodan_dns_lookup", "shodan_domain_info", "ip_lookup", "shodan_search", "shodan_count",
                                   "reverse_dns_lookup", "cve_lookup", "cpe_lookup", "cves_by_product", "api_info", "search_filters")}}
CVA = {"whois": "Network Discovery", "dns_lookup": "Network Discovery", "shodan_dns_lookup": "Network Discovery",
       "shodan_domain_info": "Network Discovery", "ssl_certificates": "Network Discovery", "ipgeolocation": "Physical Assets",
       "ip_netblocks": "Network Discovery", "vpn_proxy_detection": "Network Discovery",
       "threat_intelligence": "Website Vulnerabilities", "domain_reputation": "Website Vulnerabilities",
       "categorization": "Brand Monitoring", "free-api": "Third-Party Services", "trends-api": "Third-Party Services",
       "ip_lookup": "Website Vulnerabilities", "shodan_search": "Network Discovery", "shodan_count": "Network Discovery",
       "reverse_dns_lookup": "Network Discovery", "cve_lookup": "Website Vulnerabilities", "cpe_lookup": "Website Vulnerabilities",
       "cves_by_product": "Website Vulnerabilities", "username_search": "Employee Public Information",
       "email_breach_check": "Breach Data", "email_verification": "Employee Public Information",
       "disposable_email_check": "Employee Public Information"}
ACCOUNT_TOOLS = {"account_balance", "api_info", "search_filters"}
INVESTIGATION = [t for t in SINGLE if t not in ACCOUNT_TOOLS]

# Links that only work after a small code change: (tool, type) -> change.
NEEDS_CHANGE = {
    ("email_breach_check", "DOMAIN"): "email_breach_check must include each breach's `domain` field "
                                      "(XposedOrNot returns it; in micah-local-development since Nov 11, 2026, commit a18b933)",
}

# Links that type-match but don't work: (A, B) -> reason.
_NO_DNS = f"www.pay.{DOMAIN} (the certificate's other name) has no DNS record, so there is no site to check"
EXCLUDE = {("ssl_certificates", b): _NO_DNS for b in
           ("categorization", "free-api", "domain_reputation", "ipgeolocation", "shodan_dns_lookup", "ssl_certificates")}

# Tools that return nothing another tool can take.
DEAD_END = {
    "threat_intelligence": "returns only the indicator you asked about and its feed listings, so there's nothing new to pass on",
    "domain_reputation": "returns only a score, test results and warnings",
    "categorization": "returns only content categories",
    "free-api": "returns only technology category names and counts, no product names (Nov 11 probe)",
}


def links(a, b):
    """Link types by which b can take a's output, most natural first."""
    if a == b or (a, b) in EXCLUDE:
        return []
    return sorted((t for t in GIVES.get(a, {}) if t in TAKES[b]), key=PRIORITY.index)


def step(tool, args, given=None):
    s = {"tool": tool, "server": SERVER.get(tool, "whoisxml"), "args": args}
    if given:
        s["input_from_previous"] = given
    return s


def first_args(tool, out_type):
    """Arguments of a first step. Only the breach chains start from a different input."""
    if (tool, out_type) == ("email_breach_check", "DOMAIN"):
        return {"email": TEST_EMAIL}
    if (tool, out_type) == ("ipgeolocation", "IP"):
        return {"domain_name": DOMAIN}
    if (tool, out_type) == ("vpn_proxy_detection", "ASN"):
        return {"ip_address": IP}
    if (tool, out_type) == ("ssl_certificates", "HOST"):
        return {"domain": f"pay.{DOMAIN}"}
    if (tool, out_type) == ("shodan_count", out_type):
        return {"query": 'http.title:"Tidegate Solutions"', "facets": {"ORG": "org", "ASN": "asn", "PRODUCT": "product", "DOMAIN": "domain"}[out_type]}
    return SINGLE[tool][1]


def later(tool, t, value):
    return step(tool, TAKES[tool][t][1](value), t)


def cva_of(tools):
    return sorted({CVA[t] for t in tools if t in CVA})


def build():
    tests, n = [], 0

    def add(kind, query, steps, links_used):
        nonlocal n
        n += 1
        tools = [s["tool"] for s in steps]
        ev = [{"from": steps[i]["tool"], "type": t, "evidence": GIVES[steps[i]["tool"]][t][2]} for i, t in enumerate(links_used)]
        rec = {"id": n, "kind": kind, "query": query, "expected_tools": tools, "steps": steps,
               "cva_categories": cva_of(tools)}
        if ev:
            rec["links"] = ev
        need = [NEEDS_CHANGE[(steps[i]["tool"], t)] for i, t in enumerate(links_used) if (steps[i]["tool"], t) in NEEDS_CHANGE]
        if need:
            rec["needs_code_change"] = need[0]
        tests.append(rec)

    for t, (q, args) in SINGLE.items():
        add("single", q, [step(t, args)], [])

    excluded = []
    for a, b in itertools.permutations(INVESTIGATION, 2):
        ls = links(a, b)
        if ls:
            t = ls[0]
            phrase, value, _ = GIVES[a][t]
            add("pair", f"{phrase}. Then {TAKES[b][t][0]}.", [step(a, first_args(a, t)), later(b, t, value)], [t])
        else:
            if (a, b) in EXCLUDE:
                reason = EXCLUDE[(a, b)]
            elif a in DEAD_END:
                reason = f"{a} {DEAD_END[a]}"
            else:
                gives = ", ".join(sorted(GIVES[a])) or "nothing"
                takes = ", ".join(sorted(TAKES[b]))
                reason = f"{a} gives {gives}; {b} takes only {takes}"
            excluded.append({"first": a, "second": b, "reason": reason})

    for a, b, c in TRIPLES:
        t1 = links(a, b)[0]
        fresh = [t for t in links(b, c) if t != t1]  # the middle step should hand on something new
        t2 = (fresh or links(b, c))[0]
        p1, v1, _ = GIVES[a][t1]
        q = f"{p1}. Then {TAKES[b][t1][0]}, and {TAKE[t2]}. Finally, {TAKES[c][t2][0]}."
        add("triple", q, [step(a, first_args(a, t1)), later(b, t1, v1), later(c, t2, "<from step 2>")], [t1, t2])
    return tests, excluded


# Hand-picked three-tool chains: realistic analyst paths, spread over the CVA
# categories (grouped by the category the chain is mainly about).
TRIPLES = [
    # Website Vulnerabilities
    ("dns_lookup", "ip_lookup", "cves_by_product"),
    ("shodan_dns_lookup", "ip_lookup", "cve_lookup"),
    ("ip_lookup", "cpe_lookup", "cves_by_product"),
    ("ip_lookup", "cves_by_product", "cve_lookup"),
    ("cve_lookup", "cpe_lookup", "cves_by_product"),
    ("shodan_search", "cpe_lookup", "cves_by_product"),
    ("shodan_domain_info", "dns_lookup", "threat_intelligence"),
    ("reverse_dns_lookup", "shodan_dns_lookup", "ip_lookup"),
    # Network Discovery
    ("dns_lookup", "ip_netblocks", "shodan_count"),
    ("shodan_dns_lookup", "ip_netblocks", "shodan_search"),
    ("shodan_domain_info", "dns_lookup", "reverse_dns_lookup"),
    ("ip_lookup", "shodan_search", "reverse_dns_lookup"),
    ("vpn_proxy_detection", "ip_netblocks", "shodan_count"),
    ("whois", "dns_lookup", "ip_netblocks"),
    # Physical Assets
    ("shodan_dns_lookup", "ipgeolocation", "ip_netblocks"),
    ("shodan_domain_info", "shodan_dns_lookup", "ipgeolocation"),
    ("whois", "shodan_search", "ipgeolocation"),
    # Third-Party Services: who Tidegate depends on
    ("dns_lookup", "ip_lookup", "trends-api"),
    ("dns_lookup", "whois", "dns_lookup"),
    ("whois", "shodan_dns_lookup", "ip_netblocks"),
    ("ip_lookup", "trends-api", "whois"),
    ("shodan_count", "whois", "dns_lookup"),
    # Employee Public Information
    ("whois", "username_search", "threat_intelligence"),
    ("whois", "email_verification", "dns_lookup"),
    ("whois", "disposable_email_check", "domain_reputation"),
    ("whois", "ipgeolocation", "shodan_count"),
    # Breach Data (needs the email_breach_check change)
    ("email_breach_check", "whois", "dns_lookup"),
    ("email_breach_check", "dns_lookup", "ip_lookup"),
    # Brand Monitoring
    ("whois", "disposable_email_check", "categorization"),
    ("whois", "username_search", "categorization"),
]

if __name__ == "__main__":
    tests, excluded = build()
    out = {
        "description": "OSINT Research Platform - Benchmark v2 (every agent tool, every chaining pair, three-tool chains)",
        "version": "2.1", "created": "2026-11-11",
        "targets": {"main": {"domain": DOMAIN, "ip": IP, "email": EMAIL, "username": "sreyes"},
                    "vendors": "Tidegate's own vendors as its records name them (Microsoft mail, GoDaddy nameservers/payments, Amazon hosting)",
                    "breach_test_email": TEST_EMAIL,
                    "note": "Tidegate Solutions is a fictional CTF company. All lookups are passive or a single harmless visit."},
        "notes": "Primary metric: did the agent call every tool in expected_tools. Later steps take their input from the step "
                 "before (input_from_previous = link type; links[].evidence = where we saw the tool return that value). "
                 "Argument values are expected from earlier runs; '<...>' means they depend on the earlier result. "
                 "Items with needs_code_change only work after that change.",
        "counts": {k: sum(t["kind"] == k for t in tests) for k in ("single", "pair", "triple")},
        "tests": tests,
        "excluded_pairs": excluded,
    }
    out["counts"]["excluded_pairs"] = len(excluded)
    out["counts"]["needs_code_change"] = sum("needs_code_change" in t for t in tests)
    (HERE / "benchmark-v2.json").write_text(json.dumps(out, indent=2) + "\n")
    print(out["counts"])
