"""
Page Reader for OSINT Research Platform

Lets the agent read one web page or PDF as text, either live or from the
Internet Archive's Wayback Machine. Free, no API key.

Three tools use this module:
- read_webpage: one plain GET of the given URL (a LIVE visit to that site).
  If the live visit fails, it falls back to the newest Wayback copy.
  DISABLED pending a decision (the site sees the visit from the server's IP);
  see READ_WEBPAGE_ENABLED below.
- read_archived_page: reads the Wayback copy of a URL closest to a date.
  Passive: only archive.org is contacted.
- wayback_snapshots: lists archived copies of a URL, or every archived URL
  under a site (finds old, hidden or unlinked pages). Passive.

Deliberately limited: one GET per page (plus redirects), no forms, no
JavaScript, no images or scripts loaded, no crawling. Size and time capped.
Only public internet addresses are fetched, so the platform can't be used to
read its own server's private network.

API docs: Wayback CDX server
https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
"""

import io
import ipaddress
import re
import socket
import sys
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import requests


# read_webpage is DISABLED pending a decision (Nov 13, Micah): it visits the
# target site from the platform server's IP, so the site can see the visit.
# Question for Anirban / Dr. Luther. To re-enable, set this to True: it puts
# the tool back in tool_registry.TOOLS, the local server's list, the agent's
# allow-list (mcp_client.py) and the MCP server (mcp_server.py). Lives here
# because this file has no project imports, so the MCP server (run as a
# script) and the Django code (a package) can both read it.
READ_WEBPAGE_ENABLED = False

USER_AGENT = "osint-research-platform (page reader)"
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 20
TOTAL_DEADLINE = 45          # seconds for a whole download, redirects included
MAX_BYTES = 10 * 1024 * 1024  # stop downloading after 10 MB
MAX_REDIRECTS = 5

DEFAULT_MAX_CHARS = 8000
MAX_CHARS_CAP = 40000
DEFAULT_MAX_LINKS = 40
MAX_LINKS_CAP = 200
MAX_SCRIPTS = 60
MAX_COMMENTS = 20
MAX_META = 30

CDX_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK_HOST = "web.archive.org"
DEFAULT_SNAPSHOT_LIMIT = 50
SNAPSHOT_LIMIT_CAP = 500
MATCH_TYPES = ("exact", "prefix", "host", "domain")

_WAYBACK_TS_RE = re.compile(r"/web/(\d{4,14})(?:[a-z]{2}_)?/", re.I)


class PageReadError(Exception):
    """A problem worth telling the agent about, in plain words."""


# --------------------------------------------------------------------------
# Input checks
# --------------------------------------------------------------------------

def normalize_url(url) -> str | None:
    """Trim a URL, add https:// if no scheme; None if it isn't a usable http(s) URL."""
    if not isinstance(url, str):
        return None
    cleaned = url.strip()
    if not cleaned or len(cleaned) > 2048 or any(c.isspace() for c in cleaned):
        return None
    if "://" not in cleaned:
        cleaned = "https://" + cleaned
    parts = urlsplit(cleaned)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    if parts.username or parts.password:
        return None
    return cleaned


def _check_public_host(url: str) -> None:
    """Refuse URLs whose host is (or resolves to) a private or local address."""
    host = urlsplit(url).hostname or ""
    if host.lower() in ("localhost",) or host.lower().endswith((".localhost", ".local", ".internal")):
        raise PageReadError("That address is on a private network; only public websites can be read.")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise PageReadError(f"The host name {host} doesn't resolve (no DNS record).")
    for info in infos:
        address = info[4][0].split("%")[0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not ip.is_global:
            raise PageReadError("That address is on a private network; only public websites can be read.")


def _clamp(value, default: int, low: int, high: int) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(value, high))


def parse_date(value) -> str | None:
    """'2018', '2018-07', '2018-07-15' or '20180715' -> a Wayback timestamp prefix."""
    if value in (None, ""):
        return None
    digits = re.sub(r"[^0-9]", "", str(value))
    if len(digits) < 4 or len(digits) > 14:
        raise PageReadError(f"Couldn't read the date '{value}'. Use YYYY, YYYY-MM or YYYY-MM-DD.")
    return digits


def iso_from_timestamp(ts: str | None) -> str | None:
    """'20180715123000' -> '2018-07-15T12:30:00Z'."""
    if not ts or len(ts) < 8:
        return None
    ts = (ts + "00000000000000")[:14]
    try:
        return datetime.strptime(ts, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Fetching: one GET, redirects followed by hand so every hop is checked
# --------------------------------------------------------------------------

def fetch(url: str, session=None) -> dict:
    """
    GET a URL with size, time and redirect limits.

    Returns {final_url, status_code, content_type, body (bytes), cut_short}.
    Raises PageReadError for anything the agent should be told about.
    """
    http = session or requests
    deadline = time.monotonic() + TOTAL_DEADLINE
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        _check_public_host(current)
        try:
            response = http.get(
                current,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,application/pdf,text/plain;q=0.9,*/*;q=0.5",
                },
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                allow_redirects=False,
                stream=True,
            )
        except requests.Timeout:
            raise PageReadError("The site did not respond in time.")
        except requests.exceptions.SSLError:
            raise PageReadError("The site's HTTPS certificate couldn't be verified.")
        except requests.RequestException as e:
            raise PageReadError(f"Could not connect to the site ({type(e).__name__}).")

        if response.status_code in (301, 302, 303, 307, 308) and response.headers.get("Location"):
            location = urljoin(current, response.headers["Location"])
            response.close()
            next_url = normalize_url(location)
            if next_url is None:
                raise PageReadError("The site redirected to an address that isn't a web page.")
            current = next_url
            continue

        body = bytearray()
        cut_short = False
        try:
            for chunk in response.iter_content(chunk_size=65536):
                body.extend(chunk)
                if len(body) >= MAX_BYTES:
                    cut_short = True
                    del body[MAX_BYTES:]
                    break
                if time.monotonic() > deadline:
                    cut_short = True
                    break
        except requests.RequestException as e:
            if not body:
                raise PageReadError(f"The download failed ({type(e).__name__}).")
            cut_short = True
        finally:
            response.close()

        return {
            "final_url": current,
            "status_code": response.status_code,
            "content_type": (response.headers.get("Content-Type") or "").split(";")[0].strip().lower(),
            "charset": _charset_from_header(response.headers.get("Content-Type") or ""),
            "body": bytes(body),
            "cut_short": cut_short,
        }
    raise PageReadError(f"Too many redirects (more than {MAX_REDIRECTS}).")


def _charset_from_header(content_type: str) -> str | None:
    match = re.search(r"charset=([\w.:-]+)", content_type, re.I)
    return match.group(1).strip("\"'") if match else None


# --------------------------------------------------------------------------
# Turning the body into text
# --------------------------------------------------------------------------

_SKIP_TAGS = {"script", "style", "noscript", "template", "svg", "iframe", "object"}
_BLOCK_TAGS = {
    "p", "div", "br", "li", "ul", "ol", "tr", "td", "th", "table", "section", "article",
    "header", "footer", "nav", "aside", "main", "h1", "h2", "h3", "h4", "h5", "h6",
    "blockquote", "pre", "dd", "dt", "dl", "form", "hr", "address", "figcaption", "title",
}


class _HTMLExtractor(HTMLParser):
    """Collects visible text, title, meta tags, links, script sources and HTML comments."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.parts: list[str] = []
        self.title_parts: list[str] = []
        self.meta: dict[str, str] = {}
        self.links: list[dict] = []
        self._link_index: dict[str, int] = {}
        self.scripts: list[str] = []
        self.inline_scripts = 0
        self.comments: list[str] = []
        self._skip_depth = 0
        self._in_title = False
        self._open_link: int | None = None

    def handle_starttag(self, tag, attrs):
        attrs = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and attrs.get("href"):
            self.base_url = urljoin(self.base_url, attrs["href"])
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            key = (attrs.get("name") or attrs.get("property") or attrs.get("http-equiv") or "").strip().lower()
            if key and attrs.get("content") and len(self.meta) < MAX_META and key not in self.meta:
                self.meta[key] = attrs["content"].strip()[:300]
        elif tag == "script":
            if attrs.get("src"):
                src = urljoin(self.base_url, attrs["src"].strip())
                if src not in self.scripts and len(self.scripts) < MAX_SCRIPTS:
                    self.scripts.append(src)
            else:
                self.inline_scripts += 1
        elif tag == "a" and attrs.get("href"):
            href = attrs["href"].strip()
            if not href.lower().startswith(("javascript:", "#")):
                absolute = urljoin(self.base_url, href)
                if absolute not in self._link_index:
                    self._link_index[absolute] = len(self.links)
                    self.links.append({"url": absolute, "text": ""})
                self._open_link = self._link_index[absolute]

        if tag in _SKIP_TAGS:
            self._skip_depth += 1
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "a":
            self._open_link = None
        if tag in _SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        if self._in_title:
            self.title_parts.append(data)
            return
        if self._skip_depth:
            return
        self.parts.append(data)
        if self._open_link is not None:
            link = self.links[self._open_link]
            if len(link["text"]) < 120:
                link["text"] = (link["text"] + " " + data).strip()[:120]

    def handle_comment(self, data):
        comment = " ".join(data.split())
        if comment and len(self.comments) < MAX_COMMENTS:
            self.comments.append(comment[:300])


def _tidy_text(text: str) -> str:
    lines = [" ".join(line.split()) for line in text.splitlines()]
    out, blank = [], False
    for line in lines:
        if line:
            out.append(line)
            blank = False
        elif not blank and out:
            out.append("")
            blank = True
    return "\n".join(out).strip()


def _decode(body: bytes, charset: str | None) -> str:
    if not charset:
        match = re.search(rb"<meta[^>]+charset=[\"']?([\w.:-]+)", body[:4096], re.I)
        charset = match.group(1).decode("ascii", "ignore") if match else "utf-8"
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _looks_like_pdf(content_type: str, body: bytes) -> bool:
    return content_type == "application/pdf" or body[:5] == b"%PDF-"


def _looks_like_html(content_type: str, body: bytes) -> bool:
    if content_type in ("text/html", "application/xhtml+xml"):
        return True
    head = body[:1024].lstrip().lower()
    return head.startswith((b"<!doctype html", b"<html")) or b"<html" in head


def extract(page: dict) -> dict:
    """Turn a fetched page into {kind, title, text, meta, links, scripts, comments, pdf_pages}."""
    body, content_type = page["body"], page["content_type"]

    if _looks_like_pdf(content_type, body):
        if page.get("cut_short"):
            raise PageReadError(f"The PDF is larger than {MAX_BYTES // (1024 * 1024)} MB, so it wasn't read.")
        return _extract_pdf(body)

    if _looks_like_html(content_type, body):
        parser = _HTMLExtractor(page["final_url"])
        parser.feed(_decode(body, page.get("charset")))
        parser.close()
        return {
            "kind": "html",
            "title": " ".join("".join(parser.title_parts).split()) or None,
            "text": _tidy_text("".join(parser.parts)),
            "meta": parser.meta,
            "links": parser.links,
            "scripts": parser.scripts,
            "inline_scripts": parser.inline_scripts,
            "comments": parser.comments,
        }

    if content_type.startswith("text/") or content_type.endswith(("json", "xml", "javascript")) or not content_type:
        return {"kind": "text", "title": None, "text": _decode(body, page.get("charset")).strip()}

    raise PageReadError(f"This is a {content_type} file, which the page reader can't turn into text.")


def _extract_pdf(body: bytes) -> dict:
    try:
        from pypdf import PdfReader
    except ImportError:
        raise PageReadError("This is a PDF, and PDF reading isn't installed here (needs the pypdf package).")
    try:
        reader = PdfReader(io.BytesIO(body))
        if reader.is_encrypted:
            try:
                reader.decrypt("")
            except Exception:
                raise PageReadError("This PDF is password-protected.")
        texts = []
        for number, pdf_page in enumerate(reader.pages, start=1):
            page_text = (pdf_page.extract_text() or "").strip()
            if page_text:
                texts.append(f"[page {number}]\n{page_text}")
        info = reader.metadata or {}
        meta = {}
        for key in ("/Title", "/Author", "/Creator", "/Producer", "/CreationDate", "/ModDate", "/Subject"):
            value = info.get(key)
            if value:
                meta[key.strip("/").lower()] = str(value)[:300]
        text = _tidy_text("\n\n".join(texts))
        return {
            "kind": "pdf",
            "title": meta.get("title"),
            "text": text,
            "meta": meta,
            "pdf_pages": len(reader.pages),
            "note": None if text else "The PDF has no text layer (probably scanned images); nothing to read.",
        }
    except PageReadError:
        raise
    except Exception as e:
        raise PageReadError(f"The PDF couldn't be read ({type(e).__name__}).")


# --------------------------------------------------------------------------
# Shaping the result for the agent
# --------------------------------------------------------------------------

def _empty_result(url) -> dict:
    return {
        "url": url,
        "final_url": None,
        "source": None,          # "live" or "wayback"
        "archived_at": None,     # when the Wayback copy was captured
        "archive_url": None,
        "status_code": None,
        "content_type": None,
        "kind": None,            # "html", "pdf" or "text"
        "title": None,
        "text": "",
        "start": 0,
        "total_chars": 0,
        "more_text": False,
        "error": None,
    }


def _fill(result: dict, page: dict, content: dict, start: int, max_chars: int, max_links: int) -> dict:
    text = content.get("text") or ""
    result.update({
        "final_url": page["final_url"],
        "status_code": page["status_code"],
        "content_type": page["content_type"] or None,
        "kind": content["kind"],
        "title": content.get("title"),
        "text": text[start:start + max_chars],
        "start": start,
        "total_chars": len(text),
        "more_text": start + max_chars < len(text),
    })
    for key in ("meta", "scripts", "inline_scripts", "comments", "pdf_pages", "note"):
        if content.get(key) not in (None, [], {}):
            result[key] = content[key]
    if content.get("links"):
        result["links"] = content["links"][:max_links]
        result["total_links"] = len(content["links"])
    if page.get("cut_short"):
        result["note"] = "The page was very large or slow, so only the first part was downloaded."
    return result


def _unwrap_wayback_url(final_url: str) -> str:
    """The id_ replay URL -> the original URL that was archived."""
    match = re.search(r"/web/\d{4,14}(?:[a-z]{2}_)?/(.+)$", final_url, re.I)
    return match.group(1) if match else final_url


class PageReaderAgent:
    """Read a page live, with the Wayback Machine as a fallback."""

    def __init__(self, session=None):
        self.session = session

    @property
    def name(self) -> str:
        return "page_reader"

    def read_live(self, url, start=0, max_chars=DEFAULT_MAX_CHARS, max_links=DEFAULT_MAX_LINKS,
                  fallback_to_archive=True, **kwargs) -> dict:
        """One GET of the URL. If that fails and fallback_to_archive, read the newest Wayback copy. Never raises."""
        cleaned = normalize_url(url)
        result = _empty_result(cleaned or url)
        if cleaned is None:
            result["error"] = "That doesn't look like a web address (http or https)."
            return result
        start = _clamp(start, 0, 0, 10_000_000)
        max_chars = _clamp(max_chars, DEFAULT_MAX_CHARS, 200, MAX_CHARS_CAP)
        max_links = _clamp(max_links, DEFAULT_MAX_LINKS, 0, MAX_LINKS_CAP)

        print(f"[{self.name}] live read: {urlsplit(cleaned).hostname}", file=sys.stderr)
        live_error = None
        try:
            page = fetch(cleaned, self.session)
            if page["status_code"] >= 400:
                live_error = f"The site returned HTTP {page['status_code']}."
            else:
                # The visit worked; a file we can't read isn't a reason to try the archive.
                result["source"] = "live"
                try:
                    content = extract(page)
                except PageReadError as e:
                    result.update(final_url=page["final_url"], status_code=page["status_code"],
                                  content_type=page["content_type"] or None, error=str(e))
                    return result
                return _fill(result, page, content, start, max_chars, max_links)
        except PageReadError as e:
            live_error = str(e)
            if "private network" in live_error or "isn't a web page" in live_error:
                result["error"] = live_error
                return result

        if not fallback_to_archive:
            result["error"] = live_error
            return result
        archived = self.read_archived(cleaned, timestamp=None, start=start, max_chars=max_chars,
                                      max_links=max_links)
        archived["url"] = cleaned
        archived["live_error"] = live_error
        if archived["error"]:
            archived["error"] = f"Live visit failed ({live_error}) and no archived copy could be read: {archived['error']}"
        return archived

    def read_archived(self, url, timestamp=None, start=0, max_chars=DEFAULT_MAX_CHARS,
                      max_links=DEFAULT_MAX_LINKS, **kwargs) -> dict:
        """Read the Wayback copy closest to timestamp (newest if none). Only archive.org is contacted. Never raises."""
        cleaned = normalize_url(url)
        result = _empty_result(cleaned or url)
        if cleaned is None:
            result["error"] = "That doesn't look like a web address (http or https)."
            return result
        start = _clamp(start, 0, 0, 10_000_000)
        max_chars = _clamp(max_chars, DEFAULT_MAX_CHARS, 200, MAX_CHARS_CAP)
        max_links = _clamp(max_links, DEFAULT_MAX_LINKS, 0, MAX_LINKS_CAP)
        try:
            ts = parse_date(timestamp) or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        except PageReadError as e:
            result["error"] = str(e)
            return result

        # "id_" asks for the page exactly as archived, without the Wayback toolbar
        # or rewritten links. Wayback redirects to the closest capture it has.
        replay = f"https://{WAYBACK_HOST}/web/{ts}id_/{cleaned}"
        print(f"[{self.name}] archived read: {urlsplit(cleaned).hostname} near {ts[:8]}", file=sys.stderr)
        try:
            page = fetch(replay, self.session)
        except PageReadError as e:
            result["error"] = f"Wayback Machine: {e}"
            return result

        if urlsplit(page["final_url"]).hostname != WAYBACK_HOST:
            result["error"] = "The Wayback Machine redirected outside the archive; not followed."
            return result
        if page["status_code"] == 404:
            result["error"] = ("The Wayback Machine has no readable copy (HTTP 404): either the URL was never "
                               "archived, or the archived copy was itself a 'not found' page. "
                               "wayback_snapshots lists what exists.")
            return result
        if page["status_code"] == 429:
            result["error"] = "The Wayback Machine is rate-limiting requests (HTTP 429). Wait a minute and try again."
            return result
        if page["status_code"] >= 400:
            result["error"] = f"The Wayback Machine returned HTTP {page['status_code']}."
            return result

        captured = _WAYBACK_TS_RE.search(page["final_url"])
        captured_ts = captured.group(1) if captured else None
        try:
            content = extract(page)
        except PageReadError as e:
            result["error"] = str(e)
            return result
        _fill(result, page, content, start, max_chars, max_links)
        result["source"] = "wayback"
        result["archive_url"] = (f"https://{WAYBACK_HOST}/web/{captured_ts}/{_unwrap_wayback_url(page['final_url'])}"
                                 if captured_ts else page["final_url"])
        result["final_url"] = _unwrap_wayback_url(page["final_url"])
        result["archived_at"] = iso_from_timestamp(captured_ts)
        return result


class WaybackSnapshotsAgent:
    """List archived captures from the Wayback CDX API. Only archive.org is contacted."""

    def __init__(self, timeout: int = 30, session=None):
        self.timeout = timeout
        self.session = session

    @property
    def name(self) -> str:
        return "wayback_snapshots"

    def run(self, url, match_type="exact", from_date=None, to_date=None, limit=DEFAULT_SNAPSHOT_LIMIT,
            newest_first=False, only_ok=False, **kwargs) -> dict:
        """
        exact: every distinct capture of this one URL (identical consecutive captures merged).
        prefix / host / domain: each distinct URL archived under that path, host, or domain
        (domain includes subdomains), with its first matching capture. Never raises.
        """
        result = {"url": url, "match_type": match_type, "snapshots": [], "count": 0,
                  "maybe_more": False, "error": None}
        cleaned = url.strip() if isinstance(url, str) else ""
        cleaned = re.sub(r"^https?://", "", cleaned, flags=re.I)
        if not cleaned or len(cleaned) > 2048 or any(c.isspace() for c in cleaned) or "." not in cleaned.split("/")[0]:
            result["error"] = "Give a URL or domain, e.g. example.com or example.com/about."
            return result
        if match_type not in MATCH_TYPES:
            result["error"] = f"match_type must be one of: {', '.join(MATCH_TYPES)}."
            return result
        if match_type in ("host", "domain"):
            cleaned = cleaned.split("/")[0]
        result["url"] = cleaned
        limit = _clamp(limit, DEFAULT_SNAPSHOT_LIMIT, 1, SNAPSHOT_LIMIT_CAP)
        try:
            date_from = parse_date(from_date)
            date_to = parse_date(to_date)
        except PageReadError as e:
            result["error"] = str(e)
            return result

        params = [
            ("url", cleaned),
            ("matchType", match_type),
            ("output", "json"),
            ("fl", "timestamp,original,statuscode,mimetype,length"),
            ("collapse", "digest" if match_type == "exact" else "urlkey"),
            # Ask for one extra row so we can tell the agent there's more.
            ("limit", str(-(limit + 1) if newest_first else limit + 1)),
        ]
        if date_from:
            params.append(("from", date_from))
        if date_to:
            params.append(("to", date_to))
        if only_ok:
            params.append(("filter", "statuscode:200"))

        print(f"[{self.name}] CDX {match_type} lookup", file=sys.stderr)
        http = self.session or requests
        try:
            response = http.get(CDX_URL, params=params, headers={"User-Agent": USER_AGENT},
                                timeout=self.timeout)
        except requests.Timeout:
            result["error"] = "The Wayback Machine did not respond in time. Try a narrower search (dates or exact URL)."
            return result
        except requests.RequestException as e:
            result["error"] = f"Could not reach the Wayback Machine ({type(e).__name__})."
            return result

        if response.status_code == 429:
            result["error"] = "The Wayback Machine is rate-limiting requests (HTTP 429). Wait a minute and try again."
            return result
        if response.status_code in (502, 503, 504):
            result["error"] = (f"The Wayback Machine returned HTTP {response.status_code}. Big sites often time out "
                               "with host or domain searches; try a date range, or prefix on one path.")
            return result
        if response.status_code != 200:
            result["error"] = f"The Wayback Machine returned HTTP {response.status_code}."
            return result
        if not response.text.strip():
            return result  # no captures
        try:
            rows = response.json()
        except ValueError:
            result["error"] = "The Wayback Machine returned a response that isn't JSON."
            return result
        if not isinstance(rows, list):
            result["error"] = "The Wayback Machine returned an unexpected response."
            return result

        if rows and rows[0] == ["timestamp", "original", "statuscode", "mimetype", "length"]:
            rows = rows[1:]
        rows = [r for r in rows if isinstance(r, list) and len(r) >= 5]
        if newest_first:
            rows.reverse()
        result["maybe_more"] = len(rows) > limit
        rows = rows[:limit]
        result["snapshots"] = [
            {
                "timestamp": ts,
                "archived_at": iso_from_timestamp(ts),
                "url": original,
                "status": None if status in ("-", "") else status,
                "mimetype": mimetype,
                "archive_url": f"https://{WAYBACK_HOST}/web/{ts}/{original}",
            }
            for ts, original, status, mimetype, _length in (r[:5] for r in rows)
        ]
        result["count"] = len(result["snapshots"])
        return result
