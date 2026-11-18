"""
SEC EDGAR agent for OSINT Research Platform

Two lookups in the SEC's public filing database:
- company_filings: a company's profile (industry, addresses, phone, former
  names) and its recent filings, by ticker, CIK or name.
- full_text_search: which filings mention a phrase (e.g. a vendor's name), with
  the filing companies. Good for "who lists X as a supplier or customer?".
Passive: only sec.gov is contacted. Free, no key.

CVA category: Third-Party Services (Physical Assets 2nd: business addresses).
Rate limit: at most 10 requests/second per user, and every request must send a
User-Agent naming who you are with a contact email (SEC "fair access" policy).
That User-Agent comes from SEC_USER_AGENT in .env, never from code.
Docs: https://www.sec.gov/search-filings/edgar-application-programming-interfaces
      https://www.sec.gov/about/developer-resources (fair access)
Full-text search (efts) is the backend of https://efts.sec.gov/LATEST/search-index
used by EDGAR's own full-text search page; it is not formally documented.
"""

import re
import threading
import time
from urllib.parse import quote

from .free_api_common import clamp_int, env, log, missing_env_error, request_json


TICKERS_URL = "https://www.sec.gov/files/company_tickers.json"
SUBMISSIONS_URL = "https://data.sec.gov/submissions/CIK{cik:010d}.json"
FTS_URL = "https://efts.sec.gov/LATEST/search-index"
ARCHIVE_URL = "https://www.sec.gov/Archives/edgar/data/{cik}/{accession}/{document}"
FTS_PAGE_URL = "https://www.sec.gov/edgar/search/#/q={query}"
PROVIDER = "SEC EDGAR"
ENV_UA = "SEC_USER_AGENT"
UA_HELP = "your name or lab plus a contact email, e.g. 'VT OSINT lab you@vt.edu'; SEC requires it"
MIN_INTERVAL = 0.15          # seconds between calls: stays under 10 requests/second
TICKER_CACHE_SECONDS = 24 * 3600
DEFAULT_MAX = 20
MAX_CAP = 100

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_lock = threading.Lock()
_state = {"last_call": 0.0, "tickers": None, "tickers_at": 0.0}


def clear_cache() -> None:
    with _lock:
        _state.update(last_call=0.0, tickers=None, tickers_at=0.0)


def _get(url, **kwargs):
    """One throttled GET with the SEC User-Agent. Returns (data, error, status)."""
    with _lock:
        wait = MIN_INTERVAL - (time.time() - _state["last_call"])
        if wait > 0:
            time.sleep(wait)
        _state["last_call"] = time.time()
    return request_json(
        "GET", url, PROVIDER, headers={"User-Agent": env(ENV_UA)}, timeout=20,
        status_messages={403: "SEC EDGAR refused the request (HTTP 403). SEC blocks requests "
                              "without a real contact in the User-Agent: check SEC_USER_AGENT "
                              "in .env, and slow down if many calls were made."},
        **kwargs,
    )


def _split_list(value) -> list[str]:
    if not isinstance(value, str):
        return []
    return [part.strip().upper() for part in re.split(r"[,\s]+", value) if part.strip()]


class SecEdgarAgent:
    """Company profiles, recent filings and full-text search from SEC EDGAR."""

    name = "sec_edgar"

    def _ticker_table(self):
        with _lock:
            fresh = _state["tickers"] and time.time() - _state["tickers_at"] < TICKER_CACHE_SECONDS
            if fresh:
                return _state["tickers"], None
        data, error, _ = _get(TICKERS_URL)
        if error:
            return None, error
        if not isinstance(data, dict):
            return None, "SEC EDGAR returned an unexpected company list."
        rows = [r for r in data.values() if isinstance(r, dict) and r.get("cik_str")]
        with _lock:
            _state.update(tickers=rows, tickers_at=time.time())
        return rows, None

    def _resolve(self, company: str):
        """Ticker, CIK or name -> (cik, candidates, error)."""
        digits = company.upper().removeprefix("CIK").strip()
        if digits.isdigit():
            return int(digits), [], None
        rows, error = self._ticker_table()
        if error:
            return None, [], error
        upper = company.upper()
        for row in rows:
            if str(row.get("ticker", "")).upper() == upper:
                return int(row["cik_str"]), [], None
        named = [r for r in rows if upper in str(r.get("title", "")).upper()]
        exact = [r for r in named if str(r.get("title", "")).upper().rstrip(".") in
                 (upper, upper + " INC", upper + ", INC", upper + " CORP")]
        if len(exact) == 1 or len(named) == 1:
            return int((exact or named)[0]["cik_str"]), [], None
        candidates = [{"name": r.get("title"), "ticker": r.get("ticker"), "cik": r.get("cik_str")}
                      for r in named[:10]]
        return None, candidates, None

    def company_filings(self, company: str, forms: str = "",
                        max_filings: int = DEFAULT_MAX, **kwargs) -> dict:
        """
        company: ticker (AAPL), CIK (320193) or name. forms: e.g. "10-K, 8-K".
        Returns: company profile fields, filings (newest first, with url), error.
        """
        company = company.strip() if isinstance(company, str) else ""
        result = {"query": company, "cik": None, "name": None, "filings": [],
                  "candidates": [], "error": None}
        problem = missing_env_error(PROVIDER, [ENV_UA], UA_HELP)
        if problem:
            result["error"] = problem
            return result
        if not company or len(company) > 150:
            result["error"] = "Give a company ticker, CIK or name."
            return result
        max_filings = clamp_int(max_filings, DEFAULT_MAX, 1, MAX_CAP)
        wanted_forms = set(_split_list(forms))

        log(self.name, f"company lookup: {company}")
        cik, candidates, error = self._resolve(company)
        if error:
            result["error"] = error
            return result
        if cik is None:
            result["candidates"] = candidates
            result["error"] = (
                "Several companies match; pick one and ask again by ticker or CIK."
                if candidates else
                "No listed company by that name. Only companies with a stock ticker are "
                "in the name list; try sec_filing_search with the name to find its CIK."
            )
            return result

        data, error, status = _get(SUBMISSIONS_URL.format(cik=cik), empty_statuses=(404,))
        if error:
            result["error"] = error
            return result
        if status == 404 or not isinstance(data, dict):
            result["error"] = f"SEC EDGAR has no filer with CIK {cik}."
            return result

        recent = (data.get("filings") or {}).get("recent") or {}
        columns = ["accessionNumber", "filingDate", "reportDate", "form",
                   "primaryDocument", "primaryDocDescription"]
        rows = zip(*[recent.get(c) or [] for c in columns])
        filings = []
        for accession, filed, period, form, document, description in rows:
            if wanted_forms and str(form).upper() not in wanted_forms:
                continue
            filings.append({
                "form": form, "filed": filed, "period": period or None,
                "description": description or None,
                "url": ARCHIVE_URL.format(cik=cik, accession=str(accession).replace("-", ""),
                                          document=document) if document else None,
            })
            if len(filings) >= max_filings:
                break

        addresses = {}
        for kind, addr in (data.get("addresses") or {}).items():
            if isinstance(addr, dict) and addr.get("street1"):
                parts = [addr.get("street1"), addr.get("street2"), addr.get("city"),
                         addr.get("stateOrCountryDescription") or addr.get("stateOrCountry"),
                         addr.get("zipCode")]
                addresses[kind] = ", ".join(p for p in parts if p)

        result.update({
            "cik": cik,
            "name": data.get("name"),
            "tickers": data.get("tickers") or [],
            "industry": data.get("sicDescription"),
            "entity_type": data.get("entityType"),
            "state_of_incorporation": data.get("stateOfIncorporation"),
            "phone": data.get("phone"),
            "addresses": addresses,
            "former_names": [f.get("name") for f in data.get("formerNames") or []
                             if isinstance(f, dict)][:10],
            "filings": filings,
        })
        log(self.name, f"{len(filings)} filings listed")
        return result

    def full_text_search(self, query: str, forms: str = "", start_date: str = "",
                         end_date: str = "", max_results: int = DEFAULT_MAX, **kwargs) -> dict:
        """
        Search the text of filings since 2001. Wrap a phrase in double quotes for
        an exact match. Returns: total, results (company, cik, form, filed, url), error.
        """
        query = query.strip() if isinstance(query, str) else ""
        result = {"query": query, "total": 0, "results": [], "search_page": None, "error": None}
        problem = missing_env_error(PROVIDER, [ENV_UA], UA_HELP)
        if problem:
            result["error"] = problem
            return result
        if not query or len(query) > 300:
            result["error"] = "Give words or a quoted phrase to search for."
            return result
        for label, value in (("start_date", start_date), ("end_date", end_date)):
            if value and not (isinstance(value, str) and _DATE_RE.match(value)):
                result["error"] = f"{label} must be YYYY-MM-DD."
                return result
        max_results = clamp_int(max_results, DEFAULT_MAX, 1, MAX_CAP)

        params = {"q": query}
        if _split_list(forms):
            params["forms"] = ",".join(_split_list(forms))
        if start_date or end_date:
            params.update(dateRange="custom", startdt=start_date or "2001-01-01",
                          enddt=end_date or time.strftime("%Y-%m-%d"))

        log(self.name, "full-text search")
        hits_seen, rows, page = 0, [], 0
        while len(rows) < max_results and page < 5:
            if page:
                params["from"] = page * 100
            data, error, _ = _get(FTS_URL, params=params)
            if error:
                result["error"] = error
                return result
            hits = (data.get("hits") if isinstance(data, dict) else None) or {}
            total = hits.get("total")
            result["total"] = total.get("value", 0) if isinstance(total, dict) else (total or 0)
            batch = hits.get("hits") or []
            for hit in batch:
                if isinstance(hit, dict):
                    rows.append(self._tidy_hit(hit))
            hits_seen += len(batch)
            page += 1
            if len(batch) < 100 or hits_seen >= result["total"]:
                break

        result["results"] = rows[:max_results]
        result["search_page"] = FTS_PAGE_URL.format(query=quote(query, safe=""))
        log(self.name, f"{result['total']} filings match")
        return result

    @staticmethod
    def _tidy_hit(hit: dict) -> dict:
        source = hit.get("_source") or {}
        ciks = source.get("ciks") or []
        names = source.get("display_names") or []
        accession, _, document = str(hit.get("_id", "")).partition(":")
        cik = int(ciks[0]) if ciks and str(ciks[0]).isdigit() else None
        url = None
        if cik and accession and document:
            url = ARCHIVE_URL.format(cik=cik, accession=accession.replace("-", ""), document=document)
        return {
            "company": names[0] if names else None,
            "other_companies": names[1:5],
            "cik": cik,
            "form": source.get("form") or source.get("file_type"),
            "filed": source.get("file_date"),
            "period": source.get("period_ending"),
            "locations": (source.get("biz_locations") or [])[:3],
            "url": url,
        }

