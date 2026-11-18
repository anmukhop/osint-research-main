"""
Reddit agent for OSINT Research Platform (live Reddit Data API)

Three read-only lookups on Reddit's official API:
- search: posts mentioning a company, product or phrase (site-wide or in one
  subreddit).
- post_comments: read a post and its comments.
- user_activity: an account's recent posts and comments.
Passive: only Reddit is contacted; nothing is posted, voted or messaged.

CVA category: Brand Monitoring (user_activity: Employee Public Information).
Account: Reddit account -> https://www.reddit.com/prefs/apps -> "create app",
type "script". Set REDDIT_CLIENT_ID (the string under the app name) and
REDDIT_CLIENT_SECRET in .env. Reddit asks for a descriptive User-Agent naming
your Reddit account: set REDDIT_USER_AGENT, e.g.
"python:vt-osint-research:v1.0 (by /u/<your account>)"; without it a generic one is sent.
Uses app-only OAuth (client credentials): no Reddit password is stored.
Limits: free tier is 100 queries per minute per OAuth client (Reddit Data API
wiki); the X-Ratelimit-Remaining header is reported back. Terms: Reddit Data
API Terms (Micah read them Nov 13, 2026: fine for this research use).
Docs: https://www.reddit.com/dev/api
"""

import re
import threading
import time
from datetime import datetime, timezone

from .free_api_common import clamp_int, env, log, missing_env_error, request_json


TOKEN_URL = "https://www.reddit.com/api/v1/access_token"
API_URL = "https://oauth.reddit.com"
PROVIDER = "Reddit"
ENV_NAMES = ["REDDIT_CLIENT_ID", "REDDIT_CLIENT_SECRET"]
ENV_HELP = "reddit.com/prefs/apps -> create app, type 'script'"
DEFAULT_USER_AGENT = "python:osint-research-platform:v1.0"
SORTS = ("relevance", "hot", "top", "new", "comments")
TIMES = ("hour", "day", "week", "month", "year", "all")
DEFAULT_MAX = 25
MAX_CAP = 100
MAX_COMMENTS_CAP = 200

_SUBREDDIT_RE = re.compile(r"^[A-Za-z0-9_]{2,21}$")
_USER_RE = re.compile(r"^[A-Za-z0-9_-]{3,20}$")
_POST_ID_RE = re.compile(r"(?:comments/|^t3_|^)([a-z0-9]{5,10})(?:/|$)", re.I)
_token = {"value": None, "expires": 0.0}
_lock = threading.Lock()


def clear_cache() -> None:
    with _lock:
        _token.update(value=None, expires=0.0)


def _utc(seconds) -> str | None:
    if not isinstance(seconds, (int, float)):
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _clean_name(value, prefix) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    text = re.sub(r"^(https?://)?(www\.|old\.)?reddit\.com/", "", text, flags=re.I)
    return re.sub(rf"^/?{prefix}/", "", text, flags=re.I).strip("/")


class RedditAgent:
    """Search Reddit posts, read a thread, or list an account's activity."""

    name = "reddit"

    def _user_agent(self) -> str:
        return env("REDDIT_USER_AGENT") or DEFAULT_USER_AGENT

    def _bearer(self, force_new=False):
        with _lock:
            if not force_new and _token["value"] and time.time() < _token["expires"]:
                return _token["value"], None
        data, error, _ = request_json(
            "POST", TOKEN_URL, PROVIDER, timeout=15,
            auth=(env("REDDIT_CLIENT_ID"), env("REDDIT_CLIENT_SECRET")),
            data={"grant_type": "client_credentials"},
            headers={"User-Agent": self._user_agent()},
            status_messages={401: "Reddit rejected the app login (HTTP 401). Check "
                                  "REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET in .env."},
        )
        if error:
            return None, error
        token = data.get("access_token") if isinstance(data, dict) else None
        if not token:
            reason = data.get("error") if isinstance(data, dict) else None
            return None, f"Reddit's login returned no token ({reason or 'no reason given'})."
        lifetime = clamp_int(data.get("expires_in"), 3600, 60, 86400)
        with _lock:
            _token.update(value=token, expires=time.time() + lifetime - 60)
        return token, None

    def _get(self, path, params):
        """GET an API path with the app token; retry once with a fresh token on 401."""
        problem = missing_env_error(PROVIDER, ENV_NAMES, ENV_HELP)
        if problem:
            return None, problem, None
        for attempt in (1, 2):
            token, error = self._bearer(force_new=attempt == 2)
            if error:
                return None, error, None
            data, error, status = request_json(
                "GET", f"{API_URL}{path}", PROVIDER, timeout=20,
                params={**params, "raw_json": 1},
                headers={"Authorization": f"bearer {token}", "User-Agent": self._user_agent()},
                empty_statuses=(404,),
                status_messages={401: "Reddit login expired.",
                                 403: "Reddit refused (HTTP 403): the subreddit or account is "
                                      "private, banned or suspended.",
                                 429: "Reddit rate limit reached (100 requests/minute). "
                                      "Wait a minute."},
            )
            if status != 401:
                return data, error, status
        return None, error, status

    # ------------------------------------------------------------------
    def search(self, query: str, subreddit: str = "", sort: str = "relevance",
               time_range: str = "all", max_results: int = DEFAULT_MAX, **kwargs) -> dict:
        query = query.strip() if isinstance(query, str) else ""
        subreddit = _clean_name(subreddit, "r")
        sort = sort if sort in SORTS else "relevance"
        time_range = time_range if time_range in TIMES else "all"
        result = {"query": query, "subreddit": subreddit or None, "sort": sort,
                  "time_range": time_range, "post_count": 0, "posts": [], "error": None}
        if not query or len(query) > 512:
            result["error"] = "Give words to search for (at most 512 characters)."
            return result
        if subreddit and not _SUBREDDIT_RE.match(subreddit):
            result["error"] = "subreddit must be a name like OSINT (no r/ needed)."
            return result
        limit = clamp_int(max_results, DEFAULT_MAX, 1, MAX_CAP)
        path = f"/r/{subreddit}/search" if subreddit else "/search"
        params = {"q": query, "sort": sort, "t": time_range, "limit": limit, "type": "link"}
        if subreddit:
            params["restrict_sr"] = "on"
        log(self.name, "post search")
        data, error, status = self._get(path, params)
        if error:
            result["error"] = error
            return result
        if status == 404:
            result["error"] = f"No subreddit r/{subreddit}."
            return result
        posts = [self._post(c.get("data") or {}) for c in self._children(data)
                 if c.get("kind") == "t3"]
        result["post_count"] = len(posts)
        result["posts"] = posts[:limit]
        return result

    def post_comments(self, post: str, max_comments: int = 50, **kwargs) -> dict:
        """post: a post URL, 'reddit.com/comments/<id>', 't3_<id>' or the bare id."""
        text = post.strip() if isinstance(post, str) else ""
        match = _POST_ID_RE.search(text)
        result = {"post": None, "comment_count": 0, "comments": [], "truncated": False,
                  "error": None}
        if not text or not match:
            result["error"] = "Give a Reddit post URL or post id (e.g. 1abc23d)."
            return result
        post_id = match.group(1).lower()
        limit = clamp_int(max_comments, 50, 1, MAX_COMMENTS_CAP)
        log(self.name, "read thread")
        data, error, status = self._get(f"/comments/{post_id}",
                                        {"limit": limit, "sort": "top", "depth": 5})
        if error:
            result["error"] = error
            return result
        if status == 404 or not isinstance(data, list) or len(data) < 2:
            result["error"] = f"No Reddit post with id {post_id}."
            return result
        posts = [c.get("data") or {} for c in self._children(data[0]) if c.get("kind") == "t3"]
        if posts:
            result["post"] = self._post(posts[0], full_text=True)
        comments = []
        self._walk(self._children(data[1]), 0, comments)
        result["comment_count"] = len(comments)
        result["comments"] = comments[:limit]
        result["truncated"] = len(comments) > limit
        return result

    def user_activity(self, username: str, kind: str = "all",
                      max_results: int = DEFAULT_MAX, **kwargs) -> dict:
        """kind: all, posts or comments. Newest first."""
        username = _clean_name(username, "(u|user)").lstrip("@")
        kind = kind if kind in ("all", "posts", "comments") else "all"
        result = {"username": username, "account": None, "kind": kind,
                  "item_count": 0, "items": [], "error": None}
        if not _USER_RE.match(username):
            result["error"] = "Give a Reddit username (3-20 letters, digits, _ or -)."
            return result
        limit = clamp_int(max_results, DEFAULT_MAX, 1, MAX_CAP)
        log(self.name, "user activity")
        about, error, status = self._get(f"/user/{username}/about", {})
        if error:
            result["error"] = error
            return result
        if status == 404 or not isinstance(about, dict):
            result["error"] = f"No Reddit account u/{username} (or it was deleted)."
            return result
        info = about.get("data") or {}
        if info.get("is_suspended"):
            result["error"] = f"u/{username} is suspended."
            return result
        result["account"] = {
            "name": info.get("name"),
            "created": _utc(info.get("created_utc")),
            "post_karma": info.get("link_karma"),
            "comment_karma": info.get("comment_karma"),
        }
        path = {"all": "overview", "posts": "submitted", "comments": "comments"}[kind]
        data, error, _ = self._get(f"/user/{username}/{path}", {"limit": limit, "sort": "new"})
        if error:
            result["error"] = error
            return result
        items = []
        for child in self._children(data):
            body = child.get("data") or {}
            if child.get("kind") == "t3":
                items.append({"type": "post", **self._post(body)})
            elif child.get("kind") == "t1":
                items.append({"type": "comment", **self._comment(body)})
        result["item_count"] = len(items)
        result["items"] = items[:limit]
        return result

    # ------------------------------------------------------------------
    @staticmethod
    def _children(listing) -> list:
        if not isinstance(listing, dict):
            return []
        return [c for c in (listing.get("data") or {}).get("children") or [] if isinstance(c, dict)]

    @staticmethod
    def _post(d: dict, full_text: bool = False) -> dict:
        text = d.get("selftext") or ""
        return {
            "id": d.get("id"),
            "title": d.get("title"),
            "subreddit": d.get("subreddit"),
            "author": d.get("author"),
            "created": _utc(d.get("created_utc")),
            "score": d.get("score"),
            "comments": d.get("num_comments"),
            "url": f"https://www.reddit.com{d['permalink']}" if d.get("permalink") else None,
            "link": d.get("url") if not d.get("is_self") else None,
            "text": text if full_text else (text[:500] or None),
        }

    @staticmethod
    def _comment(d: dict) -> dict:
        return {
            "id": d.get("id"),
            "author": d.get("author"),
            "subreddit": d.get("subreddit"),
            "created": _utc(d.get("created_utc")),
            "score": d.get("score"),
            "text": (d.get("body") or "")[:1500],
            "url": f"https://www.reddit.com{d['permalink']}" if d.get("permalink") else None,
        }

    def _walk(self, children, depth, out) -> None:
        for child in children:
            if child.get("kind") != "t1":
                continue
            body = child.get("data") or {}
            out.append({"depth": depth, **self._comment(body)})
            replies = body.get("replies")
            if isinstance(replies, dict):
                self._walk(self._children(replies), depth + 1, out)
