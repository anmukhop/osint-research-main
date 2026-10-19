// Service worker: handles tab events, relays API calls for content scripts
// and sidepanel. All network requests go through here to avoid CORS issues.

const DEFAULT_APP_URL = "http://localhost:8000";

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

async function getAppUrl() {
  const result = await chrome.storage.sync.get({ appUrl: DEFAULT_APP_URL });
  return result.appUrl.replace(/\/$/, "");
}

async function getEvents() {
  const result = await chrome.storage.local.get({ events: [] });
  return result.events;
}

async function saveEvent(event) {
  const events = await getEvents();
  events.unshift(event);
  if (events.length > 200) events.splice(200);
  await chrome.storage.local.set({ events });
}

async function clearEvents() {
  await chrome.storage.local.set({ events: [] });
}

// ---------------------------------------------------------------------------
// App-URL exclusion
// Note: We now capture searches on the OSINT app itself to include them in team summaries
// ---------------------------------------------------------------------------

async function isAppUrl(url) {
  try {
    const u = new URL(url);
    const base = await getAppUrl();
    const appHost = new URL(base).host;
    // Skip localhost / 127.0.0.1 (dev server) but allow capturing on configured app URL
    // This allows team summaries to include queries made within the OSINT app interface
    const skipHosts = new Set([
      "localhost:8000",
      "127.0.0.1:8000",
    ]);
    return skipHosts.has(u.host);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// API helpers
//
// IMPORTANT: The `Cookie` request header is a "forbidden header" in the
// Fetch/XHR spec — browsers silently drop it even inside extension service
// workers. We work around this by:
//   1. Reading the Django session cookie via chrome.cookies (allowed for
//      permitted origins in extensions).
//   2. Sending it in a custom `X-Session-Id` header that Django can read
//      and use to look up the session / user on the server side.
// ---------------------------------------------------------------------------

async function apiFetch(path, options = {}) {
  const base = await getAppUrl();
  const url = `${base}${path}`;

  const sessionCookie = await chrome.cookies.get({ url: base, name: "sessionid" });
  const csrfCookie   = await chrome.cookies.get({ url: base, name: "csrftoken" });

  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  // X-Session-Id is a custom header — not a forbidden header, so it IS sent.
  if (sessionCookie) headers["X-Session-Id"] = sessionCookie.value;
  if (csrfCookie)    headers["X-CSRFToken"]  = csrfCookie.value;

  try {
    const resp = await fetch(url, {
      ...options,
      headers,
      // Do NOT use credentials:"include" — it triggers CORS preflight and
      // SameSite=Lax cookie restrictions that block the session cookie anyway.
      // The X-Session-Id header is our authentication mechanism instead.
    });
    if (!resp.ok) {
      console.warn(`[OSINT] API ${path} returned ${resp.status}`);
      return null;
    }
    return await resp.json();
  } catch (err) {
    console.warn(`[OSINT] API ${path} failed:`, err);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Auth / status polling
// ---------------------------------------------------------------------------

let cachedStatus = null;
let lastStatusFetch = 0;

async function fetchStatus(force = false) {
  const now = Date.now();
  if (!force && cachedStatus && now - lastStatusFetch < 30_000) {
    return cachedStatus;
  }
  const data = await apiFetch("/api/extension/status/");
  if (data) {
    cachedStatus = data;
    lastStatusFetch = now;
    await chrome.storage.local.set({ status: data });
  }
  return cachedStatus;
}

// ---------------------------------------------------------------------------
// Send a browsing event to the web app (best-effort)
// ---------------------------------------------------------------------------

async function pushEvent(event) {
  const status = await fetchStatus();
  if (!status?.authenticated || !status?.context_aware_enabled) return;

  await apiFetch("/api/extension/events/", {
    method: "POST",
    body: JSON.stringify(event),
  });
}

// ---------------------------------------------------------------------------
// Extract search query from a URL
// ---------------------------------------------------------------------------

const SEARCH_PARAMS = ["q", "query", "search", "s", "p", "text", "keyword", "term", "wd"];

function extractSearchQuery(url) {
  try {
    const u = new URL(url);
    for (const param of SEARCH_PARAMS) {
      const val = u.searchParams.get(param);
      if (val && val.trim()) return val.trim();
    }
  } catch { /* not a valid URL */ }
  return "";
}

function isSearchUrl(url) {
  try {
    const u = new URL(url);
    const searchHosts = ["google.", "bing.", "duckduckgo.", "yahoo.", "search.yahoo.",
                         "yandex.", "baidu.", "ecosia.", "startpage.", "brave.com/search"];
    const isSearchHost  = searchHosts.some(h => u.hostname.includes(h));
    const hasSearchPath = /\/(search|find|results|query)/i.test(u.pathname);
    const hasSearchParam = SEARCH_PARAMS.some(p => u.searchParams.has(p));
    return (isSearchHost || hasSearchPath) && hasSearchParam;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Handle completed navigations
// ---------------------------------------------------------------------------

chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (details.url.startsWith("chrome") || details.url.startsWith("about:")) return;

  // Skip the OSINT app itself — it has its own team workspace view.
  if (await isAppUrl(details.url)) return;

  const tab = await chrome.tabs.get(details.tabId).catch(() => null);
  if (!tab) return;

  const searchQuery = extractSearchQuery(details.url);
  const eventType = (isSearchUrl(details.url) && searchQuery) ? "search" : "visit";

  let pageInfo = { page_title: tab.title || "", top_heading: "" };
  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: details.tabId },
      func: () => ({
        page_title: document.title,
        top_heading: document.querySelector("h1")?.innerText?.trim() || "",
      }),
    }).catch(() => []);
    if (result?.result) pageInfo = { ...pageInfo, ...result.result };
  } catch { /* scripting blocked on some pages */ }

  const hostname = (() => {
    try { return new URL(details.url).hostname; } catch { return details.url; }
  })();

  const event = {
    event_type: eventType,
    url: details.url,
    site_name: hostname,
    page_title: pageInfo.page_title,
    top_heading: pageInfo.top_heading,
    search_query: searchQuery,
    recorded_at: new Date().toISOString(),
  };

  await saveEvent(event);
  await pushEvent(event);

  chrome.runtime.sendMessage({ type: "NEW_EVENT", event }).catch(() => {});
});

// ---------------------------------------------------------------------------
// Listen for search-box submissions forwarded by content.js
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "SEARCH_BOX_SUBMIT") {
    (async () => {
      // Skip search-box events originating from the OSINT app itself.
      if (sender.url && await isAppUrl(sender.url)) {
        sendResponse({ ok: true, skipped: true });
        return;
      }

      const { url, site_name, page_title, top_heading, search_query } = msg;
      const event = {
        event_type: "search",
        url,
        site_name,
        page_title,
        top_heading,
        search_query,
        recorded_at: new Date().toISOString(),
      };
      await saveEvent(event);
      await pushEvent(event);
      chrome.runtime.sendMessage({ type: "NEW_EVENT", event }).catch(() => {});
      sendResponse({ ok: true });
    })().catch((err) => {
      console.warn("[OSINT] SEARCH_BOX_SUBMIT failed:", err);
      sendResponse({ ok: false, error: String(err) });
    });
    return true;
  }
});

// ---------------------------------------------------------------------------
// Messages from the side panel
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "GET_STATUS") {
    fetchStatus(true)
      .then(status => sendResponse({ status }))
      .catch((err) => {
        console.warn("[OSINT] GET_STATUS failed:", err);
        sendResponse({ status: null, error: String(err) });
      });
    return true;
  }
  if (msg.type === "GET_EVENTS") {
    getEvents().then(events => sendResponse({ events }));
    return true;
  }
  if (msg.type === "CLEAR_EVENTS") {
    clearEvents().then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg.type === "FETCH_REMOTE_EVENTS") {
    apiFetch("/api/extension/events/recent/")
      .then(data => sendResponse({ events: data?.events || [] }));
    return true;
  }
  if (msg.type === "SET_APP_URL") {
    chrome.storage.sync.set({ appUrl: msg.url }).then(() => {
      cachedStatus = null;
      lastStatusFetch = 0;
      sendResponse({ ok: true });
    });
    return true;
  }
});

// ---------------------------------------------------------------------------
// Open the side panel when the action button is clicked
// ---------------------------------------------------------------------------

chrome.action.onClicked.addListener(async (tab) => {
  await chrome.sidePanel.open({ tabId: tab.id });
});

// Initial status fetch on startup
fetchStatus(true);
