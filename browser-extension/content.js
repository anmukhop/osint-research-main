// Content script: detects search-box form submissions on any page
// and forwards them to the background service worker.

(function () {
  "use strict";

  // Avoid double-injecting
  if (window.__osintContextInjected) return;
  window.__osintContextInjected = true;

  function getTopHeading() {
    return document.querySelector("h1")?.innerText?.trim() || "";
  }

  function getSearchQuery(form) {
    // Look for common search input names/types
    const candidates = form.querySelectorAll(
      'input[type="search"], input[name="q"], input[name="query"],' +
      ' input[name="search"], input[name="s"], input[name="text"],' +
      ' input[name="keyword"], input[name="term"], input[name="wd"]'
    );
    for (const el of candidates) {
      if (el.value?.trim()) return el.value.trim();
    }
    // Fallback: any text input that looks like it has content
    const texts = form.querySelectorAll('input[type="text"]');
    for (const el of texts) {
      if (el.value?.trim().length > 2) return el.value.trim();
    }
    return "";
  }

  function isLikelySearchForm(form) {
    const action = (form.action || "").toLowerCase();
    const id = (form.id || "").toLowerCase();
    const cls = (form.className || "").toLowerCase();
    const keywords = ["search", "find", "query", "lookup"];
    return keywords.some(k => action.includes(k) || id.includes(k) || cls.includes(k));
  }

  document.addEventListener("submit", (e) => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;

    const query = getSearchQuery(form);
    if (!query) return;

    // Only forward if the form seems to be a search form or has a query value
    // (broad check — let background decide relevance)
    const hostname = location.hostname;
    const page_title = document.title;
    const top_heading = getTopHeading();

    // Construct the URL the form will submit to
    let submitUrl = location.href;
    try {
      const base = new URL(form.action || location.href, location.href);
      const params = new URLSearchParams(new FormData(form));
      base.search = params.toString();
      submitUrl = base.toString();
    } catch {
      // fall back to current URL
    }

    chrome.runtime.sendMessage({
      type: "SEARCH_BOX_SUBMIT",
      url: submitUrl,
      site_name: hostname,
      page_title,
      top_heading,
      search_query: query,
    });
  }, true); // capture phase catches forms before they navigate away
})();
