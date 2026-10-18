"use strict";

// ---------------------------------------------------------------------------
// Elements
// ---------------------------------------------------------------------------
const statusDot = document.getElementById("statusDot");
const authUser = document.getElementById("authUser");
const authTeam = document.getElementById("authTeam");
const captureStatus = document.getElementById("captureStatus");
const authCard = document.getElementById("authCard");
const notLoggedIn = document.getElementById("notLoggedIn");
const appLink = document.getElementById("appLink");
const controls = document.getElementById("controls");
const eventsCount = document.getElementById("eventsCount");
const feed = document.getElementById("feed");
const emptyState = document.getElementById("emptyState");
const refreshBtn = document.getElementById("refreshBtn");
const clearBtn = document.getElementById("clearBtn");
const remoteBtn = document.getElementById("remoteBtn");
const appUrlInput = document.getElementById("appUrlInput");
const saveUrlBtn = document.getElementById("saveUrlBtn");

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let currentEvents = [];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function msg(type, payload = {}) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type, ...payload }, (resp) => {
      if (chrome.runtime.lastError) {
        console.warn(`[OSINT] ${type} message failed:`, chrome.runtime.lastError.message);
        resolve({});
        return;
      }
      resolve(resp || {});
    });
  });
}

function timeSince(iso) {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function escapeHtml(s) {
  if (!s) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function shortUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname + (u.pathname !== "/" ? u.pathname : "");
  } catch {
    return url;
  }
}

// ---------------------------------------------------------------------------
// Render status
// ---------------------------------------------------------------------------

function renderStatus(status) {
  if (!status || !status.authenticated) {
    statusDot.className = "header-dot off";
    authCard.style.display = "none";
    notLoggedIn.style.display = "block";
    controls.style.display = "none";
    return;
  }

  notLoggedIn.style.display = "none";
  authCard.style.display = "flex";
  controls.style.display = "flex";

  authUser.textContent = status.username || "—";
  authTeam.textContent = status.team_name || "No team";

  if (status.context_aware_enabled) {
    captureStatus.textContent = "ON";
    captureStatus.className = "value on";
    statusDot.className = "header-dot active";
  } else {
    captureStatus.textContent = "OFF — toggle on the web app";
    captureStatus.className = "value off";
    statusDot.className = "header-dot inactive";
  }
}

// ---------------------------------------------------------------------------
// Render events
// ---------------------------------------------------------------------------

function renderEvents(events) {
  currentEvents = events;
  eventsCount.textContent = `${events.length} event${events.length !== 1 ? "s" : ""}`;

  if (!events.length) {
    emptyState.style.display = "block";
    // Clear any existing cards
    feed.querySelectorAll(".event-card").forEach(el => el.remove());
    return;
  }

  emptyState.style.display = "none";
  feed.querySelectorAll(".event-card").forEach(el => el.remove());

  events.forEach(ev => {
    const card = document.createElement("div");
    card.className = "event-card";

    const timestamp = ev.recorded_at || ev.created_at || "";
    const timeLabel = timestamp ? timeSince(timestamp) : "";
    const typeClass = ev.event_type === "search" ? "search" : "visit";
    const typeLabel = ev.event_type === "search" ? "search" : "visit";

    const headingLine = ev.top_heading
      ? `<div class="event-heading">${escapeHtml(ev.top_heading)}</div>`
      : ev.page_title
        ? `<div class="event-heading">${escapeHtml(ev.page_title)}</div>`
        : "";

    const searchLine = ev.search_query
      ? `<div class="event-search">${escapeHtml(ev.search_query)}</div>`
      : "";

    card.innerHTML = `
      <div class="event-header">
        <span class="event-type-badge ${typeClass}">${typeLabel}</span>
        <span class="event-site">${escapeHtml(ev.site_name || shortUrl(ev.url))}</span>
        <span class="event-time">${escapeHtml(timeLabel)}</span>
      </div>
      <div class="event-body">
        ${headingLine}
        ${searchLine}
        <div class="event-url">${escapeHtml(shortUrl(ev.url))}</div>
      </div>
    `;

    feed.appendChild(card);
  });
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

async function init() {
  // Load saved app URL into settings input
  const stored = await chrome.storage.sync.get({ appUrl: "https://osint-research-production.up.railway.app/" });
  appUrlInput.value = stored.appUrl;
  appLink.href = stored.appUrl;
  appLink.textContent = stored.appUrl;

  // Refresh status from background
  const { status = null } = await msg("GET_STATUS");
  renderStatus(status);

  // Load local events
  const { events = [] } = await msg("GET_EVENTS");
  renderEvents(events);
}

// ---------------------------------------------------------------------------
// Button wiring
// ---------------------------------------------------------------------------

refreshBtn.addEventListener("click", async () => {
  refreshBtn.style.opacity = "0.5";
  try {
    const { status = null } = await msg("GET_STATUS");
    renderStatus(status);
    const { events = [] } = await msg("GET_EVENTS");
    renderEvents(events);
  } finally {
    refreshBtn.style.opacity = "";
  }
});

clearBtn.addEventListener("click", async () => {
  await msg("CLEAR_EVENTS");
  renderEvents([]);
});

remoteBtn.addEventListener("click", async () => {
  remoteBtn.textContent = "Loading…";
  remoteBtn.disabled = true;
  try {
    const { events = [] } = await msg("FETCH_REMOTE_EVENTS");
    // Merge with local, deduplicate by id if available
    const seen = new Set(currentEvents.map(e => e.id).filter(Boolean));
    const merged = [...currentEvents];
    for (const e of events) {
      if (!e.id || !seen.has(e.id)) {
        merged.push(e);
        if (e.id) seen.add(e.id);
      }
    }
    merged.sort((a, b) => {
      const ta = new Date(a.recorded_at || a.created_at || 0).getTime();
      const tb = new Date(b.recorded_at || b.created_at || 0).getTime();
      return tb - ta;
    });
    renderEvents(merged);
  } finally {
    remoteBtn.textContent = "Load from server";
    remoteBtn.disabled = false;
  }
});

saveUrlBtn.addEventListener("click", async () => {
  const url = appUrlInput.value.trim().replace(/\/$/, "");
  if (!url) return;
  await msg("SET_APP_URL", { url });
  appLink.href = url;
  appLink.textContent = url;
  saveUrlBtn.textContent = "Saved!";
  setTimeout(() => (saveUrlBtn.textContent = "Save"), 1500);
  // Re-fetch status with new URL
  const { status = null } = await msg("GET_STATUS");
  renderStatus(status);
});

// ---------------------------------------------------------------------------
// Listen for live events pushed from background
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "NEW_EVENT") {
    const events = [msg.event, ...currentEvents];
    if (events.length > 200) events.splice(200);
    renderEvents(events);
  }
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
init();
