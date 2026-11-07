// honeynet dashboard shell: login, hash router, range filter, theme, live-stream status.
import { h, svg, mount, api, AuthError, safeText, toast, ago } from "./js/util.js";
import { startLive, stopLive, onState, isPaused, setPaused, lastEventAt } from "./js/live.js";
import { overview } from "./js/views/overview.js";
import { sessions, session, ipProfile } from "./js/views/sessions.js";
import { samples, sample } from "./js/views/samples.js";
import { attack, iocs, alerts, system } from "./js/views/misc.js";

const app = document.getElementById("app");
const RANGES = [[1, "1h"], [6, "6h"], [24, "24h"], [168, "7d"], [720, "30d"]];
const NAV = [["#/", "Overview", /^#\/?$/, "overview"], ["#/sessions", "Sessions", /^#\/(sessions|session\/|ip\/)/, "sessions"], ["#/samples", "Samples", /^#\/sample/, "samples"],
  ["#/attack", "ATT&CK", /^#\/attack/, "attack"], ["#/iocs", "Indicators", /^#\/iocs/, "iocs"], ["#/alerts", "Alerts", /^#\/alerts/, "alerts"], ["#/system", "System", /^#\/system/, "system"]];
const ROUTES = [
  [/^#\/?$/, overview, true], [/^#\/sessions$/, sessions], [/^#\/session\/([A-Za-z0-9_-]{1,40})$/, session], [/^#\/ip\/([^/]+)$/, ipProfile],
  [/^#\/samples$/, samples], [/^#\/sample\/([0-9a-f]{64})$/, sample], [/^#\/attack$/, attack, true], [/^#\/iocs$/, iocs], [/^#\/alerts$/, alerts], [/^#\/system$/, system],
];
const ICONS = {
  overview: [["rect", { x: 3, y: 3, width: 7, height: 9, rx: 1.5 }], ["rect", { x: 14, y: 3, width: 7, height: 5, rx: 1.5 }], ["rect", { x: 14, y: 12, width: 7, height: 9, rx: 1.5 }], ["rect", { x: 3, y: 16, width: 7, height: 5, rx: 1.5 }]],
  sessions: [["polyline", { points: "4 17 10 11 4 5" }], ["line", { x1: 12, y1: 19, x2: 20, y2: 19 }]],
  samples: [["path", { d: "M21 8 12 3 3 8v8l9 5 9-5z" }], ["path", { d: "m3 8 9 5 9-5M12 13v8" }]],
  attack: [["circle", { cx: 12, cy: 12, r: 9 }], ["circle", { cx: 12, cy: 12, r: 5 }], ["circle", { cx: 12, cy: 12, r: 1 }]],
  iocs: [["path", { d: "M12 3 4 6v6c0 4.5 3.3 8 8 9 4.7-1 8-4.5 8-9V6z" }], ["path", { d: "M12 8v5M12 16h.01" }]],
  alerts: [["path", { d: "M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" }], ["path", { d: "M10.3 21a1.9 1.9 0 0 0 3.4 0" }]],
  system: [["rect", { x: 3, y: 4, width: 18, height: 7, rx: 2 }], ["rect", { x: 3, y: 13, width: 18, height: 7, rx: 2 }], ["path", { d: "M7 7.5h.01M7 16.5h.01" }]],
  theme: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M12 3a9 9 0 0 1 0 18z", fill: "currentColor" }]],
  logout: [["path", { d: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" }], ["polyline", { points: "16 17 21 12 16 7" }], ["line", { x1: 21, y1: 12, x2: 9, y2: 12 }]],
  pause: [["rect", { x: 6, y: 4, width: 4, height: 16, rx: 1 }], ["rect", { x: 14, y: 4, width: 4, height: 16, rx: 1 }]],
  play: [["polygon", { points: "6 4 20 12 6 20" }]],
};
function icon(name) {
  return svg("svg", { viewBox: "0 0 24 24", "aria-hidden": "true", focusable: "false" }, (ICONS[name] || []).map(([tag, attrs]) => svg(tag, attrs)));
}

let hours = Number(localStorage.getItem("hn.hours")) || 24;
if (!RANGES.some(([v]) => v === hours)) hours = 24;
let cleanups = [];
let token = 0;
let shell = null;
let authed = false;
let pollTimer = null;
let tickTimer = null;

// ---------------------------------------------------------------------------- theme: night watch (default), daylight, follow the system
const THEME_NAMES = { dark: "night", light: "daylight", auto: "follows the system" };
function currentTheme() { const t = localStorage.getItem("hn.theme"); return t === "light" || t === "auto" ? t : "dark"; }
function applyTheme() {
  const t = currentTheme();
  if (t === "dark") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = t;
  document.dispatchEvent(new CustomEvent("honeynet:theme"));
}
function cycleTheme() {
  const next = { dark: "light", light: "auto", auto: "dark" }[currentTheme()];
  if (next === "dark") localStorage.removeItem("hn.theme"); else localStorage.setItem("hn.theme", next);
  applyTheme();
  toast(`Theme: ${THEME_NAMES[next]}`);
}
applyTheme();

// ---------------------------------------------------------------------------- brand mark: a honeycomb cell with the bait inside
function logo() {
  return svg("svg", { viewBox: "0 0 32 32", "aria-hidden": "true", focusable: "false" },
    svg("path", { d: "M16 2.8 27.6 9.4v13.2L16 29.2 4.4 22.6V9.4z", fill: "none", stroke: "var(--accent)", "stroke-width": "2", "stroke-linejoin": "round" }),
    svg("path", { d: "M16 10.2l4.8 2.8v5.6L16 21.4l-4.8-2.8V13z", fill: "var(--accent)" }));
}

// ---------------------------------------------------------------------------- login
function showLogin(message = "") {
  stopLive();
  authed = false; shell = null;
  clearInterval(pollTimer); clearInterval(tickTimer);
  const err = h("div", { class: "err", role: "alert", text: message });
  const pw = h("input", { type: "password", autocomplete: "current-password", "aria-label": "Password", placeholder: "Password", required: true, autofocus: true });
  const form = h("form", { onsubmit: async (e) => {
    e.preventDefault();
    err.textContent = "";
    try {
      await api("/api/login", { method: "POST", json: { password: pw.value }, noAuthRedirect: true });
      pw.value = "";
      boot();
    } catch (x) { err.textContent = x.status === 429 ? "Too many attempts. Wait a minute and try again." : "That password is not right."; pw.select(); }
  } },
    h("div", { class: "brand" }, logo(), h("span", { text: "honeynet" })),
    h("div", { class: "muted", text: "Private dashboard. Sign in to see what has been hitting your honeypots." }), pw, err,
    h("button", { class: "primary", type: "submit", text: "Sign in" }));
  mount(app, h("div", { class: "login" }, form));
  pw.focus();
}
document.addEventListener("honeynet:auth", () => { if (authed) showLogin("Your session expired. Sign in again."); });

// ---------------------------------------------------------------------------- shell
function buildShell() {
  const nav = h("nav", { class: "nav", "aria-label": "Main" },
    NAV.map(([href, label, , ic]) => h("a", { href, "data-href": href, title: label }, icon(ic), h("span", { text: label }))));
  const alertsBadge = h("span", { class: "badge-count hidden", text: "0", title: "unacknowledged alerts" });
  nav.querySelector('[data-href="#/alerts"]').append(alertsBadge);

  const dot = h("i", { class: "dot" });
  const statusText = h("span");
  const status = h("span", { class: "status", role: "status", "aria-live": "off" }, dot, statusText);
  const range = h("div", { class: "seg", role: "group", "aria-label": "Time range" },
    RANGES.map(([v, l]) => h("button", { text: l, "aria-pressed": String(v === hours), "data-v": v, onclick: () => setHours(v) })));
  const pauseIcon = h("span", { class: "ico" }, icon("pause"));
  const pauseLabel = h("span", { text: "Pause live" });
  const pauseBtn = h("button", { class: "ghost pause", title: "Stop the feed and map from updating so you can read", "aria-pressed": "false", onclick: () => setPaused(!isPaused()) }, pauseIcon, pauseLabel);
  const main = h("main", { id: "main", tabindex: -1 });

  mount(app, h("div", { class: "shell" },
    h("button", { class: "skip", text: "Skip to content", onclick: () => main.focus() }),
    h("aside", { class: "rail" },
      h("a", { class: "brand", href: "#/", "aria-label": "honeynet overview" }, logo(), h("span", { text: "honeynet" })), nav,
      h("div", { class: "rail-foot" },
        h("button", { title: "Switch between night, daylight and system theme", onclick: cycleTheme }, icon("theme"), h("span", { text: "Theme" })),
        h("button", { title: "Sign out", onclick: async () => { try { await api("/api/logout", { method: "POST", json: {} }); } catch { /* ignore */ } location.hash = "#/"; showLogin(); } }, icon("logout"), h("span", { text: "Sign out" })))),
    h("div", { class: "content" },
      h("div", { class: "bar" }, status, h("span", { class: "spacer" }), range, pauseBtn),
      main)));

  let conn = "connecting";
  const paint = () => {
    const paused = isPaused();
    dot.className = "dot " + (conn === "off" ? "off" : paused ? "paused" : conn === "live" ? "live" : "");
    const last = lastEventAt();
    mount(statusText,
      conn === "off" ? "Offline. The live stream disconnected." :
      conn !== "live" ? "Reconnecting to the live stream…" :
      paused ? "Paused. The feed and map are frozen; new events still arrive." :
      last ? [h("b", { text: "Live" }), ` – last event ${ago(last / 1000)}`] : [h("b", { text: "Live" }), " – waiting for the first event"]);
    pauseLabel.textContent = paused ? "Resume live" : "Pause live";
    pauseBtn.setAttribute("aria-pressed", String(paused));
    mount(pauseIcon, icon(paused ? "play" : "pause"));
  };
  onState((s) => { conn = s; paint(); });
  document.addEventListener("honeynet:pause", paint);
  clearInterval(tickTimer); tickTimer = setInterval(paint, 1000);
  paint();

  document.addEventListener("honeynet:alerts", (e) => { alertsBadge.textContent = e.detail; alertsBadge.classList.toggle("hidden", !e.detail); });
  shell = { main, nav, range, alertsBadge };
  const poll = async () => {
    try { const hl = await api("/api/health"); alertsBadge.textContent = hl.alerts_unacked; alertsBadge.classList.toggle("hidden", !hl.alerts_unacked); } catch { /* shown elsewhere */ }
  };
  poll(); clearInterval(pollTimer); pollTimer = setInterval(poll, 30000);
}

function setHours(v) {
  hours = v; localStorage.setItem("hn.hours", String(v));
  shell.range.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(Number(b.dataset.v) === v)));
  route();
}

// ---------------------------------------------------------------------------- router
async function route() {
  if (!shell) return;
  const my = ++token;
  cleanups.forEach((f) => { try { f(); } catch { /* best effort */ } });
  cleanups = [];
  const hash = location.hash || "#/";
  shell.nav.querySelectorAll("a").forEach((a) => {
    const entry = NAV.find((n) => n[0] === a.dataset.href);
    if (entry && entry[2].test(hash)) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  let matched = null;
  for (const [re, view, usesRange] of ROUTES) { const m = re.exec(hash); if (m) { matched = { view, usesRange, params: m.slice(1) }; break; } }
  shell.range.classList.toggle("hidden", !(matched && matched.usesRange));
  const host = h("div");
  mount(shell.main, host);
  if (!matched) { mount(host, h("section", { class: "card" }, h("h1", { text: "Page not found" }), h("p", null, h("a", { href: "#/", text: "Go back to the overview" })))); return; }
  const ctx = { hours, params: matched.params, onCleanup: (f) => cleanups.push(f) };
  try {
    await matched.view(host, ctx);
    if (my === token) window.scrollTo({ top: 0 });
  } catch (e) {
    if (my !== token || e instanceof AuthError) return;
    mount(host, h("section", { class: "card" }, h("h2", { text: "This page did not load" }),
      h("p", { class: "muted", text: safeText(e.message || String(e)) }), h("button", { text: "Try again", onclick: route })));
  }
}
window.addEventListener("hashchange", route);

// ---------------------------------------------------------------------------- boot
async function boot() {
  try {
    const me = await api("/api/me", { noAuthRedirect: true });
    if (me.auth_required && !me.authed) { showLogin(); return; }
    authed = true;
    buildShell();
    startLive();
    route();
  } catch (e) {
    mount(app, h("div", { class: "login" }, h("div", { class: "card" }, h("h2", { text: "The dashboard cannot be reached" }), h("p", { class: "muted", text: safeText(e.message) }), h("button", { text: "Try again", onclick: boot }))));
  }
}
boot();
