// honeynet dashboard shell: login, hash router, range filter, theme, live-stream status.
import { h, svg, mount, clear, api, AuthError, safeText, toast } from "./js/util.js";
import { startLive, stopLive, onState } from "./js/live.js";
import { overview } from "./js/views/overview.js";
import { sessions, session, ipProfile } from "./js/views/sessions.js";
import { samples, sample } from "./js/views/samples.js";
import { attack, iocs, alerts, system } from "./js/views/misc.js";

const app = document.getElementById("app");
const RANGES = [[1, "1h"], [6, "6h"], [24, "24h"], [168, "7d"], [720, "30d"]];
const NAV = [["#/", "Overview", /^#\/?$/], ["#/sessions", "Sessions", /^#\/(sessions|session\/)/], ["#/samples", "Samples", /^#\/sample/], ["#/attack", "ATT&CK", /^#\/attack/],
  ["#/iocs", "Indicators", /^#\/iocs/], ["#/alerts", "Alerts", /^#\/alerts/], ["#/system", "System", /^#\/system/]];
const ROUTES = [
  [/^#\/?$/, overview, true], [/^#\/sessions$/, sessions], [/^#\/session\/([A-Za-z0-9_-]{1,40})$/, session], [/^#\/ip\/([^/]+)$/, ipProfile],
  [/^#\/samples$/, samples], [/^#\/sample\/([0-9a-f]{64})$/, sample], [/^#\/attack$/, attack, true], [/^#\/iocs$/, iocs], [/^#\/alerts$/, alerts], [/^#\/system$/, system],
];

let hours = Number(localStorage.getItem("hn.hours")) || 24;
if (!RANGES.some(([v]) => v === hours)) hours = 24;
let cleanups = [];
let token = 0;
let shell = null;
let authed = false;
let pollTimer = null;

// ---------------------------------------------------------------------------- theme
function applyTheme() {
  const t = localStorage.getItem("hn.theme");
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  document.dispatchEvent(new CustomEvent("honeynet:theme"));
}
function cycleTheme() {
  const cur = localStorage.getItem("hn.theme") || "auto";
  const next = { auto: "light", light: "dark", dark: "auto" }[cur];
  if (next === "auto") localStorage.removeItem("hn.theme"); else localStorage.setItem("hn.theme", next);
  applyTheme();
  toast(`Theme: ${next}`);
}
applyTheme();

// ---------------------------------------------------------------------------- login
function showLogin(message = "") {
  stopLive();
  authed = false; shell = null;
  clearInterval(pollTimer);
  const err = h("div", { class: "err", role: "alert", text: message });
  const pw = h("input", { type: "password", autocomplete: "current-password", "aria-label": "Password", required: true, autofocus: true });
  const form = h("form", { onsubmit: async (e) => {
    e.preventDefault();
    err.textContent = "";
    try {
      await api("/api/login", { method: "POST", json: { password: pw.value }, noAuthRedirect: true });
      pw.value = "";
      boot();
    } catch (x) { err.textContent = x.status === 429 ? "Too many attempts. Wait a bit and try again." : "Wrong password."; pw.select(); }
  } },
    h("div", { class: "brand" }, logo(), h("span", { text: "honeynet" })),
    h("div", { class: "muted", text: "Private dashboard. Sign in to continue." }), pw, err,
    h("button", { class: "primary", type: "submit", text: "Sign in" }));
  mount(app, h("div", { class: "login" }, form));
  pw.focus();
}
document.addEventListener("honeynet:auth", () => { if (authed) showLogin("Session expired. Please sign in again."); });

function logo() {
  return svg("svg", { viewBox: "0 0 32 32", "aria-hidden": "true" },
    svg("path", { d: "M16 4 5 8.5v7.5c0 6 4.6 10.4 11 12 6.4-1.6 11-6 11-12V8.5z", fill: "none", stroke: "var(--accent)", "stroke-width": "2.4", "stroke-linejoin": "round" }),
    svg("circle", { cx: 16, cy: 15, r: 3.4, fill: "var(--s2)" }));
}

// ---------------------------------------------------------------------------- shell
function buildShell() {
  const nav = h("nav", { class: "nav", "aria-label": "Main" }, NAV.map(([href, label]) => h("a", { href, text: label, "data-href": href })));
  const alertsBadge = h("span", { class: "badge-count hidden", text: "0", title: "unacknowledged alerts" });
  nav.querySelector('[data-href="#/alerts"]').append(alertsBadge);
  const dot = h("i", { class: "dot" });
  const liveText = h("span", { text: "connecting" });
  const range = h("div", { class: "seg", role: "group", "aria-label": "Time range" },
    RANGES.map(([v, l]) => h("button", { text: l, "aria-pressed": String(v === hours), "data-v": v, onclick: () => setHours(v) })));
  const main = h("main", { id: "main", tabindex: -1 });
  mount(app,
    h("header", { class: "topbar" },
      h("a", { class: "brand", href: "#/", "aria-label": "honeynet overview" }, logo(), h("span", { text: "honeynet" })), nav, h("span", { class: "spacer" }),
      range, h("span", { class: "pill", title: "live event stream" }, dot, liveText),
      h("button", { class: "ghost", text: "Theme", title: "Cycle light / dark / automatic", onclick: cycleTheme }),
      h("button", { class: "ghost", text: "Sign out", onclick: async () => { try { await api("/api/logout", { method: "POST", json: {} }); } catch { /* ignore */ } location.hash = "#/"; showLogin(); } })),
    main);
  onState((s) => { dot.className = "dot " + (s === "live" ? "live" : s === "off" ? "off" : ""); liveText.textContent = s === "live" ? "live" : s === "off" ? "offline" : "reconnecting"; });
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
  if (!matched) { mount(host, h("section", { class: "card" }, h("h1", { text: "Not found" }), h("p", null, h("a", { href: "#/", text: "Back to the overview" })))); return; }
  const ctx = { hours, params: matched.params, onCleanup: (f) => cleanups.push(f) };
  try {
    await matched.view(host, ctx);
    if (my === token) window.scrollTo({ top: 0 });
  } catch (e) {
    if (my !== token || e instanceof AuthError) return;
    mount(host, h("section", { class: "card" }, h("h2", { text: "Could not load this page" }),
      h("p", { class: "muted", text: safeText(e.message || String(e)) }), h("button", { text: "Retry", onclick: route })));
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
    mount(app, h("div", { class: "login" }, h("div", { class: "card" }, h("h2", { text: "Dashboard unreachable" }), h("p", { class: "muted", text: safeText(e.message) }), h("button", { text: "Retry", onclick: boot }))));
  }
}
boot();
