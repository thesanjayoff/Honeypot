// Small DOM + formatting helpers. Everything attacker-controlled goes through textContent / text nodes -
// nothing here ever parses HTML from a string (a test enforces it).

const SVG_NS = "http://www.w3.org/2000/svg";

function apply(el, attrs) {
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.setAttribute("class", v);
    else if (k === "text") el.textContent = v;
    else if (k === "style" && typeof v === "object") for (const [p, val] of Object.entries(v)) el.style.setProperty(p, val);
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "value" || k === "checked" || k === "disabled" || k === "selected") el[k] = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
}
function append(el, kids) {
  for (const c of kids.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}
export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  apply(el, attrs);
  append(el, kids);
  return el;
}
export function svg(tag, attrs, ...kids) {
  const el = document.createElementNS(SVG_NS, tag);
  apply(el, attrs);
  append(el, kids);
  return el;
}
export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
export function mount(el, ...kids) { clear(el); append(el, kids); return el; }

// ---------------------------------------------------------------------------- hostile text
// Control characters, bidi overrides and zero-width characters are shown as visible escapes so a
// recorded terminal session can never move the cursor, recolour the page or spoof text direction.
const CTL_RANGES = [[0, 8], [0x0b, 0x1f], [0x7f, 0x9f], [0xad, 0xad], [0x61c, 0x61c], [0x180e, 0x180e], [0x200b, 0x200f], [0x2028, 0x202e],
  [0x2060, 0x206f], [0xfeff, 0xfeff], [0xfff9, 0xfffb]];
const CTL = new RegExp("[" + CTL_RANGES.map(([a, b]) => String.fromCharCode(a) + (b > a ? "-" + String.fromCharCode(b) : "")).join("") + "]", "g");
export function ctlName(ch) {
  const c = ch.codePointAt(0);
  if (c === 0x1b) return "\\e";
  if (c === 0x0d) return "\\r";
  if (c === 0x07) return "\\a";
  if (c === 0x08) return "\\b";
  return c <= 0xff ? "\\x" + c.toString(16).padStart(2, "0") : "\\u" + c.toString(16).padStart(4, "0");
}
export function safeText(s) { return String(s ?? "").replace(CTL, ctlName); }
// Returns nodes: plain text with <span class="ctl"> for each escaped control character.
export function visible(s) {
  s = String(s ?? "");
  const out = [];
  let last = 0;
  for (const m of s.matchAll(CTL)) {
    if (m.index > last) out.push(document.createTextNode(s.slice(last, m.index)));
    out.push(h("span", { class: "ctl", text: ctlName(m[0]) }));
    last = m.index + m[0].length;
  }
  if (last < s.length) out.push(document.createTextNode(s.slice(last)));
  return out;
}

// ---------------------------------------------------------------------------- formatting
export function num(n) { return n === null || n === undefined ? "–" : Number(n).toLocaleString("en-US"); }
export function compact(n) {
  n = Number(n) || 0;
  const a = Math.abs(n);
  if (a < 10000) return Math.round(n).toLocaleString("en-US");
  if (a < 1e6) return (n / 1e3).toFixed(a < 1e5 ? 1 : 0).replace(/\.0$/, "") + "K";
  if (a < 1e9) return (n / 1e6).toFixed(a < 1e7 ? 1 : 0).replace(/\.0$/, "") + "M";
  return (n / 1e9).toFixed(1).replace(/\.0$/, "") + "B";
}
export function bytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}
const pad = (n) => String(n).padStart(2, "0");
export function clock(ts, seconds = true) {
  const d = new Date(ts * 1000);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}` + (seconds ? `:${pad(d.getSeconds())}` : "");
}
export function dateTime(ts) {
  if (!ts) return "–";
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
export function ago(ts) {
  if (!ts) return "–";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 5) return "just now";
  if (s < 90) return Math.round(s) + "s ago";
  if (s < 5400) return Math.round(s / 60) + "m ago";
  if (s < 129600) return Math.round(s / 3600) + "h ago";
  return Math.round(s / 86400) + "d ago";
}
export function duration(s) {
  s = Number(s) || 0;
  if (s < 1) return "<1s";
  if (s < 90) return Math.round(s) + "s";
  if (s < 5400) return Math.round(s / 60) + "m";
  return (s / 3600).toFixed(1) + "h";
}
export function plural(n, word, many) { n = Number(n) || 0; return `${num(n)} ${n === 1 ? word : (many || word + "s")}`; }
export function pct(x) { return Math.round((Number(x) || 0) * 100) + "%"; }
export function short(s, n = 16) { s = String(s ?? ""); return s.length > n ? s.slice(0, n) + "…" : s; }

// ---------------------------------------------------------------------------- ids + links
const IP_OK = /^[0-9a-fA-F:.]{2,45}$/;
const SHA_OK = /^[0-9a-f]{64}$/;
const SID_OK = /^[A-Za-z0-9_-]{1,40}$/;
export function ipLink(ip, text) {
  ip = String(ip ?? "");
  if (!IP_OK.test(ip)) return h("span", { class: "mono", text: safeText(ip) });
  return h("a", { class: "mono", href: `#/ip/${encodeURIComponent(ip)}`, text: text ?? ip });
}
export function sessionLink(id, text) {
  if (!id || !SID_OK.test(id)) return h("span", { class: "muted", text: "–" });
  return h("a", { class: "mono", href: `#/session/${id}`, text: text ?? id.slice(0, 8) });
}
export function sampleLink(sha, text) {
  if (!SHA_OK.test(String(sha))) return h("span", { class: "mono", text: safeText(sha) });
  return h("a", { class: "mono", href: `#/sample/${sha}`, text: text ?? sha.slice(0, 12) + "…" });
}
export function attackLink(id, text) {
  if (!/^T\d{4}(\.\d{3})?$/.test(String(id))) return h("span", { class: "chip", text: safeText(id) });
  return h("a", { class: "chip", href: `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`, target: "_blank", rel: "noopener noreferrer nofollow", title: "MITRE ATT&CK (opens attack.mitre.org)", text: text ?? id });
}

// Fixed service -> categorical slot (colour follows the entity, never its rank).
const SERVICE_SLOT = { ssh: 1, telnet: 2, http: 3, mysql: 4, redis: 5, fetcher: 6, ftp: 7, smb: 8 };
export function svcColor(name) { return `var(--s${SERVICE_SLOT[name] || 6})`; }
export function svcTag(name) {
  return h("span", { class: "svc" }, h("i", { class: "swatch", style: { background: svcColor(name) } }), safeText(name));
}
const CLS_GLYPH = { malicious: "▲", suspicious: "◆", benign: "●", scanner: "◌", unknown: "○" };
export function clsBadge(c) {
  c = c || "unknown";
  return h("span", { class: `badge ${/^[a-z]+$/.test(c) ? c : "unknown"}`, title: "GreyNoise-style classification" }, CLS_GLYPH[c] || "○", " ", safeText(c));
}
export function levelBadge(l) {
  l = l || "info";
  return h("span", { class: `badge ${/^[a-z]+$/.test(l) ? l : "info"}` }, safeText(l));
}

// ---------------------------------------------------------------------------- network
export class AuthError extends Error {}
export async function api(path, opts = {}) {
  const method = opts.method || "GET";
  const headers = { "X-Requested-With": "honeynet", Accept: "application/json" };
  let body;
  if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(opts.json); }
  const r = await fetch(path, { method, headers, body, credentials: "same-origin", cache: "no-store", signal: opts.signal });
  if (r.status === 401 && !opts.noAuthRedirect) {
    document.dispatchEvent(new CustomEvent("honeynet:auth"));
    throw new AuthError("login required");
  }
  if (!r.ok) {
    let msg = r.statusText;
    try { const j = await r.json(); msg = j.error || j.detail || msg; } catch { /* not json */ }
    const e = new Error(`${r.status} ${typeof msg === "string" ? msg : JSON.stringify(msg)}`);
    e.status = r.status;
    throw e;
  }
  return opts.text ? r.text() : r.json();
}
export function qs(params) {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") u.set(k, v);
  const s = u.toString();
  return s ? "?" + s : "";
}

let toastTimer = null;
export function toast(msg) {
  document.querySelectorAll(".toast").forEach((t) => t.remove());
  const t = h("div", { class: "toast", role: "status", text: msg });
  document.body.append(t);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.remove(), 4000);
}
export async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast("Copied"); } catch { toast("Copy failed - select the text and press Ctrl+C"); }
}
export function emptyState(text) { return h("div", { class: "empty", text }); }
export function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
