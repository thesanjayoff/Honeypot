import { h, mount, api, qs, num, compact, clock, safeText, ipLink, sessionLink, svcTag, svcColor, emptyState, debounce } from "../util.js";
import { timeColumns, hbars, segmentedBar } from "../charts.js";
import { createMap } from "../map.js";
import { onEvent } from "../live.js";

const METRICS = [["conns", "Connections"], ["auth", "Login attempts"], ["exploits", "Exploit attempts"], ["cmds", "Commands"], ["files", "Files captured"]];
const QUIET = new Set(["conn.close", "client.fingerprint", "log.suppressed"]);
const INTERESTING = new Set(["cmd.input", "exploit.attempt", "download.attempt", "file.captured", "file.exec_attempt", "session.open", "cron.install", "net.outbound_attempt", "db.query"]);

function tile(label, value, extra, href, cls = "") {
  const inner = [h("div", { class: "label", text: label }), h("div", { class: "value", text: value }), extra];
  return h("div", { class: `tile ${cls}` }, href ? h("a", { href }, inner) : inner);
}

function deltaNode(cur, prev, hours) {
  if (!prev) return h("div", { class: "delta", text: cur ? "no earlier data to compare" : "" });
  const d = Math.round(((cur - prev) / prev) * 100);
  const word = hours >= 48 ? `previous ${Math.round(hours / 24)} days` : `previous ${hours}h`;
  return h("div", { class: `delta ${d > 0 ? "up" : d < 0 ? "down" : ""}`, text: `${d > 0 ? "▲ +" : d < 0 ? "▼ " : "= "}${d}% vs ${word}` });
}

export async function overview(root, ctx) {
  const hours = ctx.hours;
  const tilesEl = h("div", { class: "tiles" });
  const mapHost = h("div", { class: "mapbox" });
  const feedEl = h("div", { class: "feed", role: "log", "aria-label": "Live events" });
  const timeBody = h("div"), timeTools = h("div", { class: "tools" });
  const tops = {};
  const topDefs = [
    ["countries", "Top countries", {}],
    ["asns", "Top networks (ASN)", {}],
    ["ips", "Top source IPs", {}],
    ["usernames", "Usernames tried", {}],
    ["passwords", "Passwords tried", {}],
    ["credentials", "Credential pairs", {}],
    ["commands", "Commands run", {}],
    ["exploits", "Exploit rules hit", {}],
    ["techniques", "ATT&CK techniques", {}],
    ["ports", "Ports targeted", {}],
    ["clients", "SSH / HTTP clients", {}],
  ];
  const svcBody = h("div");
  let metric = "conns";
  let feedFilter = "all";
  let lastTs = {};

  const metricSeg = h("div", { class: "seg", role: "group", "aria-label": "Chart metric" },
    METRICS.map(([k, l]) => h("button", { "aria-pressed": String(k === metric), text: l, "data-k": k, onclick: (e) => { metric = k; [...metricSeg.children].forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.k === k))); drawSeries(); } })));

  const feedSeg = h("div", { class: "seg", role: "group", "aria-label": "Feed filter" },
    [["all", "All"], ["hot", "Active attacks"]].map(([k, l]) => h("button", { "aria-pressed": String(k === feedFilter), text: l, "data-k": k, onclick: () => { feedFilter = k; [...feedSeg.children].forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.k === k))); loadFeed(); } })));

  const map = createMap(mapHost);
  let series = null, seriesHandle = null;

  mount(root,
    h("div", { class: "page-head" }, h("h1", { text: "Overview" }), h("span", { class: "sub", text: `last ${hours >= 48 ? Math.round(hours / 24) + " days" : hours + " hours"}` })),
    tilesEl,
    h("div", { class: "grid g-map" },
      h("section", { class: "card flush" }, h("header", null, h("h2", { text: "Attack sources" }), h("span", { class: "sub", text: "where connections come from" })), mapHost),
      h("section", { class: "card feedcard" }, h("header", null, h("h2", { text: "Live feed" }), h("div", { class: "tools" }, feedSeg)), feedEl)),
    h("section", { class: "card", style: { "margin-top": "14px" } },
      h("header", null, h("h2", { text: "Activity over time" }), h("div", { class: "tools" }, metricSeg, timeTools)), timeBody),
    h("div", { class: "grid g3", style: { "margin-top": "14px" } },
      h("section", { class: "card" }, h("header", null, h("h2", { text: "Services targeted" }), h("span", { class: "sub", text: "connections" })), svcBody),
      topDefs.map(([k, title]) => {
        const body = h("div");
        tops[k] = body;
        return h("section", { class: "card" }, h("header", null, h("h2", { text: title })), body);
      })));

  function drawSeries() {
    if (!series) return;
    if (seriesHandle) seriesHandle.destroy();
    mount(timeTools);
    seriesHandle = timeColumns(timeBody, { points: series.points, services: series.services, metric, bucket: series.bucket,
      label: METRICS.find((m) => m[0] === metric)[1] });
    timeTools.append(seriesHandle.toggle);
  }

  function renderTop(k, rows) {
    const body = tops[k];
    let el;
    if (k === "ips") {
      rows = rows.map((r) => ({ ...r, key: r.ip, name: [r.country, r.org].filter(Boolean).join(" · ") }));
      el = hbars(rows, { link: (r) => `#/ip/${encodeURIComponent(r.key)}`, label: (r) => `${r.key}${r.country ? "  " + r.country : ""}`, unit: "events" });
    } else if (k === "techniques") {
      el = hbars(rows, { link: () => "#/attack", label: (r) => `${r.key} ${r.name}`, unit: "hits", sub: (r) => [{ label: "tactic", value: r.tactic }] });
    } else if (k === "usernames" || k === "passwords" || k === "credentials") {
      el = hbars(rows, { label: (r) => (r.key === "" ? "(empty)" : r.key), unit: "attempts", sub: (r) => (r.ok ? [{ label: "accepted", value: num(r.ok) }] : []) });
    } else if (k === "exploits") {
      el = hbars(rows, { label: (r) => `${r.key}${r.cve ? " · " + r.cve : ""}`, unit: "hits", sub: (r) => [{ label: "category", value: r.category || "–" }] });
    } else if (k === "asns") {
      el = hbars(rows, { label: (r) => `AS${r.key} ${r.name || ""}`, unit: "connections" });
    } else {
      el = hbars(rows, { unit: "count" });
    }
    mount(body, el);
  }

  async function load() {
    root.classList.add("reloading");
    try {
      const [sum, ts, mp, ...rest] = await Promise.all([
        api("/api/summary" + qs({ hours })), api("/api/timeseries" + qs({ hours })), api("/api/map" + qs({ hours })),
        ...topDefs.map(([k]) => api("/api/top" + qs({ what: k, hours, limit: 8 }))), api("/api/top" + qs({ what: "services", hours, limit: 12 }))]);
      const svcRows = rest.pop();
      mount(tilesEl,
        tile("Connections", num(sum.connections), deltaNode(sum.connections, sum.connections_prev, hours), null, "hero"),
        tile("Unique source IPs", compact(sum.unique_ips), h("div", { class: "delta", text: `${num(sum.new_ips)} first seen in this window` }), "#/sessions"),
        tile("Logins accepted", num(sum.logins), h("div", { class: "delta", text: `${compact(sum.auth_attempts)} attempts` }), "#/sessions"),
        tile("Commands run", num(sum.commands), h("div", { class: "delta", text: `${num(sum.sessions)} shell sessions` }), "#/sessions"),
        tile("Exploit attempts", num(sum.exploits), h("div", { class: "delta", text: `${num(sum.http_requests)} HTTP requests` })),
        tile("Samples captured", num(sum.new_samples), h("div", { class: "delta", text: `${num(sum.samples_total)} total` }), "#/samples"));
      series = ts; drawSeries();
      map.setPoints(mp.points);
      topDefs.forEach(([k], i) => renderTop(k, rest[i]));
      mount(svcBody, svcRows.length ? [segmentedBar(svcRows.map((r) => ({ name: r.key, n: r.n, color: svcColor(r.key) }))), h("div", { style: { height: "10px" } }),
        hbars(svcRows, { serviceKeys: true, unit: "connections" })] : emptyState("No connections in this window"));
    } finally { root.classList.remove("reloading"); }
  }

  // ------------------------------------------------------------------ feed
  function feedRow(e, fresh) {
    const where = e.session ? sessionLink(e.session, e.event) : h("span", { text: e.event });
    return h("div", { class: "row" + (fresh ? " new" : "") },
      h("span", { class: "muted num", text: clock(e.ts) }), svcTag(e.service),
      h("span", { class: "what", title: safeText(e.summary || "") }, ipLink(e.src_ip), " ", h("b", null, where), h("span", { class: "ink2", text: safeText(e.summary || "") })));
  }
  const keep = (e) => !QUIET.has(e.event) && (feedFilter === "all" || INTERESTING.has(e.event));
  async function loadFeed() {
    const rows = await api("/api/events" + qs({ limit: 80 }));
    mount(feedEl, rows.filter(keep).slice(0, 40).map((e) => feedRow(e, false)));
    if (!feedEl.firstChild) mount(feedEl, emptyState("Waiting for attackers…"));
  }
  const refreshSoon = debounce(() => { load().catch(() => {}); }, 8000);
  const off = onEvent((e) => {
    if (!keep(e)) return;
    if (feedEl.firstChild && feedEl.firstChild.classList.contains("empty")) mount(feedEl);
    feedEl.prepend(feedRow(e, true));
    while (feedEl.children.length > 60) feedEl.lastChild.remove();
    if (e.event === "conn.open" || e.event === "exploit.attempt") map.pulse(e.lat, e.lon);
    refreshSoon();
  });
  const timer = setInterval(() => { load().catch(() => {}); }, 60000);
  ctx.onCleanup(() => { off(); clearInterval(timer); map.destroy(); if (seriesHandle) seriesHandle.destroy(); });

  await Promise.all([load(), loadFeed()]);
}
