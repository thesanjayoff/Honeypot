import { h, svg, mount, api, qs, num, compact, clock, ago, safeText, ipLink, sessionLink, svcTag, svcColor, emptyState, debounce } from "../util.js";
import { timeColumns, hbars, segmentedBar } from "../charts.js";
import { createMap } from "../map.js";
import { onEvent } from "../live.js";

const METRICS = [["conns", "Connections"], ["auth", "Login attempts"], ["exploits", "Exploit attempts"], ["cmds", "Commands"], ["files", "Files captured"]];
const QUIET = new Set(["conn.close", "client.fingerprint", "log.suppressed"]);
const INTERESTING = new Set(["cmd.input", "exploit.attempt", "download.attempt", "file.captured", "file.exec_attempt", "session.open", "cron.install", "net.outbound_attempt", "db.query"]);
const VERB = {
  "cmd.input": "ran", "exploit.attempt": "tried an exploit:", "download.attempt": "tried to download", "file.captured": "left a file:", "file.exec_attempt": "tried to run a file:",
  "session.open": "opened a shell", "cron.install": "installed a cron job:", "net.outbound_attempt": "tried to reach out:", "db.query": "ran a query:",
};

// Short words for the feed (the full event name stays in the tooltip and on the session page)
const SHORT = { "auth.attempt": "login", "auth.success": "login ok", "cmd.input": "ran", "exploit.attempt": "exploit", "conn.open": "connect", "http.request": "request",
  "download.attempt": "download", "file.captured": "file", "session.open": "shell", "session.close": "left", "db.query": "query", "probe": "probe" };

// The three tabbed panels: [panel title, [[api key, tab label], ...]]
const PANELS = [
  ["Who is knocking", [["countries", "Countries"], ["asns", "Networks"], ["ips", "Source IPs"], ["clients", "Clients"]]],
  ["Logins they try", [["usernames", "Usernames"], ["passwords", "Passwords"], ["credentials", "Pairs"]]],
  ["What they do", [["commands", "Commands"], ["exploits", "Exploits"], ["techniques", "ATT&CK"], ["ports", "Ports"]]],
];
const TOP_KEYS = PANELS.flatMap(([, tabs]) => tabs.map(([k]) => k));

function sparkline(points, field) {
  const vals = points.map((p) => p[field] || 0);
  if (vals.length < 2 || !Math.max(...vals)) return null;
  const W = 100, H = 30, max = Math.max(...vals);
  const x = (i) => (i / (vals.length - 1)) * W, y = (v) => H - 2 - (v / max) * (H - 5);
  const line = vals.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(2)},${y(v).toFixed(2)}`).join(" ");
  return svg("svg", { class: "spark", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", "aria-hidden": "true", focusable: "false" },
    svg("path", { class: "area", d: `${line} L${W},${H} L0,${H} Z` }), svg("path", { class: "ln", d: line, "vector-effect": "non-scaling-stroke" }));
}

function tile(label, value, extra, href, cls = "", spark = null) {
  const inner = [h("div", { class: "label", text: label }), h("div", { class: "value", text: value }), extra, spark];
  return h("div", { class: `tile ${cls}` }, href ? h("a", { href }, inner) : inner);
}

function deltaNode(cur, prev, hours) {
  if (!prev) return h("div", { class: "delta", text: cur ? "nothing earlier to compare with" : "" });
  const d = Math.round(((cur - prev) / prev) * 100);
  const word = hours >= 48 ? `the previous ${Math.round(hours / 24)} days` : `the previous ${hours}h`;
  return h("div", { class: `delta ${d > 0 ? "up" : d < 0 ? "down" : ""}`, text: `${d > 0 ? "▲ " : d < 0 ? "▼ " : ""}${d > 0 ? "+" : ""}${d}% against ${word}` });
}

// A card with a few tabs; each tab shows one ranked list.
function tabbed(title, tabs) {
  const body = h("div");
  const els = {};
  let cur = tabs[0][0];
  const seg = h("div", { class: "seg sm", role: "group", "aria-label": `${title}: choose a list` },
    tabs.map(([k, l]) => h("button", { text: l, "data-k": k, "aria-pressed": String(k === cur), onclick: () => select(k) })));
  function select(k) {
    cur = k;
    [...seg.children].forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.k === k)));
    mount(body, els[k] || emptyState("Loading…"));
  }
  const el = h("section", { class: "card" }, h("header", null, h("h2", { text: title })), h("div", { class: "tabrow" }, seg), body);
  select(cur);
  return { el, set(k, node) { els[k] = node; if (k === cur) select(k); } };
}

export async function overview(root, ctx) {
  const hours = ctx.hours;
  const tilesEl = h("div", { class: "tiles" });
  const latestEl = h("div", { class: "latest", role: "status" });
  const mapHost = h("div", { class: "mapbox" });
  const feedEl = h("div", { class: "feed", role: "log", "aria-label": "Live events" });
  const timeBody = h("div"), timeTools = h("div", { class: "tools" });
  const svcBody = h("div");
  const panels = PANELS.map(([title, tabs]) => tabbed(title, tabs));
  const panelOf = (k) => panels[PANELS.findIndex(([, tabs]) => tabs.some(([t]) => t === k))];
  let metric = "conns";
  let feedFilter = "all";
  let lastNotable = null;

  const metricSeg = h("div", { class: "seg sm", role: "group", "aria-label": "Chart metric" },
    METRICS.map(([k, l]) => h("button", { "aria-pressed": String(k === metric), text: l, "data-k": k, onclick: () => { metric = k; [...metricSeg.children].forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.k === k))); drawSeries(); } })));

  const feedSeg = h("div", { class: "seg sm", role: "group", "aria-label": "Feed filter" },
    [["all", "Everything"], ["hot", "Attacks only"]].map(([k, l]) => h("button", { "aria-pressed": String(k === feedFilter), text: l, "data-k": k, onclick: () => { feedFilter = k; [...feedSeg.children].forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.k === k))); loadFeed(); } })));

  const map = createMap(mapHost);
  let series = null, seriesHandle = null;

  mount(root,
    h("div", { class: "page-head" }, h("h1", { text: "Overview" }), h("span", { class: "sub", text: `last ${hours >= 48 ? Math.round(hours / 24) + " days" : hours + " hours"}` })),
    latestEl,
    tilesEl,
    h("div", { class: "grid g-map" },
      h("section", { class: "card flush" }, h("header", null, h("h2", { text: "Where attacks come from" }), h("span", { class: "sub", text: "hover a bubble for details" })), mapHost),
      h("section", { class: "card feedcard" }, h("header", null, h("h2", { text: "Live feed" }), h("div", { class: "tools" }, feedSeg)), feedEl)),
    h("div", { class: "grid g-chart", style: { "margin-top": "16px" } },
      h("section", { class: "card" }, h("header", null, h("h2", { text: "Activity over time" }), h("div", { class: "tools" }, metricSeg, timeTools)), timeBody),
      h("section", { class: "card" }, h("header", null, h("h2", { text: "Services targeted" }), h("span", { class: "sub", text: "connections" })), svcBody)),
    h("div", { class: "grid g3", style: { "margin-top": "16px" } }, panels.map((p) => p.el)));

  function drawSeries() {
    if (!series) return;
    if (seriesHandle) seriesHandle.destroy();
    mount(timeTools);
    seriesHandle = timeColumns(timeBody, { points: series.points, services: series.services, metric, bucket: series.bucket,
      label: METRICS.find((m) => m[0] === metric)[1] });
    timeTools.append(seriesHandle.toggle);
  }

  function renderTop(k, rows) {
    let el;
    if (k === "ips") {
      rows = rows.map((r) => ({ ...r, key: r.ip || r.key }));
      el = hbars(rows, { link: (r) => `#/ip/${encodeURIComponent(r.key)}`, label: (r) => [r.key, [r.country, r.org].filter(Boolean).join(" ")], unit: "events", mono: true });
    } else if (k === "techniques") {
      el = hbars(rows, { link: () => "#/attack", label: (r) => [r.name, r.key], unit: "hits", sub: (r) => [{ label: "tactic", value: r.tactic }] });
    } else if (k === "usernames" || k === "passwords" || k === "credentials") {
      el = hbars(rows, { label: (r) => (r.key === "" ? "(empty)" : r.key), unit: "attempts", mono: true, sub: (r) => (r.ok ? [{ label: "accepted", value: num(r.ok) }] : []) });
    } else if (k === "commands") {
      el = hbars(rows, { unit: "count", mono: true, label: (r) => String(r.key) });
    } else if (k === "exploits") {
      el = hbars(rows, { label: (r) => [r.key, r.cve || ""], unit: "hits", sub: (r) => [{ label: "category", value: r.category || "–" }] });
    } else if (k === "asns") {
      el = hbars(rows, { label: (r) => [r.name || `AS${r.key}`, ""], unit: "connections", sub: (r) => [{ label: "ASN", value: `AS${r.key}` }] });
    } else if (k === "countries") {
      el = hbars(rows, { label: (r) => [r.name || r.key, ""], unit: "connections", sub: (r) => [{ label: "country code", value: r.key }] });
    } else if (k === "ports") {
      el = hbars(rows, { label: (r) => [String(r.key), r.name || ""], unit: "connections" });
    } else {
      el = hbars(rows, { unit: "count", mono: k === "clients" });
    }
    panelOf(k).set(k, el);
  }

  async function load() {
    root.classList.add("reloading");
    try {
      const [sum, ts, mp, svcRows, ...rest] = await Promise.all([
        api("/api/summary" + qs({ hours })), api("/api/timeseries" + qs({ hours })), api("/api/map" + qs({ hours })),
        api("/api/top" + qs({ what: "services", hours, limit: 12 })),
        ...TOP_KEYS.map((k) => api("/api/top" + qs({ what: k, hours, limit: 8 })))]);
      const pts = ts.points;
      mount(tilesEl,
        tile("Connections", num(sum.connections), deltaNode(sum.connections, sum.connections_prev, hours), null, "hero", sparkline(pts, "conns")),
        tile("Unique source IPs", compact(sum.unique_ips), h("div", { class: "delta", text: `${num(sum.new_ips)} seen for the first time` }), "#/sessions"),
        tile("Logins accepted", num(sum.logins), h("div", { class: "delta", text: `of ${compact(sum.auth_attempts)} attempts` }), "#/sessions"),
        tile("Commands run", num(sum.commands), h("div", { class: "delta", text: `in ${num(sum.sessions)} shell sessions` }), "#/sessions", "", sparkline(pts, "cmds")),
        tile("Exploit attempts", num(sum.exploits), h("div", { class: "delta", text: `among ${num(sum.http_requests)} web requests` }), null, "", sparkline(pts, "exploits")),
        tile("Samples captured", num(sum.new_samples), h("div", { class: "delta", text: `${num(sum.samples_total)} in total` }), "#/samples"));
      series = ts; drawSeries();
      map.setPoints(mp.points); map.setHome(mp.home);
      TOP_KEYS.forEach((k, i) => renderTop(k, rest[i]));
      mount(svcBody, svcRows.length ? [segmentedBar(svcRows.map((r) => ({ name: r.key, n: r.n, color: svcColor(r.key) }))), h("div", { style: { height: "12px" } }),
        hbars(svcRows, { serviceKeys: true, unit: "connections" })] : emptyState("No connections in this time range"));
    } finally { root.classList.remove("reloading"); }
  }

  // ------------------------------------------------------------------ latest attack (the one thing worth a glance)
  function paintLatest() {
    const e = lastNotable;
    if (!e) {
      latestEl.className = "latest";
      mount(latestEl, h("span", { class: "lt-label", text: "Latest" }), h("span", { class: "muted", text: "Nothing notable yet. When someone runs a command, tries an exploit or leaves a file, it shows up here." }));
      return;
    }
    latestEl.className = `latest ${/^[a-z]+$/.test(e.classification || "") ? e.classification : ""}`;
    mount(latestEl,
      h("span", { class: "lt-label", text: "Latest" }), h("span", { class: "muted num lt-time", title: clock(e.ts), text: ago(e.ts) }), svcTag(e.service),
      h("span", { class: "lt-what" }, ipLink(e.src_ip), e.country ? h("span", { class: "muted", text: ` (${safeText(e.country)})` }) : null, " ",
        h("span", { class: "ink2", text: VERB[e.event] || safeText(e.event) }), " ", h("span", { class: "mono lt-cmd", text: safeText(e.summary || "") })));
  }

  // ------------------------------------------------------------------ feed
  function feedRow(e, fresh) {
    const word = SHORT[e.event] || e.event;
    const where = e.session ? sessionLink(e.session, word) : h("span", { text: word });
    return h("div", { class: "row" + (fresh ? " new" : ""), title: safeText(e.event) },
      h("span", { class: "muted num", text: clock(e.ts) }), svcTag(e.service),
      h("span", { class: "what", title: safeText(e.summary || "") }, ipLink(e.src_ip), " ", h("b", null, where), h("span", { class: "ink2", text: safeText(e.summary || "") })));
  }
  const keep = (e) => !QUIET.has(e.event) && (feedFilter === "all" || INTERESTING.has(e.event));
  async function loadFeed() {
    const rows = await api("/api/events" + qs({ limit: 120 }));
    mount(feedEl, rows.filter(keep).slice(0, 40).map((e) => feedRow(e, false)));
    if (!feedEl.firstChild) mount(feedEl, emptyState("Waiting for attackers…"));
    const n = rows.find((e) => INTERESTING.has(e.event));
    if (n && (!lastNotable || n.ts > lastNotable.ts)) lastNotable = n;
    paintLatest();
  }
  const refreshSoon = debounce(() => { load().catch(() => {}); }, 8000);
  const off = onEvent((e) => {
    if (INTERESTING.has(e.event)) { lastNotable = e; paintLatest(); }
    if (!keep(e)) return;
    if (feedEl.firstChild && feedEl.firstChild.classList.contains("empty")) mount(feedEl);
    feedEl.prepend(feedRow(e, true));
    while (feedEl.children.length > 60) feedEl.lastChild.remove();
    if (e.event === "conn.open" || e.event === "exploit.attempt") map.pulse(e.lat, e.lon, e.classification);
    refreshSoon();
  });
  const onResume = () => { Promise.all([load(), loadFeed()]).catch(() => {}); };
  document.addEventListener("honeynet:resume", onResume);
  const timer = setInterval(() => { load().catch(() => {}); }, 60000);
  const ageTimer = setInterval(() => { if (lastNotable) paintLatest(); }, 15000);
  ctx.onCleanup(() => { off(); clearInterval(timer); clearInterval(ageTimer); document.removeEventListener("honeynet:resume", onResume); map.destroy(); if (seriesHandle) seriesHandle.destroy(); });

  paintLatest();
  await Promise.all([load(), loadFeed()]);
}
