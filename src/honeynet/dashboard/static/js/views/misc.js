import { h, mount, clear, api, qs, num, compact, dateTime, ago, safeText, visible, ipLink, svcTag, levelBadge, attackLink, emptyState, bytes, copy, debounce, toast, duration, pct } from "../util.js";
import { table, showTip, hideTip } from "../charts.js";

// ---------------------------------------------------------------------------- ATT&CK matrix
function level(n, max) {
  if (!n) return 0;
  return Math.max(1, Math.min(5, Math.ceil((Math.log10(n + 1) / Math.log10(max + 1)) * 5)));
}

export async function attack(root, ctx) {
  const hours = ctx.hours;
  const d = await api("/api/attack" + qs({ hours }));
  const max = Math.max(1, ...d.tactics.flatMap((t) => t.techniques.map((x) => x.n)));
  const seen = d.tactics.flatMap((t) => t.techniques).filter((x) => x.n > 0).length;
  mount(root,
    h("div", { class: "page-head" }, h("h1", { text: "MITRE ATT&CK" }),
      h("span", { class: "sub", text: `${seen} techniques observed in the last ${hours >= 48 ? Math.round(hours / 24) + " days" : hours + " hours"}, ${num(d.total)} hits in all` })),
    h("p", { class: "muted", text: "Techniques are inferred from what attackers actually did in the honeypots (commands, exploit rules, scans, credential guessing). Darker = more hits. Click a technique to open it on attack.mitre.org." }),
    h("div", { class: "legend" }, ["transparent", "var(--seq-1)", "var(--seq-2)", "var(--seq-3)", "var(--seq-5)", "var(--seq-6)"].map((c, l) =>
      h("span", null, h("i", { class: "swatch", style: { background: c, border: "1px solid var(--axis)" } }), l === 0 ? "none" : l === 5 ? `${compact(max)}+ hits` : ""))),
    h("div", { class: "matrix" }, d.tactics.map((t) => h("div", { class: "col" },
      h("h3", { text: t.name }),
      t.techniques.map((x) => {
        const a = h("a", { class: `tech l${level(x.n, max)}`, href: x.url, target: "_blank", rel: "noopener noreferrer nofollow" },
          x.n ? h("span", { class: "tn", text: compact(x.n) }) : null, h("span", { class: "tid", text: x.id }), safeText(x.name));
        const ex = d.examples[x.id];
        const show = (px, py) => showTip(px, py, `${x.id} ${x.name}`, [{ label: "hits", value: num(x.n) }, { label: "distinct IPs", value: num(x.ips) }, { label: "last", value: x.last ? ago(x.last) : "never" }].concat(ex ? [{ label: "example", value: safeText(ex).slice(0, 60) }] : []));
        a.addEventListener("pointermove", (e) => show(e.clientX, e.clientY));
        a.addEventListener("pointerleave", hideTip);
        a.addEventListener("focus", () => { const b = a.getBoundingClientRect(); show(b.left + 30, b.top + 10); });
        a.addEventListener("blur", hideTip);
        return a;
      })))));
}

// ---------------------------------------------------------------------------- IOCs + exports
function dl(label, href, note) {
  return h("div", { style: { margin: "6px 0" } }, h("a", { class: "chip", href, download: "", text: label }), note ? h("span", { class: "muted", text: " " + note }) : null);
}

export async function iocs(root) {
  let type = "", kind = "", q = "";
  const body = h("tbody");
  const formats = ["txt", "csv", "json", "ipset", "iptables", "nft", "ufw", "pf"];
  const level_ = h("select", { "aria-label": "Blocklist level" }, [["suspicious", "malicious + suspicious"], ["malicious", "malicious only"], ["all", "everything seen"]].map(([v, l]) => h("option", { value: v, text: l })));
  const days = h("select", { "aria-label": "Window" }, [[7, "last 7 days"], [30, "last 30 days"], [90, "last 90 days"]].map(([v, l]) => h("option", { value: v, text: l })));
  days.value = "30";
  const links = h("div");
  const drawLinks = () => mount(links,
    h("div", { class: "muted", text: "Only public, non-allow-listed addresses are exported; your own IP and secrets are always removed." }),
    h("div", null, formats.map((f) => h("a", { class: "chip", href: `/api/export/blocklist${qs({ fmt: f, level: level_.value, days: days.value })}`, download: "", text: f }))));
  level_.addEventListener("change", drawLinks); days.addEventListener("change", drawLinks);
  drawLinks();

  const typeSel = h("select", { "aria-label": "Type", onchange: (e) => { type = e.target.value; load(); } },
    [["", "All types"], ["ip", "IP"], ["domain", "Domain"], ["url", "URL"], ["endpoint", "IP:port"], ["wallet", "Wallet"], ["hash", "Hash"], ["path", "Path"], ["credential", "Credential"], ["mutex", "Mutex"]].map(([v, l]) => h("option", { value: v, text: l })));
  const kindSel = h("select", { "aria-label": "Origin", onchange: (e) => { kind = e.target.value; load(); } },
    [["", "Observed + analysed"], ["observed", "Observed live"], ["analysis", "From sample analysis"], ["both", "Confirmed by both"]].map(([v, l]) => h("option", { value: v, text: l })));
  const search = h("input", { type: "search", placeholder: "search indicators", "aria-label": "Search", oninput: debounce((e) => { q = e.target.value.trim(); load(); }, 250) });

  mount(root,
    h("div", { class: "page-head" }, h("h1", { text: "Indicators & exports" })),
    h("div", { class: "grid g3" },
      h("section", { class: "card" }, h("header", null, h("h2", { text: "Blocklist" }), h("span", { class: "sub", text: "attacker source IPs" })),
        h("div", { class: "filters" }, level_, days), links,
        h("p", { class: "muted", text: "ipset / iptables / nft / ufw / pf are ready-to-load rule files for your own gateway. Review before loading; classification can include shared NAT or scanners you want to keep." })),
      h("section", { class: "card" }, h("header", null, h("h2", { text: "C2 & payload hosts" }), h("span", { class: "sub", text: "from sample analysis + captured URLs" })),
        dl("C2 IPs (txt)", "/api/export/c2?what=ips&fmt=txt"), dl("C2 domains (txt)", "/api/export/c2?what=domains&fmt=txt"), dl("Payload URLs (txt)", "/api/export/c2?what=urls&fmt=txt"), dl("All C2 indicators (json)", "/api/export/c2?fmt=json")),
      h("section", { class: "card" }, h("header", null, h("h2", { text: "IOC feed & reports" })),
        dl("IOCs (JSON)", "/api/export/iocs?fmt=json&min_confidence=0.4"), dl("IOCs (CSV)", "/api/export/iocs?fmt=csv&min_confidence=0.4", "formula-safe"),
        dl("Daily summary - last 24h (HTML)", "/api/export/report?fmt=html&hours=24"), dl("Daily summary (Markdown)", "/api/export/report?fmt=md&hours=24"), dl("Daily summary (JSON)", "/api/export/report?fmt=json&hours=24"))),
    h("div", { class: "filters", style: { "margin-top": "16px" } }, typeSel, kindSel, search),
    h("section", { class: "card flush" }, h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Type", "Indicator", "Origin", "Conf.", "Scope", "Context", "Hits", "Last seen", ""].map((t, i) => h("th", { class: i === 3 || i === 6 ? "num" : "", text: t })))), body))));

  async function load() {
    const rows = await api("/api/iocs" + qs({ type, kind, q, limit: 300 }));
    mount(body, rows.length ? rows.map((r) => h("tr", null,
      h("td", null, h("span", { class: "badge", text: r.type })), h("td", { class: "mono break" }, ...visible(r.value)),
      h("td", { text: r.kind }), h("td", { class: "num", text: pct(r.confidence) }), h("td", { class: "muted", text: r.scope }),
      h("td", { class: "muted", text: safeText(r.context || "") }), h("td", { class: "num", text: num(r.hits) }),
      h("td", { class: "nowrap", title: dateTime(r.last_seen), text: ago(r.last_seen) }),
      h("td", null, h("button", { class: "ghost", text: "copy", onclick: () => copy(r.value) })))) : h("tr", null, h("td", { colspan: 9 }, emptyState("No indicators yet"))));
  }
  await load();
}

// ---------------------------------------------------------------------------- alerts
export async function alerts(root, ctx) {
  const list = h("div");
  const ch = h("span");
  async function load() {
    const d = await api("/api/alerts?limit=200");
    mount(ch, d.channels.length ? d.channels.map((c) => h("span", { class: "chip", text: c })) : h("span", { class: "muted", text: "No delivery channel configured - alerts are kept here only. Set HONEYNET_ALERT_WEBHOOK_URL and/or the SMTP variables." }));
    document.dispatchEvent(new CustomEvent("honeynet:alerts", { detail: d.alerts.filter((a) => !a.acked).length }));
    mount(list, d.alerts.length ? d.alerts.map((a) => h("div", { class: "alert-row" + (a.acked ? " acked" : "") },
      h("span", { class: "muted nowrap", title: dateTime(a.ts), text: ago(a.ts) }), levelBadge(a.severity),
      h("div", null, h("strong", { text: safeText(a.title) }), h("div", { class: "body ink2" }, ...visible(a.detail)),
        h("span", { class: "muted", text: `${a.kind}, ${a.delivered ? "delivered" : "not delivered"}` }),
        /^[0-9a-f]{64}$/.test(a.key || "") ? [", ", h("a", { href: `#/sample/${a.key}`, text: "open sample" })] : null),
      a.acked ? h("span", { class: "muted", text: "acknowledged" }) : h("button", { text: "Acknowledge", onclick: async () => { await api("/api/alerts/ack", { method: "POST", json: { id: a.id } }); load(); } }))) : emptyState("No alerts yet"));
  }
  mount(root,
    h("div", { class: "page-head" }, h("h1", { text: "Alerts" }), ch, h("span", { class: "spacer" }),
      h("button", { text: "Acknowledge all", onclick: async () => { await api("/api/alerts/ack", { method: "POST", json: {} }); load(); } })),
    h("section", { class: "card" }, list));
  await load();
  const t = setInterval(() => load().catch(() => {}), 30000);
  ctx.onCleanup(() => clearInterval(t));
}

// ---------------------------------------------------------------------------- system
export async function system(root) {
  const [hl, cf] = await Promise.all([api("/api/health"), api("/api/config")]);
  const yesno = (v, on = "enabled", off = "off") => h("span", { class: `badge ${v ? "benign" : "unknown"}`, text: v ? on : off });
  mount(root,
    h("div", { class: "page-head" }, h("h1", { text: "System" }), h("span", { class: "sub", text: `honeynet ${safeText(cf.version)}${cf.test_mode ? " (test mode)" : ""}` })),
    cf.test_mode ? h("section", { class: "card", style: { "margin-bottom": "14px", "border-color": "var(--warn)" } }, h("strong", { text: "Test mode. " }),
      "Documentation-range addresses are accepted as attackers, locations are simulated and the dashboard may run without a password. Never use test mode on a public host.") : null,
    h("div", { class: "grid g2" },
      h("section", { class: "card" }, h("header", null, h("h2", { text: "Pipeline" })), h("dl", { class: "kv" },
        h("dt", { text: "Dashboard uptime" }), h("dd", { text: duration(hl.uptime) }),
        h("dt", { text: "Events stored" }), h("dd", { text: num(hl.events_total) }),
        h("dt", { text: "Rejected lines" }), h("dd", { text: `${num(hl.rejected_lines)} (malformed or hostile event lines dropped by the parser)` }),
        h("dt", { text: "Samples awaiting analysis" }), h("dd", { text: num(hl.analysis_pending) }),
        h("dt", { text: "Database" }), h("dd", { text: bytes(hl.db_bytes) }),
        h("dt", { text: "Retention" }), h("dd", { text: `${cf.retention_days} days` }),
        h("dt", { text: "Analysis backend" }), h("dd", { text: safeText(cf.analysis_backend) }))),
      h("section", { class: "card" }, h("header", null, h("h2", { text: "Enrichment & alerts" })), h("dl", { class: "kv" },
        h("dt", { text: "GeoIP / ASN" }), h("dd", null, cf.geoip_simulated ? h("span", { class: "badge medium", text: "simulated (test mode)" }) : yesno((cf.geoip || []).length, `${(cf.geoip || []).join(", ")} (offline)`, "no GeoLite2 files found")),
        h("dt", { text: "AbuseIPDB" }), h("dd", null, yesno(cf.abuseipdb, "enabled (daily budget)", "off (optional)")),
        h("dt", { text: "MalwareBazaar" }), h("dd", null, yesno(cf.bazaar, "enabled (hash-only)", "off (optional)")),
        h("dt", { text: "Alert channels" }), h("dd", { text: cf.alert_channels.length ? cf.alert_channels.join(", ") : "none" })))),
    h("section", { class: "card flush", style: { "margin-top": "14px" } }, h("header", null, h("h2", { text: "Honeypot services" }), h("span", { class: "sub", text: "events received per service" })),
      table([{ label: "Service", render: (r) => svcTag(r.service) }, { label: "Listening on", cls: "mono", render: (r) => (cf.ports[r.service] || []).join(", ") }, { label: "Events", num: true, key: "events" },
        { label: "Last event", render: (r) => ago(r.last) }], hl.services)));
}
