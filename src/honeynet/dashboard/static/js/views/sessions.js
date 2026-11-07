import { h, mount, clear, api, qs, num, dateTime, clock, ago, duration, safeText, visible, ipLink, sessionLink, sampleLink, svcTag, clsBadge, attackLink, emptyState, bytes, short, plural } from "../util.js";
import { table, miniColumns, hbars } from "../charts.js";

// ---------------------------------------------------------------------------- list
export async function sessions(root, ctx) {
  let service = "", onlyCmds = true, ip = "", offset = 0;
  const PAGE = 50;
  const body = h("div"), more = h("button", { text: "Load more", class: "hidden" });
  const svcSel = h("select", { "aria-label": "Service", onchange: (e) => { service = e.target.value; reset(); } },
    [["", "All services"], ["ssh", "SSH"], ["telnet", "Telnet"], ["http", "HTTP"], ["mysql", "MySQL"], ["redis", "Redis"]].map(([v, l]) => h("option", { value: v, text: l })));
  const cmdBox = h("input", { type: "checkbox", checked: true, onchange: (e) => { onlyCmds = e.target.checked; reset(); } });
  const ipIn = h("input", { type: "search", placeholder: "filter by IP", "aria-label": "Source IP", size: 18,
    onchange: (e) => { ip = e.target.value.trim(); reset(); } });
  const tbody = h("tbody");
  const tbl = h("div", { class: "tablewrap" }, h("table", null,
    h("thead", null, h("tr", null, ["Started", "Service", "Source", "Login", "Client", "Duration", "Cmds", "Files", "Class", ""].map((t, i) => h("th", { class: i === 6 || i === 7 ? "num" : "", text: t })))), tbody));

  mount(root,
    h("div", { class: "page-head" }, h("h1", { text: "Sessions" }), h("span", { class: "sub", text: "recorded attacker sessions - open one to replay it" })),
    h("div", { class: "filters" }, svcSel, h("label", null, cmdBox, "Only sessions with commands or queries"), ipIn),
    h("section", { class: "card flush" }, tbl, body), h("div", { style: { padding: "12px 0" } }, more));

  async function page() {
    more.disabled = true;
    const rows = await api("/api/sessions" + qs({ limit: PAGE, offset, service, ip, with_commands: onlyCmds ? "true" : "" }));
    rows.forEach((s) => tbody.append(h("tr", null,
      h("td", { class: "nowrap", title: dateTime(s.first_ts), text: ago(s.first_ts) }), h("td", null, svcTag(s.service)),
      h("td", null, ipLink(s.src_ip), " ", h("span", { class: "muted", text: s.country || "" })),
      h("td", { class: "mono break", text: safeText(s.username ? `${s.username}:${s.password || ""}` : (s.method || "")) }),
      h("td", { class: "muted", text: safeText(short(s.client || "", 28)) }),
      h("td", { text: duration(s.duration) }), h("td", { class: "num", text: num(s.commands + s.queries) }), h("td", { class: "num", text: num(s.files) }),
      h("td", null, clsBadge(s.classification)), h("td", null, sessionLink(s.id, "Replay")))));
    offset += rows.length;
    more.classList.toggle("hidden", rows.length < PAGE);
    more.disabled = false;
    if (!tbody.firstChild) mount(body, emptyState("No sessions match"));
    else clear(body);
  }
  function reset() { clear(tbody); offset = 0; page(); }
  more.addEventListener("click", page);
  await page();
}

// ---------------------------------------------------------------------------- replay
function kv(d) {
  return Object.entries(d || {}).filter(([, v]) => v !== "" && v !== null && v !== undefined)
    .map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join("  ");
}

// A frame -> array of {cls, nodes} lines for the terminal.
function frameLines(f, s) {
  const L = (cls, ...text) => ({ cls, text: text.join("") });
  const d = f.data || {};
  switch (f.event) {
    case "conn.open": return [L("meta", `── connection opened from ${s.src_ip}:${s.src_port ?? "?"} to port ${s.dst_port ?? "?"}`)];
    case "conn.close": return [L("meta", `── connection closed${d.reason ? " (" + d.reason + ")" : ""}`)];
    case "client.fingerprint": return [L("meta", `fingerprint: ${kv(d)}`)];
    case "auth.attempt": return [L(f.success ? "warn" : "meta", `login ${f.success ? "ACCEPTED" : "rejected"}: ${f.username}:${f.password}${f.method ? "  [" + f.method + "]" : ""}`)];
    case "session.open": return [L("meta", `── session opened ${kv({ user: d.username, client: d.client_version || d.client })}`)];
    case "session.close": return [L("meta", `── session closed ${kv({ duration: d.duration, reason: d.reason })}`)];
    case "session.exec": return [{ cls: "cmd", prompt: "exec$ ", text: String(d.command || "") }];
    case "cmd.input": {
      const out = [{ cls: "cmd", prompt: `${f.user || "root"}@host:${f.cwd || "~"}${f.user === "root" || !f.user ? "#" : "$"} `, text: String(f.input ?? "") }];
      if (f.output) out.push(L("out", String(f.output).replace(/\n$/, "")));
      (f.attack || []).forEach((a) => out.push(L("meta", `   ↳ ATT&CK ${a.id} ${a.name}`)));
      return out;
    }
    case "download.attempt": return [L("warn", `⇣ download ${d.via ? "(" + d.via + ") " : ""}${d.url || ""}${d.fetched ? "  [fetched]" : "  [not fetched - recorded only]"}`)];
    case "file.captured": return [L("warn", `■ file captured ${short(d.sha256 || "", 16)} ${bytes(d.size)} ${d.path || ""}`), { cls: "sample", sha: d.sha256 }];
    case "file.exec_attempt": return [L("bad", `▶ executing dropped file blocked: ${d.path || ""} ${(d.args || []).join(" ")}  (honeypot never runs samples)`)];
    case "exploit.attempt": return [L("bad", `⚠ exploit [${d.category || "?"}] ${d.rule || ""} ${d.cve || ""}  ${d.path || d.snippet || ""}`)];
    case "http.request": return [L("out", `${d.method || "?"} ${d.path || ""}  ${d.ua || d.user_agent || ""}`)];
    case "db.query": return [L("out", `${d.engine || "db"}> ${d.query || d.command || ""}`)];
    case "cron.install": return [L("warn", `crontab installed:\n${d.crontab || ""}`)];
    case "net.outbound_attempt": return [L("warn", `↗ outbound blocked: ${d.tool || ""} ${d.target || ""} ${d.args || ""}`)];
    case "sftp.open": return [L("warn", `sftp ${d.write ? "write" : "read"} ${d.path || ""}`)];
    case "probe": return [L("meta", `probe: ${kv(d)}`)];
    default: return [L("meta", `${f.event} ${kv(d)}`)];
  }
}

export async function session(root, ctx) {
  const sid = ctx.params[0];
  const s = await api("/api/sessions/" + encodeURIComponent(sid));
  const frames = s.frames || [];
  const term = h("div", { class: "term", role: "log", tabindex: 0, "aria-label": "Session transcript" });
  const pos = h("span", { class: "muted num", text: "" });
  const scrub = h("input", { type: "range", min: 0, max: frames.length, value: frames.length, "aria-label": "Replay position" });
  let timer = null, idx = frames.length, speed = 1;

  function paint(upTo) {
    clear(term);
    for (let i = 0; i < upTo; i++) addFrame(frames[i], false);
    pos.textContent = `${upTo} / ${frames.length}`;
    term.scrollTop = term.scrollHeight;
  }
  function addFrame(f) {
    for (const ln of frameLines(f, s)) {
      if (ln.cls === "sample") { if (ln.sha) term.append(h("div", { class: "meta" }, "   ↳ ", sampleLink(ln.sha, "view analysis"))); continue; }
      term.append(h("div", { class: ln.cls }, ...(ln.prompt !== undefined
        ? [h("span", { class: "prompt" }, ...visible(ln.prompt)), h("span", { class: "cmd" }, ...visible(ln.text))] : visible(ln.text))));
    }
  }
  function stop() { clearTimeout(timer); timer = null; playBtn.textContent = "Replay"; }
  function step() {
    if (idx >= frames.length) { stop(); return; }
    addFrame(frames[idx]); idx++;
    scrub.value = idx; pos.textContent = `${idx} / ${frames.length}`;
    term.scrollTop = term.scrollHeight;
    if (idx >= frames.length) { stop(); return; }
    const gap = Math.min(1.6, Math.max(0.04, frames[idx].t - frames[idx - 1].t)) * 1000 / speed;
    timer = setTimeout(step, gap);
  }
  const playBtn = h("button", { class: "primary", text: "Replay", onclick: () => {
    if (timer) { stop(); return; }
    if (idx >= frames.length) { idx = 0; paint(0); scrub.value = 0; }
    playBtn.textContent = "Pause"; step();
  } });
  scrub.addEventListener("input", () => { stop(); idx = Number(scrub.value); paint(idx); });
  const speedSel = h("select", { "aria-label": "Replay speed", onchange: (e) => { speed = Number(e.target.value); } },
    [1, 2, 5, 20].map((v) => h("option", { value: v, text: v + "×" })));
  ctx.onCleanup(stop);

  const info = h("dl", { class: "kv" },
    h("dt", { text: "Source" }), h("dd", null, ipLink(s.src_ip), " ", [s.country_name, s.org].filter(Boolean).map(safeText).join(", ")),
    h("dt", { text: "Service" }), h("dd", null, svcTag(s.service), ` port ${s.dst_port ?? "?"}`),
    h("dt", { text: "Started" }), h("dd", { text: `${dateTime(s.first_ts)} (${duration(s.duration)})` }),
    h("dt", { text: "Login" }), h("dd", { class: "mono", text: safeText(s.username ? `${s.username} / ${s.password || ""}  (${s.method || ""})` : "none") }),
    h("dt", { text: "Client" }), h("dd", { class: "mono", text: safeText(s.client || "–") }),
    s.hassh ? [h("dt", { text: "HASSH" }), h("dd", { class: "mono", text: safeText(s.hassh) })] : null,
    h("dt", { text: "Class" }), h("dd", null, clsBadge(s.classification)),
    h("dt", { text: "Activity" }), h("dd", { text: [[s.commands, "command"], [s.downloads, "download"], [s.files, "file"], [s.exploits, "exploit"], [s.queries, "query", "queries"]].filter(([n]) => n).map(([n, w, m]) => plural(n, w, m)).join(", ") || "nothing recorded" }));

  mount(root,
    h("div", { class: "crumbs" }, h("a", { href: "#/sessions", text: "Sessions" }), " / ", h("span", { class: "mono", text: sid })),
    h("div", { class: "page-head" }, h("h1", { text: "Session replay" }), svcTag(s.service)),
    h("div", { class: "grid g-map" },
      h("section", { class: "card" },
        h("div", { class: "player" }, playBtn, h("label", null, "Speed ", speedSel), scrub, pos,
          h("button", { class: "ghost", text: "Show all", onclick: () => { stop(); idx = frames.length; scrub.value = idx; paint(idx); } })),
        term,
        h("p", { class: "muted", text: "Control characters from the attacker are shown as escapes like \\e or \\x07 and are never interpreted. Nothing here executes." })),
      h("div", { class: "grid" },
        h("section", { class: "card" }, h("header", null, h("h2", { text: "Details" })), info),
        h("section", { class: "card" }, h("header", null, h("h2", { text: "MITRE ATT&CK" })),
          (s.attack || []).length ? (s.attack || []).map((a) => h("div", { class: "techrow" }, attackLink(a.id), h("span", { text: safeText(a.name) }), h("span", { class: "muted", text: `seen ${plural(a.n, "time")}, ${safeText(a.tactic)}` }))) : emptyState("No techniques mapped")))));
  paint(frames.length);
}

// ---------------------------------------------------------------------------- IP profile
export async function ipProfile(root, ctx) {
  const ip = decodeURIComponent(ctx.params[0]);
  const p = await api("/api/ips/" + encodeURIComponent(ip));
  const i = p.info;
  const tl = (p.timeline || []).slice().reverse();
  mount(root,
    h("div", { class: "crumbs" }, h("a", { href: "#/", text: "Overview" }), " / IP"),
    h("div", { class: "page-head" }, h("h1", { class: "mono", text: safeText(ip) }), clsBadge(i.classification), (i.tags || []).map((t) => h("span", { class: "chip", text: safeText(t) }))),
    h("div", { class: "grid g2" },
      h("section", { class: "card" }, h("header", null, h("h2", { text: "Profile" })), h("dl", { class: "kv" },
        h("dt", { text: "Location" }), h("dd", { text: safeText([i.city, i.country_name || i.country].filter(Boolean).join(", ") || "unknown") }),
        h("dt", { text: "Network" }), h("dd", { text: safeText(i.asn ? `AS${i.asn} ${i.org || ""}` : i.org || "unknown") }),
        h("dt", { text: "First / last seen" }), h("dd", { text: `${dateTime(i.first_seen)} to ${dateTime(i.last_seen)}` }),
        h("dt", { text: "Volume" }), h("dd", { text: [plural(i.events, "event"), plural(i.conns, "connection"), `${num(i.auth)} logins tried`, plural(i.cmds, "command"), plural(i.exploits, "exploit"), plural(i.files, "file")].join(", ") }),
        h("dt", { text: "Services hit" }), h("dd", null, (i.services || []).map((s) => svcTag(s)).flatMap((n) => [n, " "])),
        h("dt", { text: "Ports" }), h("dd", { class: "mono", text: (i.ports || []).join(", ") }),
        h("dt", { text: "AbuseIPDB" }), h("dd", { text: i.abuse_score == null ? "not checked (optional, off by default)" : `${i.abuse_score}% confidence of abuse (checked ${ago(i.abuse_checked)})` }))),
      h("section", { class: "card" }, h("header", null, h("h2", { text: "Activity" }), h("span", { class: "sub", text: "events per hour" })),
        tl.length ? miniColumns(tl.map((t) => t.n), { height: 90, label: "events" }) : emptyState("No timeline"))),
    h("div", { class: "grid g3", style: { "margin-top": "14px" } },
      h("section", { class: "card" }, h("header", null, h("h2", { text: "Credentials tried" })),
        table([{ label: "Username", key: "username", cls: "mono" }, { label: "Password", key: "password", cls: "mono" }, { label: "×", num: true, key: "n" }, { label: "OK", render: (r) => (r.ok ? "yes" : "") }], p.credentials)),
      h("section", { class: "card" }, h("header", null, h("h2", { text: "Exploit rules" })),
        table([{ label: "Rule", key: "rule", cls: "mono" }, { label: "CVE", key: "cve" }, { label: "×", num: true, key: "n" }], p.exploits)),
      h("section", { class: "card" }, h("header", null, h("h2", { text: "ATT&CK" })),
        p.techniques.length ? p.techniques.map((t) => h("div", null, attackLink(t.id), " ", safeText(t.name), h("span", { class: "muted", text: ` ×${t.n}` }))) : emptyState("None"))),
    h("section", { class: "card flush", style: { "margin-top": "14px" } }, h("header", null, h("h2", { text: "Sessions" })),
      table([{ label: "When", render: (s) => h("span", { title: dateTime(s.first_ts), text: ago(s.first_ts) }) }, { label: "Service", render: (s) => svcTag(s.service) },
        { label: "Login", cls: "mono", render: (s) => safeText(s.username ? `${s.username}:${s.password || ""}` : "") }, { label: "Cmds", num: true, render: (s) => s.commands + s.queries },
        { label: "", render: (s) => sessionLink(s.id, "Replay") }], p.sessions)),
    p.commands.length ? h("section", { class: "card", style: { "margin-top": "14px" } }, h("header", null, h("h2", { text: "Commands" })),
      h("div", { class: "term" }, p.commands.map((c) => h("div", null, h("span", { class: "meta", text: clock(c.ts) + "  " }), h("span", { class: "cmd" }, ...visible(c.input)))))) : null,
    p.samples.length ? h("section", { class: "card", style: { "margin-top": "14px" } }, h("header", null, h("h2", { text: "Files dropped" })),
      table([{ label: "SHA-256", render: (r) => sampleLink(r.sha256) }, { label: "Family", render: (r) => safeText(r.family_name || "pending analysis") }, { label: "Size", num: true, render: (r) => bytes(r.size) }], p.samples)) : null);
}
