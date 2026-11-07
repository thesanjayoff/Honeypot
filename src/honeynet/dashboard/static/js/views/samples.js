import { h, mount, clear, api, qs, num, dateTime, ago, safeText, visible, ipLink, sessionLink, sampleLink, svcTag, levelBadge, attackLink, emptyState, bytes, pct, copy, debounce, toast, short } from "../util.js";
import { table, miniColumns } from "../charts.js";

const STATUS_LABEL = { pending: "queued for analysis", analyzed: "analysed", failed: "analysis failed" };

function meter(value, max, level) {
  const w = Math.max(2, Math.min(100, (value / max) * 100));
  return h("div", { class: `meter ${level || ""}`, role: "meter", "aria-valuenow": Math.round(value), "aria-valuemin": 0, "aria-valuemax": max },
    h("i", { style: { width: w + "%" } }));
}

// ---------------------------------------------------------------------------- list
export async function samples(root) {
  let q = "";
  const body = h("tbody");
  const search = h("input", { type: "search", placeholder: "search SHA-256, MD5 or family", "aria-label": "Search samples", size: 30,
    oninput: debounce((e) => { q = e.target.value.trim(); load(); }, 250) });
  mount(root,
    h("div", { class: "page-head" }, h("h1", { text: "Captured samples" }),
      h("span", { class: "sub", text: "stored in quarantine, analysed statically in a network-less container, never executed" })),
    h("div", { class: "filters" }, search),
    h("section", { class: "card flush" }, h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["First seen", "SHA-256", "Family", "Risk", "Type", "Size", "Seen", "Sources", "Status"].map((t, i) => h("th", { class: i === 5 || i === 6 || i === 7 ? "num" : "", text: t })))), body))));
  async function load() {
    const rows = await api("/api/samples" + qs({ limit: 200, q }));
    mount(body, rows.map((s) => h("tr", null,
      h("td", { class: "nowrap", title: dateTime(s.first_seen), text: ago(s.first_seen) }),
      h("td", null, sampleLink(s.sha256)),
      h("td", null, s.family_name ? [safeText(s.family_name), " ", h("span", { class: "muted", text: pct(s.family_conf) })] : h("span", { class: "muted", text: "–" })),
      h("td", null, s.risk_level ? [levelBadge(s.risk_level), " ", h("span", { class: "muted num", text: s.risk_score })] : "–"),
      h("td", { class: "muted", text: safeText([s.file_type, s.arch !== "unknown" ? s.arch : ""].filter(Boolean).join(", ")) }),
      h("td", { class: "num", text: bytes(s.size) }), h("td", { class: "num", text: num(s.count) }), h("td", { class: "num", text: num(s.sources) }),
      h("td", null, h("span", { class: `badge ${s.status === "failed" ? "high" : s.status === "pending" ? "medium" : "info"}`, text: STATUS_LABEL[s.status] || s.status }),
        s.bazaar && s.bazaar.known ? h("span", { class: "badge high", title: "MalwareBazaar knows this hash", text: " in MalwareBazaar" }) : null))));
    if (!rows.length) mount(body, h("tr", null, h("td", { colspan: 9 }, emptyState("No samples captured yet"))));
  }
  await load();
}

// ---------------------------------------------------------------------------- report helpers
function snippetBlock(rep, key) {
  const sn = rep.snippets && rep.snippets[key];
  if (!sn) return null;
  const hl = sn.highlight;
  return h("div", { class: "snippet" },
    h("div", { class: "ttl", text: `${sn.kind}: ${safeText(sn.title || key)}` }),
    h("pre", { tabindex: 0 }, sn.lines.map((ln, i) => h("span", { class: "ln" + (i === hl ? " hl" : "") }, ...visible(ln), "\n"))));
}

function snippetToggle(rep, key, label = "show code") {
  if (!key || !rep.snippets || !rep.snippets[key]) return null;
  const holder = h("div");
  const btn = h("button", { class: "ghost", "aria-expanded": "false", text: label, onclick: () => {
    const open = btn.getAttribute("aria-expanded") === "true";
    btn.setAttribute("aria-expanded", String(!open));
    btn.textContent = open ? label : "hide code";
    if (open) clear(holder); else mount(holder, snippetBlock(rep, key));
  } });
  return h("span", null, btn, holder);
}

function finding(rep, b) {
  const evs = b.evidence || [];
  return h("div", { class: "finding" },
    h("div", { class: "fh" },
      h("h3", { text: b.title }), h("span", { class: "badge", text: b.category.replace(/_/g, " ") }),
      h("span", { class: `sevbar s${b.severity}`, title: `severity ${b.severity} of 5` }, [1, 2, 3, 4, 5].map((i) => h("i", { class: i <= b.severity ? "on" : "" }))),
      h("span", { class: "muted", text: `confidence ${pct(b.confidence)}` }), (b.mitre || []).map((t) => attackLink(t))),
    h("p", { text: b.description }),
    evs.slice(0, 8).map((e) => h("div", { class: "ev" },
      h("div", { class: "evh" }, h("span", { class: "badge", text: e.kind }),
        h("code", { class: "break" }, ...visible(short(e.detail, 160))),
        h("span", { class: "muted", text: e.address != null ? `@ 0x${Number(e.address).toString(16)}` : e.offset != null ? `offset 0x${Number(e.offset).toString(16)}` : e.line ? `line ${e.line}` : "" }),
        snippetToggle(rep, e.snippet)),
      e.pseudocode ? h("pre", { class: "snippet" }, ...visible(e.pseudocode)) : null)),
    evs.length > 8 ? h("div", { class: "muted", text: `+ ${evs.length - 8} more evidence items in the JSON report` }) : null);
}

function iocTable(rep, rows) {
  return table([
    { label: "Type", render: (r) => h("span", { class: "badge", text: r.type }) },
    { label: "Indicator", cls: "mono break", render: (r) => h("span", null, ...visible(r.value)) },
    { label: "Conf.", num: true, render: (r) => pct(r.confidence) },
    { label: "Scope", render: (r) => safeText(r.scope || "") },
    { label: "Where", render: (r) => h("span", null, safeText(r.context || r.kind || ""), " ", snippetToggle(rep, r.snippet, "code")) },
    { label: "", render: (r) => h("button", { class: "ghost", text: "copy", onclick: () => copy(r.value) }) },
  ], rows);
}

// ---------------------------------------------------------------------------- report page
export async function sample(root, ctx) {
  const sha = ctx.params[0];
  const d = await api("/api/samples/" + encodeURIComponent(sha));
  const rep = d.report;
  const bz = d.bazaar;
  const head = h("section", { class: "card" });

  const hashRow = (label, v) => v ? [h("dt", { text: label }), h("dd", null, h("span", { class: "mono", text: v }), " ", h("button", { class: "ghost", text: "copy", onclick: () => copy(v) }))] : null;
  const fam = rep && rep.family;
  const kvEl = h("dl", { class: "kv" },
    hashRow("SHA-256", d.sha256), hashRow("MD5", (rep && rep.md5) || (d.md5 && !/^0+$/.test(d.md5) ? d.md5 : "")), hashRow("SHA-1", rep && rep.sha1),
    h("dt", { text: "File" }), h("dd", { text: safeText(rep ? `${rep.file.description}, ${rep.file.arch !== "unknown" ? rep.file.arch + ", " : ""}${bytes(rep.size)}${rep.truncated ? " (truncated for analysis)" : ""}` : `${d.file_type || "unknown"}, ${bytes(d.size)}`) }),
    h("dt", { text: "Seen" }), h("dd", { text: `${num(d.count)}× between ${dateTime(d.first_seen)} and ${dateTime(d.last_seen)}` }),
    h("dt", { text: "MalwareBazaar" }), h("dd", null, bz ? (bz.known ? [h("span", { class: "badge high", text: "known" }), " ", safeText([bz.signature, bz.file_type, (bz.tags || []).join(" ")].filter(Boolean).join(", "))] : h("span", { class: "badge benign", text: "not found (hash-only lookup)" })) : "not checked",
      d.bazaar_enabled ? [" ", h("button", { class: "ghost", text: "look up hash", onclick: async () => { try { await api(`/api/samples/${sha}/lookup`, { method: "POST", json: {} }); toast("Lookup queued - the file itself is never uploaded"); } catch (e) { toast(e.message); } } })] : [" ", h("span", { class: "muted", text: "(optional; off - set HONEYNET_BAZAAR_ENABLED + key)" })]));

  mount(head,
    h("div", { class: "page-head" }, h("div", null, h("div", { class: "crumbs" }, h("a", { href: "#/samples", text: "Samples" }), " / ", h("span", { class: "mono", text: sha.slice(0, 16) + "…" })),
      h("h1", { text: fam ? fam.name : "Sample" })),
      rep ? levelBadge(rep.risk.level) : null, h("span", { class: "spacer" }),
      rep ? h("a", { class: "chip", href: `/api/samples/${sha}/report.json`, text: "download JSON report" }) : null),
    kvEl);

  const sections = [head];
  if (!rep) {
    sections.push(h("section", { class: "card" }, h("header", null, h("h2", { text: "Analysis" })),
      h("p", { text: `This sample is ${STATUS_LABEL[d.status] || d.status}. The analyser container picks up new files from quarantine automatically; reload in a few seconds.` })));
  } else {
    sections.push(
      h("div", { class: "grid g2" },
        h("section", { class: "card" }, h("header", null, h("h2", { text: "Family" }), h("span", { class: "sub", text: "explainable score - every reason below was found in the file" })),
          h("div", { class: "page-head" }, h("strong", { text: fam.name }), h("div", { style: { width: "160px" } }, meter(fam.confidence * 100, 100, fam.confidence > 0.7 ? "" : "medium")), h("span", { class: "muted", text: pct(fam.confidence) + " confidence" })),
          h("p", { class: "ink2", text: fam.description }),
          h("ul", null, fam.reasons.map((r) => h("li", { text: r }))),
          rep.alternatives && rep.alternatives.length ? h("div", null, h("h3", { text: "Other candidates considered" }),
            rep.alternatives.slice(0, 4).map((a) => h("div", { class: "muted", text: `${a.name} - ${pct(a.confidence)} (${a.reasons.slice(0, 2).join("; ")})` }))) : null),
        h("section", { class: "card" }, h("header", null, h("h2", { text: "Risk" })),
          h("div", { class: "page-head" }, h("strong", { class: "num", text: `${rep.risk.score} / 100` }), h("div", { style: { width: "160px" } }, meter(rep.risk.score, 100, rep.risk.level)), levelBadge(rep.risk.level)),
          h("h3", { text: "MITRE ATT&CK (from static findings)" }),
          (rep.mitre || []).length ? (rep.mitre || []).map((t) => attackLink(t)) : h("span", { class: "muted", text: "none mapped" }),
          rep.packing && rep.packing.packed ? h("p", null, h("span", { class: "badge medium", text: "packed / obfuscated" }), " ", safeText((rep.packing.indicators || []).join("; "))) : null)),
      h("section", { class: "card" }, h("header", null, h("h2", { text: `Behaviours (${rep.behaviors.length})` }), h("span", { class: "sub", text: "each finding links to the code or bytes behind it" })),
        rep.behaviors.length ? rep.behaviors.map((b) => finding(rep, b)) : emptyState("No malicious behaviours identified")),
      h("section", { class: "card flush" }, h("header", null, h("h2", { text: `Indicators of compromise (${rep.iocs.length})` }), h("span", { class: "sub", text: "also feed the IOC list and the blocklist export" })),
        rep.iocs.length ? iocTable(rep, rep.iocs.slice(0, 200)) : emptyState("No indicators extracted")));

    if (rep.c2_candidates && rep.c2_candidates.length) {
      sections.splice(sections.length - 1, 0, h("section", { class: "card" }, h("header", null, h("h2", { text: "C2 candidates" })),
        rep.c2_candidates.map((c) => h("div", null, h("span", { class: "badge", text: c.type }), " ", h("span", { class: "mono" }, ...visible(c.value)), h("span", { class: "muted", text: `  ${pct(c.confidence)}` })))));
    }

    const sec = rep.sections || [];
    sections.push(
      h("div", { class: "grid g2" },
        h("section", { class: "card" }, h("header", null, h("h2", { text: "Structure" })),
          h("dl", { class: "kv" },
            h("dt", { text: "Format" }), h("dd", { text: `${rep.file.format} ${rep.file.bits ? rep.file.bits + "-bit" : ""} ${rep.file.endian || ""}` }),
            h("dt", { text: "Entry point" }), h("dd", { class: "mono", text: rep.file.entry ? "0x" + rep.file.entry.toString(16) : "–" }),
            h("dt", { text: "Linking" }), h("dd", { text: `${rep.file.static ? "static" : "dynamic"}${rep.file.stripped ? ", stripped" : ""}${rep.file.interpreter ? ", " + rep.file.interpreter : ""}` }),
            h("dt", { text: "Libraries" }), h("dd", { text: safeText((rep.file.libraries || []).join(", ") || "none") }),
            h("dt", { text: "Backend" }), h("dd", { text: safeText(`${rep.backend.name} (${rep.backend.version}), ${rep.backend.instructions} instructions, ${rep.backend.syscall_sites} syscall sites`) }),
            h("dt", { text: "Analysis" }), h("dd", { text: `${rep.analysis_ms} ms, static analysis only, the sample was never executed` })),
          rep.errors && rep.errors.length ? h("p", { class: "muted", text: "Notes: " + safeText(rep.errors.join("; ")) }) : null),
        h("section", { class: "card" }, h("header", null, h("h2", { text: "Entropy" }), h("span", { class: "sub", text: `overall ${rep.entropy.overall} (0-8; above ~7.2 looks compressed or encrypted)` })),
          rep.entropy.profile.length > 1 ? miniColumns(rep.entropy.profile, { max: 8, height: 90, label: "entropy (bits/byte)", marks: { threshold: 7.2 } }) : emptyState("File too small for a profile"))));

    if (sec.length) sections.push(h("section", { class: "card flush" }, h("header", null, h("h2", { text: "Sections / segments" })),
      table([{ label: "Name", cls: "mono", render: (r) => safeText(r.name) }, { label: "Address", cls: "mono", render: (r) => "0x" + r.vaddr.toString(16) },
        { label: "Offset", cls: "mono", render: (r) => "0x" + r.offset.toString(16) }, { label: "Size", num: true, render: (r) => num(r.size) },
        { label: "Flags", cls: "mono", key: "flags" }, { label: "Entropy", num: true, render: (r) => r.entropy.toFixed(2) }], sec)));
    if ((rep.imports || []).length) sections.push(h("section", { class: "card" }, h("header", null, h("h2", { text: `Imports (${rep.imports.length})` })),
      h("div", { class: "mono break", text: safeText(rep.imports.slice(0, 150).map((i) => (i.library ? `${i.library}!${i.name}` : i.name)).join("  ")) })));
    if ((rep.syscalls || []).length) sections.push(h("section", { class: "card flush" }, h("header", null, h("h2", { text: `System calls recovered from machine code (${rep.syscalls.length})` })),
      table([{ label: "Address", cls: "mono", render: (r) => "0x" + r.address.toString(16) }, { label: "Call", cls: "mono", render: (r) => `${r.name}(${r.args.map((a) => (a === null ? "?" : a)).join(", ")})` }, { label: "No.", num: true, key: "number" }], rep.syscalls.slice(0, 80))));
    const strs = (rep.strings && rep.strings.interesting) || [];
    if (strs.length) sections.push(h("section", { class: "card flush" }, h("header", null, h("h2", { text: `Strings of interest (${rep.strings.count} total)` }), rep.strings.xor_key != null ? h("span", { class: "sub", text: `XOR-decoded table, key 0x${Number(rep.strings.xor_key).toString(16)}` }) : null),
      table([{ label: "Offset", cls: "mono", render: (r) => "0x" + r.offset.toString(16) }, { label: "String", cls: "mono break", render: (r) => h("span", null, ...visible(short(r.text, 200))) }, { label: "Tags", render: (r) => (r.tags || []).map((t) => h("span", { class: "chip", text: t })) }], strs.slice(0, 80))));
    if ((rep.decoded_layers || []).length) sections.push(h("section", { class: "card" }, h("header", null, h("h2", { text: "Decoded layers" }), h("span", { class: "sub", text: "base64 / compression layers unwrapped statically" })),
      rep.decoded_layers.map((l) => h("div", null, h("div", { class: "muted", text: `${l.encoding} at offset ${l.offset}` }), h("pre", null, ...visible(short(l.text, 1500)))))));
  }

  const srcTable = (rows) => table([
    { label: "When", render: (x) => h("span", { title: dateTime(x.ts), text: ago(x.ts) }) }, { label: "Source", render: (x) => ipLink(x.src_ip) },
    { label: "Service", render: (x) => svcTag(x.service) }, { label: "How", render: (x) => safeText(`${x.origin}${x.via ? " / " + x.via : ""}`) },
    { label: "URL / path", cls: "mono break", render: (x) => safeText(short(x.url || x.path || "", 120)) },
    { label: "", render: (x) => (x.session ? sessionLink(x.session, "Open session") : "") }], rows);
  const srcBody = h("div");
  const SHOW = 12;
  if (!d.sources.length) mount(srcBody, emptyState("No source recorded"));
  else {
    mount(srcBody, srcTable(d.sources.slice(0, SHOW)));
    if (d.sources.length > SHOW) srcBody.append(h("div", { style: { padding: "8px 16px 12px" } },
      h("button", { text: `Show all ${d.sources.length}`, onclick: (e) => { mount(srcBody, srcTable(d.sources)); } })));
  }
  sections.push(h("section", { class: "card flush" }, h("header", null, h("h2", { text: `Where it came from (${d.sources.length})` })), srcBody));

  mount(root, sections.map((s, i) => (i === 0 ? s : h("div", { style: { "margin-top": "14px" } }, s))));
}
