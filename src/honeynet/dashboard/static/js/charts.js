// Hand-written SVG/HTML charts: thin marks, 4px rounded data ends, 2px surface gaps, hover tooltips
// that list every series, a legend for >= 2 series and a table view for every chart.
import { h, svg, clear, mount, compact, num, clock, safeText, svcColor, svcTag, bytes } from "./util.js";

// ---------------------------------------------------------------------------- tooltip
let tipEl = null;
function tip() {
  if (!tipEl) { tipEl = h("div", { class: "tooltip hidden", role: "tooltip" }); document.body.append(tipEl); }
  return tipEl;
}
export function showTip(x, y, head, rows) {
  const t = tip();
  mount(t, head ? h("div", { class: "t-head", text: head }) : null,
    rows.map((r) => h("div", { class: "t-row" },
      h("span", { class: "t-key" }, r.color ? h("i", { class: "swatch line", style: { background: r.color } }) : null, r.label),
      h("b", { text: r.value }))));
  t.classList.remove("hidden");
  const w = t.offsetWidth, hh = t.offsetHeight;
  let left = x + 14, top = y + 14;
  if (left + w > window.innerWidth - 8) left = x - w - 14;
  if (top + hh > window.innerHeight - 8) top = y - hh - 14;
  t.style.setProperty("left", Math.max(4, left) + "px");
  t.style.setProperty("top", Math.max(4, top) + "px");
}
export function hideTip() { if (tipEl) tipEl.classList.add("hidden"); }

function niceMax(v) {
  if (v <= 4) return 4;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
function axisFmt(v) { return v >= 10000 ? compact(v) : String(v); }

// ---------------------------------------------------------------------------- legend + table toggle
export function legend(items) {
  return h("div", { class: "legend", role: "list" },
    items.map((i) => h("span", { role: "listitem" }, h("i", { class: "swatch", style: { background: i.color } }), i.label)));
}

export function table(columns, rows, opts = {}) {
  return h("div", { class: "tablewrap" }, h("table", null,
    h("thead", null, h("tr", null, columns.map((c) => h("th", { class: c.num ? "num" : "", text: c.label })))),
    h("tbody", null, rows.map((r) => h("tr", null, columns.map((c) => {
      const v = c.render ? c.render(r) : r[c.key];
      const cell = v instanceof Node || Array.isArray(v) ? v : typeof v === "number" ? (c.num ? num(v) : String(v)) : safeText(v);
      return h("td", { class: (c.num ? "num " : "") + (c.cls || "") }, cell);
    }))))), opts.caption ? h("div", { class: "muted", text: opts.caption }) : null);
}

// ---------------------------------------------------------------------------- stacked columns over time
// points: [{t, by_service:{svc:n}, <metric>}], mode "stack" (by service) or "single" (one series)
export function timeColumns(host, { points, services, metric = "conns", bucket = 3600, height = 230, label = "Connections", color = "var(--s1)" }) {
  const stack = metric === "conns" && services.length > 0;
  const order = stack ? services.slice().sort((a, b) => slot(a) - slot(b)) : [label];
  const valuesAt = (p) => (stack ? order.map((s) => p.by_service[s] || 0) : [p[metric] || 0]);
  const colorOf = (i) => (stack ? svcColor(order[i]) : color);
  const totals = points.map((p) => valuesAt(p).reduce((a, b) => a + b, 0));
  const max = niceMax(Math.max(1, ...totals));

  const view = h("div", { class: "chart" });
  const tbl = h("div", { class: "hidden" });
  const toggle = h("button", { class: "ghost", "aria-pressed": "false", text: "Table", title: "Show the same data as a table" });
  const chartWrap = h("div", null,
    stack ? legend(order.map((s) => ({ label: s, color: svcColor(s) }))) : null, view, tbl);

  let shown = false;
  toggle.addEventListener("click", () => {
    shown = !shown;
    toggle.setAttribute("aria-pressed", String(shown));
    view.classList.toggle("hidden", shown);
    tbl.classList.toggle("hidden", !shown);
    if (shown) {
      const cols = [{ label: "Time", render: (p) => stamp(p.t, bucket, true) }]
        .concat(stack ? order.map((s) => ({ label: s, num: true, render: (p) => p.by_service[s] || 0 })) : [{ label, num: true, render: (p) => p[metric] || 0 }]);
      if (stack) cols.push({ label: "Total", num: true, render: (p) => p.conns });
      mount(tbl, table(cols, points.filter((p) => (stack ? p.conns : p[metric]) > 0).reverse().slice(0, 200)));
    } else draw();
  });

  function draw() {
    const W = Math.max(280, view.clientWidth || host.clientWidth || 600), H = height;
    const m = { l: 40, r: 6, t: 8, b: 22 };
    const iw = W - m.l - m.r, ih = H - m.t - m.b;
    const n = points.length;
    const slotW = iw / Math.max(1, n);
    const bw = Math.min(24, Math.max(2, slotW * 0.72));
    const y = (v) => m.t + ih - (v / max) * ih;
    const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "img", "aria-label": `${label} over time, ${points.length} intervals, peak ${Math.max(...totals)}` });
    for (let i = 0; i <= 4; i++) {
      const v = (max / 4) * i, yy = y(v);
      root.append(svg("line", { class: i === 0 ? "axis-line" : "grid-line", x1: m.l, x2: W - m.r, y1: yy, y2: yy }));
      root.append(svg("text", { x: m.l - 6, y: yy + 4, "text-anchor": "end", text: axisFmt(Math.round(v)) }));
    }
    const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(iw / 78))));
    points.forEach((p, i) => {
      const cx = m.l + slotW * i + slotW / 2;
      if (i % every === 0) root.append(svg("text", { x: cx, y: H - 6, "text-anchor": "middle", text: stamp(p.t, bucket, false) }));
    });
    const hover = svg("rect", { fill: "var(--raised)", opacity: 0, rx: 3, y: m.t, height: ih, width: Math.max(bw + 6, 8) });
    root.append(hover);
    points.forEach((p, i) => {
      const cx = m.l + slotW * i + slotW / 2;
      const vals = valuesAt(p);
      let acc = 0;
      const top = vals.reduce((a, v, k) => (v > 0 ? k : a), -1);
      vals.forEach((v, k) => {
        if (v <= 0) return;
        const y1 = y(acc + v), y0 = y(acc);
        const gap = k > 0 && acc > 0 ? 2 : 0;
        const hgt = Math.max(2, y0 - y1 - gap);
        const yTop = y0 - hgt;
        root.append(segment(cx - bw / 2, yTop, bw, hgt, k === top ? Math.min(4, hgt, bw / 2) : 0, colorOf(k)));
        acc += v;
      });
      const hit = svg("rect", { class: "hit", x: cx - slotW / 2, y: m.t, width: slotW, height: ih + 14, tabindex: i % every === 0 ? 0 : -1,
        "aria-label": `${stamp(p.t, bucket, true)}: ${totals[i]} ${label.toLowerCase()}` });
      const show = (px, py) => {
        hover.setAttribute("x", cx - hover.getAttribute("width") / 2);
        hover.setAttribute("opacity", ".7");
        const rows = stack
          ? order.map((s, k) => ({ label: s, value: num(vals[k]), color: colorOf(k) })).filter((r) => r.value !== "0").concat([{ label: "Total", value: num(totals[i]) }])
          : [{ label, value: num(vals[0]), color }];
        showTip(px, py, stamp(p.t, bucket, true), rows);
      };
      hit.addEventListener("pointermove", (e) => show(e.clientX, e.clientY));
      hit.addEventListener("pointerleave", () => { hover.setAttribute("opacity", 0); hideTip(); });
      hit.addEventListener("focus", () => { const r = hit.getBoundingClientRect(); show(r.left + r.width / 2, r.top + 20); });
      hit.addEventListener("blur", () => { hover.setAttribute("opacity", 0); hideTip(); });
      root.append(hit);
    });
    clear(view).append(root);
  }
  const ro = new ResizeObserver(() => { if (!shown && host.isConnected) draw(); });
  mount(host, chartWrap);
  ro.observe(host);
  draw();
  return { toggle, destroy: () => ro.disconnect() };
}
const SLOT = { ssh: 1, telnet: 2, http: 3, mysql: 4, redis: 5 };
function slot(s) { return SLOT[s] || 9; }
function segment(x, y, w, hgt, r, fill) {
  // square at the baseline, rounded data-end (top) only
  const d = r > 0
    ? `M${x},${y + hgt} V${y + r} Q${x},${y} ${x + r},${y} H${x + w - r} Q${x + w},${y} ${x + w},${y + r} V${y + hgt} Z`
    : `M${x},${y} H${x + w} V${y + hgt} H${x} Z`;
  return svg("path", { d, fill });
}
function stamp(t, bucket, long) {
  const d = new Date(t * 1000), p = (n) => String(n).padStart(2, "0");
  if (bucket >= 86400) return `${p(d.getMonth() + 1)}-${p(d.getDate())}`;
  if (long) return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
  return bucket >= 3600 && d.getHours() !== 0 ? `${p(d.getHours())}:00` : (d.getHours() === 0 && d.getMinutes() === 0 ? `${p(d.getMonth() + 1)}-${p(d.getDate())}` : `${p(d.getHours())}:${p(d.getMinutes())}`);
}

// ---------------------------------------------------------------------------- horizontal bars (top-N)
// rows: [{key, name?, n, ips?}]; link(row) -> href or null; fmt for the value; color for the fill
export function hbars(rows, { link, color = "var(--data)", unit = "", label, sub, fmt = num, serviceKeys = false, mono = false } = {}) {
  if (!rows || !rows.length) return h("div", { class: "empty", text: "Nothing yet" });
  const max = Math.max(1, ...rows.map((r) => r.n));
  return h("div", { class: "hbars", role: "list" }, rows.map((r) => {
    const href = link ? link(r) : null;
    // label(r) may return "text" or ["main text", "quieter second part"]
    const l = label ? label(r) : (r.name ? [r.name, r.key] : String(r.key));
    const [main, second] = Array.isArray(l) ? l : [l, ""];
    const full = safeText(second ? `${main} ${second}` : main);
    const fill = h("i", { class: "fill", style: { width: Math.max(0.6, (r.n / max) * 100) + "%", background: serviceKeys ? svcColor(r.key) : color } });
    const node = h(href ? "a" : "div", { class: "hbar", role: "listitem", tabindex: href ? undefined : 0, href: href || undefined, title: full },
      h("span", { class: "name" + (mono ? " mono" : "") }, safeText(main), second ? h("span", { class: "sub", text: safeText(second) }) : null),
      h("span", { class: "track" }, fill), h("span", { class: "val", text: fmt(r.n) }));
    const show = (x, y) => showTip(x, y, full, [{ label: unit || "count", value: fmt(r.n) }].concat(r.ips != null ? [{ label: "distinct IPs", value: num(r.ips) }] : [], sub ? sub(r) : []));
    node.addEventListener("pointermove", (e) => show(e.clientX, e.clientY));
    node.addEventListener("pointerleave", hideTip);
    node.addEventListener("focus", () => { const b = node.getBoundingClientRect(); show(b.left + 40, b.top + 8); });
    node.addEventListener("blur", hideTip);
    return node;
  }));
}

// ---------------------------------------------------------------------------- small column chart (entropy profile etc.)
export function miniColumns(values, { max, height = 70, label = "value", fmt = (v) => v.toFixed(2), color = "var(--data)", marks = {} } = {}) {
  const vmax = max || Math.max(...values, 1);
  const W = Math.max(320, values.length * 10), H = height, bw = Math.min(14, (W / values.length) - 2);
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", height: H, role: "img", "aria-label": `${label} profile, ${values.length} blocks`, preserveAspectRatio: "none" });
  values.forEach((v, i) => {
    const hgt = Math.max(1, (v / vmax) * (H - 4)), x = (W / values.length) * i + ((W / values.length) - bw) / 2;
    const hot = marks.threshold != null && v >= marks.threshold;
    const r = svg("rect", { x, y: H - hgt, width: bw, height: hgt, rx: Math.min(3, bw / 2), fill: hot ? "var(--s2)" : color });
    const hit = svg("rect", { class: "hit", x: (W / values.length) * i, y: 0, width: W / values.length, height: H, tabindex: -1 });
    hit.addEventListener("pointermove", (e) => showTip(e.clientX, e.clientY, `block ${i + 1}`, [{ label, value: fmt(v) }]));
    hit.addEventListener("pointerleave", hideTip);
    root.append(r, hit);
  });
  return h("div", { class: "chart" }, root);
}

// A one-whole-in-parts bar (thin segmented bar) with legend + exact numbers in the tooltip.
export function segmentedBar(parts, { height = 10 } = {}) {
  const total = parts.reduce((a, p) => a + p.n, 0) || 1;
  const bar = h("div", { class: "segbar", role: "img", "aria-label": parts.map((p) => `${p.name} ${p.n}`).join(", "),
    style: { display: "flex", gap: "2px", height: height + "px" } });
  parts.forEach((p) => {
    if (p.n <= 0) return;
    const seg = h("i", { style: { flex: String(p.n), background: p.color, "border-radius": "999px", "min-width": "3px" } });
    seg.addEventListener("pointermove", (e) => showTip(e.clientX, e.clientY, p.name, [{ label: "count", value: num(p.n) }, { label: "share", value: Math.round((p.n / total) * 100) + "%" }]));
    seg.addEventListener("pointerleave", hideTip);
    bar.append(seg);
  });
  return h("div", null, bar, legend(parts.map((p) => ({ label: `${p.name} ${compact(p.n)}`, color: p.color }))));
}

export { svcTag, bytes, clock };
