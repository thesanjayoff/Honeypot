// Canvas world map: countries from vendor/countries-110m.json (world-atlas, TopoJSON). Sources are bubbles sized by
// connection count and coloured by how many of their IPs are flagged malicious; the honeypot itself is a honeycomb
// marker (when its location is configured) and live events fly into it as arcs. No tiles, no external requests.
import { h } from "./util.js";
import { showTip, hideTip } from "./charts.js";
import { num, ago, safeText } from "./util.js";

const LAT_TOP = 84, LAT_BOTTOM = -58;
const TAU = Math.PI * 2;
const ARC_MS = 1500, RING_MS = 2200;
const SHIFTS = [0, 360, -360];
let topoPromise = null;

function loadCountries() {
  if (!topoPromise) {
    topoPromise = fetch("vendor/countries-110m.json", { credentials: "same-origin" })
      .then((r) => r.json())
      .then(decode)
      .catch(() => []);
  }
  return topoPromise;
}

function decode(topo) {
  const [sx, sy] = topo.transform.scale, [tx, ty] = topo.transform.translate;
  const arcs = topo.arcs.map((arc) => {
    let x = 0, y = 0;
    return arc.map(([dx, dy]) => { x += dx; y += dy; return [x * sx + tx, y * sy + ty]; });
  });
  const ring = (idxs) => {
    const pts = [];
    for (const i of idxs) {
      const a = i >= 0 ? arcs[i] : arcs[~i].slice().reverse();
      for (let k = pts.length ? 1 : 0; k < a.length; k++) pts.push(a[k]);
    }
    return pts;
  };
  const rings = [];
  for (const g of topo.objects.countries.geometries) {
    const polys = g.type === "Polygon" ? [g.arcs] : g.type === "MultiPolygon" ? g.arcs : [];
    for (const poly of polys) for (const r of poly) rings.push(unwrap(ring(r)));
  }
  return rings;
}

// A ring that crosses the 180th meridian jumps from +180 to -180; make longitudes continuous instead, so it is
// drawn as one shape (and again shifted by 360 degrees where it spills over the edge) rather than a streak across the map.
function unwrap(pts) {
  let off = 0, prev = pts.length ? pts[0][0] : 0, lo = Infinity, hi = -Infinity;
  const out = pts.map(([lon, lat]) => {
    if (lon - prev > 180) off -= 360; else if (prev - lon > 180) off += 360;
    prev = lon;
    lo = Math.min(lo, lon + off); hi = Math.max(hi, lon + off);
    return [lon + off, lat];
  });
  out.lo = lo; out.hi = hi;
  return out;
}

function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888"; }
const reduceMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

export function createMap(host) {
  const canvas = h("canvas", { role: "img", "aria-label": "World map of attack sources. The same data is listed in the sources tabs and the sessions page." });
  const key = (cls, text) => h("span", { class: "mk" }, h("i", { class: `mk-dot ${cls}` }), text);
  const legendEl = h("div", { class: "map-legend" },
    key("crit", "mostly flagged malicious"), key("sus", "some flagged"), key("data", "not flagged"), h("span", { class: "mk-size", text: "size = connections" }));
  host.append(canvas, legendEl);
  const ctx = canvas.getContext("2d");
  let rings = [], points = [], pulses = [], home = null, raf = 0, W = 0, H = 0, dpr = 1;
  let hover = -1;

  const X = (lon) => ((lon + 180) / 360) * W;
  const Y = (lat) => ((LAT_TOP - Math.max(LAT_BOTTOM, Math.min(LAT_TOP, lat))) / (LAT_TOP - LAT_BOTTOM)) * H;

  function size() {
    const w = Math.max(320, host.clientWidth || 640);
    dpr = Math.min(2, window.devicePixelRatio || 1);
    W = w; H = Math.round(w * (LAT_TOP - LAT_BOTTOM) / 360);
    canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
    canvas.style.setProperty("height", H + "px");
  }

  const radius = (p) => 3.5 + Math.min(15, Math.sqrt(p.count) * 0.9);
  const tone = (p) => { const share = p.ips ? p.malicious / p.ips : 0; return share >= 0.5 ? "--crit" : share > 0 ? "--sus" : "--data"; };
  const classTone = (c) => (c === "malicious" ? "--crit" : c === "suspicious" ? "--sus" : "--data");

  function bez(a, b, t) {
    const mx = (a.x + b.x) / 2, my = Math.min(a.y, b.y) - Math.hypot(a.x - b.x, a.y - b.y) * 0.28;
    const u = 1 - t;
    return { x: u * u * a.x + 2 * u * t * mx + t * t * b.x, y: u * u * a.y + 2 * u * t * my + t * t * b.y };
  }

  function hex(cx, cy, r) {
    ctx.beginPath();
    for (let i = 0; i < 6; i++) { const a = Math.PI / 6 + (i * TAU) / 6; ctx.lineTo(cx + r * Math.cos(a), cy + r * Math.sin(a)); }
    ctx.closePath();
  }

  function draw(now = performance.now()) {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = css("--land"); ctx.strokeStyle = css("--land-line"); ctx.lineWidth = 0.6;
    for (const r of rings) {
      for (const shift of SHIFTS) {
        if (r.hi + shift < -180 || r.lo + shift > 180) continue;
        ctx.beginPath();
        r.forEach(([lon, lat], i) => (i ? ctx.lineTo(X(lon + shift), Y(lat)) : ctx.moveTo(X(lon + shift), Y(lat))));
        ctx.closePath(); ctx.fill(); ctx.stroke();
      }
    }
    const surface = css("--surface");
    points.forEach((p) => {
      ctx.beginPath(); ctx.arc(X(p.lon), Y(p.lat), radius(p), 0, TAU);
      ctx.globalAlpha = 0.55; ctx.fillStyle = css(tone(p)); ctx.fill(); ctx.globalAlpha = 1;
    });
    points.forEach((p, i) => {
      ctx.beginPath(); ctx.arc(X(p.lon), Y(p.lat), radius(p), 0, TAU);
      ctx.lineWidth = i === hover ? 2.5 : 1.5; ctx.strokeStyle = i === hover ? css("--ink") : surface; ctx.stroke();
    });

    const hx = home ? X(home.lon) : 0, hy = home ? Y(home.lat) : 0;
    pulses = pulses.filter((p) => now - p.t0 < Math.max(RING_MS, home ? ARC_MS + 300 : 0));
    for (const p of pulses) {
      const col = css(p.tone), ageMs = now - p.t0, sx = X(p.lon), sy = Y(p.lat);
      const k = ageMs / RING_MS;
      if (k < 1) {
        ctx.beginPath(); ctx.arc(sx, sy, 4 + k * 24, 0, TAU);
        ctx.globalAlpha = (1 - k) * 0.85; ctx.lineWidth = 2; ctx.strokeStyle = col; ctx.stroke(); ctx.globalAlpha = 1;
        ctx.beginPath(); ctx.arc(sx, sy, 3.5, 0, TAU); ctx.fillStyle = col; ctx.fill();
      }
      if (home && ageMs < ARC_MS + 300) {
        const t = Math.min(1, ageMs / ARC_MS), tail = Math.max(0, t - 0.4);
        ctx.beginPath();
        for (let s = 0; s <= 16; s++) {
          const q = bez({ x: sx, y: sy }, { x: hx, y: hy }, tail + ((t - tail) * s) / 16);
          s ? ctx.lineTo(q.x, q.y) : ctx.moveTo(q.x, q.y);
        }
        ctx.globalAlpha = ageMs > ARC_MS ? Math.max(0, 1 - (ageMs - ARC_MS) / 300) : 0.9;
        ctx.lineWidth = 2; ctx.lineCap = "round"; ctx.strokeStyle = col; ctx.stroke(); ctx.globalAlpha = 1;
      }
    }
    if (home) {                                        // the honeypot: a honeycomb cell with the bait inside
      const beat = reduceMotion() ? 0 : (Math.sin(now / 700) + 1) / 2;
      hex(hx, hy, 11 + beat * 3); ctx.globalAlpha = 0.25 - beat * 0.1; ctx.fillStyle = css("--accent"); ctx.fill(); ctx.globalAlpha = 1;
      hex(hx, hy, 8.5); ctx.fillStyle = surface; ctx.fill(); ctx.lineWidth = 2; ctx.strokeStyle = css("--accent"); ctx.stroke();
      hex(hx, hy, 4); ctx.fillStyle = css("--accent"); ctx.fill();
    }
    const animating = (pulses.length || (home && !reduceMotion())) && !document.hidden;
    raf = animating ? requestAnimationFrame(draw) : 0;
  }
  function kick() { if (!raf) raf = requestAnimationFrame(draw); }

  canvas.addEventListener("pointermove", (e) => {
    const b = canvas.getBoundingClientRect();
    const mx = (e.clientX - b.left) * (W / b.width), my = (e.clientY - b.top) * (H / b.height);
    let best = -1, bd = 1e9;
    points.forEach((p, i) => {
      const d = Math.hypot(X(p.lon) - mx, Y(p.lat) - my);
      if (d < radius(p) + 6 && d < bd) { best = i; bd = d; }
    });
    if (best !== hover) { hover = best; draw(); }
    if (best < 0) { hideTip(); return; }
    const p = points[best];
    showTip(e.clientX, e.clientY, safeText([p.city, p.country].filter(Boolean).join(", ") || "unknown location"), [
      { label: "connections", value: num(p.count) }, { label: "source IPs", value: num(p.ips) },
      { label: "flagged malicious", value: num(p.malicious) }, { label: "last seen", value: ago(p.last) }]);
  });
  canvas.addEventListener("pointerleave", () => { hover = -1; hideTip(); draw(); });

  size();
  loadCountries().then((r) => { rings = r; draw(); });
  const ro = new ResizeObserver(() => { size(); draw(); });
  ro.observe(host);
  const onTheme = () => draw();
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", onTheme);
  document.addEventListener("honeynet:theme", onTheme);
  const onVis = () => { if (!document.hidden) draw(); };
  document.addEventListener("visibilitychange", onVis);

  return {
    setPoints(pts) { points = (pts || []).filter((p) => Number.isFinite(p.lat) && Number.isFinite(p.lon)); draw(); },
    setHome(pt) { home = pt && Number.isFinite(pt.lat) && Number.isFinite(pt.lon) ? pt : null; draw(); },
    pulse(lat, lon, classification) {
      if (!Number.isFinite(lat) || !Number.isFinite(lon) || reduceMotion()) return;
      if (pulses.length > 60) pulses.shift();
      pulses.push({ lat, lon, t0: performance.now(), tone: classTone(classification) }); kick();
    },
    destroy() {
      ro.disconnect(); if (raf) cancelAnimationFrame(raf);
      document.removeEventListener("honeynet:theme", onTheme); document.removeEventListener("visibilitychange", onVis);
      matchMedia("(prefers-color-scheme: dark)").removeEventListener("change", onTheme);
    },
  };
}
