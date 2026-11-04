// Canvas world map: countries from vendor/countries-110m.json (world-atlas, TopoJSON), attack sources as bubbles
// sized by connection count, live events as expanding rings. No tiles, no external requests.
import { h } from "./util.js";
import { showTip, hideTip } from "./charts.js";
import { num, ago, safeText } from "./util.js";

const LAT_TOP = 84, LAT_BOTTOM = -58;
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
    for (const poly of polys) for (const r of poly) rings.push(ring(r));
  }
  return rings;
}

function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888"; }

export function createMap(host) {
  const canvas = h("canvas", { role: "img", "aria-label": "World map of attack sources. The same data is listed in the countries chart and the sources table." });
  const legendEl = h("div", { class: "map-legend" }, h("span", { text: "Bubble size = connections" }), h("span", { text: "Ring = live event" }));
  host.append(canvas, legendEl);
  const ctx = canvas.getContext("2d");
  let rings = [], points = [], pulses = [], raf = 0, W = 0, H = 0, dpr = 1;
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

  function draw(now = performance.now()) {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = css("--land"); ctx.strokeStyle = css("--land-line"); ctx.lineWidth = 0.6;
    for (const r of rings) {
      ctx.beginPath();
      r.forEach(([lon, lat], i) => (i ? ctx.lineTo(X(lon), Y(lat)) : ctx.moveTo(X(lon), Y(lat))));
      ctx.closePath(); ctx.fill(); ctx.stroke();
    }
    const accent = css("--accent"), surface = css("--surface"), hot = css("--s2");
    ctx.globalAlpha = 0.5;
    points.forEach((p, i) => {
      ctx.beginPath(); ctx.arc(X(p.lon), Y(p.lat), radius(p), 0, 6.2832);
      ctx.fillStyle = accent; ctx.fill();
    });
    ctx.globalAlpha = 1;
    points.forEach((p, i) => {
      ctx.beginPath(); ctx.arc(X(p.lon), Y(p.lat), radius(p), 0, 6.2832);
      ctx.lineWidth = i === hover ? 2.5 : 1.5; ctx.strokeStyle = i === hover ? css("--ink") : surface; ctx.stroke();
    });
    pulses = pulses.filter((p) => now - p.t0 < 2200);
    for (const p of pulses) {
      const k = (now - p.t0) / 2200;
      ctx.beginPath(); ctx.arc(X(p.lon), Y(p.lat), 4 + k * 26, 0, 6.2832);
      ctx.globalAlpha = (1 - k) * 0.9; ctx.lineWidth = 2; ctx.strokeStyle = hot; ctx.stroke();
      ctx.globalAlpha = 1;
      ctx.beginPath(); ctx.arc(X(p.lon), Y(p.lat), 3.5, 0, 6.2832); ctx.fillStyle = hot; ctx.fill();
    }
    if (pulses.length && !document.hidden) raf = requestAnimationFrame(draw); else raf = 0;
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

  return {
    setPoints(pts) { points = (pts || []).filter((p) => Number.isFinite(p.lat) && Number.isFinite(p.lon)); draw(); },
    pulse(lat, lon) {
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) return;
      if (pulses.length > 60) pulses.shift();
      pulses.push({ lat, lon, t0: performance.now() }); kick();
    },
    destroy() { ro.disconnect(); if (raf) cancelAnimationFrame(raf); document.removeEventListener("honeynet:theme", onTheme); matchMedia("(prefers-color-scheme: dark)").removeEventListener("change", onTheme); },
  };
}
