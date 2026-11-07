// One shared EventSource (/api/stream). Pages subscribe; the top bar shows the connection state.
// "Pause" freezes what pages see (so an operator can read the feed); the stream itself keeps running and
// "resume" tells pages to reload so nothing is missed.
const subs = new Set();
const stateSubs = new Set();
let es = null;
let state = "connecting";
let paused = false;
let lastAt = 0;

function setState(s) { state = s; stateSubs.forEach((f) => f(s)); }

export function startLive() {
  if (es) return;
  es = new EventSource("/api/stream", { withCredentials: true });
  es.onopen = () => setState("live");
  es.onerror = () => setState(es && es.readyState === EventSource.CLOSED ? "off" : "connecting");
  es.onmessage = (m) => {
    let ev;
    try { ev = JSON.parse(m.data); } catch { return; }
    if (!ev || typeof ev !== "object") return;
    lastAt = Date.now();
    if (paused) return;
    subs.forEach((f) => { try { f(ev); } catch { /* a broken page must not stop the stream */ } });
  };
}
export function stopLive() { if (es) { es.close(); es = null; } setState("off"); }
export function onEvent(fn) { subs.add(fn); return () => subs.delete(fn); }
export function onState(fn) { stateSubs.add(fn); fn(state); return () => stateSubs.delete(fn); }
export function isPaused() { return paused; }
export function lastEventAt() { return lastAt; }
export function setPaused(p) {
  paused = Boolean(p);
  document.dispatchEvent(new CustomEvent("honeynet:pause", { detail: paused }));
  if (!paused) document.dispatchEvent(new CustomEvent("honeynet:resume"));
}
