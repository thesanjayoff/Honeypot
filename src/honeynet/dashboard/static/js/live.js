// One shared EventSource (/api/stream). Pages subscribe; the top bar shows the connection state.
const subs = new Set();
const stateSubs = new Set();
let es = null;
let state = "connecting";

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
    subs.forEach((f) => { try { f(ev); } catch { /* a broken page must not stop the stream */ } });
  };
}
export function stopLive() { if (es) { es.close(); es = null; } setState("off"); }
export function onEvent(fn) { subs.add(fn); return () => subs.delete(fn); }
export function onState(fn) { stateSubs.add(fn); fn(state); return () => stateSubs.delete(fn); }
