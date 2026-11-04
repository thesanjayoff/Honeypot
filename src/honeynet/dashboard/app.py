"""FastAPI application: JSON API + SSE feed + static single-page dashboard.

Security posture (the dashboard sits next to a honeypot full of hostile data):
  * binds 127.0.0.1 by default; reach it through an SSH tunnel/VPN; password login (signed, expiring,
    HttpOnly + SameSite=Strict cookie); refuses to start without a password outside test mode,
  * Host header allow-list (DNS-rebinding), Origin check + custom header on state-changing requests,
  * strict CSP (no inline script/style), no-store on API responses, nosniff, no referrer, no framing,
  * never serves captured malware; analysis reports only (strings in them were sanitised by the engine),
  * every string from the database was sanitised at ingest; the UI additionally renders via textContent.
"""

from __future__ import annotations

import asyncio
import mimetypes
import json
import logging
import re
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .. import __version__
from ..common.config import Settings
from . import attack, exports, queries as q, report
from .alerts import AlertManager
from .auth import COOKIE_NAME, Authenticator
from .db import DB
from .enrich import ExternalLookups, GeoResolver
from .ingest import Ingestor
from .samples import SHA_RE, AnalysisImporter, load_report

# Windows registries sometimes map .js to text/plain, which breaks module scripts under nosniff
for _ext, _mt in ((".js", "text/javascript"), (".css", "text/css"), (".json", "application/json"), (".svg", "image/svg+xml")):
    mimetypes.add_type(_mt, _ext)

log = logging.getLogger("honeynet.dashboard")
STATIC_DIR = Path(__file__).parent / "static"
IP_RE = re.compile(r"^[0-9a-fA-F:.]{2,45}$")
SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
SEC_HEADERS = {
    "Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY", "Cross-Origin-Resource-Policy": "same-origin", "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
}


class Broker:
    """Fan-out of newly ingested events to SSE clients (thread-safe publish, per-client bounded queue)."""

    def __init__(self) -> None:
        self._subs: list[tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = []
        self._lock = threading.Lock()

    def subscribe(self) -> asyncio.Queue:
        qu: asyncio.Queue = asyncio.Queue(maxsize=500)
        with self._lock:
            self._subs.append((asyncio.get_running_loop(), qu))
        return qu

    def unsubscribe(self, qu: asyncio.Queue) -> None:
        with self._lock:
            self._subs = [(lp, x) for lp, x in self._subs if x is not qu]

    def publish(self, events: list[dict]) -> None:
        with self._lock:
            subs = list(self._subs)
        for loop, qu in subs:
            def push(qu=qu, events=events):
                for e in events:
                    if qu.full():
                        try:
                            qu.get_nowait()
                        except asyncio.QueueEmpty:
                            pass
                    qu.put_nowait(e)
            try:
                loop.call_soon_threadsafe(push)
            except RuntimeError:
                pass


class Services:
    """Everything the app needs, constructed once (also used directly by tests and the CLI)."""

    def __init__(self, s: Settings) -> None:
        self.s = s
        self.started = time.time()
        self.db = DB(s.db_path)
        self.broker = Broker()
        self.geo = GeoResolver(s.geoip_dir, s.test_mode)
        self.ext = ExternalLookups(s, self.db)
        self.alerts = AlertManager(s, self.db)
        self.auth = Authenticator(s)
        self.ingestor = Ingestor(s, self.db, self.geo, self.ext, on_events=self.broker.publish,
                                 on_new_sample=self.alerts.new_sample, on_new_rule=self.alerts.new_exploit)
        self.importer = AnalysisImporter(s, self.db, on_analyzed=self.alerts.analyzed)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start_background(self) -> None:
        self.ext.start()
        for name, fn in (("ingest", self.ingestor.run_forever), ("analysis-import", self._import_loop), ("housekeeping", self._housekeeping)):
            t = threading.Thread(target=fn, name=name, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        self.ingestor.stop()
        self.ext.stop()

    def _import_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.importer.poll_once()
            except Exception:  # noqa: BLE001
                log.exception("analysis import failed")
            self._stop.wait(3)

    def _housekeeping(self) -> None:
        while not self._stop.is_set():
            try:
                self.alerts.check_spike()
                self.maybe_daily_report()
                self.ingestor.reenrich_missing(200) if self.geo.available else None
            except Exception:  # noqa: BLE001
                log.exception("housekeeping failed")
            self._stop.wait(60)

    def maybe_daily_report(self) -> Path | None:
        day = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 86400))
        if self.db.get_meta("last_daily_report") == day:
            return None
        if self.db.scalar("SELECT COUNT(*) FROM events") == 0:
            return None
        paths = report.write_daily(self.db, self.s)
        self.db.set_meta("last_daily_report", day)
        return paths["md"]


def create_app(s: Settings, *, start_background: bool = True) -> FastAPI:
    svc = Services(s)
    if svc.auth.required and not svc.auth.configured:
        raise SystemExit("refusing to start: set HONEYNET_DASHBOARD_PASSWORD_HASH (python -m honeynet hash-password) "
                         "or run with HONEYNET_TEST_MODE=1 for local-only testing")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if start_background:
            svc.start_background()
        yield
        svc.stop()

    app = FastAPI(title="honeynet dashboard", version=__version__, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.svc = svc

    allowed_hosts = {"localhost", "127.0.0.1", "[::1]", "::1", "testserver", s.dashboard_host.lower(), *[h.lower() for h in s.dashboard_allowed_hosts]}
    allowed_hosts.discard("0.0.0.0")

    # ---------------------------------------------------------------- middleware
    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = (request.headers.get("host") or "").lower()
        bare = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
        if bare not in allowed_hosts and host not in allowed_hosts:
            return PlainTextResponse("bad host", status_code=400)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin:
                o = origin.split("://", 1)[-1].lower()
                if o not in allowed_hosts and o.rsplit(":", 1)[0] not in allowed_hosts:
                    return JSONResponse({"error": "cross-origin request refused"}, status_code=403)
            if request.headers.get("x-requested-with") != "honeynet":
                return JSONResponse({"error": "missing X-Requested-With"}, status_code=403)
        resp: Response = await call_next(request)
        for k, v in SEC_HEADERS.items():
            resp.headers.setdefault(k, v)
        if request.url.path.startswith("/api"):
            resp.headers["Cache-Control"] = "no-store"
        else:
            resp.headers.setdefault("Cache-Control", "no-cache")      # always revalidate (ETag) - assets change with upgrades
        return resp

    def authed(request: Request) -> None:
        if not svc.auth.is_authed(request.cookies.get(COOKIE_NAME)):
            raise HTTPException(status_code=401, detail="login required")

    A = [Depends(authed)]

    def rng(hours: float, since: float | None = None, until: float | None = None) -> tuple[float, float]:
        return q.window(hours=hours, since=since, until=until)

    # ---------------------------------------------------------------- session
    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.get("/api/me")
    def me(request: Request) -> dict:
        return {"authed": svc.auth.is_authed(request.cookies.get(COOKIE_NAME)), "auth_required": svc.auth.required,
                "test_mode": s.test_mode, "version": __version__}

    @app.post("/api/login")
    async def login(request: Request, response: Response) -> Any:
        try:
            body = await request.json()
            password = str(body.get("password", ""))
        except Exception:  # noqa: BLE001
            raise HTTPException(400, "bad request")
        client = request.client.host if request.client else "?"
        ok, retry = await asyncio.to_thread(svc.auth.login, client, password)
        if not ok:
            hdr = {"Retry-After": str(retry)} if retry else {}
            return JSONResponse({"error": "locked, try later" if retry else "invalid password"}, status_code=429 if retry else 401, headers=hdr)
        resp = JSONResponse({"ok": True})
        resp.set_cookie(COOKIE_NAME, svc.auth.make_cookie(), max_age=s.dashboard_session_hours * 3600, httponly=True, samesite="strict",
                        secure=s.dashboard_cookie_secure, path="/")
        return resp

    @app.post("/api/logout")
    def logout(request: Request) -> Any:
        svc.auth.revoke(request.cookies.get(COOKIE_NAME))
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE_NAME, path="/")
        return resp

    # ---------------------------------------------------------------- data
    @app.get("/api/summary", dependencies=A)
    def summary(hours: float = Query(24, gt=0, le=24 * 365)) -> dict:
        return q.summary(svc.db, *rng(hours))

    @app.get("/api/timeseries", dependencies=A)
    def timeseries(hours: float = Query(24, gt=0, le=24 * 365), bucket: int | None = Query(None, ge=60, le=86400)) -> dict:
        since, until = rng(hours)
        return q.timeseries(svc.db, since, until, bucket)

    @app.get("/api/top", dependencies=A)
    def top(what: str = Query(...), hours: float = Query(24, gt=0, le=24 * 365), limit: int = Query(10, ge=1, le=100)) -> list:
        try:
            return q.top(svc.db, what, *rng(hours), limit)
        except ValueError:
            raise HTTPException(400, "unknown category")

    @app.get("/api/map", dependencies=A)
    def map_(hours: float = Query(24, gt=0, le=24 * 365)) -> dict:
        return q.map_points(svc.db, *rng(hours))

    @app.get("/api/events", dependencies=A)
    def events(limit: int = Query(100, ge=1, le=500), before: float | None = None, service: str | None = Query(None, max_length=32),
               event: str | None = Query(None, max_length=48), ip: str | None = Query(None, max_length=45),
               session: str | None = Query(None, max_length=40), q_: str | None = Query(None, alias="q", max_length=80)) -> list:
        if ip and not IP_RE.match(ip):
            raise HTTPException(400, "bad ip")
        if session and not SESSION_RE.match(session):
            raise HTTPException(400, "bad session")
        return q.recent_events(svc.db, limit, before, service, event, ip, session, q_)

    @app.get("/api/stream", dependencies=A)
    async def stream(request: Request) -> StreamingResponse:
        qu = svc.broker.subscribe()

        async def gen():
            yield "retry: 3000\n\n"
            try:
                while not await request.is_disconnected():
                    try:
                        item = await asyncio.wait_for(qu.get(), 15)
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
                        continue
                    yield f"data: {json.dumps(item, ensure_ascii=True)}\n\n"
            finally:
                svc.broker.unsubscribe(qu)

        return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    @app.get("/api/sessions", dependencies=A)
    def sessions(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), service: str | None = Query(None, max_length=32),
                 ip: str | None = Query(None, max_length=45), with_commands: bool = False, hours: float | None = Query(None, gt=0)) -> list:
        if ip and not IP_RE.match(ip):
            raise HTTPException(400, "bad ip")
        since = time.time() - hours * 3600 if hours else None
        return q.sessions_list(svc.db, limit, offset, service, ip, with_commands, since)

    @app.get("/api/sessions/{sid}", dependencies=A)
    def session(sid: str) -> dict:
        if not SESSION_RE.match(sid):
            raise HTTPException(400, "bad session id")
        d = q.session_detail(svc.db, sid)
        if d is None:
            raise HTTPException(404, "no such session")
        return d

    @app.get("/api/ips/{ip}", dependencies=A)
    def ip_profile(ip: str) -> dict:
        if not IP_RE.match(ip):
            raise HTTPException(400, "bad ip")
        d = q.ip_profile(svc.db, ip)
        if d is None:
            raise HTTPException(404, "unknown ip")
        return d

    @app.get("/api/samples", dependencies=A)
    def samples(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), q_: str | None = Query(None, alias="q", max_length=80)) -> list:
        return q.samples_list(svc.db, limit, offset, q_)

    @app.get("/api/samples/{sha}", dependencies=A)
    def sample(sha: str) -> dict:
        sha = sha.lower()
        if not SHA_RE.match(sha):
            raise HTTPException(400, "bad hash")
        d = q.sample_detail(svc.db, sha)
        if d is None:
            raise HTTPException(404, "unknown sample")
        d["report"] = load_report(s.analysis_dir, sha)
        d["bazaar_enabled"] = svc.ext.bazaar_on
        return d

    @app.get("/api/samples/{sha}/report.json", dependencies=A)
    def sample_report(sha: str) -> Response:
        sha = sha.lower()
        rep = load_report(s.analysis_dir, sha) if SHA_RE.match(sha) else None
        if rep is None:
            raise HTTPException(404, "no report")
        return Response(json.dumps(rep, indent=1), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{sha[:16]}-analysis.json"'})

    @app.post("/api/samples/{sha}/lookup", dependencies=A)
    def sample_lookup(sha: str) -> dict:
        sha = sha.lower()
        if not SHA_RE.match(sha) or not svc.db.one("SELECT 1 AS x FROM samples WHERE sha256=?", (sha,)):
            raise HTTPException(404, "unknown sample")
        if not svc.ext.bazaar_on:
            raise HTTPException(409, "MalwareBazaar lookup is disabled (HONEYNET_BAZAAR_ENABLED + HONEYNET_BAZAAR_KEY)")
        svc.ext.want_bazaar(sha)
        return {"queued": True}

    @app.get("/api/iocs", dependencies=A)
    def iocs(type: str | None = Query(None, max_length=20), kind: str | None = Query(None, max_length=12),
             q_: str | None = Query(None, alias="q", max_length=80), limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0)) -> list:
        return q.iocs_list(svc.db, type, q_, limit, offset, kind)

    @app.get("/api/attack", dependencies=A)
    def attack_(hours: float = Query(168, gt=0, le=24 * 365)) -> dict:
        return q.attack_matrix(svc.db, *rng(hours))

    @app.get("/api/alerts", dependencies=A)
    def alerts(limit: int = Query(100, ge=1, le=500)) -> dict:
        return {"alerts": svc.alerts.list(limit), "channels": svc.alerts.channels}

    @app.post("/api/alerts/ack", dependencies=A)
    async def alerts_ack(request: Request) -> dict:
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        aid = body.get("id") if isinstance(body, dict) else None
        svc.alerts.ack(int(aid) if isinstance(aid, int) else None)
        return {"ok": True}

    @app.get("/api/health", dependencies=A)
    def health() -> dict:
        per_service = svc.db.query("SELECT service, COUNT(*) AS events, MAX(ts) AS last FROM events GROUP BY service")
        now = time.time()
        for r in per_service:
            r["age"] = round(now - (r["last"] or now), 1)
        pending = int(svc.db.scalar("SELECT COUNT(*) FROM samples WHERE status='pending'"))
        try:
            dbsize = s.db_path.stat().st_size
        except OSError:
            dbsize = 0
        return {"ok": True, "uptime": round(now - svc.started), "events_total": int(svc.db.scalar("SELECT COUNT(*) FROM events")),
                "ingested_this_run": svc.ingestor.total, "rejected_lines": svc.ingestor.rejected, "services": per_service,
                "analysis_pending": pending, "db_bytes": dbsize, "alerts_unacked": int(svc.db.scalar("SELECT COUNT(*) FROM alerts WHERE acked=0"))}

    @app.get("/api/config", dependencies=A)
    def config() -> dict:
        return {"version": __version__, "test_mode": s.test_mode, "geoip": svc.geo.loaded, "geoip_simulated": s.test_mode,
                "abuseipdb": svc.ext.abuse_on, "bazaar": svc.ext.bazaar_on, "alert_channels": svc.alerts.channels,
                "retention_days": s.retention_days, "analysis_backend": s.analysis_backend, "ports": s.ports,
                "attack_matrix_tactics": attack.TACTICS, "export_formats": list(exports.FORMATS)}

    # ---------------------------------------------------------------- exports
    def attach(body: str, name: str, ctype: str) -> Response:
        return Response(s.redactor().scrub(body), media_type=ctype, headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @app.get("/api/export/blocklist", dependencies=A)
    def export_blocklist(fmt: str = Query("txt", max_length=10), level: str = Query("suspicious", max_length=12),
                         days: float = Query(30, gt=0, le=3650), min_score: int = Query(0, ge=0, le=100)) -> Response:
        if fmt not in exports.FORMATS or level not in exports.LEVELS:
            raise HTTPException(400, "bad format or level")
        entries = exports.blocklist_entries(svc.db, s, days=days, level=level, min_score=min_score)
        return attach(exports.render_blocklist(entries, fmt, level=level, days=days), f"honeynet-blocklist-{level}.{fmt}",
                      exports.CONTENT_TYPES[fmt])

    @app.get("/api/export/c2", dependencies=A)
    def export_c2(what: str = Query("ips", pattern="^(ips|domains|urls)$"), fmt: str = Query("txt", pattern="^(txt|json)$")) -> Response:
        ind = exports.c2_indicators(svc.db, s)
        if fmt == "json":
            return attach(json.dumps(ind, indent=1), "honeynet-c2.json", "application/json")
        return attach(exports.render_c2(ind, what), f"honeynet-c2-{what}.txt", "text/plain")

    @app.get("/api/export/iocs", dependencies=A)
    def export_iocs(fmt: str = Query("json", pattern="^(json|csv)$"), min_confidence: float = Query(0.0, ge=0, le=1),
                    include_private: bool = False) -> Response:
        rows = exports.ioc_rows(svc.db, s, include_private=include_private, min_confidence=min_confidence)
        return attach(exports.render_iocs(rows, fmt), f"honeynet-iocs.{fmt}", "application/json" if fmt == "json" else "text/csv")

    @app.get("/api/export/report", dependencies=A)
    def export_report(fmt: str = Query("md", pattern="^(md|html|json)$"), hours: float = Query(24, gt=0, le=24 * 90)) -> Response:
        since, until = rng(hours)
        rep = report.build(svc.db, s, since, until)
        if fmt == "json":
            return attach(json.dumps(rep, default=str, indent=1), "honeynet-report.json", "application/json")
        if fmt == "html":
            return attach(report.render_html(rep, s), "honeynet-report.html", "text/html")
        return attach(report.render_markdown(rep, s), "honeynet-report.md", "text/markdown")

    # ---------------------------------------------------------------- static SPA
    if STATIC_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
    return app


def serve(s: Settings) -> None:
    import uvicorn

    if s.dashboard_host not in ("127.0.0.1", "::1", "localhost"):
        log.warning("dashboard binds %s - make sure only an SSH tunnel/VPN/loopback-published port can reach it", s.dashboard_host)
    uvicorn.run(create_app(s), host=s.dashboard_host, port=s.dashboard_port, log_level="info", server_header=False, date_header=False,
                proxy_headers=False)
