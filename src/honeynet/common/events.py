"""Event schema, writer (honeypot side) and parser (collector side).

One JSON object per line:

    {"v":1,"id":"...","ts":1730000000.123,"service":"ssh","event":"auth.attempt",
     "src_ip":"203.0.113.9","src_port":51234,"dst_port":22,"session":"ab12...",
     "data":{...}}

The writer sanitises and bounds everything; the parser re-validates because the
event files live on a volume that a compromised honeypot container can write to.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .netutil import normalize_ip
from .redact import NULL_REDACTOR, Redactor
from .sanitize import sanitize_obj, sanitize_text

SCHEMA_VERSION = 1
MAX_LINE_BYTES = 256 * 1024

# --- canonical event names -----------------------------------------------------
CONN_OPEN = "conn.open"
CONN_CLOSE = "conn.close"
AUTH_ATTEMPT = "auth.attempt"
SESSION_OPEN = "session.open"
SESSION_CLOSE = "session.close"
CMD_INPUT = "cmd.input"
DOWNLOAD_ATTEMPT = "download.attempt"
FILE_CAPTURED = "file.captured"
FILE_EXEC = "file.exec_attempt"
HTTP_REQUEST = "http.request"
EXPLOIT = "exploit.attempt"
DB_QUERY = "db.query"
SCAN_PROBE = "probe"
LOG_SUPPRESSED = "log.suppressed"

_SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_EVENT_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,47}$")
_SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


@dataclass
class Event:
    id: str
    ts: float
    service: str
    event: str
    src_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    session: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": SCHEMA_VERSION, "id": self.id, "ts": round(self.ts, 3), "service": self.service,
            "event": self.event, "src_ip": self.src_ip, "src_port": self.src_port,
            "dst_port": self.dst_port, "session": self.session, "data": self.data,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=True)


def new_id() -> str:
    return secrets.token_hex(8)


def new_session_id() -> str:
    return secrets.token_hex(6)


def _int_or_none(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int) and 0 <= v <= 65535:
        return v
    return None


def parse_event(line: str | bytes) -> Event | None:
    """Parse + validate + re-sanitise one JSONL line. Returns None for garbage."""
    if isinstance(line, bytes):
        if len(line) > MAX_LINE_BYTES:
            return None
        line = line.decode("utf-8", "replace")
    elif len(line) > MAX_LINE_BYTES:
        return None
    line = line.strip()
    if not line or line[0] != "{":
        return None
    try:
        obj = json.loads(line)
    except (ValueError, RecursionError):
        return None
    if not isinstance(obj, dict):
        return None
    service, name = obj.get("service"), obj.get("event")
    if not isinstance(service, str) or not _SERVICE_RE.match(service):
        return None
    if not isinstance(name, str) or not _EVENT_RE.match(name):
        return None
    ip = normalize_ip(obj.get("src_ip", "")) if isinstance(obj.get("src_ip"), str) else None
    if ip is None:
        return None
    ts = obj.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not (946684800 < ts < 4102444800):
        return None
    eid = obj.get("id")
    if not isinstance(eid, str) or not re.match(r"^[A-Za-z0-9_-]{4,40}$", eid):
        eid = new_id()
    sess = obj.get("session")
    if sess is not None and not (isinstance(sess, str) and _SESSION_RE.match(sess)):
        sess = None
    data = obj.get("data")
    if not isinstance(data, dict):
        data = {}
    return Event(
        id=eid, ts=float(ts), service=service, event=name, src_ip=ip,
        src_port=_int_or_none(obj.get("src_port")), dst_port=_int_or_none(obj.get("dst_port")),
        session=sess, data=sanitize_obj(data),
    )


class _Bucket:
    __slots__ = ("window", "count")

    def __init__(self) -> None:
        self.window = 0
        self.count = 0


class EventWriter:
    """Append-only JSONL writer with sanitisation, redaction and anti-flood limits."""

    def __init__(
        self,
        service: str,
        events_dir: Path,
        *,
        redactor: Redactor = NULL_REDACTOR,
        max_per_ip_minute: int = 600,
        max_dir_bytes: int = 512 * 1024 * 1024,
        rotate_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        if not _SERVICE_RE.match(service):
            raise ValueError(f"bad service name {service!r}")
        self.service = service
        self.dir = Path(events_dir) / service
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "events.jsonl"
        self.redactor = redactor
        self.max_per_ip_minute = max_per_ip_minute
        self.max_dir_bytes = max_dir_bytes
        self.rotate_bytes = rotate_bytes
        self._lock = threading.Lock()
        self._buckets: dict[str, _Bucket] = {}
        self._suppressed: dict[str, int] = {}
        self._writes = 0
        self._disk_full = False
        self._fd: int | None = None
        self._fd_ino = -1
        self.dropped_ignored = 0
        self.listeners: list = []   # optional in-process taps (used by tests / dev mode)

    # -- public API ------------------------------------------------------------
    def emit(
        self,
        event: str,
        src_ip: str,
        *,
        src_port: int | None = None,
        dst_port: int | None = None,
        session: str | None = None,
        **data: Any,
    ) -> Event | None:
        ip = normalize_ip(src_ip) or "0.0.0.0"
        if self.redactor.is_ignored(ip):
            self.dropped_ignored += 1
            return None
        now = time.time()
        if not self._admit(ip, now):
            return None
        clean = sanitize_obj(data)
        if self.redactor.ignore_raw or self.redactor.secrets:
            clean = self.redactor.scrub_obj(clean)
        ev = Event(new_id(), now, self.service, event, ip, _int_or_none(src_port),
                   _int_or_none(dst_port), session, clean)
        self._write(ev)
        for fn in self.listeners:
            try:
                fn(ev)
            except Exception:  # noqa: BLE001 - taps must never break the honeypot
                pass
        return ev

    def emit_at(self, ts: float, event: str, src_ip: str, *, src_port: int | None = None, dst_port: int | None = None,
                session: str | None = None, **data: Any) -> Event | None:
        """Explicit-timestamp variant for the simulator's backfill (skips the flood limiter, keeps sanitising/redaction)."""
        ip = normalize_ip(src_ip) or "0.0.0.0"
        if self.redactor.is_ignored(ip):
            self.dropped_ignored += 1
            return None
        clean = sanitize_obj(data)
        if self.redactor.ignore_raw or self.redactor.secrets:
            clean = self.redactor.scrub_obj(clean)
        ev = Event(new_id(), float(ts), self.service, event, ip, _int_or_none(src_port), _int_or_none(dst_port), session, clean)
        self._write(ev)
        return ev

    # -- internals -------------------------------------------------------------
    def _admit(self, ip: str, now: float) -> bool:
        minute = int(now // 60)
        with self._lock:
            b = self._buckets.get(ip)
            if b is None:
                if len(self._buckets) > 20000:
                    self._buckets.clear()
                b = self._buckets[ip] = _Bucket()
            if b.window != minute:
                if self._suppressed.get(ip):
                    n = self._suppressed.pop(ip)
                    self._write_raw(Event(new_id(), now, self.service, LOG_SUPPRESSED, ip,
                                          data={"suppressed": n}))
                b.window, b.count = minute, 0
            b.count += 1
            if b.count > self.max_per_ip_minute:
                self._suppressed[ip] = self._suppressed.get(ip, 0) + 1
                return False
        return True

    def _write(self, ev: Event) -> None:
        with self._lock:
            self._write_raw(ev)

    def _write_raw(self, ev: Event) -> None:
        self._writes += 1
        if self._writes % 200 == 1:
            self._check_disk()
        if self._disk_full and ev.event not in (SESSION_CLOSE, FILE_CAPTURED):
            return
        line = (ev.to_json() + "\n").encode("ascii")
        try:
            fd = self._current_fd()
            os.write(fd, line)
        except OSError:
            self._close_fd()
            self._disk_full = True

    def _current_fd(self) -> int:
        """Append handle kept open between events (reopened after rotation/removal).

        Re-opening per event costs a full close-time scan on some platforms (Windows AV), so the
        handle is cached and validated with one cheap stat per write.
        """
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            self._close_fd()
            return self._open_fd()
        if self._fd is not None and st.st_ino == self._fd_ino and st.st_size < self.rotate_bytes:
            return self._fd
        if st.st_size >= self.rotate_bytes:
            self._close_fd()
            self._rotate()
            return self._open_fd()
        self._close_fd()
        return self._open_fd()

    def _open_fd(self) -> int:
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        self._fd = fd
        try:
            self._fd_ino = os.fstat(fd).st_ino
        except OSError:
            self._fd_ino = -1
        return fd

    def _close_fd(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def close(self) -> None:
        with self._lock:
            self._close_fd()

    def __del__(self) -> None:  # pragma: no cover - best effort
        try:
            self._close_fd()
        except Exception:  # noqa: BLE001
            pass

    def _rotate(self) -> None:
        old = self.path.with_suffix(".jsonl.1")
        try:
            if old.exists():
                old.unlink()
            self.path.rename(old)
        except OSError:
            pass

    def _check_disk(self) -> None:
        total = 0
        try:
            for p in self.dir.iterdir():
                total += p.stat().st_size
        except OSError:
            return
        self._disk_full = total > self.max_dir_bytes


def event_preview(ev: Event, width: int = 160) -> str:
    """One-line human readable form, safe for logs."""
    summary = ", ".join(f"{k}={sanitize_text(v, 40)}" for k, v in list(ev.data.items())[:4])
    return f"[{ev.service}] {ev.event} {ev.src_ip} {summary}"[:width]
