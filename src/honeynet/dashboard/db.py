"""SQLite store for the dashboard (WAL; one serialized writer, many readers).

Everything stored here already passed ``parse_event`` (re-validation + sanitisation), so the API
can return it as-is; the frontend still only ever uses ``textContent``.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, ts REAL NOT NULL, service TEXT NOT NULL, event TEXT NOT NULL, src_ip TEXT NOT NULL,
  src_port INTEGER, dst_port INTEGER, session TEXT, summary TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_ip ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS ix_events_session ON events(session, ts);
CREATE INDEX IF NOT EXISTS ix_events_event ON events(event, ts);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, service TEXT, src_ip TEXT, src_port INTEGER, dst_port INTEGER,
  first_ts REAL, last_ts REAL, authed INTEGER DEFAULT 0, closed INTEGER DEFAULT 0, duration REAL DEFAULT 0,
  username TEXT, password TEXT, method TEXT, client TEXT, hassh TEXT,
  commands INTEGER DEFAULT 0, downloads INTEGER DEFAULT 0, files INTEGER DEFAULT 0,
  auth_attempts INTEGER DEFAULT 0, exploits INTEGER DEFAULT 0, queries INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_sessions_ts ON sessions(first_ts);
CREATE INDEX IF NOT EXISTS ix_sessions_ip ON sessions(src_ip, first_ts);
CREATE TABLE IF NOT EXISTS auth_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, service TEXT, src_ip TEXT, session TEXT,
  username TEXT, password TEXT, method TEXT, success INTEGER);
CREATE INDEX IF NOT EXISTS ix_auth_ts ON auth_attempts(ts);
CREATE INDEX IF NOT EXISTS ix_auth_ip ON auth_attempts(src_ip);
CREATE TABLE IF NOT EXISTS commands (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, service TEXT, src_ip TEXT, session TEXT, input TEXT, status INTEGER);
CREATE INDEX IF NOT EXISTS ix_cmd_ts ON commands(ts);
CREATE TABLE IF NOT EXISTS exploits (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, service TEXT, src_ip TEXT, session TEXT, rule TEXT, cve TEXT,
  category TEXT, severity INTEGER, snippet TEXT, path TEXT, method TEXT);
CREATE INDEX IF NOT EXISTS ix_exp_ts ON exploits(ts);
CREATE INDEX IF NOT EXISTS ix_exp_rule ON exploits(rule);
CREATE TABLE IF NOT EXISTS samples (
  sha256 TEXT PRIMARY KEY, md5 TEXT, size INTEGER, first_seen REAL, last_seen REAL, count INTEGER DEFAULT 0,
  status TEXT DEFAULT 'pending', family TEXT, family_name TEXT, family_conf REAL, risk_score INTEGER, risk_level TEXT,
  file_type TEXT, arch TEXT, packed INTEGER, analyzed_at TEXT, report_mtime REAL, bazaar TEXT, bazaar_checked REAL,
  truncated INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_samples_seen ON samples(first_seen);
CREATE TABLE IF NOT EXISTS sample_sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT, ts REAL, src_ip TEXT, session TEXT, service TEXT,
  origin TEXT, url TEXT, path TEXT, via TEXT);
CREATE INDEX IF NOT EXISTS ix_ss_sha ON sample_sources(sha256);
CREATE TABLE IF NOT EXISTS iocs (
  type TEXT NOT NULL, value TEXT NOT NULL, scope TEXT DEFAULT '', confidence REAL DEFAULT 0.5, kind TEXT DEFAULT 'analysis',
  context TEXT DEFAULT '', first_seen REAL, last_seen REAL, hits INTEGER DEFAULT 1, PRIMARY KEY (type, value));
CREATE INDEX IF NOT EXISTS ix_iocs_seen ON iocs(last_seen);
CREATE TABLE IF NOT EXISTS ioc_samples (type TEXT, value TEXT, sha256 TEXT, PRIMARY KEY (type, value, sha256));
CREATE TABLE IF NOT EXISTS ip_info (
  ip TEXT PRIMARY KEY, country TEXT, country_name TEXT, city TEXT, lat REAL, lon REAL, asn INTEGER, org TEXT,
  abuse_score INTEGER, abuse_checked REAL, classification TEXT DEFAULT 'unknown', tags TEXT DEFAULT '[]',
  first_seen REAL, last_seen REAL, events INTEGER DEFAULT 0, conns INTEGER DEFAULT 0, auth INTEGER DEFAULT 0,
  sessions INTEGER DEFAULT 0, cmds INTEGER DEFAULT 0, exploits INTEGER DEFAULT 0, files INTEGER DEFAULT 0,
  enriched INTEGER DEFAULT 0, services TEXT DEFAULT '[]', ports TEXT DEFAULT '[]');
CREATE INDEX IF NOT EXISTS ix_ip_seen ON ip_info(last_seen);
CREATE INDEX IF NOT EXISTS ix_ip_country ON ip_info(country);
CREATE INDEX IF NOT EXISTS ix_ip_asn ON ip_info(asn);
CREATE TABLE IF NOT EXISTS attack_hits (
  id INTEGER PRIMARY KEY AUTOINCREMENT, technique TEXT, ts REAL, src_ip TEXT, session TEXT, event_id TEXT, evidence TEXT);
CREATE INDEX IF NOT EXISTS ix_attack_tech ON attack_hits(technique, ts);
CREATE INDEX IF NOT EXISTS ix_attack_ts ON attack_hits(ts);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, key TEXT, title TEXT, detail TEXT, severity TEXT,
  delivered INTEGER DEFAULT 0, acked INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS ingest_state (service TEXT PRIMARY KEY, inode INTEGER, offset INTEGER, size INTEGER);
"""


class DB:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._wlock = threading.RLock()
        self._local = threading.local()
        self._wconn = self._connect()
        self._wconn.executescript(SCHEMA)
        self.set_meta("schema", str(SCHEMA_VERSION))

    def _connect(self) -> sqlite3.Connection:
        c = sqlite3.connect(str(self.path), timeout=30, isolation_level=None, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA foreign_keys=OFF")
        c.execute("PRAGMA busy_timeout=30000")
        return c

    # ---- writes (serialized) ---------------------------------------------------------
    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        with self._wlock:
            c = self._wconn
            c.execute("BEGIN IMMEDIATE")
            try:
                yield c
            except BaseException:
                c.execute("ROLLBACK")
                raise
            else:
                c.execute("COMMIT")

    def execute(self, sql: str, params: Iterable[Any] = ()) -> None:
        with self.write() as c:
            c.execute(sql, tuple(params))

    # ---- reads (per-thread connection) -----------------------------------------------
    def _rconn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = self._local.conn = self._connect()
            c.execute("PRAGMA query_only=ON")
        return c

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        return [dict(r) for r in self._rconn().execute(sql, tuple(params)).fetchall()]

    def one(self, sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
        r = self._rconn().execute(sql, tuple(params)).fetchone()
        return dict(r) if r else None

    def scalar(self, sql: str, params: Iterable[Any] = (), default: Any = 0) -> Any:
        r = self._rconn().execute(sql, tuple(params)).fetchone()
        return default if r is None or r[0] is None else r[0]

    # ---- meta ------------------------------------------------------------------------
    def get_meta(self, key: str, default: str | None = None) -> str | None:
        r = self.one("SELECT value FROM meta WHERE key=?", (key,))
        return r["value"] if r else default

    def set_meta(self, key: str, value: str) -> None:
        self.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def close(self) -> None:
        try:
            self._wconn.close()
        except sqlite3.Error:
            pass

    def prune(self, older_than_ts: float) -> int:
        """Retention: drop raw rows (keeps samples, IOCs, IP profiles and alerts)."""
        n = 0
        with self.write() as c:
            for table, col in (("events", "ts"), ("auth_attempts", "ts"), ("commands", "ts"), ("exploits", "ts"),
                               ("attack_hits", "ts")):
                n += c.execute(f"DELETE FROM {table} WHERE {col} < ?", (older_than_ts,)).rowcount
            n += c.execute("DELETE FROM sessions WHERE last_ts < ?", (older_than_ts,)).rowcount
        return n


def now() -> float:
    return time.time()
