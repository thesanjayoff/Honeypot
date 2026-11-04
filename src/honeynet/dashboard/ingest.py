"""Collector: tails the honeypots' JSONL event files into SQLite and maintains the derived tables.

The event volume is written by containers an attacker may have partially compromised, so every
line goes through ``parse_event`` again and every number/string is bounded before it is stored.
Rotation (events.jsonl -> events.jsonl.1) is followed by inode, nothing is ever deleted here.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import urllib.parse
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..common.config import Settings
from ..common.events import Event, parse_event
from ..common.netutil import is_public, is_test_net
from ..common.sanitize import sanitize_text
from . import attack, classify
from .db import DB
from .enrich import ExternalLookups, GeoResolver

log = logging.getLogger("honeynet.ingest")
MAX_READ = 16 * 1024 * 1024
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def summarize(ev: Event) -> str:
    d, e = ev.data, ev.event
    if e == "auth.attempt":
        pw = d.get("password", "")
        return f"{d.get('username', '')}:{pw} ({d.get('method', '')}) {'OK' if d.get('success') else 'fail'}"
    if e == "cmd.input":
        return str(d.get("input", ""))[:300]
    if e == "http.request":
        return f"{d.get('method', '')} {str(d.get('path', ''))[:200]} -> {d.get('status', '')}"
    if e == "exploit.attempt":
        return f"{d.get('rule', '')} {d.get('cve', '')} [{d.get('category', '')}]".strip()
    if e == "db.query":
        return str(d.get("query", ""))[:300]
    if e == "file.captured":
        return f"{str(d.get('sha256', ''))[:16]} {d.get('size', 0)}B via {d.get('via', '')}"
    if e == "download.attempt":
        return str(d.get("url", ""))[:300]
    if e in ("session.open", "session.close"):
        return f"{d.get('username', '')} {d.get('method', '') or d.get('reason', '')}".strip()
    if e == "probe":
        return str(d.get("proto_guess", ""))
    if e == "client.fingerprint":
        return str(d.get("client_version") or d.get("client_name") or d.get("opts_hash") or "")[:120]
    if e == "conn.close":
        return f"{d.get('duration', 0)}s {d.get('reason', '')}"
    return ", ".join(f"{k}={sanitize_text(v, 40)}" for k, v in list(d.items())[:3])[:200]


class Ingestor:
    def __init__(self, settings: Settings, db: DB, geo: GeoResolver, ext: ExternalLookups | None = None,
                 on_events: Callable[[list[dict]], None] | None = None, on_new_sample: Callable[[dict], None] | None = None,
                 on_new_rule: Callable[[dict], None] | None = None) -> None:
        self.s, self.db, self.geo, self.ext = settings, db, geo, ext
        self.on_events, self.on_new_sample, self.on_new_rule = on_events, on_new_sample, on_new_rule
        self.redactor = settings.redactor()
        self._seen_attack: set[tuple[str, int, str]] = set()
        self._stop = threading.Event()
        self.total = 0
        self.rejected = 0
        self._lock = threading.Lock()

    # -- file following ---------------------------------------------------------------
    def _services(self) -> list[Path]:
        try:
            return sorted(p for p in self.s.events_dir.iterdir() if p.is_dir())
        except OSError:
            return []

    def _read_from(self, path: Path, offset: int) -> tuple[list[str], int]:
        """Read complete lines from ``offset``; returns (lines, new_offset)."""
        try:
            with open(path, "rb") as fh:
                fh.seek(offset)
                chunk = fh.read(MAX_READ)
        except OSError:
            return [], offset
        end = chunk.rfind(b"\n")
        if end < 0:
            return [], offset
        body = chunk[: end + 1]
        return [ln.decode("utf-8", "replace") for ln in body.split(b"\n") if ln.strip()], offset + len(body)

    def _collect(self, sdir: Path) -> list[str]:
        name = sdir.name
        st = self.db.one("SELECT inode, offset FROM ingest_state WHERE service=?", (name,))
        cur, rot = sdir / "events.jsonl", sdir / "events.jsonl.1"
        lines: list[str] = []
        new_state: tuple[int, int] | None = None
        try:
            cur_stat = cur.stat()
        except OSError:
            cur_stat = None
        inode, offset = (st["inode"], st["offset"]) if st else (None, 0)

        if cur_stat is not None and st is not None and cur_stat.st_ino == inode:
            if cur_stat.st_size < offset:                       # truncated in place
                offset = 0
            got, offset = self._read_from(cur, offset)
            lines += got
            new_state = (cur_stat.st_ino, offset)
        else:
            # first run, or the file was rotated: finish the old file first, then start the new one at 0
            if rot.exists():
                try:
                    rot_stat = rot.stat()
                except OSError:
                    rot_stat = None
                if rot_stat is not None:
                    start = offset if (st is not None and rot_stat.st_ino == inode) else 0
                    got, _ = self._read_from(rot, start)
                    lines += got
            if cur_stat is not None:
                got, off2 = self._read_from(cur, 0)
                lines += got
                new_state = (cur_stat.st_ino, off2)
        if new_state is not None:
            self.db.execute("INSERT INTO ingest_state(service,inode,offset,size) VALUES(?,?,?,?) "
                            "ON CONFLICT(service) DO UPDATE SET inode=excluded.inode, offset=excluded.offset, size=excluded.size",
                            (name, new_state[0], new_state[1], cur_stat.st_size if cur_stat else 0))
        return lines

    # -- main loop --------------------------------------------------------------------
    def poll_once(self) -> int:
        events: list[Event] = []
        for sdir in self._services():
            for line in self._collect(sdir):
                ev = parse_event(line)
                if ev is None:
                    self.rejected += 1
                    continue
                if self.redactor.is_ignored(ev.src_ip):
                    continue
                if self.redactor.secrets:
                    ev.data = self.redactor.scrub_obj(ev.data)
                events.append(ev)
        if not events:
            return 0
        events.sort(key=lambda e: e.ts)
        return self.ingest(events)

    def ingest(self, events: list[Event]) -> int:
        stored: list[Event] = []
        new_ips: set[str] = set()
        new_samples: list[dict] = []
        new_rules: list[dict] = []
        touched: set[str] = set()
        ua_by_ip: dict[str, set[str]] = defaultdict(set)
        with self._lock, self.db.write() as c:
            for ev in events:
                if not self._apply(c, ev, new_ips, new_samples, new_rules, ua_by_ip):
                    continue
                stored.append(ev)
                touched.add(ev.src_ip)
            self._refresh_ips(c, stored, touched, ua_by_ip)
        self.total += len(stored)
        for ip in new_ips:
            self._enrich(ip)
        if self.ext:
            for ip in touched:
                self.ext.want_abuse(ip)
        for s in new_samples:
            if self.ext:
                self.ext.want_bazaar(s["sha256"])
            if self.on_new_sample:
                self.on_new_sample(s)
        for r in new_rules:
            if self.on_new_rule:
                self.on_new_rule(r)
        if self.on_events and stored:
            self.on_events([self.public_event(e) for e in stored[-200:]])
        return len(stored)

    @staticmethod
    def public_event(ev: Event) -> dict:
        return {"id": ev.id, "ts": ev.ts, "service": ev.service, "event": ev.event, "src_ip": ev.src_ip, "dst_port": ev.dst_port,
                "session": ev.session, "summary": summarize(ev)}

    # -- per event --------------------------------------------------------------------
    def _attack(self, c, tech: str, ev: Event, evidence: str, dedupe: bool = False) -> None:
        if dedupe:
            key = (ev.src_ip, int(ev.ts // 3600), tech)
            if key in self._seen_attack:
                return
            if len(self._seen_attack) > 100_000:
                self._seen_attack.clear()
            self._seen_attack.add(key)
        c.execute("INSERT INTO attack_hits(technique,ts,src_ip,session,event_id,evidence) VALUES(?,?,?,?,?,?)",
                  (tech, ev.ts, ev.src_ip, ev.session, ev.id, sanitize_text(evidence, 160)))

    def _apply(self, c, ev: Event, new_ips: set[str], new_samples: list[dict], new_rules: list[dict],
               ua_by_ip: dict[str, set[str]]) -> bool:
        d = ev.data
        cur = c.execute("INSERT OR IGNORE INTO events(id,ts,service,event,src_ip,src_port,dst_port,session,summary,data) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (ev.id, ev.ts, ev.service, ev.event, ev.src_ip, ev.src_port, ev.dst_port, ev.session, summarize(ev),
                         json.dumps(d, separators=(",", ":"))[:20000]))
        if cur.rowcount == 0:
            return False
        e = ev.event
        inc = {"events": 1, "conns": 0, "auth": 0, "cmds": 0, "exploits": 0, "files": 0, "sessions": 0}
        row = c.execute("SELECT 1 FROM ip_info WHERE ip=?", (ev.src_ip,)).fetchone()
        if row is None:
            new_ips.add(ev.src_ip)
            c.execute("INSERT INTO ip_info(ip, first_seen, last_seen) VALUES(?,?,?)", (ev.src_ip, ev.ts, ev.ts))
        sid = ev.session
        if sid:
            c.execute("INSERT INTO sessions(id,service,src_ip,src_port,dst_port,first_ts,last_ts) VALUES(?,?,?,?,?,?,?) "
                      "ON CONFLICT(id) DO UPDATE SET last_ts=max(last_ts,excluded.last_ts), first_ts=min(first_ts,excluded.first_ts)",
                      (sid, ev.service, ev.src_ip, ev.src_port, ev.dst_port, ev.ts, ev.ts))

        if e == "conn.open":
            inc["conns"] = 1
        elif e == "auth.attempt":
            inc["auth"] = 1
            c.execute("INSERT INTO auth_attempts(ts,service,src_ip,session,username,password,method,success) VALUES(?,?,?,?,?,?,?,?)",
                      (ev.ts, ev.service, ev.src_ip, sid, str(d.get("username", ""))[:128], str(d.get("password", ""))[:256],
                       str(d.get("method", ""))[:32], 1 if d.get("success") else 0))
            if sid:
                c.execute("UPDATE sessions SET auth_attempts=auth_attempts+1 WHERE id=?", (sid,))
            for t, evd in attack.map_event(e, d):
                self._attack(c, t, ev, evd, dedupe=(t != "T1078"))
        elif e == "session.open":
            inc["sessions"] = 1
            if sid:
                c.execute("UPDATE sessions SET authed=1, username=?, password=?, method=?, client=?, hassh=COALESCE(NULLIF(?,''),hassh) WHERE id=?",
                          (str(d.get("username", ""))[:64], str(d.get("password", ""))[:128], str(d.get("method", ""))[:32],
                           str(d.get("client_version", ""))[:120], str(d.get("hassh", ""))[:64], sid))
        elif e == "session.close":
            if sid:
                c.execute("UPDATE sessions SET closed=1, duration=?, downloads=? WHERE id=?",
                          (float(d.get("duration", 0) or 0), int(d.get("downloads", 0) or 0), sid))
        elif e == "client.fingerprint" and sid:
            if d.get("hassh"):
                c.execute("UPDATE sessions SET hassh=?, client=COALESCE(NULLIF(?,''),client) WHERE id=?",
                          (str(d["hassh"])[:64], str(d.get("client_version", ""))[:120], sid))
        elif e == "cmd.input":
            if not d.get("nested"):
                inc["cmds"] = 1
                if sid:
                    c.execute("UPDATE sessions SET commands=commands+1 WHERE id=?", (sid,))
            text = str(d.get("input", ""))
            c.execute("INSERT INTO commands(ts,service,src_ip,session,input,status) VALUES(?,?,?,?,?,?)",
                      (ev.ts, ev.service, ev.src_ip, sid, text[:4096], d.get("status") if isinstance(d.get("status"), int) else None))
            for t, evd in attack.map_command(text):
                self._attack(c, t, ev, evd)
        elif e == "http.request":
            ua = str(d.get("user_agent", ""))
            ua_by_ip[ev.src_ip] |= classify.ua_flags(ua)
        elif e == "exploit.attempt":
            inc["exploits"] = 1
            rule = str(d.get("rule", ""))[:80]
            first = c.execute("SELECT 1 FROM exploits WHERE rule=? LIMIT 1", (rule,)).fetchone() is None
            c.execute("INSERT INTO exploits(ts,service,src_ip,session,rule,cve,category,severity,snippet,path,method) "
                      "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                      (ev.ts, ev.service, ev.src_ip, sid, rule, str(d.get("cve", ""))[:32], str(d.get("category", ""))[:32],
                       int(d.get("severity", 1) or 1), str(d.get("snippet", ""))[:300], str(d.get("path", ""))[:500],
                       str(d.get("method", ""))[:16]))
            if sid:
                c.execute("UPDATE sessions SET exploits=exploits+1 WHERE id=?", (sid,))
            for t, evd in attack.map_event(e, d):
                self._attack(c, t, ev, evd, dedupe=True)
            if first:
                new_rules.append({"rule": rule, "cve": d.get("cve", ""), "category": d.get("category", ""),
                                  "severity": d.get("severity", 1), "src_ip": ev.src_ip, "service": ev.service,
                                  "snippet": str(d.get("snippet", ""))[:200], "ts": ev.ts})
        elif e == "db.query":
            if sid:
                c.execute("UPDATE sessions SET queries=queries+1 WHERE id=?", (sid,))
        elif e == "file.captured":
            inc["files"] = 1
            if sid:
                c.execute("UPDATE sessions SET files=files+1 WHERE id=?", (sid,))
            self._sample(c, ev, new_samples)
        elif e == "download.attempt":
            self._observed_download(c, ev)
            for t, evd in attack.map_event(e, d):
                self._attack(c, t, ev, evd)
        elif e == "probe":
            for t, evd in attack.map_event(e, d):
                self._attack(c, t, ev, evd, dedupe=True)
        elif e in ("file.exec_attempt", "cron.install", "net.outbound_attempt", "sftp.open"):
            for t, evd in attack.map_event(e, d):
                self._attack(c, t, ev, evd)
            if e == "net.outbound_attempt":
                self._observed_host(c, ev, str(d.get("target", "")), "outbound attempt from shell")

        c.execute("UPDATE ip_info SET events=events+?, conns=conns+?, auth=auth+?, cmds=cmds+?, exploits=exploits+?, files=files+?, "
                  "sessions=sessions+?, last_seen=max(last_seen,?), first_seen=min(first_seen,?) WHERE ip=?",
                  (inc["events"], inc["conns"], inc["auth"], inc["cmds"], inc["exploits"], inc["files"], inc["sessions"],
                   ev.ts, ev.ts, ev.src_ip))
        return True

    # -- samples & observed IOCs ------------------------------------------------------
    def _sample(self, c, ev: Event, new_samples: list[dict]) -> None:
        d = ev.data
        sha = str(d.get("sha256", "")).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            return
        row = c.execute("SELECT 1 FROM samples WHERE sha256=?", (sha,)).fetchone()
        size = int(d.get("size", 0) or 0)
        c.execute("INSERT INTO samples(sha256,md5,size,first_seen,last_seen,count,truncated) VALUES(?,?,?,?,?,1,?) "
                  "ON CONFLICT(sha256) DO UPDATE SET last_seen=max(last_seen,excluded.last_seen), count=count+1",
                  (sha, str(d.get("md5", ""))[:32], size, ev.ts, ev.ts, 1 if d.get("truncated") else 0))
        n = c.execute("SELECT COUNT(*) FROM sample_sources WHERE sha256=?", (sha,)).fetchone()[0]
        if n < 200:
            c.execute("INSERT INTO sample_sources(sha256,ts,src_ip,session,service,origin,url,path,via) VALUES(?,?,?,?,?,?,?,?,?)",
                      (sha, ev.ts, ev.src_ip, ev.session, ev.service, str(d.get("origin", ""))[:40], str(d.get("url", ""))[:2048],
                       str(d.get("path", ""))[:300], str(d.get("via", ""))[:40]))
        url = str(d.get("url", ""))
        if url:
            self._observed_url(c, ev, url, sha)
        if row is None:
            new_samples.append({"sha256": sha, "size": size, "src_ip": ev.src_ip, "service": ev.service, "ts": ev.ts,
                                "origin": d.get("origin", ""), "url": url[:300]})

    def _routable(self, host: str) -> tuple[bool, str]:
        """-> (worth recording, scope)"""
        if is_public(host):
            return True, "public"
        if self.s.test_mode and is_test_net(host):
            return True, "documentation"
        return False, ""

    def _add_ioc(self, c, typ: str, value: str, scope: str, conf: float, ctx: str, ts: float, sha: str | None) -> None:
        value = value[:2048]
        c.execute("INSERT INTO iocs(type,value,scope,confidence,kind,context,first_seen,last_seen,hits) VALUES(?,?,?,?,?,?,?,?,1) "
                  "ON CONFLICT(type,value) DO UPDATE SET last_seen=max(last_seen,excluded.last_seen), hits=hits+1, "
                  "confidence=max(confidence,excluded.confidence)", (typ, value, scope, conf, "observed", ctx[:200], ts, ts))
        if sha:
            c.execute("INSERT OR IGNORE INTO ioc_samples(type,value,sha256) VALUES(?,?,?)", (typ, value, sha))

    def _observed_url(self, c, ev: Event, url: str, sha: str | None) -> None:
        try:
            p = urllib.parse.urlsplit(url)
            host = p.hostname or ""
        except ValueError:
            return
        if p.scheme.lower() not in ("http", "https", "ftp", "tftp") or not HOST_RE.match(host):
            return
        self._host_ioc(c, ev, host, url, sha)

    def _host_ioc(self, c, ev: Event, host: str, url: str | None, sha: str | None) -> None:
        import ipaddress

        is_ip = True
        try:
            ipaddress.ip_address(host)
        except ValueError:
            is_ip = False
        if is_ip:
            ok, scope = self._routable(host)
            if not ok:
                return
            if url:
                self._add_ioc(c, "url", url, scope, 0.85, "payload URL seen in attacker session", ev.ts, sha)
            self._add_ioc(c, "ip", host, scope, 0.8, "payload host seen in attacker session", ev.ts, sha)
        else:
            if "." not in host or host.endswith((".local", ".internal", ".lan", ".localdomain")):
                return
            if url:
                self._add_ioc(c, "url", url, "", 0.8, "payload URL seen in attacker session", ev.ts, sha)
            self._add_ioc(c, "domain", host.lower(), "", 0.7, "payload host seen in attacker session", ev.ts, sha)

    def _observed_download(self, c, ev: Event) -> None:
        url = str(ev.data.get("url", ""))
        sha = str(ev.data.get("sha256", "")) or None
        if sha and not re.fullmatch(r"[0-9a-f]{64}", sha):
            sha = None
        if url:
            self._observed_url(c, ev, url, sha)

    def _observed_host(self, c, ev: Event, target: str, ctx: str) -> None:
        host = target.split("@")[-1].split(":")[0].split("/")[0]
        if HOST_RE.match(host):
            self._host_ioc(c, ev, host, None, None)

    # -- per-IP derived fields ----------------------------------------------------------
    def _refresh_ips(self, c, events: list[Event], touched: set[str], ua_by_ip: dict[str, set[str]]) -> None:
        services: dict[str, set[str]] = defaultdict(set)
        ports: dict[str, set[int]] = defaultdict(set)
        for ev in events:
            services[ev.src_ip].add(ev.service)
            if ev.dst_port:
                ports[ev.src_ip].add(ev.dst_port)
        for ip in touched:
            r = c.execute("SELECT * FROM ip_info WHERE ip=?", (ip,)).fetchone()
            if r is None:
                continue
            tags = set(json.loads(r["tags"] or "[]")) | ua_by_ip.get(ip, set())
            tags -= {"scanner"}                       # recomputed below
            tags |= set(classify.tags_for(dict(r), tags))
            svc = sorted(set(json.loads(r["services"] or "[]")) | services.get(ip, set()))[:20]
            prt = sorted(set(json.loads(r["ports"] or "[]")) | ports.get(ip, set()))[:50]
            cls = classify.classify(dict(r), sorted(tags), r["org"])
            c.execute("UPDATE ip_info SET tags=?, classification=?, services=?, ports=? WHERE ip=?",
                      (json.dumps(sorted(tags)), cls, json.dumps(svc), json.dumps(prt), ip))

    def _enrich(self, ip: str) -> None:
        info = self.geo.lookup(ip)
        if not info:
            return
        with self.db.write() as c:
            c.execute("UPDATE ip_info SET country=?, country_name=?, city=?, lat=?, lon=?, asn=?, org=?, enriched=1 WHERE ip=?",
                      (info.get("country"), info.get("country_name"), info.get("city"), info.get("lat"), info.get("lon"),
                       info.get("asn"), info.get("org"), ip))
            r = c.execute("SELECT * FROM ip_info WHERE ip=?", (ip,)).fetchone()
            if r is not None:
                cls = classify.classify(dict(r), json.loads(r["tags"] or "[]"), r["org"])
                c.execute("UPDATE ip_info SET classification=? WHERE ip=?", (cls, ip))

    def reenrich_missing(self, limit: int = 500) -> int:
        """Fill geo for IPs that were seen before a GeoIP database was installed."""
        rows = self.db.query("SELECT ip FROM ip_info WHERE enriched=0 ORDER BY last_seen DESC LIMIT ?", (limit,))
        for r in rows:
            self._enrich(r["ip"])
        return len(rows)

    # -- lifecycle --------------------------------------------------------------------
    def run_forever(self) -> None:
        last_prune = 0.0
        while not self._stop.is_set():
            try:
                n = self.poll_once()
            except Exception:  # noqa: BLE001 - the collector must survive anything the volume contains
                log.exception("ingest iteration failed")
                n = 0
            if time.time() - last_prune > 3600:
                last_prune = time.time()
                try:
                    cutoff = time.time() - self.s.retention_days * 86400
                    self.db.prune(cutoff)
                except Exception:  # noqa: BLE001
                    log.exception("prune failed")
            if n == 0:
                self._stop.wait(self.s.ingest_poll_seconds)

    def stop(self) -> None:
        self._stop.set()


def ensure_events_dir(settings: Settings) -> None:
    os.makedirs(settings.events_dir, exist_ok=True)
