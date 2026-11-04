"""Read-side queries shared by the HTTP API, the exports and the daily report."""

from __future__ import annotations

import json
import time
from typing import Any

from . import attack
from .db import DB

QUIET = ("conn.close", "session.close", "client.fingerprint", "log.suppressed")
BUCKETS = [60, 300, 900, 3600, 10800, 21600, 86400]


def window(hours: float | None = None, since: float | None = None, until: float | None = None) -> tuple[float, float]:
    until = until if until is not None else time.time() + 1
    if since is None:
        since = until - (hours if hours is not None else 24) * 3600
    return since, until


def pick_bucket(span_seconds: float, target_points: int = 90) -> int:
    for b in BUCKETS:
        if span_seconds / b <= target_points:
            return b
    return BUCKETS[-1]


def summary(db: DB, since: float, until: float) -> dict[str, Any]:
    def cnt(event: str) -> int:
        return int(db.scalar("SELECT COUNT(*) FROM events WHERE event=? AND ts>=? AND ts<?", (event, since, until)))

    prev_since = since - (until - since)
    conns, prev_conns = cnt("conn.open"), int(db.scalar("SELECT COUNT(*) FROM events WHERE event='conn.open' AND ts>=? AND ts<?",
                                                         (prev_since, since)))
    out = {
        "since": since, "until": until,
        "events": int(db.scalar("SELECT COUNT(*) FROM events WHERE ts>=? AND ts<?", (since, until))),
        "connections": conns, "connections_prev": prev_conns,
        "unique_ips": int(db.scalar("SELECT COUNT(DISTINCT src_ip) FROM events WHERE ts>=? AND ts<?", (since, until))),
        "new_ips": int(db.scalar("SELECT COUNT(*) FROM ip_info WHERE first_seen>=? AND first_seen<?", (since, until))),
        "auth_attempts": cnt("auth.attempt"),
        "logins": int(db.scalar("SELECT COUNT(*) FROM auth_attempts WHERE success=1 AND ts>=? AND ts<?", (since, until))),
        "sessions": int(db.scalar("SELECT COUNT(*) FROM sessions WHERE authed=1 AND first_ts>=? AND first_ts<?", (since, until))),
        "commands": cnt("cmd.input"),
        "exploits": cnt("exploit.attempt"),
        "http_requests": cnt("http.request"),
        "db_queries": cnt("db.query"),
        "files": cnt("file.captured"),
        "new_samples": int(db.scalar("SELECT COUNT(*) FROM samples WHERE first_seen>=? AND first_seen<?", (since, until))),
        "samples_total": int(db.scalar("SELECT COUNT(*) FROM samples")),
        "countries": int(db.scalar("SELECT COUNT(DISTINCT i.country) FROM events e JOIN ip_info i ON i.ip=e.src_ip "
                                    "WHERE e.event='conn.open' AND e.ts>=? AND e.ts<? AND i.country IS NOT NULL", (since, until))),
    }
    out["by_service"] = db.query("SELECT service, COUNT(*) AS n FROM events WHERE event='conn.open' AND ts>=? AND ts<? "
                                  "GROUP BY service ORDER BY n DESC", (since, until))
    return out


def timeseries(db: DB, since: float, until: float, bucket: int | None = None) -> dict[str, Any]:
    bucket = bucket or pick_bucket(until - since)
    rows = db.query(
        "SELECT CAST(ts/? AS INTEGER) AS k, service, SUM(event='conn.open') AS conns, SUM(event='auth.attempt') AS auth, "
        "SUM(event='exploit.attempt') AS exploits, SUM(event='cmd.input') AS cmds, SUM(event='file.captured') AS files "
        "FROM events WHERE ts>=? AND ts<? GROUP BY k, service", (bucket, since, until))
    first, last = int(since // bucket), int(until // bucket)
    services = sorted({r["service"] for r in rows})
    series: dict[int, dict[str, Any]] = {k: {"t": k * bucket, "by_service": {}, "conns": 0, "auth": 0, "exploits": 0, "cmds": 0, "files": 0}
                                          for k in range(first, last + 1)}
    for r in rows:
        s = series.get(r["k"])
        if s is None:
            continue
        s["by_service"][r["service"]] = r["conns"] or 0
        for f in ("conns", "auth", "exploits", "cmds", "files"):
            s[f] += r[f] or 0
    return {"bucket": bucket, "services": services, "points": [series[k] for k in sorted(series)]}


def top(db: DB, what: str, since: float, until: float, limit: int = 10) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 100))
    p = (since, until)
    if what == "ips":
        return db.query(
            "SELECT e.src_ip AS ip, COUNT(*) AS n, SUM(e.event='conn.open') AS conns, i.country, i.country_name, i.asn, i.org, "
            "i.classification, i.tags, i.abuse_score FROM events e LEFT JOIN ip_info i ON i.ip=e.src_ip "
            "WHERE e.ts>=? AND e.ts<? AND e.event NOT IN ('conn.close','session.close','client.fingerprint','log.suppressed') "
            "GROUP BY e.src_ip ORDER BY n DESC LIMIT ?", (*p, limit))
    if what == "countries":
        return db.query(
            "SELECT i.country AS key, i.country_name AS name, COUNT(*) AS n, COUNT(DISTINCT e.src_ip) AS ips FROM events e "
            "JOIN ip_info i ON i.ip=e.src_ip WHERE e.event='conn.open' AND e.ts>=? AND e.ts<? AND i.country IS NOT NULL "
            "GROUP BY i.country ORDER BY n DESC LIMIT ?", (*p, limit))
    if what == "asns":
        return db.query(
            "SELECT i.asn AS key, i.org AS name, COUNT(*) AS n, COUNT(DISTINCT e.src_ip) AS ips FROM events e "
            "JOIN ip_info i ON i.ip=e.src_ip WHERE e.event='conn.open' AND e.ts>=? AND e.ts<? AND i.asn IS NOT NULL "
            "GROUP BY i.asn ORDER BY n DESC LIMIT ?", (*p, limit))
    if what == "usernames":
        return db.query("SELECT username AS key, COUNT(*) AS n, COUNT(DISTINCT src_ip) AS ips, SUM(success) AS ok FROM auth_attempts "
                        "WHERE ts>=? AND ts<? AND username!='' GROUP BY username ORDER BY n DESC LIMIT ?", (*p, limit))
    if what == "passwords":
        return db.query("SELECT password AS key, COUNT(*) AS n, COUNT(DISTINCT src_ip) AS ips, SUM(success) AS ok FROM auth_attempts "
                        "WHERE ts>=? AND ts<? AND password!='' GROUP BY password ORDER BY n DESC LIMIT ?", (*p, limit))
    if what == "credentials":
        return db.query("SELECT username || ':' || password AS key, COUNT(*) AS n, COUNT(DISTINCT src_ip) AS ips, SUM(success) AS ok "
                        "FROM auth_attempts WHERE ts>=? AND ts<? GROUP BY username, password ORDER BY n DESC LIMIT ?", (*p, limit))
    if what == "commands":
        return db.query("SELECT substr(input,1,200) AS key, COUNT(*) AS n, COUNT(DISTINCT src_ip) AS ips FROM commands "
                        "WHERE ts>=? AND ts<? AND input!='' GROUP BY substr(input,1,200) ORDER BY n DESC LIMIT ?", (*p, limit))
    if what == "services":
        return db.query("SELECT service AS key, COUNT(*) AS n, COUNT(DISTINCT src_ip) AS ips FROM events WHERE event='conn.open' "
                        "AND ts>=? AND ts<? GROUP BY service ORDER BY n DESC LIMIT ?", (*p, limit))
    if what == "ports":
        return db.query("SELECT dst_port AS key, service AS name, COUNT(*) AS n FROM events WHERE event='conn.open' AND ts>=? AND ts<? "
                        "AND dst_port IS NOT NULL GROUP BY dst_port, service ORDER BY n DESC LIMIT ?", (*p, limit))
    if what == "exploits":
        return db.query("SELECT rule AS key, MAX(cve) AS cve, MAX(category) AS category, MAX(severity) AS severity, COUNT(*) AS n, "
                        "COUNT(DISTINCT src_ip) AS ips FROM exploits WHERE ts>=? AND ts<? GROUP BY rule ORDER BY n DESC LIMIT ?",
                        (*p, limit))
    if what == "techniques":
        rows = db.query("SELECT technique AS key, COUNT(*) AS n, COUNT(DISTINCT src_ip) AS ips FROM attack_hits WHERE ts>=? AND ts<? "
                        "GROUP BY technique ORDER BY n DESC LIMIT ?", (*p, limit))
        for r in rows:
            info = attack.technique_info(r["key"])
            r["name"], r["tactic"] = info["name"], info["tactic"]
        return rows
    if what == "clients":
        return db.query("SELECT COALESCE(NULLIF(client,''),'(unknown)') AS key, COUNT(*) AS n, COUNT(DISTINCT src_ip) AS ips FROM sessions "
                        "WHERE first_ts>=? AND first_ts<? GROUP BY key ORDER BY n DESC LIMIT ?", (*p, limit))
    raise ValueError(f"unknown top category {what!r}")


def map_points(db: DB, since: float, until: float, limit: int = 600) -> dict[str, Any]:
    rows = db.query(
        "SELECT e.src_ip AS ip, COUNT(*) AS n, MAX(e.ts) AS last, i.lat, i.lon, i.country, i.country_name, i.city, i.classification "
        "FROM events e JOIN ip_info i ON i.ip=e.src_ip WHERE e.event='conn.open' AND e.ts>=? AND e.ts<? AND i.lat IS NOT NULL "
        "GROUP BY e.src_ip ORDER BY n DESC LIMIT ?", (since, until, limit * 4))
    cells: dict[tuple[float, float], dict[str, Any]] = {}
    for r in rows:
        key = (round(r["lat"], 0), round(r["lon"], 0))
        c = cells.setdefault(key, {"lat": r["lat"], "lon": r["lon"], "country": r["country"], "city": r["city"], "count": 0, "ips": 0,
                                   "last": 0.0, "malicious": 0})
        c["count"] += r["n"]
        c["ips"] += 1
        c["last"] = max(c["last"], r["last"])
        c["malicious"] += 1 if r["classification"] == "malicious" else 0
    pts = sorted(cells.values(), key=lambda c: -c["count"])[:limit]
    return {"points": pts, "home": None}


def recent_events(db: DB, limit: int = 100, before: float | None = None, service: str | None = None, event: str | None = None,
                  ip: str | None = None, session: str | None = None, q: str | None = None, quiet: bool = True) -> list[dict[str, Any]]:
    where, params = ["1=1"], []
    if before:
        where.append("e.ts<?")
        params.append(before)
    if service:
        where.append("e.service=?")
        params.append(service)
    if event:
        where.append("e.event=?")
        params.append(event)
    elif quiet:
        where.append("e.event NOT IN ('conn.close','client.fingerprint','log.suppressed')")
    if ip:
        where.append("e.src_ip=?")
        params.append(ip)
    if session:
        where.append("e.session=?")
        params.append(session)
    if q:
        where.append("(e.summary LIKE ? ESCAPE '\\' OR e.src_ip LIKE ? ESCAPE '\\')")
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")[:80] + "%"
        params += [like, like]
    params.append(max(1, min(int(limit), 500)))
    return db.query(
        "SELECT e.id, e.ts, e.service, e.event, e.src_ip, e.dst_port, e.session, e.summary, i.country, i.classification "
        f"FROM events e LEFT JOIN ip_info i ON i.ip=e.src_ip WHERE {' AND '.join(where)} ORDER BY e.ts DESC LIMIT ?", params)


def sessions_list(db: DB, limit: int = 50, offset: int = 0, service: str | None = None, ip: str | None = None,
                  with_commands: bool = False, since: float | None = None) -> list[dict[str, Any]]:
    where, params = ["1=1"], []
    if service:
        where.append("s.service=?"); params.append(service)
    if ip:
        where.append("s.src_ip=?"); params.append(ip)
    if with_commands:
        where.append("(s.commands>0 OR s.queries>0)")
    if since:
        where.append("s.first_ts>=?"); params.append(since)
    params += [max(1, min(int(limit), 200)), max(0, int(offset))]
    return db.query(
        "SELECT s.*, i.country, i.classification FROM sessions s LEFT JOIN ip_info i ON i.ip=s.src_ip "
        f"WHERE {' AND '.join(where)} ORDER BY s.first_ts DESC LIMIT ? OFFSET ?", params)


def session_detail(db: DB, sid: str) -> dict[str, Any] | None:
    s = db.one("SELECT s.*, i.country, i.country_name, i.org, i.asn, i.classification FROM sessions s "
               "LEFT JOIN ip_info i ON i.ip=s.src_ip WHERE s.id=?", (sid,))
    if not s:
        return None
    frames = []
    t0 = s["first_ts"] or 0.0
    for r in db.query("SELECT id, ts, event, data FROM events WHERE session=? ORDER BY ts, rowid LIMIT 3000", (sid,)):
        try:
            d = json.loads(r["data"] or "{}")
        except ValueError:
            d = {}
        e = r["event"]
        f: dict[str, Any] = {"t": round(r["ts"] - t0, 3), "ts": r["ts"], "event": e}
        if e == "cmd.input":
            f.update({"input": d.get("input", ""), "output": d.get("output", ""), "status": d.get("status"), "cwd": d.get("cwd", ""),
                      "user": d.get("user", ""), "nested": bool(d.get("nested"))})
            f["attack"] = [{"id": t, "name": attack.technique_info(t)["name"]} for t, _ in attack.map_command(str(d.get("input", "")))]
        elif e == "auth.attempt":
            f.update({"username": d.get("username", ""), "password": d.get("password", ""), "success": bool(d.get("success")),
                      "method": d.get("method", "")})
        elif e in ("download.attempt", "file.captured", "file.exec_attempt", "exploit.attempt", "db.query", "http.request",
                   "session.open", "session.close", "session.exec", "cron.install", "net.outbound_attempt", "sftp.open", "client.fingerprint",
                   "conn.open", "conn.close", "probe"):
            keep = {k: v for k, v in d.items() if k not in ("body", "first_bytes_hex", "hassh_algorithms")}
            f["data"] = keep
        else:
            f["data"] = d
        frames.append(f)
    s["frames"] = frames
    s["attack"] = [dict(attack.technique_info(r["technique"]), n=r["n"]) for r in
                   db.query("SELECT technique, COUNT(*) AS n FROM attack_hits WHERE session=? GROUP BY technique ORDER BY n DESC", (sid,))]
    return s


def ip_profile(db: DB, ip: str) -> dict[str, Any] | None:
    info = db.one("SELECT * FROM ip_info WHERE ip=?", (ip,))
    if not info:
        return None
    info["tags"] = json.loads(info.get("tags") or "[]")
    info["services"] = json.loads(info.get("services") or "[]")
    info["ports"] = json.loads(info.get("ports") or "[]")
    return {
        "info": info,
        "sessions": sessions_list(db, 20, ip=ip),
        "events": recent_events(db, 40, ip=ip, quiet=True),
        "credentials": db.query("SELECT username, password, COUNT(*) AS n, MAX(success) AS ok FROM auth_attempts WHERE src_ip=? "
                                "GROUP BY username, password ORDER BY n DESC LIMIT 25", (ip,)),
        "commands": db.query("SELECT ts, substr(input,1,300) AS input FROM commands WHERE src_ip=? ORDER BY ts DESC LIMIT 25", (ip,)),
        "exploits": db.query("SELECT rule, cve, category, COUNT(*) AS n FROM exploits WHERE src_ip=? GROUP BY rule ORDER BY n DESC LIMIT 20", (ip,)),
        "samples": db.query("SELECT DISTINCT ss.sha256, s.family_name, s.risk_level, s.size FROM sample_sources ss "
                            "LEFT JOIN samples s ON s.sha256=ss.sha256 WHERE ss.src_ip=? LIMIT 20", (ip,)),
        "techniques": [dict(attack.technique_info(r["technique"]), n=r["n"]) for r in
                       db.query("SELECT technique, COUNT(*) AS n FROM attack_hits WHERE src_ip=? GROUP BY technique ORDER BY n DESC", (ip,))],
        "timeline": db.query("SELECT CAST(ts/3600 AS INTEGER)*3600 AS t, COUNT(*) AS n FROM events WHERE src_ip=? GROUP BY t ORDER BY t DESC LIMIT 72",
                             (ip,)),
    }


def samples_list(db: DB, limit: int = 100, offset: int = 0, q: str | None = None) -> list[dict[str, Any]]:
    where, params = ["1=1"], []
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")[:80] + "%"
        where.append("(sha256 LIKE ? ESCAPE '\\' OR md5 LIKE ? ESCAPE '\\' OR family_name LIKE ? ESCAPE '\\')")
        params += [like, like, like]
    params += [max(1, min(int(limit), 500)), max(0, int(offset))]
    rows = db.query(f"SELECT * FROM samples WHERE {' AND '.join(where)} ORDER BY first_seen DESC LIMIT ? OFFSET ?", params)
    for r in rows:
        r["bazaar"] = json.loads(r["bazaar"]) if r.get("bazaar") else None
        r["sources"] = int(db.scalar("SELECT COUNT(DISTINCT src_ip) FROM sample_sources WHERE sha256=?", (r["sha256"],)))
    return rows


def sample_detail(db: DB, sha: str) -> dict[str, Any] | None:
    s = db.one("SELECT * FROM samples WHERE sha256=?", (sha,))
    if not s:
        return None
    s["bazaar"] = json.loads(s["bazaar"]) if s.get("bazaar") else None
    s["sources"] = db.query("SELECT ts, src_ip, session, service, origin, url, path, via FROM sample_sources WHERE sha256=? "
                            "ORDER BY ts DESC LIMIT 100", (sha,))
    s["iocs"] = db.query("SELECT i.type, i.value, i.scope, i.confidence, i.kind, i.context FROM iocs i JOIN ioc_samples x "
                         "ON x.type=i.type AND x.value=i.value WHERE x.sha256=? ORDER BY i.confidence DESC LIMIT 300", (sha,))
    return s


def iocs_list(db: DB, typ: str | None = None, q: str | None = None, limit: int = 200, offset: int = 0,
              kind: str | None = None) -> list[dict[str, Any]]:
    where, params = ["1=1"], []
    if typ:
        where.append("type=?"); params.append(typ)
    if kind:
        where.append("kind=?"); params.append(kind)
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")[:80] + "%"
        where.append("value LIKE ? ESCAPE '\\'"); params.append(like)
    params += [max(1, min(int(limit), 1000)), max(0, int(offset))]
    return db.query(f"SELECT type, value, scope, confidence, kind, context, first_seen, last_seen, hits FROM iocs "
                    f"WHERE {' AND '.join(where)} ORDER BY last_seen DESC LIMIT ? OFFSET ?", params)


def attack_matrix(db: DB, since: float, until: float) -> dict[str, Any]:
    rows = db.query("SELECT technique, COUNT(*) AS n, COUNT(DISTINCT src_ip) AS ips, MAX(ts) AS last FROM attack_hits "
                    "WHERE ts>=? AND ts<? GROUP BY technique", (since, until))
    by_t = {r["technique"]: r for r in rows}
    tactics: dict[str, list[dict[str, Any]]] = {t: [] for t in attack.TACTICS}
    for tid, (name, tactic) in attack.TECHNIQUES.items():
        hit = by_t.get(tid)
        tactics.setdefault(tactic, []).append({"id": tid, "name": name, "n": hit["n"] if hit else 0, "ips": hit["ips"] if hit else 0,
                                                "last": hit["last"] if hit else None, "url": attack.technique_info(tid)["url"]})
    for t in tactics.values():
        t.sort(key=lambda x: (-x["n"], x["id"]))
    examples = {}
    for r in db.query("SELECT technique, evidence, MAX(ts) AS ts FROM attack_hits WHERE ts>=? AND ts<? GROUP BY technique", (since, until)):
        examples[r["technique"]] = r["evidence"]
    return {"tactics": [{"name": t, "techniques": tactics[t]} for t in attack.TACTICS if tactics.get(t)], "examples": examples,
            "total": sum(r["n"] for r in rows)}
