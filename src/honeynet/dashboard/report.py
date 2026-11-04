"""Daily summary report (markdown / HTML / JSON).  Redacted: operator IPs and configured secrets never appear."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..common.config import Settings
from ..common.sanitize import defang, html_escape, sanitize_text
from . import queries as q
from .db import DB


def build(db: DB, s: Settings, since: float, until: float) -> dict[str, Any]:
    red = s.redactor()
    summ = q.summary(db, since, until)
    ips = [r for r in q.top(db, "ips", since, until, 10) if not red.is_ignored(r["ip"])]
    ts = q.timeseries(db, since, until, 3600)
    busiest = max(ts["points"], key=lambda p: p["conns"], default=None)
    samples = db.query("SELECT sha256, size, family_name, family_conf, risk_level, risk_score, file_type, first_seen, packed FROM samples "
                       "WHERE first_seen>=? AND first_seen<? ORDER BY risk_score DESC, first_seen LIMIT 25", (since, until))
    new_iocs = db.query("SELECT type, value, scope, confidence, kind FROM iocs WHERE first_seen>=? AND first_seen<? "
                        "AND scope NOT IN ('private','infrastructure') ORDER BY confidence DESC LIMIT 40", (since, until))
    new_rules = db.query("SELECT rule, cve, category, MIN(ts) AS first FROM exploits GROUP BY rule HAVING MIN(ts)>=? AND MIN(ts)<?", (since, until))
    alerts = db.query("SELECT ts, kind, title, severity FROM alerts WHERE ts>=? AND ts<? ORDER BY ts DESC LIMIT 20", (since, until))
    return {
        "period": {"start": since, "end": until, "generated": time.time()},
        "summary": summ,
        "busiest_hour": {"t": busiest["t"], "connections": busiest["conns"]} if busiest and busiest["conns"] else None,
        "top_ips": ips,
        "top_countries": q.top(db, "countries", since, until, 8),
        "top_asns": q.top(db, "asns", since, until, 8),
        "top_usernames": q.top(db, "usernames", since, until, 10),
        "top_passwords": q.top(db, "passwords", since, until, 10),
        "top_commands": q.top(db, "commands", since, until, 10),
        "top_exploits": q.top(db, "exploits", since, until, 10),
        "top_techniques": q.top(db, "techniques", since, until, 12),
        "samples": samples,
        "new_iocs": new_iocs,
        "new_exploit_rules": new_rules,
        "alerts": alerts,
    }


def _ts(t: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else "-"


def render_markdown(rep: dict[str, Any], s: Settings | None = None) -> str:
    m = rep["summary"]
    P = rep["period"]
    L: list[str] = [f"# Honeynet daily report", "", f"Period: {_ts(P['start'])} to {_ts(P['end'])}", "",
                    "## Overview", "",
                    f"- Connections: **{m['connections']}** (previous period: {m['connections_prev']})",
                    f"- Unique source IPs: **{m['unique_ips']}** ({m['new_ips']} new), countries: {m['countries']}",
                    f"- Authentication attempts: **{m['auth_attempts']}**, successful logins: **{m['logins']}**",
                    f"- Interactive sessions: **{m['sessions']}**, commands typed: **{m['commands']}**",
                    f"- Exploit attempts: **{m['exploits']}**, HTTP requests: {m['http_requests']}, DB queries: {m['db_queries']}",
                    f"- Files captured: **{m['files']}**, new unique samples: **{m['new_samples']}**"]
    if rep.get("busiest_hour"):
        L.append(f"- Busiest hour: {_ts(rep['busiest_hour']['t'])} ({rep['busiest_hour']['connections']} connections)")

    def table(title: str, rows: list[dict], cols: list[tuple[str, str]], fmt=lambda v: str(v)) -> None:
        if not rows:
            return
        L.extend(["", f"## {title}", "", "| " + " | ".join(c[1] for c in cols) + " |", "|" + "---|" * len(cols)])
        for r in rows:
            L.append("| " + " | ".join(sanitize_text(fmt(r.get(c[0], "")), 120).replace("|", "\\|") for c in cols) + " |")

    table("Top source IPs", rep["top_ips"], [("ip", "IP"), ("n", "Events"), ("country", "CC"), ("org", "Network"), ("classification", "Class")],
          lambda v: defang(v) if isinstance(v, str) and v.count(".") == 3 else (v if v is not None else ""))
    table("Top countries", rep["top_countries"], [("name", "Country"), ("n", "Connections"), ("ips", "IPs")], lambda v: v if v is not None else "")
    table("Top networks (ASN)", rep["top_asns"], [("key", "ASN"), ("name", "Organisation"), ("n", "Connections")], lambda v: v if v is not None else "")
    table("Top usernames", rep["top_usernames"], [("key", "Username"), ("n", "Attempts"), ("ips", "IPs")])
    table("Top passwords", rep["top_passwords"], [("key", "Password"), ("n", "Attempts"), ("ips", "IPs")])
    table("Top commands", rep["top_commands"], [("key", "Command"), ("n", "Count"), ("ips", "IPs")])
    table("Exploit attempts", rep["top_exploits"], [("key", "Rule"), ("cve", "CVE"), ("category", "Category"), ("n", "Hits")])
    table("MITRE ATT&CK techniques", rep["top_techniques"], [("key", "ID"), ("name", "Technique"), ("tactic", "Tactic"), ("n", "Hits")])
    table("New malware samples", rep["samples"], [("sha256", "SHA-256"), ("size", "Bytes"), ("family_name", "Family"), ("risk_level", "Risk")],
          lambda v: v if v is not None else "(pending analysis)")
    table("New indicators", rep["new_iocs"], [("type", "Type"), ("value", "Value"), ("confidence", "Conf"), ("kind", "Source")],
          lambda v: defang(v) if isinstance(v, str) and ("http" in v or v.count(".") >= 1) else v)
    table("New exploit rules", rep["new_exploit_rules"], [("rule", "Rule"), ("cve", "CVE"), ("category", "Category")])
    table("Alerts", rep["alerts"], [("severity", "Severity"), ("kind", "Kind"), ("title", "Title")])
    text = "\n".join(L) + "\n"
    return s.redactor().scrub(text) if s else text


def render_html(rep: dict[str, Any], s: Settings | None = None) -> str:
    md = render_markdown(rep, s)
    body = []
    in_table = False
    for line in md.split("\n"):
        if line.startswith("# "):
            body.append(f"<h1>{html_escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{html_escape(line[3:])}</h2>")
        elif line.startswith("|"):
            if set(line.replace("|", "")) <= {"-"}:
                continue
            cells = [c.strip().replace("\\|", "|") for c in line.strip("|").split(" | ")]
            tag = "th" if not in_table else "td"
            if not in_table:
                body.append("<table>")
                in_table = True
            body.append("<tr>" + "".join(f"<{tag}>{html_escape(c)}</{tag}>" for c in cells) + "</tr>")
        else:
            if in_table:
                body.append("</table>")
                in_table = False
            if line.startswith("- "):
                body.append(f"<p>&bull; {html_escape(line[2:]).replace('**', '')}</p>")
            elif line.strip():
                body.append(f"<p>{html_escape(line)}</p>")
    if in_table:
        body.append("</table>")
    css = "body{font:14px system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;margin:.5rem 0}td,th{border:1px solid #ccc;padding:.2rem .5rem;text-align:left}"
    return f"<!doctype html><meta charset=utf-8><title>Honeynet daily report</title><style>{css}</style>" + "\n".join(body)


def write_daily(db: DB, s: Settings, day_start: float | None = None) -> dict[str, Path]:
    """Write md/html/json for the UTC day starting at ``day_start`` (default: yesterday)."""
    if day_start is None:
        today = time.time() // 86400 * 86400
        day_start = today - 86400
    rep = build(db, s, day_start, day_start + 86400)
    s.reports_dir.mkdir(parents=True, exist_ok=True)
    stem = time.strftime("daily-%Y-%m-%d", time.gmtime(day_start))
    out = {"md": s.reports_dir / f"{stem}.md", "html": s.reports_dir / f"{stem}.html", "json": s.reports_dir / f"{stem}.json"}
    out["md"].write_text(render_markdown(rep, s), encoding="utf-8")
    out["html"].write_text(render_html(rep, s), encoding="utf-8")
    out["json"].write_text(s.redactor().scrub(json.dumps(rep, default=str, indent=1)), encoding="utf-8")
    return out
