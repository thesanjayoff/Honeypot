"""Exports: IP blocklists (txt + firewall formats), C2/payload-host lists, IOC feeds (JSON/CSV).

Rules that make an export safe to put on a real firewall:
  * only globally routable addresses (never private/loopback/reserved/documentation - test mode excepted),
  * never the operator's own addresses (``ignore_src``) and never research scanners classed as benign,
  * IPs are re-validated here, so nothing but ``ipaddress``-normalised text reaches a shell/firewall file,
  * every CSV cell goes through ``csv_safe`` (spreadsheet formula injection).
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import time
from typing import Any

from ..common.config import Settings
from ..common.netutil import is_public, is_test_net
from ..common.sanitize import csv_safe
from .db import DB

LEVELS = {
    "malicious": ("malicious",),
    "suspicious": ("malicious", "suspicious"),
    "all": ("malicious", "suspicious", "scanner", "unknown"),
}
FORMATS = ("txt", "csv", "ipset", "iptables", "nft", "ufw", "pf", "json")


def _exportable(ip: str, s: Settings, red) -> bool:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    if red.is_ignored(ip):
        return False
    return is_public(ip) or (s.test_mode and is_test_net(ip))


def score_of(r: dict[str, Any]) -> int:
    return int(min(100, min(40, (r["auth"] or 0) * 0.5) + (r["exploits"] or 0) * 10 + (r["files"] or 0) * 20 + (r["cmds"] or 0) * 3
                   + (r.get("abuse_score") or 0) * 0.3))


def blocklist_entries(db: DB, s: Settings, *, days: float = 30, level: str = "suspicious", min_score: int = 0,
                      limit: int = 50000) -> list[dict[str, Any]]:
    classes = LEVELS.get(level, LEVELS["suspicious"])
    since = time.time() - days * 86400
    rows = db.query("SELECT ip, country, asn, org, classification, tags, events, auth, exploits, files, cmds, first_seen, last_seen, "
                    "abuse_score FROM ip_info WHERE last_seen>=? AND classification IN (" + ",".join("?" * len(classes)) + ") "
                    "ORDER BY last_seen DESC LIMIT ?", (since, *classes, limit * 2))
    red = s.redactor()
    out = []
    for r in rows:
        if not _exportable(r["ip"], s, red):
            continue
        r["score"] = score_of(r)
        if r["score"] < min_score:
            continue
        r["tags"] = json.loads(r["tags"] or "[]")
        out.append(r)
        if len(out) >= limit:
            break
    out.sort(key=lambda r: (-r["score"], r["ip"]))
    return out


def _split(entries: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    v4, v6 = [], []
    for e in entries:
        (v6 if ":" in e["ip"] else v4).append(e["ip"])
    return v4, v6


def render_blocklist(entries: list[dict[str, Any]], fmt: str, *, level: str = "suspicious", days: float = 30) -> str:
    fmt = fmt if fmt in FORMATS else "txt"
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    v4, v6 = _split(entries)
    hdr = f"# honeynet blocklist - generated {stamp} - level={level} window={days:g}d entries={len(entries)}"
    if fmt == "txt":
        return "\n".join([hdr, "# one address per line; sorted by score", *[e["ip"] for e in entries]]) + "\n"
    if fmt == "json":
        return json.dumps({"generated": stamp, "level": level, "window_days": days, "count": len(entries),
                           "entries": [{k: e[k] for k in ("ip", "score", "classification", "tags", "country", "asn", "org", "last_seen")}
                                       for e in entries]}, indent=1)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["ip", "score", "classification", "tags", "country", "asn", "org", "events", "last_seen"])
        for e in entries:
            w.writerow([csv_safe(x) for x in (e["ip"], e["score"], e["classification"], " ".join(e["tags"]), e["country"] or "",
                                              e["asn"] or "", e["org"] or "", e["events"],
                                              time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(e["last_seen"] or 0)))])
        return buf.getvalue()
    if fmt == "ipset":      # `ipset restore < file` (no comments: restore does not accept them everywhere)
        lines = ["create honeynet-block hash:ip family inet hashsize 4096 maxelem 262144 -exist", "flush honeynet-block"]
        lines += [f"add honeynet-block {ip} -exist" for ip in v4]
        lines += ["create honeynet-block6 hash:ip family inet6 hashsize 1024 maxelem 65536 -exist", "flush honeynet-block6"]
        lines += [f"add honeynet-block6 {ip} -exist" for ip in v6]
        return "\n".join(lines) + "\n"
    if fmt == "iptables":
        lines = ["#!/bin/sh", hdr, "set -e",
                 "iptables -N HONEYNET_BLOCK 2>/dev/null || iptables -F HONEYNET_BLOCK",
                 *[f"iptables -A HONEYNET_BLOCK -s {ip} -j DROP" for ip in v4],
                 "iptables -C INPUT -j HONEYNET_BLOCK 2>/dev/null || iptables -I INPUT 1 -j HONEYNET_BLOCK"]
        if v6:
            lines += ["ip6tables -N HONEYNET_BLOCK 2>/dev/null || ip6tables -F HONEYNET_BLOCK",
                      *[f"ip6tables -A HONEYNET_BLOCK -s {ip} -j DROP" for ip in v6],
                      "ip6tables -C INPUT -j HONEYNET_BLOCK 2>/dev/null || ip6tables -I INPUT 1 -j HONEYNET_BLOCK"]
        return "\n".join(lines) + "\n"
    if fmt == "nft":
        def elems(v: list[str]) -> str:
            return f"\n    elements = {{ {', '.join(v)} }}" if v else ""
        return (f"{hdr}\ntable inet honeynet {{\n  set blocklist4 {{\n    type ipv4_addr{elems(v4)}\n  }}\n"
                f"  set blocklist6 {{\n    type ipv6_addr{elems(v6)}\n  }}\n"
                "  chain input {\n    type filter hook input priority -10; policy accept;\n"
                "    ip saddr @blocklist4 drop\n    ip6 saddr @blocklist6 drop\n  }\n}\n")
    if fmt == "ufw":
        return "\n".join(["#!/bin/sh", hdr, *[f"ufw insert 1 deny from {e['ip']} to any comment 'honeynet'" for e in entries]]) + "\n"
    if fmt == "pf":
        return "\n".join([hdr.replace("# ", "# "), *[e["ip"] for e in entries]]) + "\n"
    raise ValueError(fmt)


CONTENT_TYPES = {"txt": "text/plain", "csv": "text/csv", "ipset": "text/plain", "iptables": "text/plain", "nft": "text/plain",
                 "ufw": "text/plain", "pf": "text/plain", "json": "application/json"}


# ------------------------------------------------------------------------------ C2 / payload hosts

def c2_indicators(db: DB, s: Settings, *, min_confidence: float = 0.5) -> dict[str, list[dict[str, Any]]]:
    """Attacker infrastructure learned from malware analysis and from payload URLs seen in sessions."""
    red = s.redactor()
    rows = db.query("SELECT type, value, scope, confidence, kind, context, last_seen FROM iocs WHERE type IN "
                    "('ip','endpoint','domain','url','pool') AND confidence>=? ORDER BY confidence DESC, last_seen DESC", (min_confidence,))
    ips: dict[str, dict] = {}
    domains: dict[str, dict] = {}
    urls: dict[str, dict] = {}
    for r in rows:
        if r["scope"] in ("private", "infrastructure"):
            continue
        t, v = r["type"], r["value"]
        if t in ("ip", "endpoint"):
            ip = v.rsplit(":", 1)[0] if t == "endpoint" and v.count(":") == 1 else v
            if not _exportable(ip, s, red):
                continue
            ips.setdefault(ip, r)
        elif t == "domain":
            if not v.endswith(".invalid") or s.test_mode:
                domains.setdefault(v, r)
        elif t in ("url", "pool"):
            urls.setdefault(v, r)
    return {"ips": [{"value": k, **{x: v[x] for x in ("confidence", "kind", "context", "last_seen")}} for k, v in ips.items()],
            "domains": [{"value": k, **{x: v[x] for x in ("confidence", "kind", "context", "last_seen")}} for k, v in domains.items()],
            "urls": [{"value": k, **{x: v[x] for x in ("confidence", "kind", "context", "last_seen")}} for k, v in urls.items()]}


def render_c2(ind: dict[str, list[dict[str, Any]]], what: str) -> str:
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    items = ind.get(what, [])
    return "\n".join([f"# honeynet {what} (malware infrastructure) - generated {stamp} - entries={len(items)}",
                      *[i["value"] for i in items]]) + "\n"


# ------------------------------------------------------------------------------ IOC feed

def ioc_rows(db: DB, s: Settings, *, include_private: bool = False, min_confidence: float = 0.0, limit: int = 20000) -> list[dict[str, Any]]:
    rows = db.query("SELECT type, value, scope, confidence, kind, context, first_seen, last_seen, hits FROM iocs WHERE confidence>=? "
                    "ORDER BY last_seen DESC LIMIT ?", (min_confidence, limit))
    red = s.redactor()
    out = []
    for r in rows:
        if not include_private and r["scope"] in ("private", "infrastructure"):
            continue
        if r["type"] in ("ip", "endpoint") and red.is_ignored(r["value"].rsplit(":", 1)[0]):
            continue
        r["samples"] = [x["sha256"] for x in db.query("SELECT sha256 FROM ioc_samples WHERE type=? AND value=? LIMIT 10",
                                                       (r["type"], r["value"]))]
        out.append(r)
    return out


def render_iocs(rows: list[dict[str, Any]], fmt: str) -> str:
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if fmt == "json":
        return json.dumps({"generated": stamp, "count": len(rows), "iocs": [
            {**r, "first_seen": _iso(r["first_seen"]), "last_seen": _iso(r["last_seen"])} for r in rows]}, indent=1)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["type", "value", "scope", "confidence", "source", "context", "first_seen", "last_seen", "samples"])
    for r in rows:
        w.writerow([csv_safe(x) for x in (r["type"], r["value"], r["scope"], round(r["confidence"], 2), r["kind"], r["context"],
                                          _iso(r["first_seen"]), _iso(r["last_seen"]), " ".join(r["samples"]))])
    return buf.getvalue()


def _iso(ts: float | None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)) if ts else ""
