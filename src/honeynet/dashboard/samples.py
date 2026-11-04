"""Imports analysis reports (written by the no-network analyzer) into the dashboard database.

Reports are read-only input produced inside another container, so they are validated and bounded
exactly like honeypot events.  New IOCs flow into the IOC table and therefore into the blocklist /
IOC exports; the full report stays on disk and is served as-is (already sanitised by the engine).
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..common.config import Settings
from ..common.sanitize import sanitize_text
from .db import DB

log = logging.getLogger("honeynet.samples")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_REPORT_BYTES = 48 * 1024 * 1024
IOC_TYPES = {"url", "ip", "endpoint", "domain", "wallet", "pool", "credential", "path", "mutex", "registry", "ssh_key", "cron",
             "command", "useragent"}


def load_report(analysis_dir: Path, sha: str) -> dict[str, Any] | None:
    if not SHA_RE.match(sha):
        return None
    p = analysis_dir / f"{sha}.json"
    try:
        if p.stat().st_size > MAX_REPORT_BYTES:
            return None
        rep = json.loads(p.read_text("utf-8"))
    except (OSError, ValueError):
        return None
    return rep if isinstance(rep, dict) and rep.get("sha256") == sha else None


class AnalysisImporter:
    def __init__(self, settings: Settings, db: DB, on_analyzed: Callable[[dict], None] | None = None) -> None:
        self.s, self.db, self.on_analyzed = settings, db, on_analyzed

    def poll_once(self) -> int:
        n = 0
        try:
            files = list(self.s.analysis_dir.glob("*.json"))
        except OSError:
            return 0
        for p in files:
            sha = p.stem
            if not SHA_RE.match(sha):
                continue
            try:
                mtime = p.stat().st_mtime
            except OSError:
                continue
            row = self.db.one("SELECT report_mtime FROM samples WHERE sha256=?", (sha,))
            if row and row["report_mtime"] and row["report_mtime"] >= mtime:
                continue
            rep = load_report(self.s.analysis_dir, sha)
            if rep is None:
                continue
            try:
                self.import_report(sha, rep, mtime)
                n += 1
            except Exception:  # noqa: BLE001
                log.exception("importing report %s failed", sha)
        return n

    def import_report(self, sha: str, rep: dict[str, Any], mtime: float) -> None:
        fam = rep.get("family") if isinstance(rep.get("family"), dict) else {}
        risk = rep.get("risk") if isinstance(rep.get("risk"), dict) else {}
        f = rep.get("file") if isinstance(rep.get("file"), dict) else {}
        pack = rep.get("packing") if isinstance(rep.get("packing"), dict) else {}
        status = "failed" if rep.get("status") == "failed" else "analyzed"
        now = time.time()
        was_new = False
        with self.db.write() as c:
            existing = c.execute("SELECT status FROM samples WHERE sha256=?", (sha,)).fetchone()
            was_new = existing is None or existing["status"] != "analyzed"
            c.execute("INSERT OR IGNORE INTO samples(sha256, md5, size, first_seen, last_seen, count) VALUES(?,?,?,?,?,0)",
                      (sha, str(rep.get("md5", ""))[:32], int(rep.get("size", 0) or 0), now, now))
            c.execute("UPDATE samples SET status=?, family=?, family_name=?, family_conf=?, risk_score=?, risk_level=?, file_type=?, arch=?, "
                      "packed=?, analyzed_at=?, report_mtime=? WHERE sha256=?",
                      (status, str(fam.get("id", ""))[:40], str(fam.get("name", ""))[:80], float(fam.get("confidence", 0) or 0),
                       int(risk.get("score", 0) or 0), str(risk.get("level", ""))[:12], str(f.get("description", ""))[:80],
                       str(f.get("arch", ""))[:16], 1 if pack.get("packed") else 0, str(rep.get("analyzed_at", ""))[:32], mtime, sha))
            if status == "analyzed":
                for ioc in (rep.get("iocs") or [])[:600]:
                    if not isinstance(ioc, dict) or ioc.get("type") not in IOC_TYPES:
                        continue
                    value = sanitize_text(ioc.get("value", ""), 512)
                    if not value:
                        continue
                    scope = str(ioc.get("scope", ""))[:16]
                    conf = max(0.0, min(1.0, float(ioc.get("confidence", 0.5) or 0.5)))
                    c.execute("INSERT INTO iocs(type,value,scope,confidence,kind,context,first_seen,last_seen,hits) "
                              "VALUES(?,?,?,?,'analysis',?,?,?,1) ON CONFLICT(type,value) DO UPDATE SET "
                              "last_seen=excluded.last_seen, hits=hits+1, confidence=max(confidence,excluded.confidence), "
                              "kind=CASE WHEN kind='observed' THEN 'both' ELSE kind END",
                              (ioc["type"], value, scope, conf, sanitize_text(ioc.get("context", ""), 200), now, now))
                    c.execute("INSERT OR IGNORE INTO ioc_samples(type,value,sha256) VALUES(?,?,?)", (ioc["type"], value, sha))
        if was_new and status == "analyzed" and self.on_analyzed:
            self.on_analyzed({"sha256": sha, "family": fam.get("name", ""), "family_id": fam.get("id", ""),
                              "confidence": fam.get("confidence", 0), "risk": risk.get("level", ""), "score": risk.get("score", 0),
                              "c2": [c.get("value", "") for c in (rep.get("c2_candidates") or [])[:5] if isinstance(c, dict)],
                              "mitre": (rep.get("mitre") or [])[:12], "packed": bool(pack.get("packed"))})
