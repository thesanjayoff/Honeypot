"""Alerts: new malware sample, newly seen exploit rule, traffic spike (+ analysis verdict).

Channels are optional (webhook and/or SMTP).  Alerts are always stored and shown on the dashboard;
delivery is best-effort in a background thread so a dead webhook can never stall ingestion.
Anything attacker-controlled that goes into a message passes through ``neutralize_chat``
(mentions, markup, links are defanged) - an attacker must not be able to ping the operator's
channel or smuggle a clickable phishing link into it.
"""

from __future__ import annotations

import json
import logging
import smtplib
import threading
import time
import urllib.request
from collections.abc import Callable
from email.message import EmailMessage
from typing import Any

from ..common.config import Settings
from ..common.sanitize import defang, neutralize_chat
from .db import DB
from .queries import QUIET

log = logging.getLogger("honeynet.alerts")


def _post_json(url: str, payload: dict, timeout: float = 10.0) -> None:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "honeynet-alerts"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:          # noqa: S310 - operator-configured URL
        resp.read(1024)


def _send_mail(s: Settings, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, s.smtp_from or s.smtp_user, ", ".join(s.smtp_to)
    msg.set_content(body)
    if s.smtp_port == 465:
        cls: Any = smtplib.SMTP_SSL
    else:
        cls = smtplib.SMTP
    with cls(s.smtp_host, s.smtp_port, timeout=15) as smtp:
        if cls is smtplib.SMTP and s.smtp_port != 25:
            try:
                smtp.starttls()
            except smtplib.SMTPException:
                pass
        if s.smtp_user:
            smtp.login(s.smtp_user, s.smtp_password)
        smtp.send_message(msg)


class AlertManager:
    def __init__(self, settings: Settings, db: DB, webhook: Callable[[str, dict], None] | None = None,
                 mailer: Callable[[Settings, str, str], None] | None = None, synchronous: bool = False) -> None:
        self.s, self.db = settings, db
        self._webhook = webhook or (lambda url, payload: _post_json(url, payload))
        self._mailer = mailer or _send_mail
        self.synchronous = synchronous
        self._lock = threading.Lock()

    @property
    def channels(self) -> list[str]:
        out = []
        if self.s.webhook_url:
            out.append("webhook")
        if self.s.smtp_host and self.s.smtp_to:
            out.append("email")
        return out

    # -- core -------------------------------------------------------------------------
    def raise_alert(self, kind: str, key: str, title: str, detail: str, severity: str = "info") -> int | None:
        now = time.time()
        with self._lock:
            recent = self.db.one("SELECT id FROM alerts WHERE kind=? AND key=? AND ts>?", (kind, key, now - self.s.alert_cooldown_seconds))
            if recent:
                return None
            self.db.execute("INSERT INTO alerts(ts,kind,key,title,detail,severity,delivered) VALUES(?,?,?,?,?,?,0)",
                            (now, kind, key[:200], title[:200], detail[:2000], severity))
            aid = int(self.db.scalar("SELECT MAX(id) FROM alerts"))
        if self.channels:
            if self.synchronous:
                self._deliver(aid, title, detail, severity, kind)
            else:
                threading.Thread(target=self._deliver, args=(aid, title, detail, severity, kind), daemon=True).start()
        return aid

    def _deliver(self, aid: int, title: str, detail: str, severity: str, kind: str) -> None:
        ok = True
        text = f"[honeynet/{severity}] {title}\n{detail}"
        try:
            if self.s.webhook_url:
                self._webhook(self.s.webhook_url, {"text": text, "content": text[:1900], "username": "honeynet", "kind": kind,
                                                    "severity": severity})
        except Exception as exc:  # noqa: BLE001
            ok = False
            log.warning("webhook delivery failed: %s", type(exc).__name__)
        try:
            if self.s.smtp_host and self.s.smtp_to:
                self._mailer(self.s, f"[honeynet] {title}"[:200], detail)
        except Exception as exc:  # noqa: BLE001
            ok = False
            log.warning("email delivery failed: %s", type(exc).__name__)
        self.db.execute("UPDATE alerts SET delivered=? WHERE id=?", (1 if ok else -1, aid))

    # -- triggers ---------------------------------------------------------------------
    def new_sample(self, s: dict) -> None:
        detail = (f"sha256 {s['sha256']}\nsize {s['size']} bytes, captured on {neutralize_chat(s['service'], 20)} from "
                  f"{defang(s['src_ip'])} ({neutralize_chat(s.get('origin', ''), 30)})")
        if s.get("url"):
            detail += f"\nsource URL: {neutralize_chat(defang(s['url']), 200)}"
        self.raise_alert("new_sample", s["sha256"], "New malware sample captured", detail, "high")

    def analyzed(self, a: dict) -> None:
        detail = (f"{neutralize_chat(a['family'], 80)} (confidence {float(a['confidence']):.0%}), risk {a['risk']} ({a['score']}/100)\n"
                  f"sha256 {a['sha256']}")
        if a.get("c2"):
            detail += "\nC2/infra: " + ", ".join(neutralize_chat(defang(x), 80) for x in a["c2"])
        if a.get("mitre"):
            detail += "\nATT&CK: " + ", ".join(a["mitre"])
        sev = "high" if a["risk"] in ("high", "critical") else "info"
        self.raise_alert("sample_analyzed", a["sha256"], "Sample analysis finished", detail, sev)

    def new_exploit(self, r: dict) -> None:
        detail = (f"rule {neutralize_chat(r['rule'], 80)} {neutralize_chat(r.get('cve', ''), 24)} [{neutralize_chat(r.get('category', ''), 20)}] "
                  f"on {neutralize_chat(r['service'], 20)} from {defang(r['src_ip'])}\nsnippet: {neutralize_chat(r.get('snippet', ''), 160)}")
        self.raise_alert("new_exploit", r["rule"], "New exploit attempt type seen", detail, "medium")

    def check_spike(self, now: float | None = None) -> bool:
        now = now or time.time()
        win = 300.0
        q = ("SELECT COUNT(*) FROM events WHERE ts>=? AND ts<? AND event NOT IN ('" + "','".join(QUIET) + "') AND event!='probe'")
        cur = int(self.db.scalar(q, (now - win, now + 1)))
        base_total = int(self.db.scalar(q, (now - win - 6 * 3600, now - win)))
        baseline = base_total / (6 * 3600 / win)
        if cur >= self.s.spike_min_events and cur > self.s.spike_factor * max(baseline, 1.0):
            top = self.db.query("SELECT src_ip, COUNT(*) AS n FROM events WHERE ts>=? AND ts<? GROUP BY src_ip ORDER BY n DESC LIMIT 3",
                                (now - win, now + 1))
            who = ", ".join(f"{defang(t['src_ip'])} ({t['n']})" for t in top)
            self.raise_alert("spike", "spike", "Traffic spike",
                             f"{cur} events in the last 5 minutes (baseline ~{baseline:.0f} per 5 min).\nTop sources: {who}", "high")
            return True
        return False

    def list(self, limit: int = 100) -> list[dict]:
        return self.db.query("SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (max(1, min(limit, 500)),))

    def ack(self, aid: int | None = None) -> None:
        if aid is None:
            self.db.execute("UPDATE alerts SET acked=1")
        else:
            self.db.execute("UPDATE alerts SET acked=1 WHERE id=?", (aid,))
