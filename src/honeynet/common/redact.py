"""Redaction of the operator's own addresses and secrets.

The operator's admin IP(s) must never appear in honeypot logs, exports, alerts
or reports, and neither must configured secrets (dashboard password, API keys,
webhook URLs, fetcher token...).
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from .netutil import ip_in, parse_networks

REDACTED_IP = "[REDACTED-IP]"
REDACTED_SECRET = "[REDACTED]"


class Redactor:
    def __init__(self, ignore_src: Iterable[str] = (), secrets: Iterable[str] = ()):
        self.ignore_raw = [s.strip() for s in ignore_src if s and s.strip()]
        self.nets = parse_networks(self.ignore_raw)
        # very short secrets would shred ordinary text
        self.secrets = sorted({s for s in secrets if s and len(s) >= 6}, key=len, reverse=True)
        self._ip_literals = [r for r in self.ignore_raw if "/" not in r]
        parts = [re.escape(x) for x in self._ip_literals]
        self._ip_re = (
            re.compile(r"(?<![0-9A-Fa-f:.])(?:" + "|".join(parts) + r")(?![0-9A-Fa-f:.]|\.\d)")
            if parts else None
        )

    # -- classification -------------------------------------------------------
    def is_ignored(self, ip: str | None) -> bool:
        return bool(ip) and bool(self.nets) and ip_in(ip, self.nets)

    # -- text scrubbing -------------------------------------------------------
    def scrub(self, text: str) -> str:
        if not text:
            return text
        for s in self.secrets:
            if s in text:
                text = text.replace(s, REDACTED_SECRET)
        if self._ip_re:
            text = self._ip_re.sub(REDACTED_IP, text)
        return text

    def scrub_obj(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.scrub(obj)
        if isinstance(obj, dict):
            return {k: self.scrub_obj(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.scrub_obj(v) for v in obj]
        if isinstance(obj, tuple):
            return [self.scrub_obj(v) for v in obj]
        return obj


NULL_REDACTOR = Redactor()
