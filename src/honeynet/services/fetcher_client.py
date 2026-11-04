"""Client for the sandboxed *fetcher* container (the only component allowed to
reach the internet on behalf of attackers).

Honeypot containers have no egress. When an attacker runs ``wget http://x/y`` in
the fake shell (or an exploit payload carries a URL) we *optionally* ask the
fetcher to download it into quarantine.  Disabled unless ``HONEYNET_FETCHER_URL``
is set.  The fetcher enforces SSRF protection, size/time caps and rate limits.
"""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..common.limits import SlidingCounter


@dataclass
class FetchResult:
    ok: bool
    sha256: str = ""
    md5: str = ""
    size: int = 0
    truncated: bool = False
    status: int = 0
    content_type: str = ""
    body: bytes = b""          # full body when small, otherwise a short head
    body_complete: bool = False
    error: str = ""
    new: bool = False
    extra: dict = field(default_factory=dict)


class FetcherClient:
    def __init__(self, url: str, token: str, per_ip_per_hour: int = 20, global_per_hour: int = 200) -> None:
        parts = urlsplit(url)
        self.host = parts.hostname or "fetcher"
        self.port = parts.port or 8099
        self.token = token
        self._per_ip = SlidingCounter(3600)
        self._global = SlidingCounter(3600)
        self.per_ip_limit = per_ip_per_hour
        self.global_limit = global_per_hour

    def allowed(self, src_ip: str) -> bool:
        return self._global.hit("*", self.global_limit) and self._per_ip.hit(src_ip, self.per_ip_limit)

    async def fetch(self, url: str, *, src_ip: str, session: str | None, service: str,
                    via: str = "wget") -> FetchResult:
        if not self.allowed(src_ip):
            return FetchResult(False, error="rate-limited")
        payload = json.dumps({"url": url, "src_ip": src_ip, "session": session, "service": service,
                              "via": via}).encode()
        req = (f"POST /fetch HTTP/1.1\r\nHost: fetcher\r\nAuthorization: Bearer {self.token}\r\n"
               f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n"
               f"Connection: close\r\n\r\n").encode() + payload
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), 5)
            writer.write(req)
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(256 * 1024), 60)
            writer.close()
        except (OSError, asyncio.TimeoutError) as exc:
            return FetchResult(False, error=f"fetcher-unreachable:{type(exc).__name__}")
        head, _, body = raw.partition(b"\r\n\r\n")
        try:
            doc = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            return FetchResult(False, error="bad-fetcher-response")
        if not doc.get("ok"):
            return FetchResult(False, error=str(doc.get("error", "failed"))[:120])
        data = base64.b64decode(doc.get("body_b64", "") or b"")
        return FetchResult(True, doc.get("sha256", ""), doc.get("md5", ""), int(doc.get("size", 0)),
                           bool(doc.get("truncated")), int(doc.get("status", 0)), doc.get("content_type", ""),
                           data, bool(doc.get("body_complete")), "", bool(doc.get("new")))
