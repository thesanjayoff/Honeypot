"""Sandboxed *fetcher* service - the only component that may reach the internet for attackers.

Honeypot containers ask it (over an internal-only network, with a shared token) to download a
URL that an attacker referenced (wget in the fake shell, an exploit payload...).  It:

* only fetches http/https/tftp, only from *public* IPs (SSRF guard, re-checked on redirects and
  with DNS pinning so rebinding cannot bypass it), refuses mail/SMB/RDP style ports;
* caps size, time and request rate; sends a generic user agent and no identifying data;
* streams the body straight into the quarantine store (never executes or parses it);
* returns only hashes plus (for small files) the body so the fake shell can "run" it *in the fake shell*.

Disabled unless the fetcher container is started and ``HONEYNET_FETCHER_URL`` is set.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import ipaddress
import json
import logging
import socket
import ssl
import struct
import time
from urllib.parse import urljoin, urlsplit

from .common.config import Settings, load_settings
from .common.events import FILE_CAPTURED, EventWriter
from .common.limits import SlidingCounter
from .common.quarantine import Quarantine, QuarantineFull
from .common.sanitize import sanitize_text

log = logging.getLogger("honeynet.fetcher")

BLOCKED_PORTS = {25, 110, 135, 137, 138, 139, 143, 445, 465, 587, 993, 995, 3389, 5432, 3306, 6379, 11211}
USER_AGENT = "Wget/1.20.3 (linux-gnu)"
MAX_REDIRECTS = 3
TOTAL_TIMEOUT = 40
SMALL_BODY = 64 * 1024


class FetchError(Exception):
    pass


def is_forbidden_ip(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not ip.is_global or ip.is_multicast


async def resolve_public(host: str, loop=None) -> list[str]:
    """Resolve host and require EVERY address to be public. Returns the addresses."""
    loop = loop or asyncio.get_running_loop()
    try:
        ipaddress.ip_address(host)
        addrs = [host]
    except ValueError:
        try:
            infos = await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), 8)
        except (OSError, asyncio.TimeoutError) as exc:
            raise FetchError(f"dns:{type(exc).__name__}") from None
        addrs = list(dict.fromkeys(i[4][0] for i in infos))
    if not addrs:
        raise FetchError("dns:no-address")
    for a in addrs:
        if is_forbidden_ip(ipaddress.ip_address(a)):
            raise FetchError("ssrf:non-public-address")
    return addrs


def validate_url(url: str) -> tuple[str, str, int, str]:
    if len(url) > 2048:
        raise FetchError("url-too-long")
    p = urlsplit(url)
    if p.scheme not in ("http", "https", "tftp"):
        raise FetchError("scheme-not-allowed")
    if not p.hostname:
        raise FetchError("no-host")
    port = p.port or {"http": 80, "https": 443, "tftp": 69}[p.scheme]
    if port in BLOCKED_PORTS and p.scheme != "tftp":
        raise FetchError("port-blocked")
    path = (p.path or "/") + (f"?{p.query}" if p.query else "")
    return p.scheme, p.hostname, port, path


class Fetcher:
    def __init__(self, settings: Settings) -> None:
        self.s = settings
        self.q = Quarantine(settings.quarantine_dir, settings.max_file_bytes, settings.max_quarantine_bytes)
        self.events = EventWriter("fetcher", settings.events_dir, redactor=settings.redactor())
        self.per_ip = SlidingCounter(3600)
        self.global_hits = SlidingCounter(60)
        self.sem = asyncio.Semaphore(4)
        self.seen_urls: dict[str, tuple[float, dict]] = {}

    async def fetch(self, req: dict) -> dict:
        url = str(req.get("url", ""))
        src_ip = str(req.get("src_ip", "0.0.0.0"))
        if not self.global_hits.hit("*", 30):
            return {"ok": False, "error": "global-rate-limit"}
        if not self.per_ip.hit(src_ip, 20):
            return {"ok": False, "error": "ip-rate-limit"}
        cached = self.seen_urls.get(url)
        if cached and time.time() - cached[0] < 300:
            return cached[1]
        async with self.sem:
            try:
                res = await asyncio.wait_for(self._fetch_url(url), TOTAL_TIMEOUT)
            except FetchError as e:
                res = {"ok": False, "error": str(e)}
            except asyncio.TimeoutError:
                res = {"ok": False, "error": "timeout"}
            except Exception as e:  # noqa: BLE001
                log.debug("fetch error", exc_info=True)
                res = {"ok": False, "error": f"error:{type(e).__name__}"}
        if res.get("ok"):
            self.events.emit(FILE_CAPTURED, src_ip, session=_sess(req.get("session")), sha256=res["sha256"],
                             md5=res["md5"], size=res["size"], path=sanitize_text(url, 300), origin="download",
                             via=sanitize_text(req.get("via", "fetch"), 20), url=sanitize_text(url, 2048),
                             new=res.get("new", False), truncated=res["truncated"], http_status=res.get("status", 0))
        else:
            self.events.emit("download.failed", src_ip, session=_sess(req.get("session")),
                             url=sanitize_text(url, 2048), error=res.get("error", ""))
        self.seen_urls[url] = (time.time(), res)
        if len(self.seen_urls) > 500:
            self.seen_urls.clear()
        return res

    # --------------------------------------------------------------- transports
    async def _fetch_url(self, url: str, depth: int = 0) -> dict:
        scheme, host, port, path = validate_url(url)
        addrs = await resolve_public(host)
        if scheme == "tftp":
            return await self._tftp(addrs[0], port, path.lstrip("/"))
        writer_q = self.q.writer({"url": url})
        try:
            ssl_ctx = None
            if scheme == "https":
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(addrs[0], port, ssl=ssl_ctx, server_hostname=host if ssl_ctx else None), 8)
            except (OSError, asyncio.TimeoutError) as exc:
                raise FetchError(f"connect:{type(exc).__name__}") from None
            hostline = host if port in (80, 443) else f"{host}:{port}"
            writer.write((f"GET {path} HTTP/1.0\r\nHost: {hostline}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\n"
                          f"Connection: close\r\n\r\n").encode("latin-1", "replace"))
            await writer.drain()
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = await asyncio.wait_for(reader.read(4096), 15)
                if not chunk:
                    break
                head += chunk
                if len(head) > 32768:
                    raise FetchError("bad-response-headers")
            raw_head, _, body0 = head.partition(b"\r\n\r\n")
            lines = raw_head.decode("latin-1").split("\r\n")
            try:
                status = int(lines[0].split()[1])
            except (IndexError, ValueError):
                raise FetchError("not-http") from None
            hdr = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:]) if k}
            if status in (301, 302, 303, 307, 308) and "location" in hdr:
                writer.close()
                writer_q.abort()
                if depth >= MAX_REDIRECTS:
                    raise FetchError("too-many-redirects")
                return await self._fetch_url(urljoin(url, hdr["location"]), depth + 1)
            chunked = "chunked" in hdr.get("transfer-encoding", "").lower()
            data = bytearray()
            if body0:
                data.extend(body0)
            more = True
            while more and len(data) <= self.s.max_file_bytes:
                chunk = await asyncio.wait_for(reader.read(65536), 15)
                if not chunk:
                    break
                data.extend(chunk)
            writer.close()
            body = _dechunk(bytes(data)) if chunked else bytes(data)
            writer_q.write(body)
            small = body if len(body) <= SMALL_BODY else body[:2048]
            if status >= 400 or not body:
                writer_q.abort()
                return {"ok": False, "error": f"http-{status}" if status >= 400 else "empty-body"}
            stored = writer_q.finish()
            return {"ok": True, "sha256": stored.sha256, "md5": stored.md5, "size": stored.size,
                    "truncated": stored.truncated, "status": status, "content_type": hdr.get("content-type", "")[:100],
                    "new": stored.is_new, "body_complete": len(body) <= SMALL_BODY and not stored.truncated,
                    "body_b64": base64.b64encode(small).decode()}
        except QuarantineFull:
            return {"ok": False, "error": "quarantine-full"}
        except BaseException:
            writer_q.abort()
            raise

    async def _tftp(self, addr: str, port: int, filename: str) -> dict:
        if not filename or len(filename) > 128 or "\x00" in filename:
            raise FetchError("bad-tftp-name")
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET6 if ":" in addr else socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_sendto(sock, b"\x00\x01" + filename.encode() + b"\x00octet\x00", (addr, port))
            blocks = bytearray()
            expect = 1
            peer = None
            for _ in range(self.s.max_file_bytes // 512 + 2):
                data, src = await asyncio.wait_for(loop.sock_recvfrom(sock, 600), 6)
                if src[0] != addr:
                    continue
                peer = src
                op, blk = struct.unpack(">HH", data[:4])
                if op == 5:
                    raise FetchError("tftp-error")
                if op != 3 or blk != expect:
                    continue
                blocks.extend(data[4:])
                await loop.sock_sendto(sock, struct.pack(">HH", 4, blk), peer)
                expect = (expect + 1) & 0xFFFF
                if len(data) - 4 < 512:
                    break
        except asyncio.TimeoutError:
            raise FetchError("tftp-timeout") from None
        finally:
            sock.close()
        if not blocks:
            raise FetchError("empty-body")
        stored = self.q.store(bytes(blocks), {"url": f"tftp://{addr}/{filename}"})
        small = bytes(blocks) if len(blocks) <= SMALL_BODY else bytes(blocks[:2048])
        return {"ok": True, "sha256": stored.sha256, "md5": stored.md5, "size": stored.size, "truncated": stored.truncated,
                "status": 0, "content_type": "application/octet-stream", "new": stored.is_new,
                "body_complete": len(blocks) <= SMALL_BODY, "body_b64": base64.b64encode(small).decode()}


def _sess(v) -> str | None:
    s = str(v or "")
    return s if s and len(s) <= 40 and all(c.isalnum() or c in "_-" for c in s) else None


def _dechunk(data: bytes) -> bytes:
    out = bytearray()
    buf = data
    while buf:
        line, sep, rest = buf.partition(b"\r\n")
        if not sep:
            break
        try:
            size = int(line.split(b";")[0] or b"0", 16)
        except ValueError:
            return data
        if size == 0:
            break
        out.extend(rest[:size])
        buf = rest[size + 2:]
    return bytes(out)


# ----------------------------------------------------------------------- API server

async def _handle(fetcher: Fetcher, token: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        lines = head.decode("latin-1").split("\r\n")
        method, path = lines[0].split(" ")[:2]
        hdr = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:]) if k}
        if method == "GET" and path == "/healthz":
            return await _reply(writer, 200, {"ok": True})
        if method != "POST" or path != "/fetch":
            return await _reply(writer, 404, {"ok": False})
        supplied = hdr.get("authorization", "").removeprefix("Bearer ").strip()
        if not token or not hmac.compare_digest(supplied, token):
            return await _reply(writer, 401, {"ok": False, "error": "unauthorized"})
        n = int(hdr.get("content-length", "0"))
        if n <= 0 or n > 8192:
            return await _reply(writer, 400, {"ok": False, "error": "bad-length"})
        body = await asyncio.wait_for(reader.readexactly(n), 5)
        res = await fetcher.fetch(json.loads(body))
        await _reply(writer, 200, res)
    except Exception:  # noqa: BLE001
        try:
            await _reply(writer, 400, {"ok": False, "error": "bad-request"})
        except Exception:  # noqa: BLE001
            pass
    finally:
        writer.close()


async def _reply(writer: asyncio.StreamWriter, status: int, doc: dict) -> None:
    body = json.dumps(doc).encode()
    writer.write(f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                 f"Connection: close\r\n\r\n".encode() + body)
    await writer.drain()


async def serve(settings: Settings | None = None, host: str = "0.0.0.0", port: int = 8099) -> None:
    s = settings or load_settings()
    if not s.fetcher_token:
        raise SystemExit("HONEYNET_FETCHER_TOKEN must be set for the fetcher service")
    f = Fetcher(s)
    srv = await asyncio.start_server(lambda r, w: _handle(f, s.fetcher_token, r, w), host, port, limit=65536)
    log.info("fetcher listening on %s:%d", host, port)
    async with srv:
        await srv.serve_forever()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(serve())


if __name__ == "__main__":
    main()
