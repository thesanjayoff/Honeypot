"""HTTP(S) honeypot: hand-rolled HTTP/1.x server (tolerant of garbage), fake admin pages,
signature matching, credential capture, upload/payload capture."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import ssl
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit

from ..common.events import AUTH_ATTEMPT, DOWNLOAD_ATTEMPT, EXPLOIT, FILE_CAPTURED, HTTP_REQUEST, SCAN_PROBE
from ..common.sanitize import sanitize_text
from . import http_pages as pages
from .base import Connection, TCPService, register
from .http_rules import extract_payload_urls, match_rules

log = logging.getLogger("honeynet.http")

MAX_HEAD = 16 * 1024
MAX_HEADERS = 100
MAX_REQUESTS_PER_CONN = 20
CAPTURE_MIN = 12
_REQ_LINE = re.compile(rb"^([A-Za-z]{3,20}) (\S{1,4096}) HTTP/(\d\.\d)$")
_HDR_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
USER_KEYS = ("log", "username", "user", "login", "email", "pma_username", "uname", "userid", "j_username", "name")
PASS_KEYS = ("pwd", "password", "pass", "passwd", "pma_password", "pw", "j_password", "secret")
PAYLOAD_MAGIC = (b"\x7fELF", b"MZ", b"#!", b"<?php", b"<%", b"PK\x03\x04", b"\x1f\x8b")
LOGIN_PATHS = {
    "/login", "/login.htm", "/login.html", "/login.cgi", "/login.rsp", "/admin", "/admin/login", "/index.asp",
    "/cgi-bin/luci", "/cgi-bin/login.cgi", "/boaform/admin/formlogin", "/userrpm/loginrpm.htm", "/admin/index.php",
    "/administrator", "/user/login", "/signin", "/auth", "/session", "/api/login",
}
PMA_PATHS = ("/phpmyadmin", "/pma", "/myadmin", "/mysqladmin", "/dbadmin", "/phpmyadmin/index.php", "/mysql")


@dataclass
class Request:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    body: bytes
    raw_head: bytes
    truncated_body: bool = False
    hdr: dict[str, str] = field(default_factory=dict)


def classify_probe(data: bytes) -> str:
    if data[:2] == b"\x16\x03":
        return "tls-clienthello"
    if data.startswith(b"SSH-"):
        return "ssh-banner"
    if data[:2] == b"\x03\x00":
        return "rdp-tpkt"
    if b"SMB" in data[:8]:
        return "smb"
    if data[:2] in (b"\x05\x01", b"\x05\x02"):
        return "socks5"
    if data[:2] == b"\x04\x01":
        return "socks4"
    if data.startswith(b"PRI * HTTP/2"):
        return "http2-preface"
    if data[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"CONN", b"OPTI"):
        return "http-malformed"
    if data[:1] == b"\x00":
        return "binary-null"
    return "unknown"


@register
class HTTPService(TCPService):
    name = "http"
    default_ports = [8080]
    ssl_ctx: ssl.SSLContext | None = None

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self._bg: set[asyncio.Task] = set()
        self._fetch_sem = asyncio.Semaphore(3)

    # ------------------------------------------------------------- start (TLS hook)
    async def start(self) -> None:
        for port in self.ports:
            srv = await asyncio.start_server(self._accept_factory(port), self.settings.bind_host, port,
                                             limit=self.read_limit, backlog=128, ssl=self.ssl_ctx,
                                             ssl_handshake_timeout=10 if self.ssl_ctx else None)
            self.servers.append(srv)
            log.info("%s listening on %s:%d", self.name, self.settings.bind_host, port)

    # ------------------------------------------------------------------ parsing
    async def _read_request(self, conn: Connection, first: bool) -> Request | None:
        buf = bytearray(conn.leftover)
        conn.leftover = b""
        while True:
            idx = buf.find(b"\r\n\r\n")
            sep = 4
            if idx < 0:
                idx = buf.find(b"\n\n")
                sep = 2
            if idx >= 0:
                break
            if len(buf) > MAX_HEAD:
                raise ValueError("header-too-large")
            chunk = await conn.read(4096, 15 if first else 30)
            if not chunk:
                if buf and first:
                    self._probe(conn, bytes(buf))
                return None
            buf.extend(chunk)
        head, rest = bytes(buf[:idx]), bytes(buf[idx + sep:])
        lines = head.replace(b"\r\n", b"\n").split(b"\n")
        m = _REQ_LINE.match(lines[0].strip())
        if not m:
            self._probe(conn, bytes(buf))
            return None
        method, target, version = (m.group(1).decode("ascii", "replace").upper(), m.group(2).decode("latin-1"),
                                   m.group(3).decode())
        headers: list[tuple[str, str]] = []
        for ln in lines[1:MAX_HEADERS + 1]:
            if b":" not in ln:
                continue
            k, _, v = ln.decode("latin-1").partition(":")
            if _HDR_NAME.match(k.strip()):
                headers.append((k.strip(), v.strip()))
        hdr = {k.lower(): v for k, v in headers}
        body, truncated, conn.leftover = await self._read_body(conn, hdr, rest)
        return Request(method, target, version, headers, body, head, truncated, hdr)

    async def _read_body(self, conn: Connection, hdr: dict[str, str], rest: bytes) -> tuple[bytes, bool, bytes]:
        cap = self.settings.max_http_body
        if "100-continue" in hdr.get("expect", "").lower():
            await conn.send(b"HTTP/1.1 100 Continue\r\n\r\n")
        te = hdr.get("transfer-encoding", "").lower()
        body = bytearray(rest)
        try:
            if "chunked" in te:
                data, trunc, left = await self._read_chunked(conn, body, cap)
                return data, trunc, left
            try:
                want = int(hdr.get("content-length", "0"))
            except ValueError:
                want = 0
            want = max(0, want)
            truncated = want > cap
            want = min(want, cap)
            while len(body) < want:
                chunk = await conn.read(min(65536, want - len(body)), 15)
                if not chunk:
                    break
                body.extend(chunk)
            return bytes(body[:want]), truncated, (b"" if truncated else bytes(body[want:]))
        except (asyncio.TimeoutError, TimeoutError):
            return bytes(body), True, b""

    async def _read_chunked(self, conn: Connection, buf: bytearray, cap: int) -> tuple[bytes, bool, bytes]:
        out = bytearray()
        for _ in range(4096):
            while b"\n" not in buf:
                chunk = await conn.read(4096, 15)
                if not chunk:
                    return bytes(out), False, b""
                buf.extend(chunk)
                if len(buf) > 65536:
                    return bytes(out), True, b""
            line, _, rest = bytes(buf).partition(b"\n")
            buf[:] = rest
            try:
                size = int(line.strip().split(b";")[0] or b"0", 16)
            except ValueError:
                return bytes(out), True, b""
            if size == 0:
                return bytes(out), False, bytes(buf).lstrip(b"\r\n")
            while len(buf) < size + 2:
                chunk = await conn.read(65536, 15)
                if not chunk:
                    break
                buf.extend(chunk)
            out.extend(buf[:size])
            del buf[:size + 2]
            if len(out) >= cap:
                return bytes(out[:cap]), True, b""
        return bytes(out), True, b""

    def _probe(self, conn: Connection, data: bytes) -> None:
        conn.emit(SCAN_PROBE, proto_guess=classify_probe(data), first_bytes_hex=data[:48].hex(),
                  first_bytes=sanitize_text(data[:80].decode("latin-1")), length=len(data))

    # ------------------------------------------------------------------ handling
    async def handle(self, conn: Connection) -> None:
        for n in range(MAX_REQUESTS_PER_CONN):
            try:
                req = await self._read_request(conn, first=(n == 0))
            except ValueError:
                await self._send(conn, 431, b"Request Header Fields Too Large", "text/plain", close=True)
                return
            except (asyncio.TimeoutError, TimeoutError):
                return
            if req is None:
                if n == 0:
                    try:
                        await self._send(conn, 400, b"Bad Request", "text/plain", close=True)
                    except Exception:  # noqa: BLE001
                        pass
                return
            keep = await self._process(conn, req)
            if not keep or req.truncated_body:
                return

    async def _process(self, conn: Connection, req: Request) -> bool:
        parts = urlsplit(req.target if req.target.startswith("/") else "/" + req.target.split("://", 1)[-1].split("/", 1)[-1])
        path_raw = parts.path or "/"
        path = unquote(path_raw)
        low = path.lower().rstrip("/") or "/"
        query = parts.query
        ctype = req.hdr.get("content-type", "")
        body_text = req.body.decode("utf-8", "replace")
        headers_text = "\n".join(f"{k}: {v}" for k, v in req.headers)
        matches = match_rules(req.target, headers_text, body_text, req.method)

        creds = self._extract_creds(req, low, body_text, ctype, query)
        for c in creds:
            conn.emit(AUTH_ATTEMPT, username=c["username"], password=c["password"], method=c["method"],
                      success=False, path=sanitize_text(path, 300))

        files_captured = self._capture_uploads(conn, req, path, ctype)

        urls = extract_payload_urls(req.target, body_text, headers_text)
        for u in urls[:5]:
            conn.emit(DOWNLOAD_ATTEMPT, url=sanitize_text(u, 2048), via="http-exploit", host="", fetched=False,
                      scheme=u.split(":", 1)[0].lower())
        if urls and self.ctx.fetcher and any(m["category"] in ("rce", "cmdi") for m in matches):
            self._spawn(self._fetch_payloads(conn, urls[:2]))

        status, ctype_out, body, extra = self._route(req, low, path, query, creds, matches, body_text)

        fp = hashlib.md5((",".join(k.lower() for k, _ in req.headers) + req.method + req.version).encode()).hexdigest()[:16]
        conn.emit(HTTP_REQUEST, method=req.method, path=sanitize_text(req.target, 2048), host=req.hdr.get("host", "")[:255],
                  user_agent=req.hdr.get("user-agent", "")[:300], status=status, body_len=len(req.body),
                  body=sanitize_text(body_text, 2000), content_type=ctype[:120],
                  body_sha256=hashlib.sha256(req.body).hexdigest() if req.body else "",
                  headers={k: v[:300] for k, v in req.headers[:40]}, header_fp=fp, version=req.version,
                  rules=[m["rule"] for m in matches], files=files_captured)
        for m in matches:
            conn.emit(EXPLOIT, rule=m["rule"], cve=m["cve"], category=m["category"], severity=m["severity"],
                      snippet=sanitize_text(m["snippet"], 200), path=sanitize_text(req.target, 500),
                      method=req.method)

        keep = req.hdr.get("connection", "").lower() == "keep-alive" or (
            req.version == "1.1" and req.hdr.get("connection", "").lower() != "close")
        await self._send(conn, status, body if req.method != "HEAD" else b"", ctype_out, close=not keep,
                         extra=extra, content_length=len(body))
        return keep

    # ----------------------------------------------------------------- credentials
    def _extract_creds(self, req: Request, low: str, body_text: str, ctype: str, query: str) -> list[dict]:
        out: list[dict] = []
        auth = req.hdr.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                user, _, pw = base64.b64decode(auth[6:] + "===").decode("utf-8", "replace").partition(":")
                out.append({"username": user, "password": pw, "method": "http-basic"})
            except ValueError:
                pass
        if req.method == "POST" and body_text:
            fields: dict[str, list[str]] = {}
            if "json" in ctype.lower() or body_text.lstrip().startswith("{"):
                try:
                    obj = json.loads(body_text)
                    if isinstance(obj, dict):
                        fields = {str(k).lower(): [str(v)] for k, v in obj.items() if isinstance(v, (str, int))}
                except ValueError:
                    pass
            elif "x-www-form-urlencoded" in ctype.lower() or "=" in body_text[:200]:
                fields = {k.lower(): v for k, v in parse_qs(body_text, keep_blank_values=True).items()}
            u = next((fields[k][0] for k in USER_KEYS if k in fields), None)
            p = next((fields[k][0] for k in PASS_KEYS if k in fields), None)
            if u is not None or p is not None:
                out.append({"username": u or "", "password": p or "", "method": "http-form"})
        return out

    # --------------------------------------------------------------------- uploads
    def _capture_uploads(self, conn: Connection, req: Request, path: str, ctype: str) -> list[str]:
        shas: list[str] = []
        candidates: list[tuple[bytes, str]] = []
        if req.body and "multipart/form-data" in ctype.lower():
            m = re.search(r'boundary="?([^";]+)"?', ctype, re.I)
            if m:
                delim = b"--" + m.group(1).encode("latin-1", "replace")
                for part in req.body.split(delim)[1:]:
                    head, sep, data = part.partition(b"\r\n\r\n")
                    if not sep or b"filename=" not in head.lower():
                        continue
                    fn = re.search(rb'filename="?([^";\r\n]*)', head, re.I)
                    data = data[:-2] if data.endswith(b"\r\n") else data
                    candidates.append((data, fn.group(1).decode("utf-8", "replace") if fn else ""))
        elif req.body and (req.method in ("PUT", "POST", "PATCH")) and (
                req.body.startswith(PAYLOAD_MAGIC) or req.method == "PUT"):
            candidates.append((req.body, path.rsplit("/", 1)[-1]))
        for data, filename in candidates:
            if len(data) < CAPTURE_MIN:
                continue
            stored = self.ctx.capture(data, origin="http-upload", filename=filename[:200], path=path[:300],
                                      src_ip=conn.ip, session=conn.sid, service=self.name, via=f"http-{req.method.lower()}")
            if stored:
                shas.append(stored.sha256)
                conn.emit(FILE_CAPTURED, sha256=stored.sha256, md5=stored.md5, size=stored.size, path=sanitize_text(path, 300),
                          origin="http-upload", filename=sanitize_text(filename, 200), new=stored.is_new,
                          truncated=stored.truncated, via=f"http-{req.method.lower()}", url="")
        return shas

    def _spawn(self, coro) -> None:
        t = asyncio.create_task(coro)
        self._bg.add(t)
        t.add_done_callback(self._bg.discard)

    async def _fetch_payloads(self, conn: Connection, urls: list[str]) -> None:
        async with self._fetch_sem:
            for u in urls:
                if u.lower().startswith(("http://", "https://")):
                    res = await self.ctx.fetcher.fetch(u, src_ip=conn.ip, session=conn.sid, service=self.name,
                                                       via="http-exploit")
                    conn.emit(DOWNLOAD_ATTEMPT, url=sanitize_text(u, 2048), via="http-exploit-fetch", host="",
                              fetched=res.ok, error=res.error, sha256=res.sha256, scheme="http")

    # ---------------------------------------------------------------------- routes
    def _route(self, req: Request, low: str, path: str, query: str, creds: list[dict], matches: list[dict],
               body_text: str) -> tuple[int, str, bytes, dict[str, str]]:
        html = "text/html; charset=UTF-8"
        text = "text/plain; charset=UTF-8"
        names = {m["rule"] for m in matches}
        decoded = unquote(unquote(req.target)) + " " + unquote(body_text)

        # exploit probes get "plausible" output so automated exploit chains continue
        if names & {"lfi-sensitive-file"} and "passwd" in decoded:
            return 200, text, (b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                               b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:106:112:MySQL Server:/nonexistent:/bin/false\n"), {}
        if any(m["category"] in ("rce", "cmdi") for m in matches):
            if re.search(r"(?<![\w.-])id(?![\w.-])", decoded):
                return 200, text, b"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n", {}
            if "uname" in decoded:
                return 200, text, b"Linux web01 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 x86_64 GNU/Linux\n", {}
            if "whoami" in decoded:
                return 200, text, b"www-data\n", {}
            return 200, text, b"", {}

        if low in ("/", "/index.html", "/index.htm", "/index.php"):
            return 200, html, pages.apache_default().encode(), {}
        if low == "/robots.txt":
            return 200, text, pages.robots().encode(), {}
        if low in ("/wp-login.php",):
            if req.method == "POST" and creds:
                u = creds[-1]["username"]
                msg = (f"The password you entered for the username <strong>{pages.esc(u)}</strong> is incorrect. "
                       f"<a href=\"/wp-login.php?action=lostpassword\">Lost your password?</a>"
                       if u.lower() in ("admin", "administrator", "wordpress") else
                       f"The username <strong>{pages.esc(u)}</strong> is not registered on this site.")
                return 200, html, pages.wordpress_login(msg, u).encode(), {}
            return 200, html, pages.wordpress_login().encode(), {"Set-Cookie": "wordpress_test_cookie=WP%20Cookie%20check; path=/"}
        if low in ("/wp-admin",) or low.startswith("/wp-admin/") and not low.endswith((".css", ".js")):
            return 302, html, b"", {"Location": "/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1"}
        if low == "/xmlrpc.php":
            if req.method == "POST":
                return 200, "text/xml", (b'<?xml version="1.0" encoding="UTF-8"?><methodResponse><fault><value><struct>'
                                         b"<member><name>faultCode</name><value><int>403</int></value></member><member><name>faultString</name>"
                                         b"<value><string>Incorrect username or password.</string></value></member></struct></value></fault></methodResponse>"), {}
            return 405, text, b"XML-RPC server accepts POST requests only.", {"Allow": "POST"}
        if any(low == p or low.startswith(p + "/") for p in PMA_PATHS):
            if req.method == "POST" and creds:
                u = creds[-1]["username"]
                return 200, html, pages.phpmyadmin_login(f"#1045 - Access denied for user '{pages.esc(u)}'@'localhost' (using password: YES)").encode(), {}
            return 200, html, pages.phpmyadmin_login().encode(), {"Set-Cookie": "phpMyAdmin=a8d8f1e2c0b0a7f1; path=/; HttpOnly"}
        if low in LOGIN_PATHS or low.startswith("/cgi-bin/luci"):
            if req.method == "POST" and creds:
                return 200, html, pages.router_login("Incorrect username or password.").encode(), {}
            return 200, html, pages.router_login().encode(), {}
        if low.startswith("/manager"):
            return 401, html, pages.tomcat_401().encode(), {"WWW-Authenticate": 'Basic realm="Tomcat Manager Application"'}
        if low == "/.env":
            return 200, text, pages.fake_dotenv().encode(), {}
        if low == "/.git/config":
            return 200, text, pages.fake_git_config().encode(), {}
        if low == "/.git/head":
            return 200, text, b"ref: refs/heads/master\n", {}
        if low in ("/server-status", "/server-info"):
            return 403, html, pages.forbidden(path).encode(), {}
        if req.method == "OPTIONS":
            return 200, text, b"", {"Allow": "GET,HEAD,POST,OPTIONS"}
        if req.method in ("CONNECT", "TRACE"):
            return 405, html, pages.forbidden(path).encode(), {}
        if "webshell-access" in names:
            return 200, html, b"", {}
        return 404, html, pages.not_found(path).encode(), {}

    # ------------------------------------------------------------------- output
    async def _send(self, conn: Connection, status: int, body: bytes, ctype: str, *, close: bool,
                    extra: dict[str, str] | None = None, content_length: int | None = None) -> None:
        reasons = {200: "OK", 100: "Continue", 302: "Found", 400: "Bad Request", 401: "Unauthorized",
                   403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 431: "Request Header Fields Too Large"}
        head = [f"HTTP/1.1 {status} {reasons.get(status, 'OK')}", f"Date: {pages.http_date()}",
                f"Server: {pages.SERVER_HEADER}", f"Content-Type: {ctype}",
                f"Content-Length: {len(body) if content_length is None else content_length}",
                f"Connection: {'close' if close else 'keep-alive'}", "Vary: Accept-Encoding"]
        for k, v in (extra or {}).items():
            if "\r" not in k + v and "\n" not in k + v:
                head.append(f"{k}: {v}")
        await conn.send(("\r\n".join(head) + "\r\n\r\n").encode("latin-1", "replace") + body)


# ------------------------------------------------------------------------ HTTPS

def _self_signed(keys_dir) -> tuple[str, str]:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    keys_dir.mkdir(parents=True, exist_ok=True)
    crt, key = keys_dir / "https.crt", keys_dir / "https.key"
    if crt.exists() and key.exists():
        return str(crt), str(key)
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Internal Services")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=30))
            .not_valid_after(now + timedelta(days=700)).sign(k, hashes.SHA256()))
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
    try:
        key.chmod(0o600)
    except OSError:
        pass
    return str(crt), str(key)


@register
class HTTPSService(HTTPService):
    name = "https"
    default_ports = [8443]

    async def start(self) -> None:
        crt, key = _self_signed(self.settings.keys_dir)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(crt, key)
        self.ssl_ctx = ctx
        await super().start()
