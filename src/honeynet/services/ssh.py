"""SSH honeypot (asyncssh): fake login -> fake shell, SFTP/SCP upload capture."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import struct
import time
import weakref
from pathlib import Path
from typing import Any

import asyncssh

from ..common.events import (AUTH_ATTEMPT, CONN_CLOSE, CONN_OPEN, SESSION_CLOSE, SESSION_OPEN, new_session_id)
from ..common.sanitize import sanitize_text
from ..shell.fakefs import FSError
from ..shell.session import ShellSession
from .auth_policy import decide
from .base import Service, register

log = logging.getLogger("honeynet.ssh")

SERVER_VERSION = "OpenSSH_8.4p1 Debian-5+deb11u3"
MAX_AUTH_TRIES = 6
MAX_UPLOAD = 8 * 1024 * 1024


def hassh_from_kexinit(payload: bytes) -> tuple[str, str]:
    """HASSH (client) = md5(kex;enc_c2s;mac_c2s;comp_c2s). Returns (hash, algorithm string)."""
    try:
        off = 17 if payload[:1] == b"\x14" else 16
        lists = []
        for _ in range(10):
            (n,) = struct.unpack_from(">I", payload, off)
            if n > 8192:
                return "", ""
            lists.append(payload[off + 4: off + 4 + n].decode("ascii", "replace"))
            off += 4 + n
        algs = ";".join([lists[0], lists[2], lists[4], lists[6]])
        return hashlib.md5(algs.encode()).hexdigest(), algs
    except (struct.error, IndexError, ValueError):
        return "", ""


class ConnState:
    """Per-connection state shared by the auth callbacks, shell and SFTP handlers."""

    def __init__(self, svc: "SSHService", ip: str, port: int, dst_port: int) -> None:
        self.svc, self.ip, self.port, self.dst_port = svc, ip, port, dst_port
        self.sid = new_session_id()
        self.opened = time.monotonic()
        self.attempts = 0
        self.username = ""
        self.password = ""
        self.auth_method = ""
        self.authed = False
        self.client_version = ""
        self.hassh = ""
        self.session_open_emitted = False
        self.shell: ShellSession | None = None
        self.channels = 0
        self.upload_bytes = 0
        self.closed = False

    def emit(self, event: str, **data: Any):
        return self.svc.events.emit(event, self.ip, src_port=self.port, dst_port=self.dst_port,
                                    session=self.sid, **data)

    def get_shell(self) -> ShellSession:
        if self.shell is None:
            self.shell = ShellSession(
                persona_name="debian", user=self.username or "root", emit=self.emit, ctx=self.svc.ctx,
                src_ip=self.ip, session_id=self.sid, service="ssh",
                client_info={"client_version": self.client_version})
        return self.shell

    def open_session_event(self) -> None:
        if not self.session_open_emitted:
            self.session_open_emitted = True
            self.emit(SESSION_OPEN, username=self.username, password=self.password, method=self.auth_method,
                      client_version=self.client_version, hassh=self.hassh)


class HoneySSHServer(asyncssh.SSHServer):
    def __init__(self, svc: "SSHService", dst_port: int) -> None:
        self.svc = svc
        self.dst_port = dst_port
        self.state: ConnState | None = None
        self.conn: asyncssh.SSHServerConnection | None = None
        self._kill: asyncio.TimerHandle | None = None
        self._admitted = False

    # --- connection lifecycle ---
    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername") or ("0.0.0.0", 0)
        ip = str(peer[0])
        self.conn = conn
        self.state = ConnState(self.svc, ip, int(peer[1]), self.dst_port)
        if not self.svc.ctx.limiter.acquire(ip):
            conn.abort()
            self.state = None
            return
        self._admitted = True
        self.svc.states[conn] = self.state
        self.state.emit(CONN_OPEN)
        loop = asyncio.get_running_loop()
        self._kill = loop.call_later(self.svc.settings.max_session_seconds, self._timeout)

    def _timeout(self) -> None:
        if self.conn and self.state:
            self.state.emit("session.timeout", seconds=self.svc.settings.max_session_seconds)
            self.conn.abort()

    def connection_lost(self, exc: Exception | None) -> None:
        st = self.state
        if self._kill:
            self._kill.cancel()
        if not st or st.closed:
            return
        st.closed = True
        if self.conn:
            self.svc.states.pop(self.conn, None)
        if st.shell:
            st.shell.capture_all()
        dur = round(time.monotonic() - st.opened, 2)
        if st.session_open_emitted:
            st.emit(SESSION_CLOSE, duration=dur, commands=st.shell.cmd_count if st.shell else 0,
                    username=st.username, downloads=len(st.shell.downloads) if st.shell else 0,
                    reason=type(exc).__name__ if exc else "closed")
        st.emit(CONN_CLOSE, duration=dur, reason=type(exc).__name__ if exc else "closed")
        if self._admitted:
            self.svc.ctx.limiter.release(st.ip)

    # --- authentication ---
    def begin_auth(self, username: str) -> bool:
        st = self.state
        if st and not st.client_version and self.conn:
            st.client_version = sanitize_text(self.conn.get_extra_info("client_version") or "", 200)
            kex = getattr(self.conn, "_client_kexinit", b"")
            st.hassh, algs = hassh_from_kexinit(kex)
            st.emit("client.fingerprint", client_version=st.client_version, hassh=st.hassh,
                    hassh_algorithms=algs[:1500])
        return True

    def password_auth_supported(self) -> bool:
        return True

    def kbdint_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        st = self.state
        if st:
            st.emit(AUTH_ATTEMPT, username=username, method="publickey", success=False,
                    key_type=key.algorithm.decode("ascii", "replace"), key_fingerprint=key.get_fingerprint())
        return False

    def get_kbdint_challenge(self, username: str, lang: str, submethods: str):
        return "", "", "", [("Password: ", False)]

    def validate_kbdint_response(self, username: str, responses):
        pw = responses[0] if responses else ""
        return self._check(username, pw, "keyboard-interactive")

    def validate_password(self, username: str, password: str) -> bool:
        return self._check(username, password, "password")

    def _check(self, username: str, password: str, method: str) -> bool:
        st = self.state
        if st is None:
            return False
        st.attempts += 1
        ok = decide(st.ip, username, password, self.svc.settings.ssh_accept_pct)
        st.emit(AUTH_ATTEMPT, username=username, password=password, method=method, success=ok,
                attempt=st.attempts)
        if ok:
            st.username, st.password, st.auth_method, st.authed = username, password, method, True
            st.open_session_event()
            return True
        if st.attempts >= MAX_AUTH_TRIES and self.conn:
            raise asyncssh.DisconnectError(asyncssh.DISC_NO_MORE_AUTH_METHODS_AVAILABLE,
                                           "Too many authentication failures")
        return False


# --------------------------------------------------------------------- SFTP

class _SFTPFile:
    def __init__(self, path: str, writing: bool, data: bytes = b"") -> None:
        self.path = path
        self.writing = writing
        self.buf = bytearray(data)


class HoneySFTP(asyncssh.SFTPServer):
    """SFTP/SCP backed by the attacker's fake filesystem; every upload is quarantined."""

    def __init__(self, chan: asyncssh.SSHServerChannel, svc: "SSHService") -> None:
        super().__init__(chan)
        self.svc = svc
        self.st: ConnState | None = svc.states.get(chan.get_connection())
        self.sh = self.st.get_shell() if self.st else None

    def _p(self, path: bytes | str) -> str:
        if isinstance(path, bytes):
            path = path.decode("utf-8", "replace")
        return self.sh.abspath(path) if self.sh else "/"

    def _attrs(self, path: str) -> asyncssh.SFTPAttrs:
        n = self.sh.fs.lookup(path) if self.sh else None
        if n is None:
            raise asyncssh.SFTPNoSuchFile(path)
        kind = asyncssh.FILEXFER_TYPE_DIRECTORY if n.kind == "d" else asyncssh.FILEXFER_TYPE_REGULAR
        return asyncssh.SFTPAttrs(type=kind, size=n.size, permissions=(0o40000 if n.kind == "d" else 0o100000) | n.mode,
                                  uid=n.uid, gid=n.gid, atime=int(n.mtime), mtime=int(n.mtime))

    def realpath(self, path):
        return self._p(path).encode()

    def stat(self, path):
        return self._attrs(self._p(path))

    lstat = stat

    def fstat(self, file_obj):
        return self._attrs(file_obj.path)

    def listdir(self, path):
        p = self._p(path)
        try:
            names = self.sh.fs.listdir(p)    # type: ignore[union-attr]
        except FSError as e:
            raise asyncssh.SFTPNoSuchFile(str(e))
        return [b".", b".."] + [n.encode() for n in names]

    def open(self, path, pflags, attrs):
        p = self._p(path)
        writing = bool(pflags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)) or pflags in (2, 3, 4, 6)
        if self.st:
            self.st.emit("sftp.open", path=p, write=writing)
        if writing:
            return _SFTPFile(p, True)
        n = self.sh.fs.lookup(p) if self.sh else None
        if n is None or n.kind != "f":
            raise asyncssh.SFTPNoSuchFile(p)
        return _SFTPFile(p, False, n.content)

    def read(self, file_obj, offset, size):
        return bytes(file_obj.buf[offset: offset + size])

    def write(self, file_obj, offset, data):
        if self.st:
            self.st.upload_bytes += len(data)
            if self.st.upload_bytes > MAX_UPLOAD:
                raise asyncssh.SFTPFailure("quota exceeded")
        end = offset + len(data)
        if end > MAX_UPLOAD:
            raise asyncssh.SFTPFailure("file too large")
        if len(file_obj.buf) < end:
            file_obj.buf.extend(b"\x00" * (end - len(file_obj.buf)))
        file_obj.buf[offset:end] = data
        return len(data)

    def close(self, file_obj):
        if file_obj.writing and self.sh and self.st:
            try:
                node = self.sh.fs.write(file_obj.path, bytes(file_obj.buf), origin="upload")
            except FSError:
                return
            self.sh.capture_file(file_obj.path, node, "sftp-upload", origin="upload")

    def setstat(self, path, attrs):
        if attrs.permissions is not None and self.sh:
            try:
                self.sh.fs.chmod(self._p(path), attrs.permissions & 0o7777)
            except FSError:
                pass

    def fsetstat(self, file_obj, attrs):
        pass

    def mkdir(self, path, attrs):
        try:
            self.sh.fs.mkdir(self._p(path))     # type: ignore[union-attr]
        except FSError as e:
            raise asyncssh.SFTPFailure(str(e))

    def remove(self, path):
        try:
            self.sh.fs.remove(self._p(path))    # type: ignore[union-attr]
        except FSError as e:
            raise asyncssh.SFTPNoSuchFile(str(e))

    rmdir = remove

    def rename(self, oldpath, newpath):
        try:
            self.sh.fs.move(self._p(oldpath), self._p(newpath))    # type: ignore[union-attr]
        except FSError as e:
            raise asyncssh.SFTPFailure(str(e))


# ---------------------------------------------------------------- service

@register
class SSHService(Service):
    name = "ssh"
    default_ports = [2222]

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.states: "weakref.WeakKeyDictionary[Any, ConnState]" = weakref.WeakKeyDictionary()

    def _host_keys(self) -> list[asyncssh.SSHKey]:
        kdir = self.settings.keys_dir
        kdir.mkdir(parents=True, exist_ok=True)
        keys = []
        for name, alg, kw in (("ssh_host_ed25519_key", "ssh-ed25519", {}), ("ssh_host_rsa_key", "ssh-rsa", {"key_size": 2048})):
            path = kdir / name
            if path.exists():
                keys.append(asyncssh.read_private_key(str(path)))
            else:
                key = asyncssh.generate_private_key(alg, **kw)
                path.write_bytes(key.export_private_key())
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
                keys.append(key)
        return keys

    async def start(self) -> None:
        keys = self._host_keys()
        for port in self.ports:
            srv = await asyncssh.create_server(
                lambda p=port: HoneySSHServer(self, p), self.settings.bind_host, port,
                server_host_keys=keys, server_version=SERVER_VERSION, process_factory=self._process,
                sftp_factory=lambda chan: HoneySFTP(chan, self), allow_scp=True,
                login_timeout=30, encoding="utf-8", errors="replace", line_editor=True, line_echo=True,
                keepalive_interval=0, rekey_bytes=2 ** 30)
            self.servers.append(srv)
            log.info("ssh listening on %s:%d", self.settings.bind_host, port)

    # ------------------------------------------------ interactive / exec
    async def _process(self, process: asyncssh.SSHServerProcess) -> None:
        st = self.states.get(process.channel.get_connection())
        if st is None or not st.authed:
            process.exit(1)
            return
        st.channels += 1
        if st.channels > 4:
            process.exit(1)
            return
        sh = st.get_shell()
        try:
            async with asyncio.timeout(self.settings.max_session_seconds):
                if process.command is not None:
                    await self._exec(process, st, sh)
                else:
                    await self._interactive(process, st, sh)
        except (TimeoutError, asyncssh.Error, ConnectionError, asyncio.CancelledError):
            pass
        except Exception:  # noqa: BLE001
            log.debug("ssh process error", exc_info=True)
        finally:
            try:
                process.exit(0)
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def _out(res_output: bytes, pty: bool) -> str:
        text = res_output.decode("utf-8", "replace")
        return text.replace("\r\n", "\n").replace("\n", "\r\n") if pty else text

    async def _exec(self, process, st: ConnState, sh: ShellSession) -> None:
        cmd = process.command or ""
        st.emit("session.exec", command=sanitize_text(cmd, 4096))
        res = await sh.feed(cmd, final=True)
        process.stdout.write(self._out(res.output, False))
        process.exit(res.status)

    async def _interactive(self, process, st: ConnState, sh: ShellSession) -> None:
        pty = process.get_terminal_type() is not None
        if pty:
            motd = sh.persona.motd.replace("\n", "\r\n")
            process.stdout.write(motd + f"\r\nLast login: {time.strftime('%a %b %e %H:%M:%S %Y', time.gmtime(time.time() - 7200))} from 10.0.2.2\r\n")
        while True:
            process.stdout.write(sh.prompt if sh.buffer == "" else sh.ps2)
            try:
                line = await asyncio.wait_for(process.stdin.readline(), self.settings.max_idle_seconds)
            except asyncio.TimeoutError:
                break
            except asyncssh.TerminalSizeChanged:
                continue
            except asyncssh.BreakReceived:
                sh.reset_buffer()
                continue
            except asyncssh.SignalReceived:
                sh.reset_buffer()
                continue
            if not line:
                break
            line = line.rstrip("\r\n")
            if len(line) > 8192:
                line = line[:8192]
            res = await sh.feed(line)
            if res.output:
                process.stdout.write(self._out(res.output, pty))
            if res.exit:
                process.stdout.write("logout\r\n" if pty else "")
                break
