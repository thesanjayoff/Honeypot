"""Telnet honeypot: IoT-style login prompt -> BusyBox-like fake shell (Mirai-era behaviour)."""

from __future__ import annotations

import asyncio
import hashlib

from ..common.events import AUTH_ATTEMPT, SESSION_CLOSE, SESSION_OPEN
from ..common.sanitize import sanitize_text
from ..shell.session import ShellSession
from .auth_policy import decide
from .base import Connection, TCPService, register

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
OPT_ECHO, OPT_SGA, OPT_NAWS = 1, 3, 31
MAX_LINE = 1024
MAX_TRIES = 4


class _Reader:
    """Telnet byte-stream decoder: strips IAC sequences, collects option negotiation."""

    def __init__(self, conn: Connection) -> None:
        self.conn = conn
        self.buf = bytearray()
        self.opts: list[str] = []
        self._pending_cr = False

    async def _fill(self, timeout: float | None = None) -> bool:
        data = await self.conn.read(4096, timeout)
        if not data:
            return False
        self.buf.extend(data)
        return True

    async def read_line(self, echo: bool, timeout: float | None = None) -> str | None:
        """Returns the line, or None on EOF/Ctrl-D/Ctrl-C-abort ('\\x03' returns '')."""
        line = bytearray()
        while True:
            while not self.buf:
                if not await self._fill(timeout):
                    return None
            b = self.buf.pop(0)
            if b == IAC:
                if not await self._iac():
                    return None
                continue
            if b in (10, 13):
                if b == 13:
                    # swallow the following \n or \0 if it is already buffered
                    if self.buf[:1] in (b"\n", b"\x00"):
                        self.buf.pop(0)
                    else:
                        self._pending_cr = True
                elif self._pending_cr:
                    self._pending_cr = False
                    continue
                if echo:
                    await self.conn.send(b"\r\n")
                return line.decode("utf-8", "replace")
            self._pending_cr = False
            if b == 0:
                continue
            if b == 3:
                if echo:
                    await self.conn.send(b"^C\r\n")
                return ""
            if b == 4:
                return None if not line else line.decode("utf-8", "replace")
            if b in (8, 127):
                if line:
                    line.pop()
                    if echo:
                        await self.conn.send(b"\b \b")
                continue
            if b == 27:         # swallow ANSI escape (arrow keys etc.)
                for _ in range(2):
                    if not self.buf:
                        await self._fill(2)
                    if self.buf:
                        self.buf.pop(0)
                continue
            if len(line) < MAX_LINE:
                line.append(b)
                if echo:
                    await self.conn.send(bytes([b]))

    async def _need(self, n: int) -> bool:
        while len(self.buf) < n:
            if not await self._fill(5):
                return False
        return True

    async def _iac(self) -> bool:
        if not await self._need(1):
            return False
        cmd = self.buf.pop(0)
        if cmd in (DO, DONT, WILL, WONT):
            if not await self._need(1):
                return False
            opt = self.buf.pop(0)
            self.opts.append(f"{cmd}.{opt}")
            if cmd == DO and opt not in (OPT_ECHO, OPT_SGA):
                await self.conn.send(bytes([IAC, WONT, opt]))
        elif cmd == SB:
            # subnegotiation until IAC SE (bounded)
            for _ in range(256):
                if not await self._need(2):
                    return False
                if self.buf[0] == IAC and self.buf[1] == SE:
                    del self.buf[:2]
                    break
                self.buf.pop(0)
        return True


@register
class TelnetService(TCPService):
    name = "telnet"
    default_ports = [2323]

    async def handle(self, conn: Connection) -> None:
        st = self.settings
        await conn.send(bytes([IAC, DO, OPT_ECHO, IAC, DO, OPT_NAWS, IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA]))
        from ..shell.persona import get_persona
        persona = get_persona("iot")
        if persona.login_banner:
            await conn.send(persona.login_banner.encode())
        rd = _Reader(conn)
        tries = 0
        user = password = ""
        authed = False
        fp_sent = False
        while tries < MAX_TRIES and not authed:
            await conn.send(f"{persona.hostname} login: ".encode())
            u = await rd.read_line(echo=True, timeout=30)
            if u is None:
                return
            if not fp_sent:
                fp_sent = True
                sig = hashlib.md5(",".join(rd.opts).encode()).hexdigest() if rd.opts else ""
                conn.emit("client.fingerprint", telnet_opts=",".join(rd.opts[:20]), opts_hash=sig)
            await conn.send(b"Password: ")
            pw = await rd.read_line(echo=False, timeout=30)
            if pw is None:
                return
            await conn.send(b"\r\n")
            tries += 1
            ok = decide(conn.ip, u.strip(), pw, st.ssh_accept_pct, iot=True)
            conn.emit(AUTH_ATTEMPT, username=u.strip(), password=pw, method="password", success=ok, attempt=tries)
            if ok:
                authed, user, password = True, u.strip(), pw
            else:
                await asyncio.sleep(0.4)
                await conn.send(b"Login incorrect\r\n")
        if not authed:
            return

        sh = ShellSession(persona_name="iot", user=user if user in ("root",) else "root", emit=conn.emit,
                          ctx=self.ctx, src_ip=conn.ip, session_id=conn.sid, service="telnet")
        conn.emit(SESSION_OPEN, username=user, password=password, method="password",
                  client_version=f"telnet:{len(rd.opts)}opts")
        reason = "closed"
        try:
            await conn.send(b"\r\n\r\nBusyBox v1.22.1 built-in shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n\r\n")
            while True:
                await conn.send((sh.prompt if sh.buffer == "" else sh.ps2).encode())
                line = await rd.read_line(echo=True, timeout=st.max_idle_seconds)
                if line is None:
                    reason = "eof"
                    break
                if line == "" and sh.buffer:
                    sh.reset_buffer()
                    continue
                res = await sh.feed(line)
                if res.output:
                    await conn.send(res.output.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
                if res.exit:
                    reason = "exit"
                    break
        except (asyncio.TimeoutError, TimeoutError):
            reason = "idle"
            raise
        finally:
            sh.capture_all()
            conn.emit(SESSION_CLOSE, duration=round(conn.duration, 2), commands=sh.cmd_count,
                      username=sanitize_text(user, 64), downloads=len(sh.downloads), reason=reason)
