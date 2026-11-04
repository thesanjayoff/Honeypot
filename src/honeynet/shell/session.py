"""ShellSession: one attacker's fake shell (state + capture + event glue)."""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
import zlib
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

from ..common.events import DOWNLOAD_ATTEMPT, FILE_CAPTURED, FILE_EXEC, CMD_INPUT
from ..common.sanitize import sanitize_text
from .fakefs import FakeFS, FSError, Node
from .interp import (BudgetExceeded, Incomplete, Interpreter, Proc, ShellExit, ShellSyntaxError, parse)
from .persona import Persona, build_base, get_persona

MIN_CAPTURE_BYTES = 12
_BASE_CACHE: dict[str, Any] = {}
URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{1,10}://[^\s'\"<>|;&)(\\]{3,2000}")


@dataclass
class FeedResult:
    output: bytes
    prompt_kind: str            # "ps1" | "ps2"
    exit: bool = False
    status: int = 0


class ShellSession:
    LINE_BUDGET = 400
    SESSION_BUDGET = 20000

    def __init__(self, *, persona_name: str, user: str, emit: Callable[..., Any], ctx, src_ip: str,
                 session_id: str, service: str, client_info: dict | None = None) -> None:
        self.persona: Persona = get_persona(persona_name)
        if persona_name not in _BASE_CACHE:
            _BASE_CACHE[persona_name] = build_base(self.persona)
        self.fs = FakeFS(_BASE_CACHE[persona_name])
        self.emit = emit
        self.ctx = ctx
        self.src_ip = src_ip
        self.session_id = session_id
        self.service = service
        self.user = user
        self.home = "/root" if user == "root" else f"/home/{user}"
        if not self.fs.isdir(self.home):
            try:
                self.fs.mkdir(self.home, True)
            except FSError:
                pass
        self.cwd = self.home
        self.vars: dict[str, str] = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": self.home,
            "USER": user, "LOGNAME": user, "SHELL": "/bin/sh" if self.persona.busybox else "/bin/bash",
            "PWD": self.cwd, "TERM": "xterm", "HOSTNAME": self.persona.hostname, "LANG": "C",
        }
        self.positional: list[str] = []
        self.arg0 = "sh"
        self.status = 0
        self.functions: dict = {}
        self.executed: list[str] = []
        self.terminal = bytearray()
        self.history: list[str] = []
        self.buffer = ""
        self.budget = self.SESSION_BUDGET
        self.line_budget = self.LINE_BUDGET
        self.interp = Interpreter(self)
        self.started = time.time()
        self.fetches = 0
        self.cmd_count = 0
        self.downloads: list[str] = []
        self.captured: set[str] = set()
        self.exit_requested = False
        self.client_info = client_info or {}
        self.start_mono = time.monotonic()
        self.crontab = ""

    # --------------------------------------------------------------- helpers
    @property
    def prompt(self) -> str:
        cwd = self.cwd
        if self.user != "root" and cwd == self.home:
            cwd = "~"
        elif cwd == self.home and self.user == "root":
            cwd = "~"
        tmpl = self.persona.prompt_root if self.user == "root" else self.persona.prompt_user
        return tmpl.format(cwd=cwd, user=self.user)

    @property
    def ps2(self) -> str:
        return "> "

    def tick(self) -> None:
        self.budget -= 1
        self.line_budget -= 1
        if self.budget < 0 or self.line_budget < 0:
            raise BudgetExceeded()

    def abspath(self, path: str) -> str:
        return self.fs.normpath(path, self.cwd, self.home)

    # ------------------------------------------------------------ feeding
    def reset_buffer(self) -> None:
        self.buffer = ""

    async def feed(self, line: str, final: bool = False) -> FeedResult:
        """Process one input line (without newline). Handles multi-line constructs.

        ``final=True`` (exec mode / piped scripts) turns "needs more input" into a syntax error.
        """
        self.buffer = f"{self.buffer}\n{line}" if self.buffer else line
        if not self.buffer.strip() and not self.buffer.endswith("\n"):
            self.buffer = ""
            return FeedResult(b"", "ps1")
        text = self.buffer
        try:
            tree = parse(text)
        except Incomplete:
            if final or len(text) > 64 * 1024:
                self.buffer = ""
                self.history.append(text)
                msg = b"sh: syntax error: unexpected end of file\n"
                self._log_line(text, msg, 2)
                return FeedResult(msg, "ps1", status=2)
            return FeedResult(b"", "ps2")
        except ShellSyntaxError as exc:
            self.buffer = ""
            self.history.append(text)
            msg = f"sh: {exc}\n".encode()
            self._log_line(text, msg, 2)
            return FeedResult(msg, "ps1", status=2)
        self.buffer = ""
        self.history.append(text)
        del self.history[:-200]
        return await self._execute(text, tree)

    async def _execute(self, text: str, tree) -> FeedResult:
        self.executed = []
        self.terminal = bytearray()
        self.line_budget = self.LINE_BUDGET
        proc = Proc()
        status = 0
        exit_now = False
        try:
            status = await asyncio.wait_for(self.interp.run_seq(tree, proc), 20)
        except ShellExit as e:
            status, exit_now = e.status, True
        except BudgetExceeded:
            proc.error("sh: resource temporarily unavailable\n")
            status = 1
        except asyncio.TimeoutError:
            proc.error("sh: timed out\n")
            status = 124
        except RecursionError:
            status = 1
        self.status = status
        out = bytes(self.terminal) + bytes(proc.out) + bytes(proc.err)
        if len(out) > 64 * 1024:
            out = out[: 64 * 1024]
        self._log_line(text, out, status)
        self.cmd_count += 1
        self.vars["PWD"] = self.cwd
        return FeedResult(out, "ps1", exit_now or self.exit_requested, status)

    def _log_line(self, text: str, out: bytes, status: int, nested: bool = False) -> None:
        self.emit(CMD_INPUT, input=sanitize_text(text, 4096), status=status,
                  output=sanitize_text(out.decode("utf-8", "replace"), 1500), cwd=self.cwd,
                  cmds=sorted(set(self.executed))[:20], user=self.user, **({"nested": True} if nested else {}))

    async def run_script(self, text: str, proc: Proc, args: list[str] | None = None, arg0: str = "sh") -> int:
        """Run a script/-c string in a nested interpreter frame (shared fs/vars)."""
        if self.interp.depth >= Interpreter.MAX_DEPTH:
            return 1
        try:
            tree = parse(text)
        except (Incomplete, ShellSyntaxError) as exc:
            proc.error(f"sh: {exc or 'syntax error: unexpected end of file'}\n")
            return 2
        saved = (self.positional, self.arg0)
        self.positional, self.arg0 = list(args or []), arg0
        self.interp.depth += 1
        try:
            return await self.interp.run_seq(tree, proc)
        finally:
            self.interp.depth -= 1
            self.positional, self.arg0 = saved

    # ------------------------------------------------------------ commands
    async def run_command(self, argv: list[str], proc: Proc) -> int:
        from . import commands as C

        name = argv[0]
        if "/" in name:
            path = self.abspath(name)
            base = path.rsplit("/", 1)[-1]
            node = self.fs.lookup(path)
            if node is None:
                proc.error(f"sh: {name}: {'No such file or directory' if self.persona.busybox else 'No such file or directory'}\n")
                return 127
            if node.kind == "d":
                proc.error(f"sh: {name}: Is a directory\n")
                return 126
            if node.origin == "base" and base in C.COMMANDS:
                return await C.COMMANDS[base](self, [base, *argv[1:]], proc)
            return await self.exec_file(path, node, argv, proc)
        fn = C.BUILTINS.get(name) or (C.COMMANDS.get(name) if self._command_available(name) else None)
        if fn is not None:
            try:
                return await fn(self, argv, proc)
            except FSError as e:
                proc.error(f"{name}: {e}\n")
                return 1
        # a file in cwd/PATH created by the attacker (bare name only runs if on PATH, i.e. not cwd)
        for d in self.vars.get("PATH", "").split(":"):
            node = self.fs.lookup(self.fs.normpath(f"{d}/{name}"))
            if node is not None and node.kind == "f" and node.origin != "base":
                return await self.exec_file(f"{d}/{name}", node, argv, proc)
        if self.persona.busybox:
            proc.error(f"sh: {name}: not found\n")
        else:
            proc.error(f"bash: {name}: command not found\n")
        return 127

    def _command_available(self, name: str) -> bool:
        from . import commands as C
        return name in self.persona.commands or name in C.ALWAYS

    # ------------------------------------------------------------ execution
    async def exec_file(self, path: str, node: Node, argv: list[str], proc: Proc, via_interp: bool = False) -> int:
        sha = self.capture_file(path, node, "exec")
        self.emit(FILE_EXEC, path=path, sha256=sha or "", size=len(node.content), args=[sanitize_text(a, 200) for a in argv[1:8]])
        if not via_interp and not (node.mode & 0o111):
            proc.error(f"sh: {argv[0]}: Permission denied\n")
            return 126
        data = node.content
        if data.startswith(b"#!") or (data and self._looks_like_text(data) and not data.startswith(b"\x7fELF")):
            text = data.decode("utf-8", "replace")
            return await self.run_script(text, proc, argv[1:], argv[0])
        return 0   # ELF/unknown: never executed, silently "runs"

    @staticmethod
    def _looks_like_text(data: bytes) -> bool:
        head = data[:2048]
        if not head:
            return False
        printable = sum(1 for b in head if b in (9, 10, 13) or 32 <= b < 127)
        return printable / len(head) > 0.97

    # -------------------------------------------------------------- capture
    def note_write(self, path: str) -> None:
        pass

    def capture_file(self, path: str, node: Node | None, reason: str, origin: str | None = None) -> str | None:
        if node is None or node.kind != "f" or node.origin == "base":
            return None
        data = node.content
        if len(data) < MIN_CAPTURE_BYTES:
            return None
        sha = hashlib.sha256(data).hexdigest()
        if node.captured_sha == sha:
            return sha
        stored = self.ctx.capture(data, origin=origin or node.origin, path=path, src_ip=self.src_ip,
                                  session=self.session_id, service=self.service, via=reason)
        node.captured_sha = sha
        if stored is None:
            return sha
        self.captured.add(sha)
        self.emit(FILE_CAPTURED, sha256=stored.sha256, md5=stored.md5, size=stored.size, path=path,
                  origin=origin or node.origin, new=stored.is_new, truncated=stored.truncated, via=reason,
                  url=node.meta.get("url", ""))
        return sha

    def capture_all(self) -> int:
        """Called at session end: store every file the attacker created."""
        n = 0
        for path, node in self.fs.session_files():
            if self.capture_file(path, node, "session-end"):
                n += 1
        return n

    # ------------------------------------------------------------- downloads
    async def download(self, url: str, via: str, dest: str | None, proc: Proc) -> tuple[bool, bytes, str]:
        """Handle wget/curl/tftp. Returns (ok, content, saved_path)."""
        url = url.strip()[:2048]
        if "://" not in url:
            url = "http://" + url
        parts = urlsplit(url)
        host = parts.hostname or ""
        name = (parts.path.rsplit("/", 1)[-1] or "index.html")[:128]
        self.downloads.append(url)
        fetched = False
        result = None
        fetcher = self.ctx.fetcher
        if (fetcher is not None and parts.scheme in ("http", "https", "tftp")
                and self.fetches < self.ctx.settings.fetcher_max_per_session):
            self.fetches += 1
            result = await fetcher.fetch(url, src_ip=self.src_ip, session=self.session_id,
                                         service=self.service, via=via)
            fetched = bool(result and result.ok)
        self.emit(DOWNLOAD_ATTEMPT, url=sanitize_text(url, 2048), via=via, host=sanitize_text(host, 253),
                  scheme=parts.scheme, fetched=fetched, error=(result.error if result and not result.ok else ""),
                  sha256=(result.sha256 if fetched and result else ""), dest=dest or "")
        if fetched and result:
            content = result.body
        else:
            content = b""
        saved = ""
        if dest and dest not in ("-", "/dev/stdout"):
            try:
                node = self.fs.write(dest, content, origin="download", mode=0o644)
                node.meta["url"] = url
                node.meta["fetched"] = fetched
                if fetched and result:
                    node.captured_sha = result.sha256     # already in quarantine via fetcher
                    node.meta["size"] = result.size
                saved = dest
            except FSError as e:
                proc.error(f"{via}: can't open '{dest}': {e}\n")
                return False, b"", ""
        return True, content, saved

    def fake_download_size(self, url: str) -> int:
        return 4096 + (zlib.crc32(url.encode()) % 700000)

    def fake_ip_for(self, host: str) -> str:
        h = zlib.crc32(host.encode())
        return f"198.{18 + (h >> 24) % 2}.{(h >> 16) & 255}.{(h >> 8) & 255 or 1}"

    def uptime_seconds(self) -> int:
        return 3201433 + int(time.monotonic() - self.start_mono)
