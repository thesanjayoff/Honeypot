"""Service plugin API.

Adding a new honeypot service = drop a module into ``honeynet/services`` (or into
the directory named by ``HONEYNET_PLUGIN_DIR``) containing::

    from honeynet.services.base import TCPService, Connection, register

    @register
    class FtpService(TCPService):
        name = "ftp"
        default_ports = [2121]

        async def handle(self, conn: Connection) -> None:
            conn.emit("auth.attempt", username="...", password="...", success=False)

then add a container for it in docker-compose (``command: ["ftp"]``).  The base
class gives you: connection caps, timeouts, ``conn.open/close`` events, hostile
input hardening and the event/quarantine/fetcher plumbing.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from ..common.config import Settings
from ..common.events import CONN_CLOSE, CONN_OPEN, EventWriter, new_session_id
from ..common.limits import ConnectionLimiter
from ..common.quarantine import Quarantine, QuarantineFull
from ..common.sanitize import sanitize_text
from .fetcher_client import FetcherClient

log = logging.getLogger("honeynet.service")

REGISTRY: dict[str, type["Service"]] = {}


def register(cls: type["Service"]) -> type["Service"]:
    if not cls.name:
        raise ValueError("service class needs a name")
    REGISTRY[cls.name] = cls
    return cls


@dataclass
class ServiceContext:
    settings: Settings
    events: EventWriter
    quarantine: Quarantine
    fetcher: FetcherClient | None
    limiter: ConnectionLimiter

    def capture(self, data: bytes, **source: Any):
        """Store bytes in quarantine; returns StoredFile or None (quota)."""
        try:
            return self.quarantine.store(data, source)
        except QuarantineFull:
            log.warning("quarantine full - dropping capture")
            return None
        except OSError as exc:
            log.warning("quarantine write failed: %s", exc)
            return None


class Service:
    name: ClassVar[str] = ""
    default_ports: ClassVar[list[int]] = []

    def __init__(self, ctx: ServiceContext) -> None:
        self.ctx = ctx
        self.settings = ctx.settings
        self.events = ctx.events
        self.servers: list[asyncio.AbstractServer] = []

    @property
    def ports(self) -> list[int]:
        return self.settings.service_ports(self.name) or list(self.default_ports)

    async def start(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    async def stop(self) -> None:
        for s in self.servers:
            s.close()
        for s in self.servers:
            try:
                await asyncio.wait_for(s.wait_closed(), 3)
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                pass


class Connection:
    """One accepted TCP connection with bookkeeping + event helpers."""

    def __init__(self, svc: "TCPService", reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 dst_port: int) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        ip = str(peer[0])
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        self.svc = svc
        self.reader = reader
        self.writer = writer
        self.ip = ip
        self.port = int(peer[1]) if len(peer) > 1 else 0
        self.dst_port = dst_port
        self.sid = new_session_id()
        self.opened = time.monotonic()
        self.bytes_in = 0
        self.bytes_out = 0

    def emit(self, event: str, **data: Any):
        return self.svc.events.emit(event, self.ip, src_port=self.port, dst_port=self.dst_port,
                                    session=self.sid, **data)

    async def read(self, n: int = 4096, timeout: float | None = None) -> bytes:
        t = timeout if timeout is not None else self.svc.settings.max_idle_seconds
        data = await asyncio.wait_for(self.reader.read(n), t)
        self.bytes_in += len(data)
        return data

    async def readline(self, limit: int = 4096, timeout: float | None = None) -> bytes:
        t = timeout if timeout is not None else self.svc.settings.max_idle_seconds
        try:
            data = await asyncio.wait_for(self.reader.readuntil(b"\n"), t)
        except asyncio.LimitOverrunError as exc:
            data = await self.reader.read(exc.consumed)
        except asyncio.IncompleteReadError as exc:
            data = exc.partial
        self.bytes_in += len(data)
        return data[:limit]

    async def readexactly(self, n: int, timeout: float | None = None) -> bytes:
        t = timeout if timeout is not None else self.svc.settings.max_idle_seconds
        data = await asyncio.wait_for(self.reader.readexactly(n), t)
        self.bytes_in += len(data)
        return data

    async def send(self, data: bytes) -> None:
        self.bytes_out += len(data)
        self.writer.write(data)
        await asyncio.wait_for(self.writer.drain(), 10)

    def close(self) -> None:
        try:
            self.writer.close()
        except Exception:  # noqa: BLE001
            pass

    @property
    def duration(self) -> float:
        return time.monotonic() - self.opened


class TCPService(Service):
    """Base for asyncio stream services. Subclasses implement ``handle``."""

    read_limit = 64 * 1024

    async def handle(self, conn: Connection) -> None:  # pragma: no cover
        raise NotImplementedError

    async def start(self) -> None:
        for port in self.ports:
            srv = await asyncio.start_server(self._accept_factory(port), self.settings.bind_host, port,
                                             limit=self.read_limit, backlog=128)
            self.servers.append(srv)
            log.info("%s listening on %s:%d", self.name, self.settings.bind_host, port)

    def _accept_factory(self, port: int):
        async def _cb(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await self._serve(reader, writer, port)
        return _cb

    async def _serve(self, reader, writer, port: int) -> None:
        conn = Connection(self, reader, writer, port)
        limiter = self.ctx.limiter
        if not limiter.acquire(conn.ip):
            conn.close()
            return
        conn.emit(CONN_OPEN)
        reason = "closed"
        try:
            async with asyncio.timeout(self.settings.max_session_seconds):
                await self.handle(conn)
        except TimeoutError:
            reason = "max-session-time"
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.CancelledError):
            reason = "reset"
        except Exception as exc:  # noqa: BLE001 - hostile peers must not crash the service
            reason = f"error:{type(exc).__name__}"
            log.debug("handler error %s", sanitize_text(exc), exc_info=True)
        finally:
            limiter.release(conn.ip)
            conn.emit(CONN_CLOSE, duration=round(conn.duration, 2), bytes_in=conn.bytes_in,
                      bytes_out=conn.bytes_out, reason=reason)
            conn.close()


# ---------------------------------------------------------------------- discovery


def load_builtin() -> None:
    for mod in ("ssh", "telnet", "http", "mysql", "redis"):
        try:
            importlib.import_module(f"honeynet.services.{mod}")
        except ModuleNotFoundError as exc:  # optional deps missing in this image
            log.debug("service module %s unavailable: %s", mod, exc)


def load_plugins(plugin_dir: str | None = None) -> None:
    plugin_dir = plugin_dir or os.environ.get("HONEYNET_PLUGIN_DIR")
    if not plugin_dir:
        return
    for f in sorted(Path(plugin_dir).glob("*.py")):
        spec = importlib.util.spec_from_file_location(f"honeynet_plugin_{f.stem}", f)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            log.info("loaded plugin %s", f.name)


def get_service_class(name: str) -> type[Service]:
    load_builtin()
    load_plugins()
    try:
        return REGISTRY[name]
    except KeyError:
        raise SystemExit(f"unknown service {name!r}; available: {', '.join(sorted(REGISTRY))}") from None
