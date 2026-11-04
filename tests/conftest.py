from __future__ import annotations

import asyncio
import json
import socket
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from honeynet.common.config import Settings  # noqa: E402
from honeynet.runner import build_context  # noqa: E402
from honeynet.services.base import get_service_class  # noqa: E402


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def settings(tmp_path) -> Settings:
    s = Settings()
    s.data_dir = tmp_path / "data"
    s.bind_host = "127.0.0.1"
    s.test_mode = True
    s.max_session_seconds = 20
    s.max_idle_seconds = 10
    s.max_conns_per_ip = 50
    return s


def read_events(settings: Settings, service: str) -> list[dict]:
    p = settings.events_dir / service / "events.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text("utf-8").splitlines() if line.strip()]


@asynccontextmanager
async def running(settings: Settings, name: str, port: int | None = None):
    """Start a honeypot service on a free loopback port; yields (service, port)."""
    port = port or free_port()
    settings.ports[name] = [port]
    cls = get_service_class(name)
    svc = cls(build_context(name, settings))
    await svc.start()
    try:
        yield svc, port
    finally:
        await svc.stop()
        await asyncio.sleep(0.05)


class FakeCtx:
    """Minimal ServiceContext stand-in for shell unit tests (captures to a list)."""

    def __init__(self):
        import types
        self.captures: list[tuple[bytes, dict]] = []
        self.fetcher = None
        self.settings = types.SimpleNamespace(fetcher_max_per_session=4)

    def capture(self, data: bytes, **src):
        import hashlib
        import types
        self.captures.append((data, src))
        return types.SimpleNamespace(sha256=hashlib.sha256(data).hexdigest(), md5=hashlib.md5(data).hexdigest(),
                                     size=len(data), is_new=True, truncated=False)
