"""Entry point used by every honeypot container:  ``python -m honeynet.runner ssh [http ...]``

One container normally runs exactly one service; dev mode runs several in one
process.  Each service gets its *own* EventWriter (own directory), so a container
only ever needs write access to its own log directory + the quarantine volume.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
import time
from pathlib import Path

from .common.config import load_settings
from .common.events import EventWriter
from .common.limits import ConnectionLimiter
from .common.quarantine import Quarantine
from .services.base import ServiceContext, get_service_class
from .services.fetcher_client import FetcherClient


def build_context(name: str, settings=None) -> ServiceContext:
    s = settings or load_settings()
    events = EventWriter(name, s.events_dir, redactor=s.redactor(),
                         max_per_ip_minute=s.max_events_per_ip_minute, max_dir_bytes=s.max_events_dir_bytes,
                         alias_loopback=s.test_mode)
    q = Quarantine(s.quarantine_dir, s.max_file_bytes, s.max_quarantine_bytes)
    fetcher = FetcherClient(s.fetcher_url, s.fetcher_token) if s.fetcher_url else None
    return ServiceContext(s, events, q, fetcher, ConnectionLimiter(s.max_conns_total, s.max_conns_per_ip))


async def run_services(names: list[str], settings=None, stop: asyncio.Event | None = None) -> None:
    stop = stop or asyncio.Event()
    services = []
    for n in names:
        cls = get_service_class(n)
        svc = cls(build_context(n, settings))
        await svc.start()
        services.append(svc)

    async def heartbeat() -> None:
        hb_dir = Path(os.environ.get("HONEYNET_HEARTBEAT_DIR", "/tmp"))
        while True:
            for n in names:
                try:
                    (hb_dir / f"hb-{n}").write_text(str(time.time()))
                except OSError:
                    pass
            await asyncio.sleep(10)

    hb = asyncio.create_task(heartbeat())
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # Windows
            signal.signal(sig, lambda *_: loop.call_soon_threadsafe(stop.set))
    await stop.wait()
    hb.cancel()
    for svc in services:
        await svc.stop()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="run honeypot service(s)")
    ap.add_argument("services", nargs="+")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    asyncio.run(run_services(args.services))


if __name__ == "__main__":
    main()
