"""Analyse ONE sample in a fresh, resource-limited process:  python -m honeynet.analysis.run_one SAMPLE OUT.json

Hostile files can make parsers loop or balloon, so the worker never analyses in-process.  This
entry point (a) caps CPU time / memory / output size where the OS allows, (b) disables socket
use as defence in depth (the container also has no network at all), and (c) writes the report
atomically.  The sample is only ever *read*.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import traceback
from pathlib import Path


def _deny(*_a, **_k):
    raise OSError("network access is disabled in the analysis process")


def disable_network() -> None:
    for name in ("connect", "connect_ex", "bind", "listen", "sendto"):
        setattr(socket.socket, name, _deny)
    socket.create_connection = _deny          # type: ignore[assignment]
    socket.getaddrinfo = _deny                # type: ignore[assignment]


def apply_limits(cpu_seconds: int, mem_bytes: int = 2 * 1024**3) -> None:
    try:
        import resource
    except ImportError:                       # Windows dev box: the container applies the real limits
        return
    for res, val in ((resource.RLIMIT_CPU, cpu_seconds), (resource.RLIMIT_AS, mem_bytes),
                     (resource.RLIMIT_FSIZE, 256 * 1024 * 1024), (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_CORE, 0)):
        try:
            resource.setrlimit(res, (val, val))
        except (ValueError, OSError):
            pass


def write_atomic(out: Path, report: dict) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(report, separators=(",", ":"), ensure_ascii=True), encoding="utf-8")
    os.replace(tmp, out)


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 2:
        print("usage: python -m honeynet.analysis.run_one SAMPLE OUT.json", file=sys.stderr)
        return 2
    sample, out = Path(argv[0]), Path(argv[1])
    from ..common.config import load_settings
    from . import get_backend
    from .engine import EngineConfig, analyze_file

    settings = load_settings()
    apply_limits(max(5, settings.analysis_timeout))
    disable_network()
    try:
        backend = get_backend(settings.analysis_backend, settings.analysis_command, settings.analysis_timeout)
    except Exception as exc:  # noqa: BLE001 - e.g. capstone missing: still hash/strings/IOC the file
        backend = None
        note = f"backend unavailable: {exc}"
    else:
        note = ""
    try:
        report = analyze_file(sample, backend, EngineConfig(max_size=settings.analysis_max_bytes))
        if note:
            report["errors"].append(note)
    except MemoryError:
        print("out of memory", file=sys.stderr)
        return 3
    except Exception as exc:  # noqa: BLE001
        traceback.print_exc(file=sys.stderr)
        print(f"analysis crashed: {type(exc).__name__}", file=sys.stderr)
        return 1
    write_atomic(out, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
