"""Analysis worker: watches the (read-only) quarantine and writes ``analysis/<sha256>.json``.

Runs inside the no-network analyzer container.  Each sample is analysed in a child process
with a hard timeout; a crash/timeout produces a ``status: failed`` stub so the dashboard shows
the sample honestly instead of silently hiding it.  The quarantine is only ever read.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from ..common.config import Settings, load_settings
from ..common.quarantine import is_sha256
from .engine import REPORT_VERSION
from .run_one import write_atomic

log = logging.getLogger("honeynet.analysis.worker")
_ENV_KEEP = ("PATH", "PYTHONPATH", "HOME", "LANG", "LC_ALL", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP", "VIRTUAL_ENV",
             "HONEYNET_ANALYSIS_BACKEND", "HONEYNET_ANALYSIS_COMMAND", "HONEYNET_ANALYSIS_TIMEOUT", "HONEYNET_ANALYSIS_MAX_BYTES")


def iter_samples(root: Path):
    """Read-only walk of the quarantine layout ``<aa>/<sha256>``."""
    try:
        subs = sorted(root.iterdir())
    except OSError:
        return
    for sub in subs:
        if sub.is_dir() and len(sub.name) == 2:
            try:
                for f in sorted(sub.iterdir()):
                    if is_sha256(f.name) and f.is_file():
                        yield f.name, f
            except OSError:
                continue


def report_path(analysis_dir: Path, sha: str) -> Path:
    return analysis_dir / f"{sha}.json"


def needs_analysis(analysis_dir: Path, sha: str) -> bool:
    p = report_path(analysis_dir, sha)
    try:
        return int(json.loads(p.read_text("utf-8")).get("v", 0)) < REPORT_VERSION
    except (OSError, ValueError, AttributeError):
        return True


def failure_report(sha: str, size: int, reason: str) -> dict:
    return {"v": REPORT_VERSION, "status": "failed", "sha256": sha, "size": size, "errors": [reason], "behaviors": [], "iocs": [],
            "family": {"id": "unknown", "name": "analysis failed", "kind": "unknown", "confidence": 0.0, "reasons": [reason]},
            "risk": {"score": 0, "level": "info"}, "static_only": True, "mitre": [], "snippets": {},
            "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"}


def analyze_one(sample: Path, out: Path, settings: Settings) -> bool:
    env = {k: v for k, v in os.environ.items() if k in _ENV_KEEP}
    # the child must import the same honeynet package even when it is run from a source tree
    pkg_root = str(Path(__file__).resolve().parents[2])
    env["PYTHONPATH"] = os.pathsep.join(p for p in (pkg_root, env.get("PYTHONPATH", "")) if p)
    cmd = [sys.executable, "-m", "honeynet.analysis.run_one", str(sample), str(out)]
    try:
        cp = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=settings.analysis_timeout, env=env,
                            check=False)
    except subprocess.TimeoutExpired:
        write_atomic(out, failure_report(sample.name, sample.stat().st_size, f"analysis timed out after {settings.analysis_timeout}s"))
        log.warning("timeout analysing %s", sample.name)
        return False
    if cp.returncode != 0 or not out.exists():
        tail = cp.stderr[-300:].decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
        write_atomic(out, failure_report(sample.name, sample.stat().st_size, f"analysis process exited {cp.returncode}: {tail[0][:200]}"))
        log.warning("analysis of %s failed (%s)", sample.name, cp.returncode)
        return False
    return True


class AnalysisWorker:
    def __init__(self, settings: Settings) -> None:
        self.s = settings
        self.s.analysis_dir.mkdir(parents=True, exist_ok=True)

    def run_once(self) -> int:
        done = 0
        for sha, path in iter_samples(self.s.quarantine_dir):
            if not needs_analysis(self.s.analysis_dir, sha):
                continue
            t0 = time.monotonic()
            ok = analyze_one(path, report_path(self.s.analysis_dir, sha), self.s)
            log.info("analysed %s ok=%s in %.1fs", sha[:12], ok, time.monotonic() - t0)
            done += 1
        return done

    def run_forever(self, stop: threading.Event | None = None) -> None:
        stop = stop or threading.Event()
        while not stop.is_set():
            try:
                self.run_once()
            except Exception:  # noqa: BLE001 - keep the worker alive
                log.exception("worker iteration failed")
            stop.wait(self.s.analysis_poll_seconds)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    AnalysisWorker(load_settings()).run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
