"""Quarantine store for captured files.

* Files are named by their SHA-256 (no extension, no attacker-chosen name), stored
  mode 0440 under a two-level fan-out directory.
* Content is *never* executed, imported or otherwise interpreted by this package.
  (In production the volume is additionally mounted ``noexec,nosuid,nodev``.)
* A ``<sha256>.json`` sidecar records provenance; the file bytes are immutable.
* Size is capped per file and for the whole store.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .sanitize import sanitize_obj

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class QuarantineFull(Exception):
    pass


@dataclass
class StoredFile:
    sha256: str
    md5: str
    size: int
    path: Path
    is_new: bool
    truncated: bool


def is_sha256(s: str) -> bool:
    return bool(_SHA_RE.match(s or ""))


class Quarantine:
    def __init__(self, root: Path, max_file_bytes: int = 10 * 1024 * 1024,
                 max_total_bytes: int = 2 * 1024 * 1024 * 1024) -> None:
        self.root = Path(root)
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / ".tmp").mkdir(exist_ok=True)
        self._usage_cache = (0.0, 0)

    # -- paths -------------------------------------------------------------
    def path_for(self, sha256: str) -> Path:
        if not is_sha256(sha256):
            raise ValueError("invalid sha256")
        return self.root / sha256[:2] / sha256

    def exists(self, sha256: str) -> bool:
        return is_sha256(sha256) and self.path_for(sha256).is_file()

    def iter_hashes(self):
        for sub in sorted(self.root.iterdir()):
            if sub.is_dir() and len(sub.name) == 2:
                for f in sorted(sub.iterdir()):
                    if is_sha256(f.name):
                        yield f.name

    def usage(self) -> int:
        ts, val = self._usage_cache
        if time.time() - ts < 30:
            return val
        total = 0
        for sub in self.root.iterdir():
            if sub.is_dir() and sub.name != ".tmp":
                for f in sub.iterdir():
                    try:
                        total += f.stat().st_size
                    except OSError:
                        pass
        self._usage_cache = (time.time(), total)
        return total

    # -- writing -----------------------------------------------------------
    def store(self, data: bytes, source: dict[str, Any] | None = None) -> StoredFile:
        truncated = len(data) > self.max_file_bytes
        if truncated:
            data = data[: self.max_file_bytes]
        w = self.writer(source)
        w.write(data)
        res = w.finish()
        res.truncated = res.truncated or truncated
        return res

    def writer(self, source: dict[str, Any] | None = None) -> "QuarantineWriter":
        return QuarantineWriter(self, source or {})

    def _record(self, sha256: str, md5: str, size: int, source: dict[str, Any], truncated: bool) -> None:
        meta_path = self.path_for(sha256).with_suffix(".json")
        now = time.time()
        meta: dict[str, Any] = {"sha256": sha256, "md5": md5, "size": size, "first_seen": now,
                                "last_seen": now, "count": 0, "sources": [], "truncated": truncated}
        if meta_path.exists():
            try:
                meta.update(json.loads(meta_path.read_text("utf-8")))
            except (OSError, ValueError):
                pass
        meta["last_seen"] = now
        meta["count"] = int(meta.get("count", 0)) + 1
        srcs = meta.get("sources", [])
        if len(srcs) < 50:
            srcs.append(sanitize_obj({**source, "ts": now}))
        meta["sources"] = srcs
        tmp = meta_path.with_name(meta_path.name + ".tmp")
        try:
            tmp.write_text(json.dumps(meta, separators=(",", ":")), encoding="utf-8")
            os.replace(tmp, meta_path)
        except OSError:
            pass

    def meta(self, sha256: str) -> dict[str, Any]:
        try:
            return json.loads(self.path_for(sha256).with_suffix(".json").read_text("utf-8"))
        except (OSError, ValueError):
            return {}

    def read(self, sha256: str, limit: int | None = None) -> bytes:
        with open(self.path_for(sha256), "rb") as fh:
            return fh.read(limit if limit is not None else self.max_file_bytes)


class QuarantineWriter:
    """Streaming writer with a hard size cap. Use ``write`` then ``finish``/``abort``."""

    def __init__(self, q: Quarantine, source: dict[str, Any]) -> None:
        self.q = q
        self.source = source
        self.size = 0
        self.truncated = False
        self._sha = hashlib.sha256()
        self._md5 = hashlib.md5(usedforsecurity=False)
        fd, name = tempfile.mkstemp(dir=q.root / ".tmp", prefix="q")
        self._fd = fd
        self._tmp = Path(name)
        self._done = False

    def write(self, chunk: bytes) -> bool:
        """Returns False once the cap is reached (chunk partially/fully dropped)."""
        if self.truncated:
            return False
        room = self.q.max_file_bytes - self.size
        if len(chunk) > room:
            chunk = chunk[:room]
            self.truncated = True
        if chunk:
            os.write(self._fd, chunk)
            self._sha.update(chunk)
            self._md5.update(chunk)
            self.size += len(chunk)
        return not self.truncated

    def abort(self) -> None:
        if not self._done:
            self._done = True
            try:
                os.close(self._fd)
            finally:
                self._tmp.unlink(missing_ok=True)

    def finish(self) -> StoredFile:
        if self._done:
            raise RuntimeError("writer already finished")
        self._done = True
        os.close(self._fd)
        sha, md5 = self._sha.hexdigest(), self._md5.hexdigest()
        dest = self.q.path_for(sha)
        is_new = not dest.exists()
        if is_new:
            if self.q.usage() + self.size > self.q.max_total_bytes:
                self._tmp.unlink(missing_ok=True)
                raise QuarantineFull("quarantine quota reached")
            dest.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(self._tmp, 0o440)
            os.replace(self._tmp, dest)
            self.q._usage_cache = (0.0, 0)
        else:
            self._tmp.unlink(missing_ok=True)
        self.q._record(sha, md5, self.size, self.source, self.truncated)
        return StoredFile(sha, md5, self.size, dest, is_new, self.truncated)
