"""In-memory copy-on-write filesystem for the fake shell."""

from __future__ import annotations

import fnmatch
import posixpath
import time
from dataclasses import dataclass, field

MAX_PATH = 1024
MAX_FILE = 2 * 1024 * 1024        # per file inside the fake fs
MAX_OVERLAY = 8 * 1024 * 1024     # per session


class FSError(Exception):
    """Message mirrors coreutils wording, e.g. 'No such file or directory'."""


@dataclass
class Node:
    kind: str                       # 'd' dir, 'f' file, 'l' symlink, 'c' char device
    mode: int = 0o644
    uid: int = 0
    gid: int = 0
    mtime: float = 0.0
    content: bytes = b""
    target: str = ""
    origin: str = "base"            # base | session | download | upload
    captured_sha: str = ""
    meta: dict = field(default_factory=dict)

    @property
    def size(self) -> int:
        return 4096 if self.kind == "d" else len(self.content) if self.kind == "f" else len(self.target)


def split_path(path: str) -> tuple[str, str]:
    parent, name = posixpath.split(path)
    return parent or "/", name


class BaseTree:
    """Immutable template shared by all sessions of a persona."""

    def __init__(self, nodes: dict[str, Node]) -> None:
        self.nodes = nodes
        self.children: dict[str, set[str]] = {}
        for p in nodes:
            if p != "/":
                parent, name = split_path(p)
                self.children.setdefault(parent, set()).add(name)


class FakeFS:
    def __init__(self, base: BaseTree, *, clock=time.time, max_overlay: int = MAX_OVERLAY) -> None:
        self.base = base
        self.overlay: dict[str, Node | None] = {}
        self.added: dict[str, set[str]] = {}
        self.clock = clock
        self.max_overlay = max_overlay
        self.overlay_bytes = 0

    # ------------------------------------------------------------- path logic
    @staticmethod
    def normpath(path: str, cwd: str = "/", home: str = "/root") -> str:
        if len(path) > MAX_PATH:
            raise FSError("File name too long")
        if path.startswith("~"):
            path = home + path[1:]
        if not path.startswith("/"):
            path = posixpath.join(cwd, path)
        out = posixpath.normpath(path)
        return "/" + out.lstrip("/")

    def _raw(self, path: str) -> Node | None:
        if path in self.overlay:
            return self.overlay[path]
        return self.base.nodes.get(path)

    def lookup(self, path: str, follow: bool = True) -> Node | None:
        for _ in range(8):
            n = self._raw(path)
            if n is None:
                return None
            if n.kind == "l" and follow:
                path = self.normpath(n.target, split_path(path)[0])
                continue
            return n
        raise FSError("Too many levels of symbolic links")

    def exists(self, path: str) -> bool:
        return self.lookup(path) is not None

    def isdir(self, path: str) -> bool:
        n = self.lookup(path)
        return bool(n and n.kind == "d")

    def isfile(self, path: str) -> bool:
        n = self.lookup(path)
        return bool(n and n.kind in ("f", "c"))

    def listdir(self, path: str) -> list[str]:
        n = self.lookup(path)
        if n is None:
            raise FSError("No such file or directory")
        if n.kind != "d":
            raise FSError("Not a directory")
        names = set(self.base.children.get(path, ())) | set(self.added.get(path, ()))
        return sorted(nm for nm in names if self._raw(posixpath.join(path, nm)) is not None)

    def glob(self, pattern: str, cwd: str = "/") -> list[str]:
        """Shell-style glob; returns matching paths in the same form as the pattern."""
        absolute = pattern.startswith("/")
        parts = [p for p in pattern.split("/") if p != ""]
        cands = [("/" if absolute else "", "/" if absolute else cwd)]
        for i, part in enumerate(parts):
            nxt = []
            for shown, real in cands:
                if any(c in part for c in "*?["):
                    try:
                        names = self.listdir(real)
                    except FSError:
                        continue
                    for nm in names:
                        if nm.startswith(".") and not part.startswith("."):
                            continue
                        if fnmatch.fnmatchcase(nm, part):
                            nxt.append((posixpath.join(shown, nm) if shown else nm,
                                        posixpath.join(real, nm)))
                else:
                    cand_real = posixpath.join(real, part)
                    if self._raw(cand_real) is not None:
                        nxt.append((posixpath.join(shown, part) if shown else part, cand_real))
            cands = nxt
        return sorted(s for s, _ in cands)

    # ----------------------------------------------------------- mutations
    def _check_writable(self, path: str) -> None:
        if path.startswith(("/proc", "/sys")):
            raise FSError("Permission denied")

    def _set(self, path: str, node: Node | None) -> None:
        old = self.overlay.get(path)
        if old is not None and old.kind == "f":
            self.overlay_bytes -= len(old.content)
        if node is not None and node.kind == "f":
            self.overlay_bytes += len(node.content)
        self.overlay[path] = node
        parent, name = split_path(path)
        if node is not None:
            self.added.setdefault(parent, set()).add(name)

    def mkdir(self, path: str, parents: bool = False, mode: int = 0o755) -> None:
        self._check_writable(path)
        if self._raw(path) is not None:
            if parents and self.isdir(path):
                return
            raise FSError("File exists")
        parent, _ = split_path(path)
        if not self.isdir(parent):
            if parents and parent != path:
                self.mkdir(parent, True, mode)
            else:
                raise FSError("No such file or directory")
        self._set(path, Node("d", mode | 0, mtime=self.clock(), origin="session"))

    def write(self, path: str, data: bytes, *, append: bool = False, mode: int = 0o644,
              origin: str = "session") -> Node:
        self._check_writable(path)
        parent, name = split_path(path)
        if not name:
            raise FSError("Is a directory")
        if not self.isdir(parent):
            raise FSError("No such file or directory" if self.lookup(parent) is None else "Not a directory")
        cur = self.lookup(path)
        if cur is not None and cur.kind == "d":
            raise FSError("Is a directory")
        prev = cur.content if (cur is not None and cur.kind == "f" and append) else b""
        new = prev + data
        if len(new) > MAX_FILE or self.overlay_bytes + len(data) > self.max_overlay:
            raise FSError("No space left on device")
        node = Node("f", cur.mode if cur is not None else mode, mtime=self.clock(), content=new,
                    origin=cur.origin if (cur is not None and cur.origin != "base") else origin,
                    captured_sha="", meta=dict(cur.meta) if cur is not None else {})
        self._set(path, node)
        return node

    def remove(self, path: str, recursive: bool = False) -> None:
        self._check_writable(path)
        n = self.lookup(path, follow=False)
        if n is None:
            raise FSError("No such file or directory")
        if n.kind == "d":
            if not recursive:
                raise FSError("Is a directory")
            for nm in self.listdir(path):
                self.remove(posixpath.join(path, nm), True)
        self._set(path, None)

    def rmdir(self, path: str) -> None:
        n = self.lookup(path, follow=False)
        if n is None:
            raise FSError("No such file or directory")
        if n.kind != "d":
            raise FSError("Not a directory")
        if self.listdir(path):
            raise FSError("Directory not empty")
        self._set(path, None)

    def chmod(self, path: str, mode: int) -> None:
        n = self.lookup(path)
        if n is None:
            raise FSError("No such file or directory")
        self._check_writable(path)
        clone = Node(n.kind, mode, n.uid, n.gid, self.clock(), n.content, n.target, n.origin,
                     n.captured_sha, dict(n.meta))
        self._set(path, clone)

    def copy(self, src: str, dst: str) -> None:
        n = self.lookup(src)
        if n is None:
            raise FSError("No such file or directory")
        if n.kind == "d":
            raise FSError("omitting directory")
        if self.isdir(dst):
            dst = posixpath.join(dst, split_path(src)[1])
        self.write(dst, n.content, mode=n.mode, origin=n.origin if n.origin != "base" else "session")

    def move(self, src: str, dst: str) -> None:
        n = self.lookup(src, follow=False)
        if n is None:
            raise FSError("No such file or directory")
        if self.isdir(dst):
            dst = posixpath.join(dst, split_path(src)[1])
        parent, _ = split_path(dst)
        if not self.isdir(parent):
            raise FSError("No such file or directory")
        if n.kind == "d":
            raise FSError("cannot move directory")
        clone = Node(n.kind, n.mode, n.uid, n.gid, self.clock(), n.content, n.target, n.origin,
                     n.captured_sha, dict(n.meta))
        self._set(dst, clone)
        self._set(src, None)

    def symlink(self, target: str, path: str) -> None:
        if self._raw(path) is not None:
            raise FSError("File exists")
        self._set(path, Node("l", 0o777, mtime=self.clock(), target=target, origin="session"))

    def session_files(self) -> list[tuple[str, Node]]:
        """Regular files created during the session (candidates for capture)."""
        return [(p, n) for p, n in self.overlay.items() if n is not None and n.kind == "f"]
