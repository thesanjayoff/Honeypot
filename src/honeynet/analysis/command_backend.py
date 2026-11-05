"""Adapter for an external reverse-engineering tool run headless as a subprocess.

Set ``HONEYNET_ANALYSIS_BACKEND=command`` and ``HONEYNET_ANALYSIS_COMMAND`` to the program (it
must be present in the analysis container, which has no network).  The program is invoked with
**no shell** and must implement this tiny contract; ``{file}`` is the sample path:

    <cmd> inspect  <file>                 -> stdout: JSON object (see BinaryInfo.to_dict())
    <cmd> disasm   <file> --max <N>       -> stdout: JSON list of
                                             {"address": int, "size": int, "mnemonic": str,
                                              "op_str": str, "bytes": "hex"}
    <cmd> pseudo   <file> <address>       -> stdout: decompiler text; exit status 3 = unsupported

Anything else on stdout/stderr is ignored.  A thin wrapper script around any disassembler or
decompiler CLI (rizin/radare2, Ghidra headless, IDA batch, ...) is enough.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path

from .model import AnalysisBackend, BackendUnavailable, BinaryInfo, Insn

MAX_OUTPUT = 128 * 1024 * 1024
_ENV_KEEP = ("PATH", "HOME", "LANG", "LC_ALL", "SYSTEMROOT", "TMPDIR", "TEMP")


class CommandBackend(AnalysisBackend):
    name = "command"

    def __init__(self, command: str, timeout: int = 60) -> None:
        if not command.strip():
            raise BackendUnavailable("HONEYNET_ANALYSIS_COMMAND is empty")
        # on Windows keep backslashes (posix=False) but drop the quoting shlex leaves in the tokens
        self.argv = [t.strip('"') for t in shlex.split(command, posix=os.name != "nt")]
        self.timeout = timeout

    def version(self) -> str:
        return f"external: {Path(self.argv[0]).name}"

    def _run(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        env = {k: v for k, v in os.environ.items() if k in _ENV_KEEP}
        try:
            return subprocess.run([*self.argv, *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=self.timeout,
                                  env=env, check=False)
        except FileNotFoundError as exc:
            raise BackendUnavailable(f"analysis command not found: {self.argv[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise BackendUnavailable(f"analysis command timed out after {self.timeout}s") from exc

    def _json(self, *args: str):
        cp = self._run(*args)
        if cp.returncode != 0:
            raise BackendUnavailable(f"analysis command exited {cp.returncode}: {cp.stderr[:200].decode('utf-8', 'replace')}")
        if len(cp.stdout) > MAX_OUTPUT:
            raise BackendUnavailable("analysis command output too large")
        try:
            return json.loads(cp.stdout)
        except ValueError as exc:
            raise BackendUnavailable(f"analysis command returned invalid JSON: {exc}") from exc

    def inspect(self, path: Path) -> BinaryInfo:
        d = self._json("inspect", str(path))
        if not isinstance(d, dict):
            raise BackendUnavailable("inspect must return a JSON object")
        return BinaryInfo.from_dict(d)

    def disassemble(self, path: Path, info: BinaryInfo, max_insns: int = 300_000) -> list[Insn]:
        rows = self._json("disasm", str(path), "--max", str(max_insns))
        out = []
        for r in rows[:max_insns]:
            out.append(Insn(int(r["address"]), int(r.get("size", 0)), str(r["mnemonic"]), str(r.get("op_str", "")),
                            str(r.get("bytes", ""))))
        return out

    def pseudocode(self, path: Path, info: BinaryInfo, address: int) -> str | None:
        cp = self._run("pseudo", str(path), hex(address))
        if cp.returncode != 0 or not cp.stdout.strip():
            return None
        return cp.stdout[:200_000].decode("utf-8", "replace")
