"""Evidence snippets: the disassembly / script lines / hexdump behind each finding.

Every finding in a report points at a snippet so an analyst can check the claim without
re-opening the sample.  Cross-references from code to a string are recovered with a small
per-architecture heuristic (RIP-relative, absolute immediates, ARM literal pools, MIPS
lui/addiu pairs, AArch64 adrp/add) - good enough for stripped static IoT binaries.
"""

from __future__ import annotations

import re
import struct
from bisect import bisect_right
from collections.abc import Callable

from .model import BinaryInfo, Insn
from .syscalls import SyscallSite
from .util import hexdump

_NUM = re.compile(r"(?<![\w.])#?(-?0x[0-9a-f]+|\d{5,})(?![\w])", re.I)
_RIP = re.compile(r"\[rip\s*([+-])\s*(0x[0-9a-f]+)\]", re.I)
_PCREL = re.compile(r"\[pc,\s*#(-?)(0x[0-9a-f]+|\d+)\]", re.I)
_LUI = re.compile(r"^lui\s+(\$\w+),\s*(0x[0-9a-f]+|\d+)$", re.I)
_LOW = re.compile(r"^(?:addiu|ori|addi|daddiu)\s+(\$\w+),\s*(\$\w+),\s*(-?0x[0-9a-f]+|-?\d+)$", re.I)
_ADRP = re.compile(r"^adrp\s+(x\d+),\s*#?(0x[0-9a-f]+)$", re.I)
_ADD = re.compile(r"^add\s+(x\d+),\s*(x\d+),\s*#?(0x[0-9a-f]+|\d+)$", re.I)

ReadWord = Callable[[int], "int | None"]


def vaddr_to_offset(info: BinaryInfo, vaddr: int) -> int | None:
    for s in info.sections:
        if s.vaddr and s.size and s.vaddr <= vaddr < s.vaddr + s.size:
            return s.offset + (vaddr - s.vaddr)
    return None


def offset_to_vaddr(info: BinaryInfo, off: int) -> int | None:
    for s in info.sections:
        if s.vaddr and s.size and s.offset <= off < s.offset + s.size:
            return s.vaddr + (off - s.offset)
    return None


def make_word_reader(data: bytes, info: BinaryInfo) -> ReadWord:
    fmt = (">" if info.endian == "big" else "<") + ("Q" if info.bits == 64 else "I")
    size = 8 if info.bits == 64 else 4

    def read(vaddr: int) -> int | None:
        off = vaddr_to_offset(info, vaddr)
        if off is None or off + size > len(data):
            return None
        return struct.unpack_from(fmt, data, off)[0]

    return read


def find_refs(arch: str, insns: list[Insn], targets: set[int], read_word: ReadWord) -> dict[int, list[int]]:
    """Map target vaddr -> indices of instructions that reference it."""
    refs: dict[int, list[int]] = {}
    if not targets:
        return refs
    mask = 0xFFFFFFFFFFFFFFFF if arch in ("x86_64", "aarch64") else 0xFFFFFFFF
    lui: dict[str, int] = {}
    adrp: dict[str, int] = {}

    def hit(val: int, i: int) -> None:
        if val in targets:
            lst = refs.setdefault(val, [])
            if len(lst) < 6:
                lst.append(i)

    for i, ins in enumerate(insns):
        ops = ins.op_str.lower()
        txt = f"{ins.mnemonic.lower()} {ops}"
        if arch == "x86_64":
            m = _RIP.search(ops)
            if m:
                disp = int(m.group(2), 16)
                hit((ins.address + ins.size + (disp if m.group(1) == "+" else -disp)) & mask, i)
        elif arch == "arm":
            m = _PCREL.search(ops)
            if m and ins.mnemonic.lower().startswith("ldr"):
                disp = int(m.group(2), 0) * (-1 if m.group(1) else 1)
                w = read_word(ins.address + 8 + disp)
                if w is not None:
                    hit(w, i)
        elif arch == "mips":
            m = _LUI.match(txt)
            if m:
                lui[m.group(1)] = (int(m.group(2), 0) << 16) & 0xFFFFFFFF
            else:
                m = _LOW.match(txt)
                if m and m.group(2) in lui:
                    low = int(m.group(3), 0)
                    val = (lui[m.group(2)] + (low if txt.startswith(("addiu", "addi", "daddiu")) else (low & 0xFFFF))) & 0xFFFFFFFF
                    hit(val, i)
        elif arch == "aarch64":
            m = _ADRP.match(txt)
            if m:
                adrp[m.group(1)] = int(m.group(2), 16)
            else:
                m = _ADD.match(txt)
                if m and m.group(2) in adrp:
                    hit((adrp[m.group(2)] + int(m.group(3), 0)) & mask, i)
        for n in _NUM.findall(ops):
            try:
                hit(int(n, 0) & mask, i)
            except ValueError:
                pass
    return refs


def disasm_lines(insns: list[Insn], idx: int, before: int = 6, after: int = 2,
                 notes: dict[int, str] | None = None) -> tuple[list[str], int]:
    lo, hi = max(0, idx - before), min(len(insns), idx + after + 1)
    out = []
    for j in range(lo, hi):
        i = insns[j]
        line = f"{i.address:08x}  {i.bytes_hex[:16]:<16}  {i.text()}"
        if notes and j in notes:
            line += f"    ; {notes[j]}"
        out.append(line)
    return out, idx - lo


def site_label(site: SyscallSite) -> str:
    args = ", ".join("?" if a is None else str(a) for a in site.args)
    return f"{site.name}({args})"


def script_lines(text: str, line_no: int, before: int = 3, after: int = 3) -> tuple[list[str], int]:
    lines = text.split("\n")
    lo, hi = max(0, line_no - 1 - before), min(len(lines), line_no + after)
    out = [f"{n + 1:>4}  {lines[n][:220]}" for n in range(lo, hi)]
    return out, line_no - 1 - lo


def hex_lines(data: bytes, offset: int) -> tuple[list[str], int]:
    lines = hexdump(data, offset, 48)
    return lines, min(len(lines) - 1, 1)


class SnippetBook:
    """Collects snippets keyed by id; findings refer to them by key."""

    def __init__(self, limit: int = 160) -> None:
        self.items: dict[str, dict] = {}
        self.limit = limit

    def add(self, key: str, kind: str, title: str, lines: list[str], highlight: int = 0, **extra) -> str | None:
        if key in self.items:
            return key
        if len(self.items) >= self.limit:
            return None
        self.items[key] = {"kind": kind, "title": title, "lines": lines, "highlight": highlight, **extra}
        return key
