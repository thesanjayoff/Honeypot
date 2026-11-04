"""Backend-independent helpers: entropy, string extraction, magic sniffing, hexdumps."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

ASCII_RE = re.compile(rb"[\x20-\x7e\t]{5,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def entropy_profile(data: bytes, windows: int = 64) -> list[float]:
    """Entropy per equal-sized window (for the dashboard's entropy chart)."""
    if not data:
        return []
    step = max(256, len(data) // windows)
    return [round(shannon_entropy(data[i:i + step]), 2) for i in range(0, len(data), step)][:windows]


@dataclass
class StringRef:
    offset: int
    text: str
    wide: bool = False


def extract_strings(data: bytes, limit: int = 30000) -> list[StringRef]:
    out: list[StringRef] = []
    for m in ASCII_RE.finditer(data):
        out.append(StringRef(m.start(), m.group().decode("ascii", "replace")))
        if len(out) >= limit:
            return out
    for m in UTF16_RE.finditer(data):
        out.append(StringRef(m.start(), m.group().decode("utf-16-le", "replace"), True))
        if len(out) >= limit:
            break
    out.sort(key=lambda s: s.offset)
    return out


def hexdump(data: bytes, center: int, width: int = 48) -> list[str]:
    start = max(0, center - width // 2)
    start -= start % 16
    chunk = data[start:start + width + 16]
    lines = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hexpart = " ".join(f"{b:02x}" for b in row).ljust(47)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{start + i:08x}  {hexpart}  |{asc}|")
    return lines


def sniff_type(data: bytes) -> tuple[str, str]:
    """Return (kind, description). kind: elf|pe|script|php|python|perl|gzip|zip|text|data|empty."""
    if not data:
        return "empty", "empty file"
    head = data[:8]
    if head[:4] == b"\x7fELF":
        return "elf", "ELF executable"
    if head[:2] == b"MZ":
        return "pe", "PE executable (Windows)"
    if head[:2] == b"\x1f\x8b":
        return "gzip", "gzip compressed data"
    if head[:4] == b"PK\x03\x04":
        return "zip", "ZIP archive"
    if head[:3] == b"BZh":
        return "bzip2", "bzip2 compressed data"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz", "xz compressed data"
    text = data[:4096]
    printable = sum(1 for b in text if b in (9, 10, 13) or 32 <= b < 127 or b >= 0xC2)
    ratio = printable / max(1, len(text))
    # scripts that carry a few ESC/BEL bytes are still scripts; binaries are full of NULs
    if ratio < 0.93 and not (b"\x00" not in text and ratio >= 0.80) and not text.startswith(b"#!"):
        return "data", "binary data"
    t = text.decode("utf-8", "replace")
    first = t.split("\n", 1)[0]
    if first.startswith("#!"):
        low = first.lower()
        if "python" in low:
            return "python", f"Python script ({first[:60]})"
        if "perl" in low:
            return "perl", f"Perl script ({first[:60]})"
        if "php" in low:
            return "php", "PHP script"
        return "script", f"shell script ({first[:60]})"
    if "<?php" in t[:512] or "<?=" in t[:512]:
        return "php", "PHP script"
    if re.search(r"^\s*(import |from \w+ import |def |class )", t, re.M) and re.search(r"(import (os|sys|socket|subprocess)|def )", t):
        return "python", "Python script"
    if re.search(r"\b(use strict|my \$|use IO::Socket)", t):
        return "perl", "Perl script"
    if re.search(r"\b(wget|curl|chmod|cd /|rm -|echo|export|for \w+ in|killall|crontab|tftp|busybox)\b", t):
        return "script", "shell script"
    if re.match(r"^\s*(\{|\[)", t) and re.search(r'"\w+"\s*:', t):
        return "json", "JSON text"
    return "text", "ASCII text"


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1
