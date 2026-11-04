"""Sanitisation of hostile (attacker supplied) data.

Everything an attacker can influence - usernames, passwords, commands, HTTP
headers, query strings, file names, SQL text - is treated as hostile.  The
helpers here make that data safe for:

* JSONL logs        (no raw control characters, bounded size)  -> log injection
* terminals / replay (ESC & friends become visible ``\\x1b``)   -> terminal escape injection
* HTML              (always escaped by the dashboard; ``html_escape`` here for reports)
* CSV               (formula injection guard)
* chat/webhook text (mention / markup neutralisation)
"""

from __future__ import annotations

import html
import re
from typing import Any

MAX_STR = 2048
MAX_ITEMS = 64
MAX_DEPTH = 5

# C0, DEL, C1 controls, line/paragraph separators, zero-width + bidi controls, BOM.
_UNSAFE_RE = re.compile(
    "[\x00-\x1f\x7f-\x9f  ​-‏‪-‮⁠-⁤⁦-⁩﻿]"
)
_NAMED = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}
_KEY_RE = re.compile(r"[^A-Za-z0-9_.\-]")


def _esc_char(m: re.Match[str]) -> str:
    ch = m.group(0)
    if ch in _NAMED:
        return _NAMED[ch]
    cp = ord(ch)
    return f"\\x{cp:02x}" if cp <= 0xFF else f"\\u{cp:04x}"


def to_text(value: Any) -> str:
    """Best-effort conversion to ``str`` without ever raising."""
    if isinstance(value, str):
        # lone surrogates cannot be encoded to UTF-8 -> would break json/sqlite
        return value.encode("utf-8", "backslashreplace").decode("utf-8")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("utf-8", "backslashreplace")
    return str(value)


def escape_controls(text: str) -> str:
    """Replace control / invisible / bidi characters with visible escapes."""
    return _UNSAFE_RE.sub(_esc_char, text)


def sanitize_text(value: Any, max_len: int = MAX_STR) -> str:
    """Return a bounded, control-free string safe for logs and display."""
    text = escape_controls(to_text(value))
    if len(text) > max_len:
        extra = len(text) - max_len
        text = f"{text[:max_len]}...[+{extra}]"
    return text


def sanitize_key(key: Any) -> str:
    k = _KEY_RE.sub("_", to_text(key))[:40]
    return k or "_"


def sanitize_obj(value: Any, *, depth: int = 0, max_len: int = MAX_STR) -> Any:
    """Recursively sanitise JSON-like data. Bytes are decoded, sizes are bounded."""
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if value == value and abs(value) != float("inf") else 0.0
    if isinstance(value, (str, bytes, bytearray, memoryview)):
        return sanitize_text(value, max_len)
    if depth >= MAX_DEPTH:
        return "[max-depth]"
    if isinstance(value, dict):
        out = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= MAX_ITEMS:
                out["_truncated"] = len(value) - MAX_ITEMS
                break
            out[sanitize_key(k)] = sanitize_obj(v, depth=depth + 1, max_len=max_len)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        seq = list(value)
        out_l = [sanitize_obj(v, depth=depth + 1, max_len=max_len) for v in seq[:MAX_ITEMS]]
        if len(seq) > MAX_ITEMS:
            out_l.append(f"...[+{len(seq) - MAX_ITEMS}]")
        return out_l
    return sanitize_text(value, max_len)


def sanitize_deep(value: Any, *, max_len: int = MAX_STR, max_items: int = 5000, max_depth: int = 8) -> Any:
    """Like :func:`sanitize_obj` but with generous bounds and untouched key names.

    Used for analysis reports, whose lists (IOCs, strings, snippets) are legitimately long.
    Every string - keys included - still has control/bidi characters replaced.
    """
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if value == value and abs(value) != float("inf") else 0.0
    if isinstance(value, (str, bytes, bytearray, memoryview)):
        return sanitize_text(value, max_len)
    if max_depth <= 0:
        return "[max-depth]"
    if isinstance(value, dict):
        return {sanitize_text(k, 120): sanitize_deep(v, max_len=max_len, max_items=max_items, max_depth=max_depth - 1)
                for k, v in list(value.items())[:max_items]}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [sanitize_deep(v, max_len=max_len, max_items=max_items, max_depth=max_depth - 1) for v in list(value)[:max_items]]
    return sanitize_text(value, max_len)


# --------------------------------------------------------------------------- outputs


def html_escape(value: Any) -> str:
    return html.escape(sanitize_text(value), quote=True)


_CSV_DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection (CWE-1236)."""
    text = sanitize_text(value, 4096)
    if text.startswith(_CSV_DANGEROUS):
        return "'" + text
    return text


def neutralize_chat(value: Any, max_len: int = 300) -> str:
    """Make attacker text harmless in Slack/Discord/Teams/e-mail bodies.

    Defuses mentions (@everyone, <@123>), markdown links and URL unfurling.
    """
    text = sanitize_text(value, max_len)
    text = text.replace("@", "@​").replace("<", "‹").replace(">", "›")
    text = text.replace("`", "'").replace("[", "(").replace("]", ")")
    text = re.sub(r"(?i)\b(https?|ftp)://", lambda m: m.group(1) + "[:]//", text)
    return text


def defang(value: str) -> str:
    """Defang an IOC for human display (hxxp://1.2[.]3.4)."""
    out = re.sub(r"(?i)^http", "hxxp", value)
    return out.replace(".", "[.]")


_PRINTABLE = set(range(0x20, 0x7F))


def printable_ascii(data: bytes, replace: str = ".") -> str:
    return "".join(chr(b) if b in _PRINTABLE else replace for b in data)
