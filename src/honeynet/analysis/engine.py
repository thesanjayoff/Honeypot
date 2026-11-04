"""Static analysis pipeline.  Never executes, loads or maps the sample.

``analyze_file`` -> report dict (JSON-serialisable, fully sanitised).  Only the
:class:`~honeynet.analysis.model.AnalysisBackend` interface is used to talk to the reverse
engineering tool; hashing, entropy, strings, IOCs, behaviours, family labelling and snippets
work for any backend (and for scripts, which need no backend at all).
"""

from __future__ import annotations

import base64
import binascii
import bz2
import hashlib
import lzma
import re
import tempfile
import time
import zlib
from bisect import bisect_right
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..common.sanitize import sanitize_deep
from .behaviors import Behavior, Evidence, cred_words_from, detect_behaviors
from .family import Features, label
from .iocs import IOC, extract_iocs, merge_iocs
from .model import AnalysisBackend, BackendUnavailable, BinaryInfo, Insn
from .snippets import (SnippetBook, disasm_lines, find_refs, hex_lines, make_word_reader, offset_to_vaddr, script_lines,
                       site_label)
from .syscalls import TABLES, SyscallSite, find_syscalls
from .util import StringRef, entropy_profile, extract_strings, shannon_entropy, sniff_type

REPORT_VERSION = 1
SCRIPT_KINDS = {"script", "python", "perl", "php", "text", "json"}
BENIGN_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
              "4.2.2.2", "114.114.114.114", "223.5.5.5", "119.29.29.29"}
VERSIONY = re.compile(r"\b(?:version|ver\.?|gcc|glibc|libc|release|build|v\d)\b", re.I)
XOR_MARKERS = re.compile(rb"/proc/|/bin/|/dev/|/etc/|https?://|busybox|watchdog|wget|chmod|/tmp|\.so\b", re.I)
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{48,}={0,2})(?![A-Za-z0-9+/=])")
UPX_MARKERS = (b"UPX!", b"$Info: This file is packed with the UPX", b"$Id: UPX")
PACKER_SECTIONS = {"upx0", "upx1", "upx2", ".upx0", ".upx1", ".aspack", ".adata", ".petite", ".themida", ".vmp0", ".vmp1",
                   ".mpress1", ".mpress2", ".nsp0", ".nsp1", ".enigma1", "pec1", "pec2"}


@dataclass
class EngineConfig:
    max_size: int = 25 * 1024 * 1024
    max_insns: int = 200_000
    max_strings: int = 30_000
    max_iocs: int = 300
    max_report_strings: int = 400
    xor_scan_max: int = 1024 * 1024
    decompress_limit: int = 32 * 1024 * 1024


# ----------------------------------------------------------------------------- helpers

def hash_file(path: Path) -> dict[str, str]:
    h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            for x in h.values():
                x.update(chunk)
    return {k: v.hexdigest() for k, v in h.items()}


def hashes(data: bytes) -> dict[str, str]:
    return {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}


def _decompress(kind: str, data: bytes, limit: int) -> bytes | None:
    """Single-layer, bomb-limited decompression of gzip/bzip2/xz."""
    try:
        d = {"gzip": lambda: zlib.decompressobj(16 + zlib.MAX_WBITS), "bzip2": bz2.BZ2Decompressor,
             "xz": lzma.LZMADecompressor}[kind]()
        out = d.decompress(data, limit + 1)
    except (OSError, ValueError, EOFError, zlib.error, lzma.LZMAError):
        return None
    return out[:limit] if out else None


def scan_credential_words(data: bytes, limit: int = 4 * 1024 * 1024) -> list[tuple[int, str]]:
    """Exact-token match against the default-credential vocabulary (tokens may be < 5 chars)."""
    from .behaviors import DEFAULT_CRED_WORDS, qualify_cred_hits

    seen: dict[str, int] = {}
    for m in re.finditer(rb"[\x21-\x7e]{3,24}", data[:limit]):
        w = m.group().decode("ascii").lower()
        if w in DEFAULT_CRED_WORDS and w not in seen:
            seen[w] = m.start()
    return qualify_cred_hits(sorted((o, w) for w, o in seen.items()))


def xor_decode_strings(data: bytes, plain_markers: int) -> tuple[int, list[StringRef]] | None:
    """Mirai-style tables are XOR-scrambled with one byte; recover them when markers appear."""
    if plain_markers >= 3:
        return None
    best: tuple[int, int] | None = None
    for key in range(1, 256):
        dec = data.translate(bytes(b ^ key for b in range(256)))
        n = len({m.group().lower() for m in XOR_MARKERS.finditer(dec)})
        if n >= 3 and (best is None or n > best[1]):
            best = (key, n)
    if best is None:
        return None
    key = best[0]
    dec = data.translate(bytes(b ^ key for b in range(256)))
    out = []
    for m in re.finditer(rb"[\x21-\x7e][\x20-\x7e]{4,}", dec):
        s = m.group().decode("ascii")
        good = sum(c.isalnum() or c in "/._-:%@ ?=&" for c in s) / len(s)
        if good >= 0.92 and any(c.isalpha() for c in s):
            out.append(StringRef(m.start(), s))
    return (key, out[:2000]) if out else None


def decode_embedded_layers(text: str, limit: int = 8) -> list[dict]:
    layers = []
    for m in B64_RE.finditer(text):
        try:
            raw = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        dec = raw.decode("utf-8", "replace")
        if len(dec) >= 12 and sum(c.isprintable() or c in "\n\t\r" for c in dec) / len(dec) >= 0.95:
            layers.append({"encoding": "base64", "offset": m.start(), "text": dec[:20000]})
            if len(layers) >= limit:
                break
    return layers


def packing_report(kind: str, data: bytes, info: BinaryInfo, overall: float, text: str | None) -> dict:
    ind: list[tuple[str, float]] = []
    if any(mk in data for mk in UPX_MARKERS):
        ind.append(("UPX packer signature present", 0.9))
    names = {s.name.lower() for s in info.sections}
    if names & PACKER_SECTIONS:
        ind.append((f"packer section names: {', '.join(sorted(names & PACKER_SECTIONS))}", 0.9))
    if kind == "elf":
        if not info.has_section_headers:
            ind.append(("ELF has no section headers (stripped by packer/hand-crafted)", 0.35))
        elif info.entry and info.sections and not any(
                s.executable and s.vaddr <= info.entry < s.vaddr + max(s.size, 1) for s in info.sections):
            ind.append(("entry point is outside every executable section", 0.4))
    if kind in ("elf", "pe"):
        if overall > 7.2:
            ind.append((f"overall entropy {overall:.2f} (>7.2: compressed/encrypted)", 0.55))
        elif overall > 6.8:
            ind.append((f"overall entropy {overall:.2f} (>6.8)", 0.25))
        for s in info.sections:
            if s.executable and s.entropy > 7.0 and s.size > 512:
                ind.append((f"executable section {s.name} entropy {s.entropy:.2f}", 0.5))
                break
        if any(s.executable and s.writable for s in info.sections):
            ind.append(("section is both writable and executable", 0.3))
        if kind == "pe" and 0 < len(info.imports) <= 4:
            ind.append((f"only {len(info.imports)} imports (resolved at runtime)", 0.4))
        if info.overlay_size > 1024:
            ind.append((f"{info.overlay_size} bytes of overlay data", 0.2))
    elif text is not None:
        if re.search(r"(?:base64\s+-d|openssl\s+enc|xxd\s+-r|\|\s*(?:ba)?sh\b).{0,80}", text) and B64_RE.search(text):
            ind.append(("script decodes an embedded blob and executes it", 0.8))
        if any(len(line) > 3000 for line in text.split("\n")[:50]):
            ind.append(("extremely long line (minified/obfuscated)", 0.3))
        if len(re.findall(r"\\x[0-9a-f]{2}", text, re.I)) > 80:
            ind.append(("heavy use of \\x escapes", 0.4))
        if re.search(r"eval\s*\(\s*(?:gzinflate|base64_decode|str_rot13)", text):
            ind.append(("eval(decode(...)) chain", 0.8))
    p = 1.0
    for _, w in ind:
        p *= 1 - w
    return {"packed": (1 - p) >= 0.6, "confidence": round(1 - p, 2), "indicators": [d for d, _ in ind]}


# ----------------------------------------------------------------------------- engine

def analyze_file(path: Path, backend: AnalysisBackend | None, cfg: EngineConfig | None = None) -> dict:
    cfg = cfg or EngineConfig()
    t0 = time.monotonic()
    path = Path(path)
    size = path.stat().st_size
    data = path.read_bytes()[: cfg.max_size]
    outer = {"size": size, **hash_file(path)}
    kind, desc = sniff_type(data)
    container = None
    work_path, work = path, data
    tmp: tempfile.TemporaryDirectory | None = None
    try:
        if kind in ("gzip", "bzip2", "xz"):
            inner = _decompress(kind, data, cfg.decompress_limit)
            if inner:
                tmp = tempfile.TemporaryDirectory(prefix="honeynet-inner-")
                work_path = Path(tmp.name) / "inner.bin"
                work_path.write_bytes(inner)
                work = inner
                container = {"type": kind, "inner_size": len(inner), **{f"inner_{k}": v for k, v in hashes(inner).items()}}
                kind, desc = sniff_type(inner)
        report = _analyze_core(work_path, work, kind, desc, backend, cfg)
    finally:
        if tmp:
            tmp.cleanup()
    report.update({"v": REPORT_VERSION, "sha256": outer["sha256"], "md5": outer["md5"], "sha1": outer["sha1"],
                   "size": size, "truncated": size > cfg.max_size,
                   "analyzed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z",
                   "analysis_ms": int((time.monotonic() - t0) * 1000), "static_only": True, "container": container})
    return sanitize_deep(report, max_len=4200)


def _string_index(strings: list[StringRef]) -> tuple[str, list[int], list[StringRef]]:
    parts, starts, pos = [], [], 0
    for s in strings:
        starts.append(pos)
        parts.append(s.text)
        pos += len(s.text) + 1
    return "\n".join(parts), starts, strings


def _analyze_core(path: Path, data: bytes, kind: str, desc: str, backend: AnalysisBackend | None, cfg: EngineConfig) -> dict:
    errors: list[str] = []
    is_bin = kind in ("elf", "pe")
    info = BinaryInfo(fmt=kind.upper() if is_bin else kind)
    backend_name, backend_version = (backend.name, backend.version()) if backend else ("none", "")
    if is_bin and backend is not None:
        try:
            info = backend.inspect(path)
        except BackendUnavailable as exc:
            errors.append(f"backend unavailable: {exc}")
        except Exception as exc:  # noqa: BLE001 - hostile input: degrade, never crash
            errors.append(f"inspect failed: {type(exc).__name__}: {str(exc)[:160]}")
    if info.extra.get("parse_warning"):
        errors.append(str(info.extra["parse_warning"]))

    overall = shannon_entropy(data)
    for s in info.sections:
        if s.size and 0 <= s.offset < len(data):
            s.entropy = round(shannon_entropy(data[s.offset: s.offset + min(s.size, 4 * 1024 * 1024)]), 2)

    text: str | None = None
    layers: list[dict] = []
    if kind in SCRIPT_KINDS:
        text = data.decode("utf-8", "replace")[:3_000_000]
        layers = decode_embedded_layers(text)
    packing = packing_report(kind, data, info, overall, text)

    # ---- strings -------------------------------------------------------------------
    refs = extract_strings(data, cfg.max_strings) if is_bin else []
    xor_key: int | None = None
    xor_offsets: set[int] = set()
    if is_bin and len(data) <= cfg.xor_scan_max:
        plain_markers = len({m.group().lower() for m in XOR_MARKERS.finditer(data)})
        res = xor_decode_strings(data, plain_markers)
        if res:
            xor_key, extra = res
            xor_offsets = {s.offset for s in extra}
            refs = sorted(refs + extra, key=lambda s: s.offset)
    joined, starts, ordered = _string_index(refs) if is_bin else ("", [], [])

    # ---- IOCs ----------------------------------------------------------------------
    iocs: list[IOC] = []
    string_of_ioc: dict[int, StringRef] = {}
    if is_bin:
        for ioc in extract_iocs(joined, source="binary strings", base_offset=0, max_items=cfg.max_iocs):
            pos = ioc.offset or 0
            idx = max(0, bisect_right(starts, pos) - 1)
            s = ordered[idx] if ordered else None
            if s is not None:
                intra = pos - starts[idx]
                ioc.offset = s.offset + (intra * 2 if s.wide else intra)
                ioc.extra["string_offset"] = s.offset
                if xor_key is not None and s.offset in xor_offsets:
                    ioc.context = f"{ioc.context} (XOR 0x{xor_key:02x}-decoded)"
                _adjust_ioc(ioc, s.text)
            iocs.append(ioc)
    elif text is not None:
        for ioc in extract_iocs(text, source="script", base_offset=0, max_items=cfg.max_iocs):
            ioc.extra["line"] = (text.count("\n", 0, ioc.offset or 0) + 1)
            _adjust_ioc(ioc, text[max(0, (ioc.offset or 0) - 60): (ioc.offset or 0) + 120])
            iocs.append(ioc)
        for n, layer in enumerate(layers):
            for ioc in extract_iocs(layer["text"], source=f"base64 layer {n + 1}", max_items=100):
                ioc.extra["layer"] = n + 1
                _adjust_ioc(ioc, layer["text"][:200])
                iocs.append(ioc)
    iocs = merge_iocs([iocs])[: cfg.max_iocs]

    # ---- disassembly + syscalls ----------------------------------------------------
    insns: list[Insn] = []
    sites: list[SyscallSite] = []
    if is_bin and backend is not None and info.arch in TABLES and info.fmt == "ELF":
        try:
            insns = backend.disassemble(path, info, cfg.max_insns)
            sites = find_syscalls(info.arch, insns)
        except BackendUnavailable as exc:
            errors.append(f"disassembly unavailable: {exc}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"disassembly failed: {type(exc).__name__}: {str(exc)[:160]}")
    elif is_bin and info.arch not in TABLES and info.fmt == "ELF":
        errors.append(f"no syscall table for architecture {info.arch!r}; behaviour limited to strings")

    # ---- behaviours ----------------------------------------------------------------
    str_pairs = [(s.offset, s.text) for s in refs]
    cred_words = cred_words_from([], text) if text is not None else scan_credential_words(data)
    imports = {i.name for i in info.imports}
    behaviors = detect_behaviors(strings=str_pairs, text=(text if text is not None else None), sites=sites, imports=imports,
                                 cred_words=cred_words)
    if layers:
        extra_text = "\n".join(layer["text"] for layer in layers)
        for b in detect_behaviors(strings=[], text=extra_text, sites=[], imports=set()):
            if b.id not in {x.id for x in behaviors}:
                for e in b.evidence:
                    e.detail = f"[base64 layer] {e.detail}"
                    e.offset = None
                behaviors.append(b)
    if info.fmt == "ELF" and (xor_key is not None):
        for b in behaviors:
            if any(e.kind == "string" and e.offset in xor_offsets for e in b.evidence):
                b.description += f" (strings recovered by XOR 0x{xor_key:02x} decoding)"

    # ---- snippets ------------------------------------------------------------------
    book = SnippetBook()
    _attach_snippets(book, behaviors, iocs, data, text, insns, sites, info, backend, path, xor_key, xor_offsets)

    # ---- family --------------------------------------------------------------------
    feats = Features(kind=kind, arch=info.arch, text=text if text is not None else joined,
                     behaviors={b.id: b for b in behaviors}, iocs=iocs, cred_hits=len(cred_words),
                     syscalls={s.name for s in sites} | {_IMPORT_SYS.get(i, "") for i in imports},
                     static=info.static, stripped=info.stripped, packed=packing["packed"], size=len(data),
                     lines=(text.count("\n") + 1) if text is not None else 0)
    fam, alternatives = label(feats)

    mitre = sorted({t for b in behaviors for t in b.mitre})
    c2 = _c2_candidates(iocs)
    risk = _risk(behaviors, fam.confidence if fam.id != "unknown" else 0.0, c2, packing["packed"])

    return {
        "file": {"kind": kind, "description": desc, "format": info.fmt, "arch": info.arch, "bits": info.bits,
                 "endian": info.endian, "entry": info.entry, "file_type": info.file_type, "stripped": info.stripped,
                 "static": info.static, "interpreter": info.interpreter, "libraries": info.libraries[:50],
                 "symbols": info.symbols, "has_section_headers": info.has_section_headers, "overlay_size": info.overlay_size},
        "backend": {"name": backend_name, "version": backend_version, "instructions": len(insns), "syscall_sites": len(sites)},
        "sections": [{"name": s.name, "vaddr": s.vaddr, "offset": s.offset, "size": s.size,
                      "flags": ("r" if s.readable else "-") + ("w" if s.writable else "-") + ("x" if s.executable else "-"),
                      "entropy": s.entropy} for s in info.sections[:64]],
        "imports": [{"name": i.name, "library": i.library} for i in info.imports[:300]],
        "exports": info.exports[:100],
        "entropy": {"overall": round(overall, 2), "profile": entropy_profile(data)},
        "packing": packing,
        "strings": {"count": len(refs) if is_bin else (text.count("\n") + 1 if text else 0),
                    "interesting": _interesting(refs, text, iocs, behaviors, xor_offsets, cfg.max_report_strings),
                    "xor_key": xor_key},
        "decoded_layers": [{"encoding": l["encoding"], "offset": l["offset"], "text": l["text"][:4000]} for l in layers],
        "iocs": [{**i.to_dict(), "snippet": i.extra.get("snippet")} for i in iocs],
        "c2_candidates": c2,
        "syscalls": [{"address": s.address, "name": s.name, "number": s.number, "args": s.args} for s in sites[:200]],
        "behaviors": [b.to_dict() for b in behaviors],
        "family": fam.to_dict(),
        "alternatives": [a.to_dict() for a in alternatives],
        "mitre": mitre,
        "risk": risk,
        "snippets": book.items,
        "errors": errors,
    }


_IMPORT_SYS = {"socket": "socket", "connect": "connect", "fork": "fork", "kill": "kill", "bind": "bind", "listen": "listen"}


def _adjust_ioc(ioc: IOC, around: str) -> None:
    if ioc.type == "ip":
        if ioc.value in BENIGN_IPS:
            ioc.scope, ioc.confidence, ioc.context = "infrastructure", 0.1, "well-known public resolver"
        elif VERSIONY.search(around) and around.strip() != ioc.value:
            ioc.confidence = min(ioc.confidence, 0.2)
            ioc.context = "looks like a version number"
        elif around.strip() == ioc.value:
            ioc.confidence = max(ioc.confidence, 0.8)
    elif ioc.type == "endpoint" and ioc.value.split(":")[0] in BENIGN_IPS:
        ioc.scope, ioc.confidence = "infrastructure", 0.1


def _c2_candidates(iocs: list[IOC]) -> list[dict]:
    cands = [i for i in iocs if i.type in ("endpoint", "ip", "domain", "url", "pool") and i.scope in ("public", "documentation", "")
             and i.confidence >= 0.4]
    cands.sort(key=lambda i: ({"endpoint": 0, "url": 1, "pool": 2, "domain": 3, "ip": 4}[i.type], -i.confidence))
    return [{"type": i.type, "value": i.value, "confidence": round(i.confidence, 2), "scope": i.scope} for i in cands[:20]]


def _risk(behaviors: list[Behavior], fam_conf: float, c2: list[dict], packed: bool) -> dict:
    score = sum(b.severity * b.confidence * 3 for b in behaviors) + 15 * fam_conf + min(15, 5 * len(c2)) + (5 if packed else 0)
    score = int(min(100, score))
    level = "critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20 else "low" if score >= 5 else "info"
    return {"score": score, "level": level}


def _interesting(refs: list[StringRef], text: str | None, iocs: list[IOC], behaviors: list[Behavior],
                 xor_offsets: set[int], cap: int) -> list[dict]:
    if text is not None:
        picked = []
        for n, line in enumerate(text.split("\n"), 1):
            if re.search(r"https?://|wget|curl|tftp|chmod|crontab|ssh-|/etc/|/tmp/|nc |bash|\bsh\b|base64|ftpget|busybox", line):
                picked.append({"offset": n, "text": line.strip()[:240], "tags": ["line"]})
            if len(picked) >= cap:
                break
        return picked
    wanted = {i.extra.get("string_offset") for i in iocs} | {e.offset for b in behaviors for e in b.evidence if e.offset is not None}
    key_rx = re.compile(r"/bin/|/proc/|/dev/|/etc/|/tmp|http|wget|curl|chmod|passwd|root|admin|kill|sh -c|tftp|busybox|stratum|\.so|\.sh\b", re.I)
    out: list[dict] = []
    for s in refs:
        tags = []
        if s.offset in wanted:
            tags.append("finding")
        if s.offset in xor_offsets:
            tags.append("xor")
        if key_rx.search(s.text):
            tags.append("keyword")
        if tags:
            out.append({"offset": s.offset, "text": s.text[:240], "tags": tags, "wide": s.wide})
        if len(out) >= cap:
            break
    return out


def _attach_snippets(book: SnippetBook, behaviors: list[Behavior], iocs: list[IOC], data: bytes, text: str | None,
                     insns: list[Insn], sites: list[SyscallSite], info: BinaryInfo, backend: AnalysisBackend | None,
                     path: Path, xor_key: int | None = None, xor_offsets: set[int] | None = None) -> None:
    xor_offsets = xor_offsets or set()
    addr_idx = {i.address: n for n, i in enumerate(insns)}
    site_notes = {s.index: site_label(s) for s in sites}

    # string evidence -> vaddr -> code references (one pass over the instructions)
    want: dict[int, int] = {}                              # vaddr -> file offset
    if insns:
        for off in ({e.offset for b in behaviors for e in b.evidence if e.kind == "string" and e.offset is not None}
                    | {i.extra.get("string_offset") for i in iocs if i.extra.get("string_offset") is not None}):
            va = offset_to_vaddr(info, off)
            if va is not None:
                want[va] = off
    refs = find_refs(info.arch, insns, set(want), make_word_reader(data, info)) if want else {}
    ref_by_off = {want[va]: idxs for va, idxs in refs.items()}
    pc_budget = 6

    def snippet_for_offset(off: int, title: str, label_: str) -> str | None:
        nonlocal pc_budget
        if off in ref_by_off:
            idx = ref_by_off[off][0]
            lines, hl = disasm_lines(insns, idx, 8, 3, site_notes)
            key = book.add(f"ref:{insns[idx].address:x}", "disasm", f"code referencing {label_}", lines, hl,
                           address=insns[idx].address, arch=info.arch)
            if key and backend is not None and pc_budget > 0 and f"pc:{insns[idx].address:x}" not in book.items:
                try:
                    pc = backend.pseudocode(path, info, insns[idx].address)
                except Exception:  # noqa: BLE001
                    pc = None
                if pc:
                    pc_budget -= 1
                    book.add(f"pc:{insns[idx].address:x}", "pseudocode", f"decompiler output near 0x{insns[idx].address:x}",
                             pc.split("\n")[:60], 0, address=insns[idx].address)
            return key
        if xor_key is not None and off in xor_offsets:
            view = data.translate(bytes(b ^ xor_key for b in range(256)))
            lines, hl = hex_lines(view, off)
            return book.add(f"hex:{off:x}", "hexdump", f"{title} (XOR 0x{xor_key:02x}-decoded view)", lines, hl, offset=off,
                            xor_key=xor_key)
        lines, hl = hex_lines(data, off)
        return book.add(f"hex:{off:x}", "hexdump", title, lines, hl, offset=off)

    for b in behaviors:
        done = 0
        for e in b.evidence:
            if done >= 3:
                break
            key = None
            if e.kind == "syscall" and e.address in addr_idx:
                idx = addr_idx[e.address]
                lines, hl = disasm_lines(insns, idx, 6, 2, site_notes)
                site = next((s for s in sites if s.address == e.address), None)
                key = book.add(f"sys:{e.address:x}", "disasm", f"syscall site: {site_label(site) if site else e.detail}", lines, hl,
                               address=e.address, arch=info.arch, lifted=[site_label(site)] if site else [])
                if key and backend is not None and pc_budget > 0 and f"pc:{e.address:x}" not in book.items:
                    try:
                        pc = backend.pseudocode(path, info, e.address)
                    except Exception:  # noqa: BLE001
                        pc = None
                    if pc:
                        pc_budget -= 1
                        e.pseudocode = book.add(f"pc:{e.address:x}", "pseudocode", f"decompiler output near 0x{e.address:x}",
                                                pc.split("\n")[:60], 0, address=e.address)
            elif e.kind == "string" and e.line is not None and text is not None:
                lines, hl = script_lines(text, e.line)
                key = book.add(f"line:{e.line}", "script", f"script line {e.line}", lines, hl, line=e.line)
            elif e.kind == "string" and e.offset is not None and data and text is None:
                key = snippet_for_offset(e.offset, f"bytes at file offset 0x{e.offset:x}", f"string at 0x{e.offset:x}")
            if key:
                e.snippet = key
                done += 1

    for i in iocs:
        key = None
        if text is not None and i.extra.get("line"):
            lines, hl = script_lines(text, i.extra["line"])
            key = book.add(f"line:{i.extra['line']}", "script", f"script line {i.extra['line']}", lines, hl, line=i.extra["line"])
        elif i.extra.get("string_offset") is not None and text is None:
            key = snippet_for_offset(i.extra["string_offset"], f"bytes at file offset 0x{i.extra['string_offset']:x}",
                                     f"{i.type} {i.value[:40]}")
        if key:
            i.extra["snippet"] = key
