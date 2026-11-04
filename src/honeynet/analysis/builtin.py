"""Built-in static backend: pyelftools (ELF) + pefile (PE) + capstone (disassembly).

Static only - nothing is ever loaded, mapped as executable or run.  Parsers are wrapped
defensively: malformed/packed samples are normal here and must degrade, not crash.
"""

from __future__ import annotations

import struct
from pathlib import Path

from .model import AnalysisBackend, BackendUnavailable, BinaryInfo, Import, Insn, Section

try:
    import capstone as cs
except ImportError:  # pragma: no cover
    cs = None  # type: ignore[assignment]

EM_NAMES = {3: ("x86", 32), 62: ("x86_64", 64), 40: ("arm", 32), 183: ("aarch64", 64), 8: ("mips", 32),
            20: ("ppc", 32), 21: ("ppc64", 64), 42: ("sh4", 32), 2: ("sparc", 32), 43: ("sparc64", 64),
            4: ("m68k", 32), 93: ("arc", 32), 243: ("riscv", 64), 22: ("s390", 64)}


def _capstone_cfg(info: BinaryInfo):
    if cs is None:
        raise BackendUnavailable("capstone not installed")
    big = info.endian == "big"
    endian = cs.CS_MODE_BIG_ENDIAN if big else cs.CS_MODE_LITTLE_ENDIAN
    table = {
        "x86": (cs.CS_ARCH_X86, cs.CS_MODE_32),
        "x86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
        "arm": (cs.CS_ARCH_ARM, cs.CS_MODE_ARM | endian),
        "aarch64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM | endian),
        "mips": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | endian),
        "ppc": (cs.CS_ARCH_PPC, cs.CS_MODE_32 | cs.CS_MODE_BIG_ENDIAN),
        "sparc": (cs.CS_ARCH_SPARC, cs.CS_MODE_BIG_ENDIAN),
        "m68k": (cs.CS_ARCH_M68K, cs.CS_MODE_M68K_000 | cs.CS_MODE_BIG_ENDIAN),
    }
    return table.get(info.arch)


class BuiltinBackend(AnalysisBackend):
    name = "builtin"

    @classmethod
    def available(cls) -> bool:
        return cs is not None

    def version(self) -> str:
        parts = []
        for mod in ("capstone", "elftools", "pefile"):
            try:
                m = __import__(mod)
                parts.append(f"{mod} {getattr(m, '__version__', getattr(m, '__version', '?'))}")
            except ImportError:
                pass
        return ", ".join(parts)

    # ------------------------------------------------------------------ inspect
    def inspect(self, path: Path) -> BinaryInfo:
        data = Path(path).read_bytes()[:64]
        if data[:4] == b"\x7fELF":
            return self._inspect_elf(path)
        if data[:2] == b"MZ":
            return self._inspect_pe(path)
        return BinaryInfo(fmt="unknown")

    def _inspect_elf(self, path: Path) -> BinaryInfo:
        info = self._manual_elf(path)
        try:
            from elftools.elf.elffile import ELFFile

            with open(path, "rb") as fh:
                elf = ELFFile(fh)
                info.file_type = elf["e_type"].replace("ET_", "").lower()
                info.has_section_headers = elf["e_shnum"] > 0
                secs: list[Section] = []
                for s in elf.iter_sections():
                    flags = s["sh_flags"]
                    if s["sh_type"] == "SHT_NULL":
                        continue
                    secs.append(Section(s.name or "?", s["sh_addr"], s["sh_offset"],
                                        0 if s["sh_type"] == "SHT_NOBITS" else s["sh_size"],
                                        bool(flags & 4), bool(flags & 1)))
                if secs:
                    info.sections = secs
                info.stripped = elf.get_section_by_name(".symtab") is None
                symtab = elf.get_section_by_name(".symtab")
                if symtab is not None:
                    info.symbols = symtab.num_symbols()
                    funcs = [sym.name for sym in symtab.iter_symbols() if sym["st_info"]["type"] == "STT_FUNC" and sym.name]
                    info.extra["function_symbols"] = funcs[:300]
                imports: list[Import] = []
                dynsym = elf.get_section_by_name(".dynsym")
                if dynsym is not None:
                    for sym in dynsym.iter_symbols():
                        if sym["st_shndx"] == "SHN_UNDEF" and sym.name:
                            imports.append(Import(sym.name))
                        elif sym.name and sym["st_shndx"] != "SHN_UNDEF" and sym["st_info"]["type"] == "STT_FUNC":
                            info.exports.append(sym.name)
                info.imports = imports[:2000]
                dyn = elf.get_section_by_name(".dynamic")
                if dyn is not None:
                    info.libraries = [t.needed for t in dyn.iter_tags() if t.entry.d_tag == "DT_NEEDED"]
                for seg in elf.iter_segments():
                    if seg["p_type"] == "PT_INTERP":
                        info.interpreter = seg.get_interp_name()
                info.static = not info.interpreter and not info.libraries
        except Exception as exc:  # noqa: BLE001 - malformed ELF: keep the manual header parse
            info.extra["parse_warning"] = f"pyelftools: {type(exc).__name__}: {str(exc)[:120]}"
        return info

    def _manual_elf(self, path: Path) -> BinaryInfo:
        """Header + program-header parse that survives section-header damage (UPX etc.)."""
        raw = Path(path).read_bytes()
        info = BinaryInfo(fmt="ELF")
        if len(raw) < 52:
            return info
        is64 = raw[4] == 2
        little = raw[5] != 2
        e = "<" if little else ">"
        info.bits = 64 if is64 else 32
        info.endian = "little" if little else "big"
        try:
            machine = struct.unpack_from(e + "H", raw, 18)[0]
            info.arch, bits = EM_NAMES.get(machine, (f"em{machine}", info.bits))
            if is64:
                entry, phoff, shoff = struct.unpack_from(e + "QQQ", raw, 24)
                phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", raw, 54)
            else:
                entry, phoff, shoff = struct.unpack_from(e + "III", raw, 24)
                phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", raw, 42)
            info.entry = entry
            info.has_section_headers = shnum > 0 and shoff > 0
            info.extra["e_shnum"] = shnum
            info.extra["e_phnum"] = phnum
            has_interp = has_dynamic = False
            segs: list[Section] = []
            for i in range(min(phnum, 64)):
                off = phoff + i * phentsize
                if is64:
                    p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, p_memsz, _al = struct.unpack_from(e + "IIQQQQQQ", raw, off)
                else:
                    p_type, p_offset, p_vaddr, _pa, p_filesz, p_memsz, p_flags, _al = struct.unpack_from(e + "IIIIIIII", raw, off)
                if p_type == 3:
                    has_interp = True
                elif p_type == 2:
                    has_dynamic = True
                elif p_type == 1:
                    segs.append(Section(f"LOAD#{len(segs)}", p_vaddr, p_offset, p_filesz, bool(p_flags & 1), bool(p_flags & 2),
                                        bool(p_flags & 4)))
            info.sections = segs
            info.static = not has_interp and not has_dynamic
            info.interpreter = "present" if has_interp else ""
            if not info.has_section_headers:
                info.stripped = True
        except struct.error:
            info.extra["parse_warning"] = "truncated ELF headers"
        return info

    def _inspect_pe(self, path: Path) -> BinaryInfo:
        import pefile

        info = BinaryInfo(fmt="PE", endian="little")
        try:
            pe = pefile.PE(str(path), fast_load=False)
        except pefile.PEFormatError as exc:
            info.extra["parse_warning"] = f"pefile: {exc}"
            return info
        machine = pe.FILE_HEADER.Machine
        info.arch = {0x14C: "x86", 0x8664: "x86_64", 0x1C0: "arm", 0x1C4: "arm", 0xAA64: "aarch64"}.get(machine, f"0x{machine:x}")
        info.bits = 64 if pe.OPTIONAL_HEADER.Magic == 0x20B else 32
        base = pe.OPTIONAL_HEADER.ImageBase
        info.entry = base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        info.file_type = "dll" if pe.is_dll() else "executable"
        for s in pe.sections:
            ch = s.Characteristics
            info.sections.append(Section(s.Name.rstrip(b"\x00").decode("latin-1"), base + s.VirtualAddress, s.PointerToRawData,
                                         s.SizeOfRawData, bool(ch & 0x20000000), bool(ch & 0x80000000)))
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            lib = entry.dll.decode("latin-1", "replace")
            info.libraries.append(lib)
            for imp in entry.imports:
                info.imports.append(Import(imp.name.decode("latin-1", "replace") if imp.name else f"ord{imp.ordinal}", lib))
        for sym in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or []:
            if sym.name:
                info.exports.append(sym.name.decode("latin-1", "replace"))
        info.symbols = 0
        info.stripped = True
        overlay = pe.get_overlay_data_start_offset()
        size = Path(path).stat().st_size
        info.overlay_size = max(0, size - overlay) if overlay else 0
        info.extra.update({"timestamp": pe.FILE_HEADER.TimeDateStamp, "subsystem": pe.OPTIONAL_HEADER.Subsystem,
                           "has_signature": bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size)})
        pe.close()
        return info

    # --------------------------------------------------------------- disassemble
    def disassemble(self, path: Path, info: BinaryInfo, max_insns: int = 300_000) -> list[Insn]:
        cfg = _capstone_cfg(info)
        if cfg is None:
            raise BackendUnavailable(f"no disassembler for architecture {info.arch!r}")
        raw = Path(path).read_bytes()
        md = cs.Cs(*cfg)
        md.skipdata = True
        out: list[Insn] = []
        ranges = [s for s in info.sections if s.executable and s.size > 0]
        if not ranges and info.fmt == "ELF":      # stripped section headers: fall back to the entry segment
            ranges = [s for s in info.sections if s.size > 0][:1]
        for sec in ranges:
            code = raw[sec.offset: sec.offset + sec.size]
            for i in md.disasm(code, sec.vaddr):
                out.append(Insn(i.address, i.size, i.mnemonic, i.op_str, i.bytes.hex()))
                if len(out) >= max_insns:
                    return out
        return out
