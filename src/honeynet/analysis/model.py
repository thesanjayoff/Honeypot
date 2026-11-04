"""Data model + the small adapter interface to the reverse-engineering backend.

Everything outside the ``AnalysisBackend`` implementations talks only to these types, so the
RE tool can be swapped (built-in capstone/pyelftools/pefile, an external command, ...) without
touching IOC extraction, behaviour detection, family labelling or reporting.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Section:
    name: str
    vaddr: int
    offset: int
    size: int
    executable: bool = False
    writable: bool = False
    readable: bool = True
    entropy: float = 0.0       # filled by the engine


@dataclass
class Import:
    name: str
    library: str = ""


@dataclass
class Insn:
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes_hex: str = ""

    def text(self) -> str:
        return f"{self.mnemonic} {self.op_str}".strip()


@dataclass
class BinaryInfo:
    fmt: str = "unknown"             # ELF | PE | unknown
    arch: str = "unknown"            # x86 | x86_64 | arm | aarch64 | mips | ppc | sh4 | ...
    bits: int = 0
    endian: str = "little"
    entry: int = 0
    file_type: str = ""              # e.g. executable / shared object / DLL
    sections: list[Section] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)
    symbols: int = 0
    stripped: bool = True
    static: bool = False
    has_section_headers: bool = True
    interpreter: str = ""
    overlay_size: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BinaryInfo":
        d = dict(d)
        d["sections"] = [Section(**s) for s in d.get("sections", [])]
        d["imports"] = [Import(**i) for i in d.get("imports", [])]
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})


class BackendUnavailable(RuntimeError):
    pass


class AnalysisBackend(ABC):
    """Adapter interface - three methods are all the rest of the code needs."""

    name = "abstract"

    @classmethod
    def available(cls) -> bool:
        return True

    def version(self) -> str:
        return ""

    @abstractmethod
    def inspect(self, path: Path) -> BinaryInfo:
        """Parse headers: format, architecture, sections (with file offsets), imports, entry..."""

    @abstractmethod
    def disassemble(self, path: Path, info: BinaryInfo, max_insns: int = 300_000) -> list[Insn]:
        """Linear-sweep disassembly of all executable code (best effort, bounded)."""

    def pseudocode(self, path: Path, info: BinaryInfo, address: int) -> str | None:
        """Decompiler output for the function at/around ``address`` (None if unsupported)."""
        return None
