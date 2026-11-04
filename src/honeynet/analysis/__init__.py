"""Static malware analysis for captured samples.

The rest of honeynet only needs :func:`analyze_file` and :func:`get_backend`; the reverse
engineering tool itself sits behind :class:`~honeynet.analysis.model.AnalysisBackend`.
"""

from __future__ import annotations

from .model import AnalysisBackend, BackendUnavailable, BinaryInfo, Insn


def get_backend(name: str = "builtin", command: str = "", timeout: int = 60) -> AnalysisBackend:
    """Backend factory: ``builtin`` (capstone/pyelftools/pefile), ``command`` (external tool) or ``auto``."""
    name = (name or "builtin").lower()
    if name == "command" or (name == "auto" and command):
        from .command_backend import CommandBackend

        return CommandBackend(command, timeout)
    from .builtin import BuiltinBackend

    if not BuiltinBackend.available():
        raise BackendUnavailable("capstone is not installed (pip install 'honeynet[analysis]')")
    return BuiltinBackend()


def analyze_file(path, backend: AnalysisBackend | None = None, cfg=None) -> dict:
    from .engine import analyze_file as _analyze

    return _analyze(path, backend, cfg)


__all__ = ["AnalysisBackend", "BackendUnavailable", "BinaryInfo", "Insn", "analyze_file", "get_backend"]
