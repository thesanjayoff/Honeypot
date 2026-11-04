"""Linux syscall tables + syscall-site recovery from a linear disassembly.

Stripped, statically linked IoT bots have no symbols or imports, but they still have to talk to the
kernel.  Finding ``mov eax, 41; syscall`` (x86-64), ``mov r7, #281; svc 0`` (ARM), ``li $v0, 4183;
syscall`` (MIPS) ... tells us what the code can do.  Only a subset that matters for behaviour
analysis is tabulated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .model import Insn

_COMMON_LOW = {1: "exit", 2: "fork", 3: "read", 4: "write", 5: "open", 6: "close", 10: "unlink", 11: "execve", 12: "chdir",
               15: "chmod", 20: "getpid", 23: "setuid", 26: "ptrace", 37: "kill", 38: "rename", 39: "mkdir", 40: "rmdir",
               41: "dup", 54: "ioctl", 55: "fcntl", 60: "umask", 63: "dup2", 66: "setsid", 85: "readlink", 88: "reboot",
               114: "wait4", 120: "clone", 122: "uname", 162: "nanosleep", 172: "prctl"}

TABLES: dict[str, dict[int, str]] = {
    "x86_64": {0: "read", 1: "write", 2: "open", 3: "close", 7: "poll", 9: "mmap", 10: "mprotect", 16: "ioctl", 23: "select",
               32: "dup", 33: "dup2", 35: "nanosleep", 39: "getpid", 41: "socket", 42: "connect", 43: "accept", 44: "sendto",
               45: "recvfrom", 46: "sendmsg", 47: "recvmsg", 49: "bind", 50: "listen", 54: "setsockopt", 55: "getsockopt",
               56: "clone", 57: "fork", 58: "vfork", 59: "execve", 60: "exit", 61: "wait4", 62: "kill", 63: "uname",
               72: "fcntl", 80: "chdir", 82: "rename", 83: "mkdir", 84: "rmdir", 87: "unlink", 89: "readlink", 90: "chmod",
               95: "umask", 101: "ptrace", 105: "setuid", 112: "setsid", 157: "prctl", 165: "mount", 169: "reboot",
               217: "getdents64", 231: "exit_group", 232: "epoll_wait", 257: "openat", 263: "unlinkat", 288: "accept4",
               292: "dup3"},
    "x86": {**_COMMON_LOW, 90: "mmap", 102: "socketcall", 125: "mprotect", 142: "select", 252: "exit_group", 295: "openat"},
    "arm": {**_COMMON_LOW, 82: "select", 192: "mmap2", 217: "getdents64", 248: "exit_group", 281: "socket", 282: "bind",
            283: "connect", 284: "listen", 285: "accept", 290: "sendto", 292: "recvfrom", 294: "setsockopt", 295: "getsockopt",
            296: "sendmsg", 297: "recvmsg", 322: "openat", 328: "unlinkat", 358: "dup3", 366: "accept4"},
    "aarch64": {24: "dup3", 25: "fcntl", 29: "ioctl", 34: "mkdirat", 35: "unlinkat", 49: "chdir", 56: "openat", 57: "close",
                63: "read", 64: "write", 73: "ppoll", 78: "readlinkat", 93: "exit", 94: "exit_group", 101: "nanosleep",
                117: "ptrace", 129: "kill", 142: "reboot", 146: "setuid", 157: "setsid", 160: "uname", 166: "umask",
                167: "prctl", 172: "getpid", 198: "socket", 200: "bind", 201: "listen", 202: "accept", 203: "connect",
                206: "sendto", 207: "recvfrom", 208: "setsockopt", 209: "getsockopt", 211: "sendmsg", 212: "recvmsg",
                220: "clone", 221: "execve", 222: "mmap", 226: "mprotect", 242: "accept4", 260: "wait4"},
    "mips": {4001: "exit", 4002: "fork", 4003: "read", 4004: "write", 4005: "open", 4006: "close", 4010: "unlink",
             4011: "execve", 4012: "chdir", 4015: "chmod", 4020: "getpid", 4023: "setuid", 4026: "ptrace", 4037: "kill",
             4038: "rename", 4039: "mkdir", 4041: "dup", 4054: "ioctl", 4055: "fcntl", 4060: "umask", 4063: "dup2",
             4066: "setsid", 4085: "readlink", 4088: "reboot", 4090: "mmap", 4114: "wait4", 4120: "clone", 4122: "uname",
             4125: "mprotect", 4142: "select", 4166: "nanosleep", 4168: "accept", 4169: "bind", 4170: "connect",
             4173: "getsockopt", 4174: "listen", 4176: "recvfrom", 4177: "recvmsg", 4179: "sendmsg", 4180: "sendto",
             4181: "setsockopt", 4183: "socket", 4192: "prctl", 4246: "exit_group", 4288: "openat", 4294: "unlinkat",
             4327: "dup3", 4334: "accept4"},
    "ppc": {**_COMMON_LOW, 82: "select", 326: "socket", 327: "bind", 328: "connect", 329: "listen", 330: "accept",
            335: "sendto", 337: "recvfrom", 339: "setsockopt"},
}
TABLES["sparc"] = TABLES["ppc"]
TABLES["m68k"] = TABLES["x86"]

SOCKETCALL = {1: "socket", 2: "bind", 3: "connect", 4: "listen", 5: "accept", 9: "send", 10: "recv", 11: "sendto",
              12: "recvfrom", 14: "setsockopt", 15: "getsockopt", 16: "sendmsg", 17: "recvmsg"}

SYSCALL_MNEMONICS = {"x86_64": ("syscall",), "x86": ("int",), "arm": ("svc", "swi"), "aarch64": ("svc",),
                     "mips": ("syscall",), "ppc": ("sc",)}
_NUM = r"(0x[0-9a-fA-F]+|\d+)"
NUMBER_SETTERS = {
    "x86_64": re.compile(rf"^mov\s+(?:eax|rax|ax|al),\s*{_NUM}$"),
    "x86": re.compile(rf"^mov\s+(?:eax|ax|al),\s*{_NUM}$"),
    "arm": re.compile(rf"^(?:mov|movw|movs)\s+r7,\s*#?{_NUM}$"),
    "aarch64": re.compile(rf"^mov\s+[wx]8,\s*#?{_NUM}$"),
    "mips": re.compile(rf"^(?:li\s+\$v0,\s*{_NUM}|(?:addiu|ori|addi|daddiu)\s+\$v0,\s*\$(?:zero|0),\s*{_NUM})$"),
    "ppc": re.compile(rf"^li\s+(?:r0|0),\s*{_NUM}$"),
}
ARG_SETTERS = {
    "x86_64": [re.compile(rf"^mov\s+(?:edi|rdi),\s*{_NUM}$"), re.compile(rf"^mov\s+(?:esi|rsi),\s*{_NUM}$"),
               re.compile(rf"^mov\s+(?:edx|rdx),\s*{_NUM}$")],
    "x86": [re.compile(rf"^mov\s+ebx,\s*{_NUM}$"), re.compile(rf"^mov\s+ecx,\s*{_NUM}$"), re.compile(rf"^mov\s+edx,\s*{_NUM}$")],
    "arm": [re.compile(rf"^mov\s+r{i},\s*#?{_NUM}$") for i in range(3)],
    "aarch64": [re.compile(rf"^mov\s+[wx]{i},\s*#?{_NUM}$") for i in range(3)],
    "mips": [re.compile(rf"^(?:li\s+\$a{i},\s*{_NUM}|(?:addiu|ori)\s+\$a{i},\s*\$(?:zero|0),\s*{_NUM})$") for i in range(3)],
}


@dataclass
class SyscallSite:
    index: int
    address: int
    number: int | None
    name: str
    args: list[int | None] = field(default_factory=list)


def _val(m: re.Match[str]) -> int:
    g = next(x for x in m.groups() if x is not None)
    return int(g, 0)


def _is_syscall(arch: str, insn: Insn) -> bool:
    mn = insn.mnemonic.lower()
    if mn not in SYSCALL_MNEMONICS.get(arch, ()):
        return False
    if arch == "x86":
        return insn.op_str.strip().lower() == "0x80"
    return True


def find_syscalls(arch: str, insns: list[Insn], window: int = 14) -> list[SyscallSite]:
    setter = NUMBER_SETTERS.get(arch)
    table = TABLES.get(arch)
    if setter is None or table is None:
        return []
    sites: list[SyscallSite] = []
    arg_res = ARG_SETTERS.get(arch, [])
    for i, ins in enumerate(insns):
        if not _is_syscall(arch, ins):
            continue
        number: int | None = None
        args: list[int | None] = [None, None, None]
        saw_arg = [False, False, False]
        for j in range(i - 1, max(-1, i - window - 1), -1):
            prev = insns[j]
            if _is_syscall(arch, prev):          # setup before an earlier syscall belongs to that one
                break
            text = prev.text().lower()
            if number is None:
                m = setter.match(text)
                if m:
                    number = _val(m)
            if arch in ("x86", "x86_64") and text in ("xor eax, eax", "xor rax, rax") and number is None:
                number = 0
            for k, rx in enumerate(arg_res):
                if not saw_arg[k]:
                    mm = rx.match(text)
                    if mm:
                        args[k] = _val(mm); saw_arg[k] = True
            if prev.mnemonic.lower() in ("ret", "retn", "jr", "bx", "blr") and j < i - 1:
                break
        if number is None:
            continue
        name = table.get(number, f"sys_{number}")
        if arch == "x86" and name == "socketcall" and args[0] is not None:
            name = SOCKETCALL.get(args[0], name)
        sites.append(SyscallSite(i, ins.address, number, name, args))
    return sites
