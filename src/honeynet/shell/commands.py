"""Emulated commands for the fake shell. Pure Python; nothing is ever executed."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import posixpath
import random
import re
import time
from typing import Awaitable, Callable

from .fakefs import FSError, Node, split_path
from .interp import (BreakLoop, ContinueLoop, Proc, ReturnFunc, ShellExit)

CmdFn = Callable[..., Awaitable[int]]
COMMANDS: dict[str, CmdFn] = {}
BUILTINS: dict[str, CmdFn] = {}
ALWAYS = {"cd", "export", "echo", "printf", "exit", "true", "false", "test", "[", ":", "unset", "set", "read",
          "eval", "source", ".", "shift", "return", "break", "continue", "type", "command", "alias", "umask",
          "trap", "wait", "local", "pwd", "history", "ulimit", "exec", "hash", "kill", "enable", "readonly", "fg", "bg", "jobs"}


def cmd(*names: str, builtin: bool = False):
    def deco(fn: CmdFn) -> CmdFn:
        for n in names:
            (BUILTINS if builtin else COMMANDS)[n] = fn
        return fn
    return deco


def _bytes(s: str) -> bytes:
    return s.encode("utf-8", "surrogateescape")


def _read_files(sh, files: list[str], p: Proc, name: str) -> tuple[bytes, int]:
    """Concatenate file contents (or stdin when no files / '-')."""
    if not files:
        return p.stdin, 0
    out, status = b"", 0
    for f in files:
        if f == "-":
            out += p.stdin
            continue
        try:
            node = sh.fs.lookup(sh.abspath(f))
        except FSError as e:
            p.error(f"{name}: {f}: {e}\n"); status = 1; continue
        if node is None:
            p.error(f"{name}: {f}: No such file or directory\n"); status = 1
        elif node.kind == "d":
            p.error(f"{name}: {f}: Is a directory\n"); status = 1
        else:
            out += node.content
    return out, status


def _opts(args: list[str], with_val: str = "") -> tuple[set[str], dict[str, str], list[str]]:
    """Tiny getopt: returns (flags, valued opts, positionals). '--' ends options."""
    flags: set[str] = set()
    vals: dict[str, str] = {}
    rest: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            rest.extend(args[i + 1:]); break
        if a.startswith("--") and len(a) > 2:
            k, eq, v = a[2:].partition("=")
            if eq:
                vals[k] = v
            else:
                flags.add(k)
        elif a.startswith("-") and len(a) > 1 and not a[1:].isdigit():
            j = 1
            while j < len(a):
                ch = a[j]
                if ch in with_val:
                    v = a[j + 1:] or (args[i + 1] if i + 1 < len(args) else "")
                    if not a[j + 1:]:
                        i += 1
                    vals[ch] = v
                    break
                flags.add(ch); j += 1
        else:
            rest.append(a)
        i += 1
    return flags, vals, rest


# ---------------------------------------------------------------- escapes

def _unescape(s: str) -> bytes:
    """echo -e / printf escape processing -> raw bytes (supports \\xHH for binary droppers)."""
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c != "\\" or i + 1 >= len(s):
            out += c.encode("utf-8", "surrogateescape"); i += 1; continue
        n = s[i + 1]
        simple = {"n": 10, "t": 9, "r": 13, "a": 7, "b": 8, "f": 12, "v": 11, "e": 27, "E": 27, "\\": 92}
        if n in simple:
            out.append(simple[n]); i += 2
        elif n == "c":
            break
        elif n == "x":
            m = re.match(r"[0-9a-fA-F]{1,2}", s[i + 2:])
            if m:
                out.append(int(m.group(), 16)); i += 2 + len(m.group())
            else:
                out += b"\\x"; i += 2
        elif n in "0123":
            m = re.match(r"[0-7]{1,4}", s[i + 1:])
            tok = m.group().lstrip("0") if m else ""
            out.append((int(tok, 8) if tok else 0) & 0xFF); i += 1 + len(m.group())  # type: ignore[union-attr]
        elif n in "4567":
            m = re.match(r"[0-7]{1,3}", s[i + 1:])
            out.append(int(m.group(), 8) & 0xFF); i += 1 + len(m.group())  # type: ignore[union-attr]
        else:
            out += b"\\" + n.encode(); i += 2
    return bytes(out)


# ================================================================= builtins

@cmd("echo", builtin=True)
async def c_echo(sh, argv, p):
    args = argv[1:]
    nl, esc = True, False
    while args and re.fullmatch(r"-[neE]+", args[0]):
        if "n" in args[0]:
            nl = False
        if "e" in args[0]:
            esc = True
        if "E" in args[0]:
            esc = False
        args = args[1:]
    text = " ".join(args)
    p.write(_unescape(text) if esc else _bytes(text))
    if nl:
        p.write("\n")
    return 0


@cmd("printf", builtin=True)
async def c_printf(sh, argv, p):
    if len(argv) < 2:
        p.error("printf: usage: printf format [arguments]\n"); return 2
    fmt, args = argv[1], argv[2:]
    spec_re = re.compile(r"%([-+ #0]*\d*(?:\.\d+)?[diouxXcsb%])")
    pieces = spec_re.split(fmt)          # literal, spec, literal, spec, ...
    out = bytearray()
    ai = 0
    for _ in range(64):
        used = False
        for idx, piece in enumerate(pieces):
            if idx % 2 == 0:
                out += _unescape(piece)
                continue
            if piece == "%":
                out += b"%"; continue
            used = True
            val = args[ai] if ai < len(args) else ""
            ai += 1
            conv = piece[-1]
            try:
                if conv in "di":
                    out += (("%" + piece[:-1] + "d") % int(val or 0, 0)).encode()
                elif conv in "uxXo":
                    out += (("%" + piece) % int(val or 0, 0)).encode()
                elif conv == "c":
                    out += val[:1].encode("utf-8", "surrogateescape")
                elif conv == "b":
                    out += _unescape(val)
                else:
                    out += (("%" + piece) % val).encode("utf-8", "surrogateescape")
            except (ValueError, TypeError):
                out += b""
        if ai >= len(args) or not used:
            break
    p.write(bytes(out))
    return 0


@cmd("cd", builtin=True)
async def c_cd(sh, argv, p):
    target = argv[1] if len(argv) > 1 else sh.home
    if target == "-":
        target = sh.vars.get("OLDPWD", sh.cwd)
    path = sh.abspath(target)
    node = sh.fs.lookup(path)
    if node is None:
        p.error(f"sh: cd: can't cd to {target}\n" if sh.persona.busybox else f"bash: cd: {target}: No such file or directory\n")
        return 1
    if node.kind != "d":
        p.error(f"bash: cd: {target}: Not a directory\n"); return 1
    sh.vars["OLDPWD"] = sh.cwd
    sh.cwd = path
    return 0


@cmd("pwd", builtin=True)
async def c_pwd(sh, argv, p):
    p.write(sh.cwd + "\n"); return 0


@cmd("export", "readonly", "local", builtin=True)
async def c_export(sh, argv, p):
    for a in argv[1:]:
        if a.startswith("-"):
            continue
        k, eq, v = a.partition("=")
        if eq:
            sh.vars[k] = v
    return 0


@cmd("unset", builtin=True)
async def c_unset(sh, argv, p):
    for a in argv[1:]:
        sh.vars.pop(a, None)
    return 0


@cmd("set", builtin=True)
async def c_set(sh, argv, p):
    if len(argv) == 1:
        for k, v in sorted(sh.vars.items()):
            p.write(f"{k}='{v}'\n")
    elif argv[1] == "--":
        sh.positional = argv[2:]
    return 0


@cmd("shift", builtin=True)
async def c_shift(sh, argv, p):
    n = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 1
    sh.positional = sh.positional[n:]
    return 0


@cmd("exit", "logout", builtin=True)
async def c_exit(sh, argv, p):
    raise ShellExit(int(argv[1]) if len(argv) > 1 and argv[1].lstrip("-").isdigit() else sh.status)


@cmd("return", builtin=True)
async def c_return(sh, argv, p):
    raise ReturnFunc(int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else sh.status)


@cmd("break", builtin=True)
async def c_break(sh, argv, p):
    raise BreakLoop(int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 1)


@cmd("continue", builtin=True)
async def c_continue(sh, argv, p):
    raise ContinueLoop(int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 1)


@cmd("true", ":", "alias", "umask", "trap", "wait", "hash", "fg", "bg", "jobs", "stty", "reset", "sync", "enable",
     "chattr", "chown", "chgrp", "setenforce", "swapoff", "nice", "renice", "disown", "sysctl", "ulimit", builtin=True)
async def c_true(sh, argv, p):
    if argv[0] == "ulimit":
        p.write("unlimited\n")
    if argv[0] == "enable":
        # classic telnet-IoT "enable" probe: busybox sh has no such command
        p.error("sh: enable: not found\n" if sh.persona.busybox else "bash: enable: not found\n")
        return 127
    return 0


@cmd("false", builtin=True)
async def c_false(sh, argv, p):
    return 1


@cmd("read", builtin=True)
async def c_read(sh, argv, p):
    names = [a for a in argv[1:] if not a.startswith("-")] or ["REPLY"]
    line = p.stdin.decode("utf-8", "replace").split("\n", 1)[0]
    parts = line.split(None, len(names) - 1)
    for i, n in enumerate(names):
        sh.vars[n] = parts[i] if i < len(parts) else ""
    return 0 if p.stdin else 1


@cmd("history", builtin=True)
async def c_history(sh, argv, p):
    if "-c" in argv:
        sh.history.clear(); return 0
    for i, h in enumerate(sh.history[-100:], 1):
        p.write(f"{i:5d}  {h.splitlines()[0] if h else ''}\n")
    return 0


@cmd("eval", builtin=True)
async def c_eval(sh, argv, p):
    return await sh.run_script(" ".join(argv[1:]), p, sh.positional, sh.arg0)


@cmd("source", ".", builtin=True)
async def c_source(sh, argv, p):
    if len(argv) < 2:
        return 2
    data, st = _read_files(sh, [argv[1]], p, argv[0])
    if st:
        return st
    return await sh.run_script(data.decode("utf-8", "replace"), p, argv[2:], argv[1])


@cmd("exec", builtin=True)
async def c_exec(sh, argv, p):
    if len(argv) > 1:
        return await sh.run_command(argv[1:], p)
    return 0


@cmd("type", "command", builtin=True)
async def c_type(sh, argv, p):
    args = [a for a in argv[1:] if not a.startswith("-")]
    st = 0
    for a in args:
        path = _which(sh, a)
        if path:
            p.write(f"{a} is {path}\n" if argv[0] == "type" else f"{path}\n")
        else:
            st = 1
            if argv[0] == "type":
                p.error(f"sh: type: {a}: not found\n")
    return st


def _which(sh, name: str) -> str | None:
    for d in sh.vars.get("PATH", "").split(":"):
        path = f"{d}/{name}"
        node = sh.fs.lookup(path)
        if node is not None and node.kind == "f":
            return path
    return None


@cmd("which")
async def c_which(sh, argv, p):
    st = 0
    for a in argv[1:]:
        if a.startswith("-"):
            continue
        path = _which(sh, a)
        if path:
            p.write(path + "\n")
        else:
            st = 1
    return st


@cmd("test", "[", builtin=True)
async def c_test(sh, argv, p):
    args = list(argv[1:])
    if argv[0] == "[":
        if not args or args[-1] != "]":
            p.error("sh: [: missing ]\n"); return 2
        args = args[:-1]

    def ev(a: list[str]) -> bool:
        if not a:
            return False
        if "-o" in a:
            i = a.index("-o"); return ev(a[:i]) or ev(a[i + 1:])
        if "-a" in a[1:]:
            i = a.index("-a", 1); return ev(a[:i]) and ev(a[i + 1:])
        if a[0] == "!":
            return not ev(a[1:])
        if len(a) == 1:
            return a[0] != ""
        if len(a) == 2:
            op, v = a
            path = sh.abspath(v) if v else "/nonexistent"
            node = sh.fs.lookup(path) if op in ("-e", "-f", "-d", "-s", "-x", "-r", "-w", "-L", "-c", "-h") else None
            if op == "-z": return v == ""
            if op == "-n": return v != ""
            if op == "-e": return node is not None
            if op == "-f": return bool(node and node.kind == "f")
            if op == "-d": return bool(node and node.kind == "d")
            if op in ("-L", "-h"): return bool(sh.fs.lookup(path, follow=False) and sh.fs.lookup(path, follow=False).kind == "l")  # type: ignore[union-attr]
            if op == "-s": return bool(node and node.size > 0)
            if op == "-x": return bool(node and node.mode & 0o111)
            if op in ("-r", "-w"): return node is not None
            return False
        if len(a) == 3:
            l, op, r = a
            if op in ("=", "=="): return l == r
            if op == "!=": return l != r
            try:
                li, ri = int(l), int(r)
            except ValueError:
                return False
            return {"-eq": li == ri, "-ne": li != ri, "-lt": li < ri, "-gt": li > ri, "-le": li <= ri, "-ge": li >= ri}.get(op, False)
        return False

    return 0 if ev(args) else 1


# ============================================================ sh / scripts

@cmd("sh", "bash", "ash", "dash", "zsh", "ksh")
async def c_sh(sh, argv, p):
    args = argv[1:]
    script = None
    rest: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-c" and i + 1 < len(args):
            script = args[i + 1]; rest = args[i + 2:]; break
        if a.startswith("-") and len(a) > 1:
            i += 1; continue
        break
    if script is not None:
        return await sh.run_script(script, p, rest[1:] if rest else [], rest[0] if rest else argv[0])
    if i < len(args):
        path = sh.abspath(args[i])
        node = sh.fs.lookup(path)
        if node is None:
            p.error(f"{argv[0]}: {args[i]}: No such file or directory\n" if not sh.persona.busybox else f"sh: can't open '{args[i]}'\n")
            return 127
        sha = sh.capture_file(path, node, "exec")
        sh.emit("file.exec_attempt", path=path, sha256=sha or "", size=len(node.content), args=args[i + 1:i + 8], via=argv[0])
        return await sh.run_script(node.content.decode("utf-8", "replace"), p, args[i + 1:], args[i])
    if p.stdin:
        return await sh.run_script(p.stdin.decode("utf-8", "replace"), p, [], argv[0])
    return 0


@cmd("python", "python3", "python2", "perl", "php", "ruby", "node")
async def c_interp(sh, argv, p):
    if any(a in ("--version", "-V", "-v") for a in argv[1:2]):
        p.write({"python": "Python 2.7.16", "python2": "Python 2.7.16", "python3": "Python 3.7.3",
                 "perl": "This is perl 5, version 28, subversion 1 (v5.28.1)", "php": "PHP 7.3.31-1~deb10u1 (cli)"}
                .get(argv[0], argv[0] + " 1.0") + "\n")
        return 0
    for a in argv[1:]:
        if not a.startswith("-"):
            path = sh.abspath(a)
            node = sh.fs.lookup(path)
            if node is not None and node.kind == "f":
                sha = sh.capture_file(path, node, "exec")
                sh.emit("file.exec_attempt", path=path, sha256=sha or "", size=len(node.content), via=argv[0])
            break
    return 0


@cmd("busybox")
async def c_busybox(sh, argv, p):
    if len(argv) == 1:
        p.write("BusyBox v1.22.1 (2019-03-12 17:09:40 CST) multi-call binary.\n"
                "BusyBox is copyrighted by many authors between 1998-2012.\n"
                "Licensed under GPLv2. See source distribution for detailed\ncopyright notices.\n\n"
                "Usage: busybox [function [arguments]...]\n   or: busybox --list[-full]\n   or: function [arguments]...\n\n"
                "\tBusyBox is a multi-call binary that combines many common Unix\n\tutilities into a single executable.\n\n"
                "Currently defined functions:\n\t[, [[, ash, awk, cat, chmod, cp, echo, grep, kill, ls, mkdir, mount,\n"
                "\tmv, ping, ps, rm, sh, sleep, tftp, touch, wget\n\n")
        return 0
    name = argv[1]
    if name in COMMANDS or name in BUILTINS:
        return await sh.run_command(argv[1:], p)
    p.error(f"{name}: applet not found\n")
    return 127


# ================================================================ file ops

def _mode_str(n: Node) -> str:
    t = {"d": "d", "l": "l", "c": "c"}.get(n.kind, "-")
    m = n.mode
    s = ""
    for shift in (6, 3, 0):
        bits = (m >> shift) & 7
        s += ("r" if bits & 4 else "-") + ("w" if bits & 2 else "-") + ("x" if bits & 1 else "-")
    return t + s


def _owner(sh, uid: int) -> str:
    for n, u, *_ in sh.persona.users:
        if u == uid:
            return n
    return str(uid)


def _human(n: int) -> str:
    for unit in ("", "K", "M", "G"):
        if n < 1024:
            return f"{n}{unit}" if unit == "" else f"{n:.1f}{unit}".replace(".0", "")
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f}T"


@cmd("ls", "dir", "ll")
async def c_ls(sh, argv, p):
    flags, _, paths = _opts(argv[1:])
    long = "l" in flags or argv[0] == "ll"
    show_all = "a" in flags or "A" in flags
    one = "1" in flags
    paths = paths or ["."]
    status = 0
    multi = len(paths) > 1
    for target in paths:
        for path in (sh.fs.glob(target, sh.cwd) if any(c in target for c in "*?[") else [target]) or [target]:
            ap = sh.abspath(path)
            try:
                node = sh.fs.lookup(ap)
            except FSError as e:
                p.error(f"ls: {path}: {e}\n"); status = 2; continue
            if node is None:
                p.error(f"ls: cannot access {path}: No such file or directory\n" if not sh.persona.busybox
                        else f"ls: {path}: No such file or directory\n")
                status = 2; continue
            if node.kind == "d" and "d" not in flags:
                names = sh.fs.listdir(ap)
                if show_all:
                    names = [".", ".."] + names
                else:
                    names = [n for n in names if not n.startswith(".")]
                def _node_for(n: str) -> Node:
                    if n == ".":
                        return node
                    if n == "..":
                        return sh.fs.lookup(split_path(ap)[0]) or node
                    return sh.fs.lookup(posixpath.join(ap, n)) or Node("d", 0o755)
                entries = [(n, _node_for(n)) for n in names]
                if multi:
                    p.write(f"{path}:\n")
                if long:
                    p.write(f"total {max(4, len(entries) * 4)}\n")
            else:
                entries = [(path, node)]
            if long:
                for n, nd in entries:
                    when = time.strftime("%b %e %H:%M", time.gmtime(nd.mtime or time.time()))
                    size = _human(nd.size) if "h" in flags else str(nd.size)
                    p.write(f"{_mode_str(nd)} {2 if nd.kind == 'd' else 1:>2} {_owner(sh, nd.uid):<8} {_owner(sh, nd.gid):<8} {size:>6} {when} {n}"
                            + (f" -> {nd.target}" if nd.kind == "l" else "") + "\n")
            elif one or not entries:
                for n, _ in entries:
                    p.write(n + "\n")
            else:
                p.write("  ".join(n for n, _ in entries) + "\n")
            if multi:
                p.write("\n")
    return status


@cmd("cat", "tac")
async def c_cat(sh, argv, p):
    flags, _, files = _opts(argv[1:])
    data, st = _read_files(sh, files, p, "cat")
    if argv[0] == "tac":
        data = b"\n".join(reversed(data.split(b"\n")))
    p.write(data)
    return st


@cmd("mkdir")
async def c_mkdir(sh, argv, p):
    flags, _, dirs = _opts(argv[1:])
    st = 0
    for d in dirs:
        try:
            sh.fs.mkdir(sh.abspath(d), parents="p" in flags)
        except FSError as e:
            p.error(f"mkdir: can't create directory '{d}': {e}\n"); st = 1
    return st


@cmd("rmdir")
async def c_rmdir(sh, argv, p):
    st = 0
    for d in argv[1:]:
        try:
            sh.fs.rmdir(sh.abspath(d))
        except FSError as e:
            p.error(f"rmdir: failed to remove '{d}': {e}\n"); st = 1
    return st


@cmd("rm")
async def c_rm(sh, argv, p):
    flags, _, files = _opts(argv[1:])
    st = 0
    for f in files:
        matches = sh.fs.glob(f, sh.cwd) if any(c in f for c in "*?[") else [f]
        if not matches and "f" not in flags:
            p.error(f"rm: cannot remove '{f}': No such file or directory\n"); st = 1
        for m in matches:
            path = sh.abspath(m)
            node = sh.fs.lookup(path, follow=False)
            if node is not None:
                sh.capture_file(path, node, "rm")
            try:
                sh.fs.remove(path, recursive=bool(flags & {"r", "R", "recursive"}))
            except FSError as e:
                if "f" not in flags:
                    p.error(f"rm: cannot remove '{m}': {e}\n"); st = 1
    return st


@cmd("touch")
async def c_touch(sh, argv, p):
    st = 0
    for f in argv[1:]:
        if f.startswith("-"):
            continue
        path = sh.abspath(f)
        try:
            if sh.fs.exists(path):
                sh.fs.chmod(path, sh.fs.lookup(path).mode)  # type: ignore[union-attr]
            else:
                sh.fs.write(path, b"")
        except FSError as e:
            p.error(f"touch: {f}: {e}\n"); st = 1
    return st


@cmd("cp")
async def c_cp(sh, argv, p):
    flags, _, args = _opts(argv[1:])
    if len(args) < 2:
        p.error("cp: missing file operand\n"); return 1
    st = 0
    for src in args[:-1]:
        try:
            sh.fs.copy(sh.abspath(src), sh.abspath(args[-1]))
        except FSError as e:
            p.error(f"cp: cannot stat '{src}': {e}\n"); st = 1
    return st


@cmd("mv")
async def c_mv(sh, argv, p):
    flags, _, args = _opts(argv[1:])
    if len(args) < 2:
        p.error("mv: missing file operand\n"); return 1
    st = 0
    for src in args[:-1]:
        sp = sh.abspath(src)
        node = sh.fs.lookup(sp)
        if node is not None:
            sh.capture_file(sp, node, "mv")
        try:
            sh.fs.move(sp, sh.abspath(args[-1]))
        except FSError as e:
            p.error(f"mv: cannot move '{src}': {e}\n"); st = 1
    return st


@cmd("ln")
async def c_ln(sh, argv, p):
    flags, _, args = _opts(argv[1:])
    if len(args) == 2 and "s" in flags:
        try:
            sh.fs.symlink(args[0], sh.abspath(args[1]))
        except FSError as e:
            p.error(f"ln: {e}\n"); return 1
    return 0


def _apply_mode(cur: int, spec: str) -> int | None:
    if re.fullmatch(r"[0-7]{3,4}", spec):
        return int(spec, 8)
    m = cur
    for clause in spec.split(","):
        mm = re.fullmatch(r"([ugoa]*)([-+=])([rwxXst]*)", clause)
        if not mm:
            return None
        who, op, perms = mm.groups()
        who = who or "a"
        bits = 0
        for ch in perms:
            bits |= {"r": 4, "w": 2, "x": 1}.get(ch, 0)
        mask = 0
        for w in who.replace("a", "ugo"):
            shift = {"u": 6, "g": 3, "o": 0}[w]
            mask |= bits << shift
        m = (m | mask) if op == "+" else (m & ~mask) if op == "-" else ((m & ~(0o777 if who in ("a",) else mask)) | mask)
    return m


@cmd("chmod")
async def c_chmod(sh, argv, p):
    raw = argv[1:]
    raw_nonflag = [a for a in raw if not (a.startswith("-") and a[1:2] in "Rcfv" and len(a) <= 3)]
    if len(raw_nonflag) < 2:
        p.error("chmod: missing operand\n"); return 1
    spec, files = raw_nonflag[0], raw_nonflag[1:]
    st = 0
    for f in files:
        for m in (sh.fs.glob(f, sh.cwd) if any(c in f for c in "*?[") else [f]) or [f]:
            path = sh.abspath(m)
            node = sh.fs.lookup(path)
            if node is None:
                p.error(f"chmod: {m}: No such file or directory\n" if sh.persona.busybox else f"chmod: cannot access '{m}': No such file or directory\n")
                st = 1; continue
            new = _apply_mode(node.mode, spec)
            if new is None:
                p.error(f"chmod: invalid mode '{spec}'\n"); return 1
            try:
                sh.fs.chmod(path, new)
            except FSError as e:
                p.error(f"chmod: {m}: {e}\n"); st = 1; continue
            if new & 0o111:
                sh.capture_file(path, sh.fs.lookup(path), "chmod+x")
    return st


@cmd("stat")
async def c_stat(sh, argv, p):
    for f in argv[1:]:
        if f.startswith("-"):
            continue
        n = sh.fs.lookup(sh.abspath(f))
        if n is None:
            p.error(f"stat: cannot stat '{f}': No such file or directory\n"); return 1
        p.write(f"  File: {f}\n  Size: {n.size}\t\tBlocks: 8\t IO Block: 4096\t{'directory' if n.kind == 'd' else 'regular file'}\n"
                f"Access: ({n.mode & 0o7777:04o}/{_mode_str(n)})  Uid: (    0/    root)   Gid: (    0/    root)\n")
    return 0


def _file_desc(sh, data: bytes) -> str:
    if not data:
        return "empty"
    if data[:4] == b"\x7fELF":
        bits = "64-bit" if data[4] == 2 else "32-bit"
        endian = "LSB" if len(data) > 5 and data[5] == 1 else "MSB"
        mach = int.from_bytes(data[18:20], "little" if endian == "LSB" else "big") if len(data) >= 20 else 0
        name = {0x3E: "x86-64", 0x28: "ARM", 0x03: "Intel 80386", 0x08: "MIPS", 0xB7: "ARM aarch64", 0x14: "PowerPC", 0x2A: "Renesas SH"}.get(mach, "unknown arch")
        return f"ELF {bits} {endian} executable, {name}, version 1 (SYSV), statically linked, stripped"
    if data.startswith(b"#!"):
        interp = data.split(b"\n", 1)[0].decode("latin-1")
        return f"{'POSIX shell script' if 'sh' in interp else 'script'}, ASCII text executable"
    if sh._looks_like_text(data):
        return "ASCII text"
    return "data"


@cmd("file")
async def c_file(sh, argv, p):
    for f in [a for a in argv[1:] if not a.startswith("-")]:
        n = sh.fs.lookup(sh.abspath(f))
        if n is None:
            p.write(f"{f}: cannot open `{f}' (No such file or directory)\n")
        elif n.kind == "d":
            p.write(f"{f}: directory\n")
        else:
            p.write(f"{f}: {_file_desc(sh, n.content)}\n")
    return 0


@cmd("head", "tail")
async def c_headtail(sh, argv, p):
    args = argv[1:]
    n, bytes_mode, files = 10, False, []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-n", "-c") and i + 1 < len(args):
            n = int(args[i + 1].lstrip("+")) if args[i + 1].lstrip("+").isdigit() else 10
            bytes_mode = a == "-c"; i += 2; continue
        if re.fullmatch(r"-[nc]\d+", a):
            n = int(a[2:]); bytes_mode = a[1] == "c"; i += 1; continue
        if re.fullmatch(r"-\d+", a):
            n = int(a[1:]); i += 1; continue
        if a.startswith("-") and len(a) > 1:
            i += 1; continue
        files.append(a); i += 1
    data, st = _read_files(sh, files, p, argv[0])
    if bytes_mode:
        p.write(data[:n] if argv[0] == "head" else data[-n:] if n else b"")
    else:
        lines = data.split(b"\n")
        trailing = lines[-1] == b""
        if trailing:
            lines = lines[:-1]
        sel = lines[:n] if argv[0] == "head" else lines[-n:] if n else []
        p.write(b"\n".join(sel) + (b"\n" if sel else b""))
    return st


@cmd("wc")
async def c_wc(sh, argv, p):
    flags, _, files = _opts(argv[1:])
    data, st = _read_files(sh, files, p, "wc")
    lines, words, chars = data.count(b"\n"), len(data.split()), len(data)
    parts = []
    if "l" in flags: parts.append(str(lines))
    if "w" in flags: parts.append(str(words))
    if "c" in flags or "m" in flags: parts.append(str(chars))
    if not parts:
        parts = [str(lines), str(words), str(chars)]
    p.write(" ".join(parts) + (f" {files[0]}" if files else "") + "\n")
    return st


@cmd("tee")
async def c_tee(sh, argv, p):
    flags, _, files = _opts(argv[1:])
    for f in files:
        try:
            sh.fs.write(sh.abspath(f), p.stdin, append="a" in flags)
        except FSError as e:
            p.error(f"tee: {f}: {e}\n")
    p.write(p.stdin)
    return 0


@cmd("grep", "egrep", "fgrep")
async def c_grep(sh, argv, p):
    flags, vals, rest = _opts(argv[1:], "e")
    pat = vals.get("e")
    if pat is None:
        if not rest:
            p.error("Usage: grep [OPTIONS] PATTERN [FILE]...\n"); return 2
        pat, rest = rest[0], rest[1:]
    try:
        rx = re.compile(re.escape(pat) if (argv[0] == "fgrep" or "F" in flags) else pat, re.I if "i" in flags else 0)
    except re.error:
        rx = re.compile(re.escape(pat))
    if "w" in flags:
        rx = re.compile(r"\b" + rx.pattern + r"\b", rx.flags)
    data, st = _read_files(sh, rest, p, "grep")
    count, out = 0, []
    for ln, line in enumerate(data.decode("utf-8", "replace").split("\n"), 1):
        hit = bool(rx.search(line))
        if hit != ("v" in flags):
            count += 1
            if "o" in flags and "v" not in flags:
                out.extend(m.group() for m in rx.finditer(line))
            else:
                out.append(f"{ln}:{line}" if "n" in flags else line)
    if "q" in flags:
        return 0 if count else 1
    if "c" in flags:
        p.write(f"{count}\n")
    else:
        p.write("".join(o + "\n" for o in out))
    return 0 if count else 1


def _fields(line: str, sep: str | None) -> list[str]:
    return line.split(sep) if sep else line.split()


@cmd("awk", "gawk", "mawk")
async def c_awk(sh, argv, p):
    flags, vals, rest = _opts(argv[1:], "F")
    if not rest:
        p.error("awk: no program\n"); return 2
    prog, files = rest[0], rest[1:]
    sep = vals.get("F")
    if sep == "\\t":
        sep = "\t"
    data, st = _read_files(sh, files, p, "awk")
    m = re.fullmatch(r"\s*(?:(NR|FNR)\s*(==|!=|>|<|>=|<=)\s*(\d+)|/(.*?)/)?\s*(?:\{(.*)\})?\s*", prog, re.S)
    if not m:
        return 0
    var, op, num, regex, body = m.groups()
    body = (body if body is not None else "print $0").strip().rstrip(";").strip()
    for nr, line in enumerate(data.decode("utf-8", "replace").split("\n"), 1):
        if line == "" and nr == data.count(b"\n") + 1:
            continue
        if var:
            a, b = nr, int(num)
            ok = {"==": a == b, "!=": a != b, ">": a > b, "<": a < b, ">=": a >= b, "<=": a <= b}[op]
            if not ok:
                continue
        if regex is not None and not re.search(regex, line):
            continue
        f = _fields(line, sep)
        if body.startswith("print") or body == "":
            expr = body[5:].strip()
            if not expr:
                p.write(line + "\n"); continue
            outs = []
            for seg in _split_commas(expr):
                outs.append(_awk_concat(seg, line, f))
            p.write(" ".join(outs) + "\n")
    return st


def _split_commas(s: str) -> list[str]:
    out, cur, q = [], "", False
    for ch in s:
        if ch == '"':
            q = not q
        if ch == "," and not q:
            out.append(cur); cur = ""
        else:
            cur += ch
    out.append(cur)
    return out


def _awk_concat(seg: str, line: str, f: list[str]) -> str:
    out = ""
    for tok in re.findall(r'"(?:[^"\\]|\\.)*"|\$\(?NF(?:-\d+)?\)?|\$\d+|NR|NF|\S+', seg):
        if tok.startswith('"'):
            out += _unescape(tok[1:-1]).decode("latin-1")
        elif tok == "$0":
            out += line
        elif tok.startswith("$"):
            t = tok.strip("$()")
            if t.startswith("NF"):
                idx = len(f) - (int(t[3:]) if len(t) > 2 else 0)
            else:
                idx = int(t)
            out += f[idx - 1] if 1 <= idx <= len(f) else ""
        elif tok == "NF":
            out += str(len(f))
    return out


@cmd("sed")
async def c_sed(sh, argv, p):
    flags, vals, rest = _opts(argv[1:], "e")
    progs = [vals["e"]] if "e" in vals else ([rest.pop(0)] if rest else [])
    data, st = _read_files(sh, rest, p, "sed")
    lines = data.decode("utf-8", "replace").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    out = []
    for nr, line in enumerate(lines, 1):
        printed = False
        drop = False
        for prog in progs:
            for part in prog.split(";"):
                part = part.strip()
                m = re.fullmatch(r"s(.)(.*?)(?<!\\)\1(.*?)(?<!\\)\1([gi]*)", part)
                if m:
                    try:
                        line = re.sub(m.group(2), m.group(3).replace("\\1", r"\1"), line, count=0 if "g" in m.group(4) else 1,
                                      flags=re.I if "i" in m.group(4) else 0)
                    except re.error:
                        pass
                elif re.fullmatch(r"(\d+)?d", part):
                    n = re.match(r"(\d+)", part)
                    if not n or int(n.group(1)) == nr:
                        drop = True
                elif re.fullmatch(r"(\d+)p", part) and "n" in flags:
                    if int(part[:-1]) == nr:
                        printed = True
        if drop:
            continue
        if "n" not in flags or printed:
            out.append(line)
    p.write("".join(l + "\n" for l in out))
    return st


@cmd("cut")
async def c_cut(sh, argv, p):
    flags, vals, rest = _opts(argv[1:], "dfc")
    data, st = _read_files(sh, rest, p, "cut")
    delim = vals.get("d", "\t")
    spec = vals.get("f") or vals.get("c") or "1"

    def picks(n: int) -> list[int]:
        idx: list[int] = []
        for part in spec.split(","):
            if "-" in part:
                a, _, b = part.partition("-")
                idx.extend(range(int(a or 1), int(b or n) + 1))
            elif part.isdigit():
                idx.append(int(part))
        return idx

    for line in data.decode("utf-8", "replace").split("\n")[:-1] if data.endswith(b"\n") else data.decode("utf-8", "replace").split("\n"):
        if "c" in vals:
            p.write("".join(line[i - 1] for i in picks(len(line)) if 0 < i <= len(line)) + "\n")
        else:
            parts = line.split(delim)
            p.write(delim.join(parts[i - 1] for i in picks(len(parts)) if 0 < i <= len(parts)) + "\n")
    return st


@cmd("sort")
async def c_sort(sh, argv, p):
    flags, _, files = _opts(argv[1:])
    data, st = _read_files(sh, files, p, "sort")
    lines = data.decode("utf-8", "replace").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if "n" in flags:
        lines.sort(key=lambda l: float(m.group()) if (m := re.match(r"-?\d+(\.\d+)?", l.strip())) else 0.0)
    else:
        lines.sort()
    if "r" in flags:
        lines.reverse()
    if "u" in flags:
        lines = list(dict.fromkeys(lines))
    p.write("".join(l + "\n" for l in lines))
    return st


@cmd("uniq")
async def c_uniq(sh, argv, p):
    flags, _, files = _opts(argv[1:])
    data, st = _read_files(sh, files, p, "uniq")
    out: list[tuple[str, int]] = []
    for l in data.decode("utf-8", "replace").split("\n")[:-1]:
        if out and out[-1][0] == l:
            out[-1] = (l, out[-1][1] + 1)
        else:
            out.append((l, 1))
    p.write("".join((f"{c:>7} {l}\n" if "c" in flags else f"{l}\n") for l, c in out))
    return st


@cmd("tr")
async def c_tr(sh, argv, p):
    flags, _, sets = _opts(argv[1:])
    text = p.stdin.decode("utf-8", "replace")

    def expand(s: str) -> str:
        s = s.replace("[:lower:]", "a-z").replace("[:upper:]", "A-Z").replace("[:digit:]", "0-9").replace("[:space:]", " \t\n")
        out = ""
        i = 0
        while i < len(s):
            if i + 2 < len(s) and s[i + 1] == "-":
                out += "".join(chr(c) for c in range(ord(s[i]), ord(s[i + 2]) + 1)); i += 3
            else:
                out += s[i]; i += 1
        return out.replace("\\n", "\n")
    if "d" in flags and sets:
        d = set(expand(sets[0]))
        text = "".join(c for c in text if c not in d)
    elif len(sets) >= 2:
        a, b = expand(sets[0]), expand(sets[1])
        b = (b + b[-1:] * len(a))[: len(a)] if b else b
        text = text.translate(str.maketrans(a, b))
    p.write(text)
    return 0


@cmd("xargs")
async def c_xargs(sh, argv, p):
    flags, _, rest = _opts(argv[1:])
    base = rest or ["echo"]
    items = p.stdin.decode("utf-8", "replace").split()
    if not items:
        return 0
    return await sh.run_command(base + items, p)


@cmd("find")
async def c_find(sh, argv, p):
    args = argv[1:]
    start = args[0] if args and not args[0].startswith("-") else "."
    name = None
    kind = None
    maxdepth = 6
    for i, a in enumerate(args):
        if a == "-name" and i + 1 < len(args): name = args[i + 1]
        if a == "-type" and i + 1 < len(args): kind = args[i + 1]
        if a == "-maxdepth" and i + 1 < len(args) and args[i + 1].isdigit(): maxdepth = int(args[i + 1])
    import fnmatch
    base = sh.abspath(start)
    count = 0

    def walk(path: str, shown: str, depth: int):
        nonlocal count
        node = sh.fs.lookup(path, follow=False)
        if node is None or count > 300:
            return
        ok = (not name or fnmatch.fnmatchcase(posixpath.basename(path), name)) and (
            not kind or (kind == "f" and node.kind == "f") or (kind == "d" and node.kind == "d"))
        if ok:
            p.write(shown + "\n"); count += 1
        if node.kind == "d" and depth < maxdepth:
            for n in sh.fs.listdir(path):
                walk(posixpath.join(path, n), posixpath.join(shown, n), depth + 1)
    if sh.fs.lookup(base) is None:
        p.error(f"find: '{start}': No such file or directory\n"); return 1
    walk(base, start, 0)
    return 0


@cmd("basename")
async def c_basename(sh, argv, p):
    if len(argv) > 1:
        b = posixpath.basename(argv[1].rstrip("/"))
        if len(argv) > 2 and b.endswith(argv[2]):
            b = b[: -len(argv[2])]
        p.write(b + "\n")
    return 0


@cmd("dirname")
async def c_dirname(sh, argv, p):
    if len(argv) > 1:
        p.write((posixpath.dirname(argv[1].rstrip("/")) or ".") + "\n")
    return 0


@cmd("md5sum", "sha256sum", "sha1sum")
async def c_hashsum(sh, argv, p):
    algo = {"md5sum": "md5", "sha256sum": "sha256", "sha1sum": "sha1"}[argv[0]]
    files = [a for a in argv[1:] if not a.startswith("-")]
    if not files:
        p.write(f"{hashlib.new(algo, p.stdin).hexdigest()}  -\n"); return 0
    st = 0
    for f in files:
        data, s = _read_files(sh, [f], p, argv[0])
        st |= s
        if not s:
            p.write(f"{hashlib.new(algo, data).hexdigest()}  {f}\n")
    return st


@cmd("base64")
async def c_base64(sh, argv, p):
    flags, _, files = _opts(argv[1:])
    data, st = _read_files(sh, files, p, "base64")
    if "d" in flags or "decode" in flags or "D" in flags:
        try:
            p.write(base64.b64decode(re.sub(rb"\s+", b"", data) + b"=" * (-len(re.sub(rb"\s+", b"", data)) % 4)))
        except (binascii.Error, ValueError):
            p.error("base64: invalid input\n"); return 1
    else:
        enc = base64.b64encode(data)
        p.write(b"".join(enc[i:i + 76] + b"\n" for i in range(0, len(enc), 76)) if enc else b"")
    return st


@cmd("strings")
async def c_strings(sh, argv, p):
    data, st = _read_files(sh, [a for a in argv[1:] if not a.startswith("-")], p, "strings")
    for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
        p.write(m.group() + b"\n")
    return st


@cmd("dd")
async def c_dd(sh, argv, p):
    kv = dict(a.split("=", 1) for a in argv[1:] if "=" in a)
    bs = int(re.sub(r"\D", "", kv.get("bs", "512")) or 512) * (1024 if kv.get("bs", "").lower().endswith("k") else 1024 * 1024 if kv.get("bs", "").lower().endswith("m") else 1)
    count = int(kv.get("count", 1))
    src = kv.get("if")
    if src in ("/dev/zero",):
        data = b"\x00" * min(bs * count, 1 << 20)
    elif src in ("/dev/urandom", "/dev/random"):
        data = random.randbytes(min(bs * count, 1 << 16))
    elif src:
        data, st = _read_files(sh, [src], p, "dd")
        if st: return st
        data = data[: bs * count] if "count" in kv else data
    else:
        data = p.stdin
    if "of" in kv and kv["of"] != "/dev/null":
        try:
            sh.fs.write(sh.abspath(kv["of"]), data)
        except FSError as e:
            p.error(f"dd: can't open '{kv['of']}': {e}\n"); return 1
    elif "of" not in kv:
        p.write(data)
    p.error(f"{count}+0 records in\n{count}+0 records out\n")
    return 0


@cmd("tar", "gzip", "gunzip", "unzip", "zcat", "bzip2", "xz", "unxz", "bunzip2", "7z")
async def c_archive(sh, argv, p):
    return 0


# ============================================================ system info

@cmd("id")
async def c_id(sh, argv, p):
    u = sh.user
    uid = 0 if u == "root" else next((x[1] for x in sh.persona.users if x[0] == u), 1000)
    p.write(f"uid={uid}({u}) gid={uid}({u}) groups={uid}({u})\n"); return 0


@cmd("whoami")
async def c_whoami(sh, argv, p):
    p.write(sh.user + "\n"); return 0


@cmd("hostname")
async def c_hostname(sh, argv, p):
    p.write(sh.persona.hostname + "\n"); return 0


@cmd("uname")
async def c_uname(sh, argv, p):
    flags, _, _ = _opts(argv[1:])
    per = sh.persona
    if not flags:
        p.write("Linux\n"); return 0
    if "a" in flags:
        p.write(per.uname_a + "\n"); return 0
    parts = []
    if "s" in flags: parts.append("Linux")
    if "n" in flags: parts.append(per.hostname)
    if "r" in flags: parts.append(per.kernel_release)
    if "v" in flags: parts.append(per.kernel_version)
    if "m" in flags or "p" in flags or "i" in flags: parts.append(per.machine)
    if "o" in flags: parts.append("GNU/Linux")
    p.write(" ".join(parts) + "\n"); return 0


@cmd("arch")
async def c_arch(sh, argv, p):
    p.write(sh.persona.machine + "\n"); return 0


@cmd("getconf")
async def c_getconf(sh, argv, p):
    if len(argv) > 1 and argv[1] == "LONG_BIT":
        p.write(f"{sh.persona.elf_bits}\n")
    return 0


@cmd("lsb_release")
async def c_lsb(sh, argv, p):
    p.write(f"Distributor ID:\tDebian\nDescription:\t{sh.persona.os_pretty}\nRelease:\t10\nCodename:\tbuster\n"); return 0


@cmd("uptime")
async def c_uptime(sh, argv, p):
    s = sh.uptime_seconds()
    p.write(f" {time.strftime('%H:%M:%S', time.gmtime())} up {s // 86400} days, {(s % 86400) // 3600:2d}:{(s % 3600) // 60:02d},  1 user,  load average: 0.08, 0.03, 0.01\n"); return 0


@cmd("date")
async def c_date(sh, argv, p):
    p.write(time.strftime("%a %b %e %H:%M:%S UTC %Y", time.gmtime()) + "\n"); return 0


@cmd("w", "who", "users")
async def c_who(sh, argv, p):
    if argv[0] == "w":
        p.write(f" {time.strftime('%H:%M:%S', time.gmtime())} up {sh.uptime_seconds() // 86400} days,  1 user,  load average: 0.08, 0.03, 0.01\n"
                "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                f"{sh.user:<8} pts/0    {sh.src_ip:<16} {time.strftime('%H:%M', time.gmtime())}    0.00s  0.02s  0.00s w\n")
    elif argv[0] == "who":
        p.write(f"{sh.user}     pts/0        {time.strftime('%Y-%m-%d %H:%M', time.gmtime())} ({sh.src_ip})\n")
    else:
        p.write(sh.user + "\n")
    return 0


@cmd("last", "lastlog", "lastb")
async def c_last(sh, argv, p):
    p.write(f"{sh.user:<8} pts/0        {sh.src_ip:<16} {time.strftime('%a %b %e %H:%M', time.gmtime())}   still logged in\n\nwtmp begins {time.strftime('%a %b %e %H:%M:%S %Y', time.gmtime(time.time() - 86400 * 80))}\n"); return 0


@cmd("free")
async def c_free(sh, argv, p):
    flags, _, _ = _opts(argv[1:])
    t = sh.persona.mem_total_kb
    div, unit = (1024, "m") if ("m" in flags) else (1, "") if not flags & {"h"} else (1024, "h")
    used, free, shared, cache, avail = t // 3, t // 3, t // 100, t // 5, t // 2
    fmt = (lambda v: f"{v // div:>11}") if "h" not in flags else (lambda v: f"{_human(v * 1024):>11}")
    p.write("              total        used        free      shared  buff/cache   available\n"
            f"Mem:{fmt(t)}{fmt(used)}{fmt(free)}{fmt(shared)}{fmt(cache)}{fmt(avail)}\n"
            f"Swap:{fmt(0 if sh.persona.busybox else 1048572)}{fmt(0)}{fmt(0 if sh.persona.busybox else 1048572)}\n")
    return 0


@cmd("df")
async def c_df(sh, argv, p):
    flags, _, _ = _opts(argv[1:])
    if "h" in flags:
        p.write("Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        29G  4.1G   24G  15% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm\n")
    else:
        p.write("Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/sda1       30298176 4300212  24724892  15% /\ntmpfs            2023216       0   2023216   0% /dev/shm\n")
    return 0


@cmd("mount")
async def c_mount(sh, argv, p):
    node = sh.fs.lookup("/proc/mounts")
    p.write(node.content if node else b""); return 0


@cmd("lscpu")
async def c_lscpu(sh, argv, p):
    pr = sh.persona
    p.write(f"Architecture:        {pr.machine}\nCPU op-mode(s):      32-bit, 64-bit\nByte Order:          Little Endian\nCPU(s):              {pr.cpu_cores}\n"
            f"Thread(s) per core:  1\nCore(s) per socket:  {pr.cpu_cores}\nSocket(s):           1\nModel name:          {pr.cpu_model}\nCPU MHz:             2399.998\n"
            "L3 cache:            35840K\n"); return 0


@cmd("nproc")
async def c_nproc(sh, argv, p):
    p.write(f"{sh.persona.cpu_cores}\n"); return 0


@cmd("lsmod")
async def c_lsmod(sh, argv, p):
    p.write("Module                  Size  Used by\nnf_conntrack          106496  0\n"); return 0


@cmd("dmesg")
async def c_dmesg(sh, argv, p):
    p.error("dmesg: read kernel buffer failed: Operation not permitted\n"); return 1


@cmd("ps")
async def c_ps(sh, argv, p):
    flags, _, _ = _opts(argv[1:])
    me = 9000 + (sh.cmd_count % 700)
    procs = list(sh.persona.processes) + [(me - 3, sh.user, "sshd: root@pts/0" if sh.service == "ssh" else "/usr/sbin/telnetd"),
                                           (me - 2, sh.user, "-sh" if sh.persona.busybox else "-bash"), (me, sh.user, "ps " + " ".join(argv[1:]))]
    if not flags and len(argv) == 1:
        p.write("  PID TTY          TIME CMD\n")
        for pid, _u, c in procs[-2:]:
            p.write(f"{pid:5d} pts/0    00:00:00 {c.split()[0].lstrip('-')}\n")
        return 0
    if sh.persona.busybox:
        p.write("  PID USER       VSZ STAT COMMAND\n")
        for pid, u, c in procs:
            p.write(f"{pid:5d} {u:<8} {1200 + pid % 900:5d} S    {c}\n")
    else:
        p.write("USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n")
        for pid, u, c in procs:
            p.write(f"{u:<8} {pid:5d}  0.0  0.{pid % 9 + 1}  {20000 + pid % 9000:5d}  {2000 + pid % 3000:4d} ?        Ss   Sep12   0:0{pid % 9} {c}\n")
    return 0


@cmd("top", "htop")
async def c_top(sh, argv, p):
    pr = sh.persona
    p.write(f"top - {time.strftime('%H:%M:%S', time.gmtime())} up {sh.uptime_seconds() // 86400} days,  1 user,  load average: 0.08, 0.03, 0.01\n"
            f"Tasks:  {len(pr.processes) + 3} total,   1 running, {len(pr.processes) + 2} sleeping,   0 stopped,   0 zombie\n"
            "%Cpu(s):  1.0 us,  0.3 sy,  0.0 ni, 98.7 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st\n"
            f"KiB Mem : {pr.mem_total_kb:>8} total, {pr.mem_total_kb // 3:>8} free, {pr.mem_total_kb // 3:>8} used, {pr.mem_total_kb // 5:>8} buff/cache\n\n"
            "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND\n")
    for pid, u, c in pr.processes[:6]:
        p.write(f"{pid:5d} {u:<9} 20   0  {20000 + pid % 9000:6d}  {2000 + pid % 3000:5d}   1800 S   0.0  0.1   0:0{pid % 9}.12 {c.split()[0]}\n")
    return 0


@cmd("ifconfig")
async def c_ifconfig(sh, argv, p):
    p.write("eth0      Link encap:Ethernet  HWaddr 52:54:00:12:34:56\n          inet addr:10.0.2.15  Bcast:10.0.2.255  Mask:255.255.255.0\n"
            "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n          RX packets:71203 errors:0 dropped:0 overruns:0 frame:0\n"
            "          TX packets:50412 errors:0 dropped:0 overruns:0 carrier:0\n\nlo        Link encap:Local Loopback\n          inet addr:127.0.0.1  Mask:255.0.0.0\n"
            "          UP LOOPBACK RUNNING  MTU:65536  Metric:1\n\n"); return 0


@cmd("ip")
async def c_ip(sh, argv, p):
    if len(argv) > 1 and argv[1].startswith("r"):
        p.write("default via 10.0.2.2 dev eth0\n10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15\n")
    else:
        p.write("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0\n")
    return 0


@cmd("netstat", "ss")
async def c_netstat(sh, argv, p):
    p.write("Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            f"tcp        0      0 10.0.2.15:22            {sh.src_ip}:51234      ESTABLISHED\n"); return 0


@cmd("env", "printenv")
async def c_env(sh, argv, p):
    for k, v in sh.vars.items():
        p.write(f"{k}={v}\n")
    return 0


@cmd("sleep")
async def c_sleep(sh, argv, p):
    try:
        secs = float(argv[1]) if len(argv) > 1 else 0
    except ValueError:
        p.error("sleep: invalid number\n"); return 1
    await asyncio.sleep(min(secs, 0.4))   # fast-forwarded: bots must not tie up the box
    return 0


@cmd("ping")
async def c_ping(sh, argv, p):
    host = next((a for a in argv[1:] if not a.startswith("-")), "")
    if not host:
        p.error("ping: usage error: Destination address required\n"); return 1
    ip = host if re.fullmatch(r"[\d.]+", host) else sh.fake_ip_for(host)
    p.write(f"PING {host} ({ip}) 56(84) bytes of data.\n")
    for i in range(3):
        p.write(f"64 bytes from {ip}: icmp_seq={i + 1} ttl=57 time={12 + i * 0.7:.1f} ms\n")
    p.write(f"\n--- {host} ping statistics ---\n3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n"); return 0


@cmd("kill", "pkill", "killall", "skill")
async def c_kill(sh, argv, p):
    if argv[0] in ("pkill", "killall"):
        names = [a for a in argv[1:] if not a.startswith("-")]
        known = " ".join(c for _, _, c in sh.persona.processes)
        hit = any(n in known for n in names)
        if not hit and argv[0] == "killall" and names:
            p.error(f"{argv[0]}: {names[0]}: no process killed\n")
        return 0 if hit else 1
    return 0


@cmd("nohup", "timeout", "setsid", "time", "stdbuf", "ionice", "chroot")
async def c_nohup(sh, argv, p):
    args = argv[1:]
    if argv[0] == "timeout" and args:
        args = args[1:]
    while args and args[0].startswith("-"):
        args = args[1:]
    return await sh.run_command(args, p) if args else 0


@cmd("sudo", "doas")
async def c_sudo(sh, argv, p):
    args = argv[1:]
    while args and args[0].startswith("-"):
        args = args[1:]
    return await sh.run_command(args, p) if args else 1


@cmd("su")
async def c_su(sh, argv, p):
    return 0


@cmd("passwd", "chpasswd")
async def c_passwd(sh, argv, p):
    if argv[0] == "passwd":
        p.write("Enter new UNIX password: \nRetype new UNIX password: \npasswd: password updated successfully\n")
    return 0


@cmd("useradd", "adduser", "userdel", "usermod", "groupadd")
async def c_useradd(sh, argv, p):
    if argv[0] in ("useradd", "adduser"):
        name = next((a for a in reversed(argv[1:]) if not a.startswith("-")), None)
        if name:
            try:
                sh.fs.write("/etc/passwd", f"{name}:x:1100:1100::/home/{name}:/bin/sh\n".encode(), append=True)
            except FSError:
                pass
    return 0


@cmd("crontab")
async def c_crontab(sh, argv, p):
    flags, _, rest = _opts(argv[1:], "u")
    if "l" in flags:
        if sh.crontab:
            p.write(sh.crontab)
            return 0
        p.error(f"no crontab for {sh.user}\n"); return 1
    if "r" in flags:
        sh.crontab = ""; return 0
    if rest or "-" in argv[1:]:
        data, st = _read_files(sh, [r for r in rest if r != "-"], p, "crontab")
        sh.crontab = data.decode("utf-8", "replace")[:8192]
        sh.emit("cron.install", crontab=sh.crontab[:2000])
    return 0


@cmd("service", "systemctl", "rc-service", "update-rc.d", "chkconfig", "invoke-rc.d")
async def c_service(sh, argv, p):
    if argv[0] == "systemctl" and len(argv) > 2 and argv[1] in ("status", "is-active"):
        p.error(f"Unit {argv[2]}.service could not be found.\n"); return 4
    return 0


@cmd("iptables", "ip6tables", "ufw", "firewall-cmd", "nft")
async def c_iptables(sh, argv, p):
    if "-L" in argv or "-S" in argv:
        p.write("Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\n\n"
                "Chain FORWARD (policy ACCEPT)\ntarget     prot opt source               destination\n\n"
                "Chain OUTPUT (policy ACCEPT)\ntarget     prot opt source               destination\n")
    return 0


@cmd("apt", "apt-get", "yum", "dnf", "apk", "dpkg", "rpm", "opkg")
async def c_pkg(sh, argv, p):
    if len(argv) > 1 and argv[1] in ("install", "add"):
        pkg = next((a for a in argv[2:] if not a.startswith("-")), "")
        p.error(f"E: Unable to locate package {pkg}\n"); return 100
    p.write("Reading package lists... Done\n")
    return 0


@cmd("reboot", "shutdown", "halt", "poweroff", "init", "telinit")
async def c_reboot(sh, argv, p):
    if argv[0] in ("init", "telinit") and not any(a in ("0", "6") for a in argv):
        return 0
    p.write("\nBroadcast message from root@" + sh.persona.hostname + "\n\tThe system is going down for reboot NOW!\n")
    raise ShellExit(0)


@cmd("nc", "ncat", "netcat", "telnet", "socat", "ssh", "scp", "rsync", "ftp", "sftp")
async def c_net(sh, argv, p):
    host = next((a for a in argv[1:] if not a.startswith("-") and not re.fullmatch(r"\d+", a)), "")
    sh.emit("net.outbound_attempt", tool=argv[0], target=host[:200], args=" ".join(argv[1:6])[:300])
    if argv[0] in ("ssh", "scp"):
        p.error(f"ssh: connect to host {host.split('@')[-1] or 'localhost'} port 22: Connection timed out\n"); return 255
    return 1


# ================================================================ downloads

def _progress_wget(sh, url, name, size, ip, host, port, scheme) -> str:
    kb = size / 1024
    if sh.persona.busybox:
        return (f"Connecting to {host} ({ip}:{port})\n{name[:16]:<16} 100% |*******************************| {size:>6}  0:00:00 ETA\n")
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    return (f"--{ts}--  {url}\nResolving {host} ({host})... {ip}\nConnecting to {host} ({host})|{ip}|:{port}... connected.\n"
            f"HTTP request sent, awaiting response... 200 OK\nLength: {size} ({kb:.0f}K) [application/octet-stream]\nSaving to: '{name}'\n\n"
            f"{name[:20]:<20} 100%[===================>] {kb:>6.1f}K  --.-KB/s    in 0.1s\n\n"
            f"{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} (2.1 MB/s) - '{name}' saved [{size}/{size}]\n\n")


@cmd("wget")
async def c_wget(sh, argv, p):
    from urllib.parse import urlsplit
    flags, vals, urls = _opts(argv[1:], "OoPUtTe")
    if not urls:
        p.error("wget: missing URL\nUsage: wget [OPTION]... [URL]...\n"); return 1
    quiet = "q" in flags
    st = 0
    for url in urls[:5]:
        full = url if "://" in url else "http://" + url
        parts = urlsplit(full)
        name = vals.get("O") or (parts.path.rsplit("/", 1)[-1] or "index.html")
        to_stdout = name == "-"
        dest = None if to_stdout else sh.abspath(posixpath.join(vals.get("P", ""), name) if "P" in vals else name)
        ok, content, saved = await sh.download(full, "wget", dest, p)
        if not ok:
            st = 1; continue
        size = len(content) or sh.fake_download_size(full)
        if to_stdout:
            p.write(content)
        if not quiet:
            host = parts.hostname or ""
            ip = host if re.fullmatch(r"[\d.]+", host) else sh.fake_ip_for(host)
            p.error(_progress_wget(sh, full, name, size, ip, host, parts.port or (443 if parts.scheme == "https" else 80), parts.scheme))
    return st


@cmd("curl")
async def c_curl(sh, argv, p):
    from urllib.parse import urlsplit
    flags, vals, urls = _opts(argv[1:], "oAHXdmuTeb")
    remote_name = "O" in flags
    if "output" in vals:
        vals["o"] = vals["output"]
    if not urls:
        p.error("curl: try 'curl --help' for more information\n"); return 2
    silent = bool(flags & {"s", "silent"})
    st = 0
    for url in urls[:5]:
        full = url if "://" in url else "http://" + url
        parts = urlsplit(full)
        if "T" in vals or "d" in vals or "X" in vals and vals["X"].upper() in ("POST", "PUT"):
            sh.emit("net.outbound_attempt", tool="curl", target=full[:300], args="upload/post")
        dest = None
        if "o" in vals and vals["o"] != "-":
            dest = sh.abspath(vals["o"])
        elif remote_name:
            dest = sh.abspath(parts.path.rsplit("/", 1)[-1] or "index.html")
        ok, content, saved = await sh.download(full, "curl", dest, p)
        if not ok:
            st = 1; continue
        if dest is None:
            p.write(content)
        elif not silent:
            size = len(content) or sh.fake_download_size(full)
            p.error(f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                    f"                                 Dload  Upload   Total   Spent    Left  Speed\n100 {size}  100 {size}    0     0  2145k      0 --:--:-- --:--:-- --:--:-- 2145k\n")
    return st


@cmd("tftp")
async def c_tftp(sh, argv, p):
    flags, vals, rest = _opts(argv[1:], "rl")
    remote = vals.get("r", "")
    if "get" in rest:                       # classic client:  tftp HOST -c get FILE
        i = rest.index("get")
        remote = rest[i + 1] if i + 1 < len(rest) else ""
        rest = [x for j, x in enumerate(rest) if j not in (i, i + 1)]
    host = rest[0] if rest else ""
    if not host or not remote:
        p.error("BusyBox v1.22.1 multi-call binary.\n\nUsage: tftp [OPTIONS] HOST [PORT]\n"); return 1
    local = vals.get("l") or posixpath.basename(remote)
    ok, content, saved = await sh.download(f"tftp://{host}/{remote}", "tftp", sh.abspath(local), p)
    return 0 if ok else 1


@cmd("ftpget", "ftpput")
async def c_ftpget(sh, argv, p):
    flags, vals, rest = _opts(argv[1:], "upP")
    if len(rest) < 2 or argv[0] == "ftpput":
        return 1
    host = rest[0]
    local = rest[1]
    remote = rest[2] if len(rest) > 2 else local
    cred = f"{vals.get('u', 'anonymous')}:{vals.get('p', '')}@" if "u" in vals else ""
    ok, content, saved = await sh.download(f"ftp://{cred}{host}/{remote}", "ftpget", sh.abspath(local), p)
    return 0 if ok else 1
