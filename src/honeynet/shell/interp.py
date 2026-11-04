"""A small POSIX-ish shell interpreter (parser + evaluator) for the fake shell.

It understands what drive-by attackers actually send: ``;`` ``&&`` ``||`` ``|`` ``&``,
quotes, ``$VAR`` / ``$(cmd)`` / backticks, redirections, heredocs, ``if/for/while/case``,
``{ ...; }`` groups and simple functions.  It never touches the real system: every
command is a Python emulation operating on :class:`FakeFS`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .fakefs import FSError

if TYPE_CHECKING:  # pragma: no cover
    from .session import ShellSession


class Incomplete(Exception):
    """Input ends in the middle of a construct - ask for another line."""


class ShellSyntaxError(Exception):
    pass


class ShellExit(Exception):
    def __init__(self, status: int = 0) -> None:
        self.status = status


class BreakLoop(Exception):
    def __init__(self, n: int = 1) -> None:
        self.n = n


class ContinueLoop(Exception):
    def __init__(self, n: int = 1) -> None:
        self.n = n


class ReturnFunc(Exception):
    def __init__(self, status: int = 0) -> None:
        self.status = status


class BudgetExceeded(Exception):
    pass


# =============================================================== tokenizer

@dataclass
class Word:
    parts: list[tuple[str, str]]   # (kind, text) kind: lit | sq | dq | cmd | dqcmd

    @property
    def raw(self) -> str:
        return "".join(t for _, t in self.parts)

    @property
    def quoted(self) -> bool:
        return any(k in ("sq", "dq", "dqcmd") for k, _ in self.parts)

    @property
    def plain_literal(self) -> str | None:
        if len(self.parts) == 1 and self.parts[0][0] == "lit" and "$" not in self.parts[0][1]:
            return self.parts[0][1]
        if self.parts and all(k == "lit" and "$" not in t for k, t in self.parts):
            return "".join(t for _, t in self.parts)
        return None


@dataclass
class Redir:
    fd: int
    op: str                      # > >> < << >&
    target: Word | None = None
    body: str = ""
    quoted_delim: bool = False


@dataclass
class Tok:
    kind: str                    # word | op | nl
    word: Word | None = None
    op: str = ""
    redir: Redir | None = None   # for heredoc/fd redirects fully resolved by tokenizer


_OPS3 = ("<<-",)
_OPS2 = ("&&", "||", ">>", "<<", ">&", "<&", ";;", "&>")
_OPS1 = ";&|()<>"
_ANSI_ESC = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "e": "\x1b",
             "\\": "\\", "'": "'", '"': '"'}


def _decode_ansi_c(s: str) -> str:
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c != "\\" or i + 1 >= len(s):
            out.append(c)
            i += 1
            continue
        n = s[i + 1]
        if n in _ANSI_ESC:
            out.append(_ANSI_ESC[n]); i += 2
        elif n == "x":
            m = re.match(r"[0-9a-fA-F]{1,2}", s[i + 2:])
            if m:
                out.append(chr(int(m.group(), 16))); i += 2 + len(m.group())
            else:
                out.append("\\x"); i += 2
        elif n in "01234567":
            m = re.match(r"[0-7]{1,3}", s[i + 1:])
            out.append(chr(int(m.group(), 8) & 0xFF)); i += 1 + len(m.group())
        else:
            out.append("\\" + n); i += 2
    return "".join(out)


def _match_paren(src: str, i: int) -> int:
    """src[i] == '(' just after '$'. Returns index of the matching ')'."""
    depth, j, n = 0, i, len(src)
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == "'":
            k = src.find("'", j + 1)
            if k < 0:
                raise Incomplete()
            j = k + 1
            continue
        if c == '"':
            j += 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            j += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    raise Incomplete()


def tokenize(src: str) -> list[Tok]:
    toks: list[Tok] = []
    i, n = 0, len(src)
    pending_heredocs: list[Redir] = []
    parts: list[tuple[str, str]] = []
    lit: list[str] = []
    in_word = False

    def flush_lit() -> None:
        if lit:
            parts.append(("lit", "".join(lit)))
            lit.clear()

    def end_word() -> None:
        nonlocal in_word, parts
        flush_lit()
        if in_word:
            toks.append(Tok("word", word=Word(parts)))
        parts = []
        in_word = False

    while i < n:
        c = src[i]
        if c in " \t":
            end_word(); i += 1; continue
        if c == "\n":
            end_word()
            toks.append(Tok("nl"))
            i += 1
            for hd in pending_heredocs:       # consume bodies right after the newline
                body_lines = []
                while True:
                    if i >= n:
                        raise Incomplete()
                    j = src.find("\n", i)
                    line = src[i:] if j < 0 else src[i:j]
                    i = n if j < 0 else j + 1
                    cmp_line = line.lstrip("\t") if hd.op == "<<-" else line
                    if cmp_line == hd.target.raw:  # type: ignore[union-attr]
                        break
                    body_lines.append(line.lstrip("\t") if hd.op == "<<-" else line)
                    if j < 0:
                        raise Incomplete()
                hd.body = "\n".join(body_lines) + ("\n" if body_lines else "")
            pending_heredocs.clear()
            continue
        if c == "#" and not in_word:
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "\\":
            if i + 1 >= n:
                raise Incomplete()
            if src[i + 1] == "\n":
                i += 2; continue
            lit.append("\\$" if src[i + 1] == "$" else src[i + 1]); in_word = True; i += 2; continue
        if c == "'":
            k = src.find("'", i + 1)
            if k < 0:
                raise Incomplete()
            flush_lit(); parts.append(("sq", src[i + 1:k])); in_word = True; i = k + 1; continue
        if c == '"':
            flush_lit()
            i += 1
            buf: list[str] = []
            while True:
                if i >= n:
                    raise Incomplete()
                ch = src[i]
                if ch == '"':
                    i += 1; break
                if ch == "\\" and i + 1 < n:
                    nx = src[i + 1]
                    if nx in '"\\$`':
                        buf.append("\\" + nx if nx == "$" else nx); i += 2; continue
                    if nx == "\n":
                        i += 2; continue
                    buf.append(ch); i += 1; continue
                if ch == "$" and i + 1 < n and src[i + 1] == "(":
                    k = _match_paren(src, i + 1)
                    if buf:
                        parts.append(("dq", "".join(buf))); buf = []
                    parts.append(("dqcmd", src[i + 2:k])); i = k + 1; continue
                if ch == "`":
                    k = src.find("`", i + 1)
                    if k < 0:
                        raise Incomplete()
                    if buf:
                        parts.append(("dq", "".join(buf))); buf = []
                    parts.append(("dqcmd", src[i + 1:k])); i = k + 1; continue
                buf.append(ch); i += 1
            if buf or not parts:
                parts.append(("dq", "".join(buf)))
            in_word = True
            continue
        if c == "$" and i + 1 < n and src[i + 1] == "'":
            k = i + 2
            while k < n and src[k] != "'":
                k += 2 if src[k] == "\\" else 1
            if k >= n:
                raise Incomplete()
            flush_lit(); parts.append(("sq", _decode_ansi_c(src[i + 2:k]))); in_word = True; i = k + 1; continue
        if c == "$" and i + 1 < n and src[i + 1] == "(":
            k = _match_paren(src, i + 1)
            flush_lit(); parts.append(("cmd", src[i + 2:k])); in_word = True; i = k + 1; continue
        if c == "`":
            k = src.find("`", i + 1)
            if k < 0:
                raise Incomplete()
            flush_lit(); parts.append(("cmd", src[i + 1:k])); in_word = True; i = k + 1; continue
        if c in ";&|()<>":
            # fd-prefixed redirection like 2>/dev/null or 1>&2
            fd_prefix = None
            if c in "<>" and in_word and not parts and len(lit) == 1 and lit[0].isdigit():
                fd_prefix = int(lit[0]); lit.clear(); in_word = False
            else:
                end_word()
            op = None
            for cand in _OPS3 + _OPS2:
                if src.startswith(cand, i):
                    op = cand; break
            if op is None:
                op = c
            i += len(op)
            if op in (">", ">>", "<", ">&", "<&", "<<", "<<-", "&>"):
                # next word is the target
                while i < n and src[i] in " \t":
                    i += 1
                sub = _read_simple_word(src, i)
                if sub is None:
                    raise ShellSyntaxError("syntax error near unexpected token `newline'")
                w, i = sub
                fd = fd_prefix if fd_prefix is not None else (0 if op.startswith("<") else 1)
                both = op == "&>"
                if both:
                    op, fd = ">", 1
                r = Redir(fd, op, w)
                if op in ("<<", "<<-"):
                    r.quoted_delim = w.quoted
                    r.target = Word([("lit", w.raw)])
                    pending_heredocs.append(r)
                toks.append(Tok("op", op="redir", redir=r))
                if both:
                    toks.append(Tok("op", op="redir", redir=Redir(2, ">&", Word([("lit", "1")]))))
                continue
            toks.append(Tok("op", op=op))
            continue
        lit.append(c); in_word = True; i += 1
    end_word()
    if pending_heredocs:
        raise Incomplete()
    return toks


def _read_simple_word(src: str, i: int) -> tuple[Word, int] | None:
    n = len(src)
    parts: list[tuple[str, str]] = []
    lit: list[str] = []
    start = i
    while i < n and src[i] not in " \t\n;&|()<>":
        c = src[i]
        if c == "'":
            k = src.find("'", i + 1)
            if k < 0:
                raise Incomplete()
            if lit:
                parts.append(("lit", "".join(lit))); lit = []
            parts.append(("sq", src[i + 1:k])); i = k + 1; continue
        if c == '"':
            k = i + 1
            while k < n and src[k] != '"':
                k += 2 if src[k] == "\\" else 1
            if k >= n:
                raise Incomplete()
            if lit:
                parts.append(("lit", "".join(lit))); lit = []
            parts.append(("dq", src[i + 1:k])); i = k + 1; continue
        if c == "\\" and i + 1 < n:
            lit.append(src[i + 1]); i += 2; continue
        lit.append(c); i += 1
    if lit:
        parts.append(("lit", "".join(lit)))
    if i == start:
        return None
    return Word(parts), i


# ================================================================= parser

@dataclass
class Simple:
    assigns: list[tuple[str, Word]] = field(default_factory=list)
    words: list[Word] = field(default_factory=list)
    redirs: list[Redir] = field(default_factory=list)


@dataclass
class Pipeline:
    cmds: list
    negate: bool = False


@dataclass
class AndOr:
    first: Pipeline
    rest: list[tuple[str, Pipeline]] = field(default_factory=list)


@dataclass
class Seq:
    items: list[tuple[AndOr, bool]] = field(default_factory=list)   # (andor, background)


@dataclass
class If:
    branches: list[tuple[Seq, Seq]]
    other: Seq | None = None


@dataclass
class While:
    cond: Seq
    body: Seq
    until: bool = False


@dataclass
class For:
    var: str
    words: list[Word] | None
    body: Seq


@dataclass
class Case:
    word: Word
    items: list[tuple[list[Word], Seq]]


@dataclass
class Group:
    body: Seq
    subshell: bool = False


@dataclass
class FuncDef:
    name: str
    body: object


_RESERVED = {"if", "then", "elif", "else", "fi", "while", "until", "do", "done", "for", "in", "case", "esac", "{", "}", "!"}
_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)


class Parser:
    def __init__(self, toks: list[Tok]) -> None:
        self.t = toks
        self.i = 0

    # helpers
    def peek(self) -> Tok | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def next(self) -> Tok | None:
        tok = self.peek()
        self.i += 1
        return tok

    def _is_op(self, tok: Tok | None, *ops: str) -> bool:
        return bool(tok and tok.kind == "op" and tok.op in ops)

    def _kw(self, tok: Tok | None) -> str | None:
        if tok and tok.kind == "word" and tok.word and len(tok.word.parts) == 1 and tok.word.parts[0][0] == "lit":
            v = tok.word.parts[0][1]
            if v in _RESERVED:
                return v
        return None

    def skip_nl(self) -> None:
        while (t := self.peek()) and (t.kind == "nl"):
            self.i += 1

    def skip_seps(self) -> None:
        while (t := self.peek()) and (t.kind == "nl" or self._is_op(t, ";")):
            self.i += 1

    # grammar
    def parse_script(self) -> Seq:
        seq = self.parse_seq(stop=set())
        if self.peek() is not None:
            raise ShellSyntaxError(f"syntax error near unexpected token `{self._desc(self.peek())}'")
        return seq

    def _desc(self, tok: Tok | None) -> str:
        if tok is None:
            return "newline"
        return tok.op if tok.kind == "op" else tok.word.raw if tok.word else "newline"

    def parse_seq(self, stop: set[str]) -> Seq:
        seq = Seq()
        self.skip_seps()
        while (tok := self.peek()) is not None:
            kw = self._kw(tok)
            if kw in stop or self._is_op(tok, ")") and ")" in stop:
                break
            if self._is_op(tok, ")") or kw in {"then", "elif", "else", "fi", "do", "done", "esac", "}", "in"} and kw not in stop:
                if self._is_op(tok, ")"):
                    break
                raise ShellSyntaxError(f"syntax error near unexpected token `{kw}'")
            ao = self.parse_andor()
            bg = False
            if self._is_op(self.peek(), "&"):
                self.i += 1; bg = True
            seq.items.append((ao, bg))
            self.skip_seps()
        return seq

    def parse_andor(self) -> AndOr:
        first = self.parse_pipeline()
        rest = []
        while self._is_op(self.peek(), "&&", "||"):
            op = self.next().op  # type: ignore[union-attr]
            self.skip_nl()
            if self.peek() is None:
                raise Incomplete()
            rest.append((op, self.parse_pipeline()))
        return AndOr(first, rest)

    def parse_pipeline(self) -> Pipeline:
        negate = False
        if self._kw(self.peek()) == "!":
            self.i += 1; negate = True
        cmds = [self.parse_command()]
        while self._is_op(self.peek(), "|"):
            self.i += 1
            self.skip_nl()
            if self.peek() is None:
                raise Incomplete()
            cmds.append(self.parse_command())
        return Pipeline(cmds, negate)

    def parse_command(self):
        tok = self.peek()
        if tok is None:
            raise Incomplete()
        kw = self._kw(tok)
        if kw == "if":
            return self.parse_if()
        if kw in ("while", "until"):
            return self.parse_while()
        if kw == "for":
            return self.parse_for()
        if kw == "case":
            return self.parse_case()
        if kw == "{":
            self.i += 1
            body = self.parse_seq({"}"})
            if self._kw(self.peek()) != "}":
                raise Incomplete()
            self.i += 1
            return self._with_redirs(Group(body))
        if self._is_op(tok, "("):
            self.i += 1
            body = self.parse_seq({")"})
            if not self._is_op(self.peek(), ")"):
                raise Incomplete()
            self.i += 1
            return self._with_redirs(Group(body, True))
        # function definition: name ( ) { ... }
        nxt = self.t[self.i + 1] if self.i + 1 < len(self.t) else None
        if tok.kind == "word" and nxt and self._is_op(nxt, "(") and self.i + 2 < len(self.t) and self._is_op(self.t[self.i + 2], ")"):
            name = tok.word.raw  # type: ignore[union-attr]
            self.i += 3
            self.skip_nl()
            body = self.parse_command()
            return FuncDef(name, body)
        return self.parse_simple()

    def _with_redirs(self, node):
        redirs = []
        while (t := self.peek()) and t.kind == "op" and t.op == "redir":
            redirs.append(t.redir); self.i += 1
        if redirs:
            return _Wrapped(node, redirs)
        return node

    def parse_simple(self) -> Simple:
        s = Simple()
        seen_cmd = False
        while (t := self.peek()) is not None:
            if t.kind == "word":
                w = t.word
                assert w is not None
                if not seen_cmd:
                    lit = w.parts[0][1] if w.parts and w.parts[0][0] == "lit" else ""
                    m = _ASSIGN_RE.match(lit) if lit else None
                    if m:
                        val_parts = list(w.parts)
                        val_parts[0] = ("lit", m.group(2))
                        s.assigns.append((m.group(1), Word([p for p in val_parts if p[1] != "" or p[0] != "lit"] or [("lit", "")])))
                        self.i += 1
                        continue
                s.words.append(w); seen_cmd = True; self.i += 1
            elif t.kind == "op" and t.op == "redir":
                s.redirs.append(t.redir); self.i += 1   # type: ignore[arg-type]
            else:
                break
        if not s.words and not s.assigns and not s.redirs:
            raise ShellSyntaxError(f"syntax error near unexpected token `{self._desc(self.peek())}'")
        return s

    def parse_if(self) -> If:
        self.i += 1
        branches = []
        cond = self.parse_seq({"then"})
        if self._kw(self.peek()) != "then":
            raise Incomplete()
        self.i += 1
        body = self.parse_seq({"elif", "else", "fi"})
        branches.append((cond, body))
        other = None
        while True:
            kw = self._kw(self.peek())
            if kw == "elif":
                self.i += 1
                c = self.parse_seq({"then"})
                if self._kw(self.peek()) != "then":
                    raise Incomplete()
                self.i += 1
                branches.append((c, self.parse_seq({"elif", "else", "fi"})))
            elif kw == "else":
                self.i += 1
                other = self.parse_seq({"fi"})
            elif kw == "fi":
                self.i += 1
                break
            else:
                raise Incomplete()
        return self._with_redirs(If(branches, other))

    def parse_while(self):
        until = self._kw(self.peek()) == "until"
        self.i += 1
        cond = self.parse_seq({"do"})
        if self._kw(self.peek()) != "do":
            raise Incomplete()
        self.i += 1
        body = self.parse_seq({"done"})
        if self._kw(self.peek()) != "done":
            raise Incomplete()
        self.i += 1
        return self._with_redirs(While(cond, body, until))

    def parse_for(self):
        self.i += 1
        tok = self.next()
        if tok is None or tok.kind != "word":
            raise Incomplete()
        var = tok.word.raw  # type: ignore[union-attr]
        words = None
        self.skip_nl()
        if self._kw(self.peek()) == "in":
            self.i += 1
            words = []
            while (t := self.peek()) and t.kind == "word" and self._kw(t) != "do":
                words.append(t.word); self.i += 1       # type: ignore[arg-type]
        self.skip_seps()
        if self._kw(self.peek()) != "do":
            raise Incomplete()
        self.i += 1
        body = self.parse_seq({"done"})
        if self._kw(self.peek()) != "done":
            raise Incomplete()
        self.i += 1
        return self._with_redirs(For(var, words, body))

    def parse_case(self):
        self.i += 1
        tok = self.next()
        if tok is None or tok.kind != "word":
            raise Incomplete()
        word = tok.word
        self.skip_nl()
        if self._kw(self.peek()) != "in":
            raise Incomplete()
        self.i += 1
        items = []
        self.skip_seps()
        while self.peek() is not None and self._kw(self.peek()) != "esac":
            if self._is_op(self.peek(), "("):
                self.i += 1
            pats = []
            while (t := self.peek()) and t.kind == "word":
                pats.append(t.word); self.i += 1
                if self._is_op(self.peek(), "|"):
                    self.i += 1
                else:
                    break
            if not self._is_op(self.peek(), ")"):
                raise Incomplete()
            self.i += 1
            body = self._case_body()
            items.append((pats, body))
            self.skip_seps()
        if self._kw(self.peek()) != "esac":
            raise Incomplete()
        self.i += 1
        return Case(word, items)  # type: ignore[arg-type]

    def _case_body(self) -> Seq:
        seq = Seq()
        self.skip_seps()
        while (tok := self.peek()) is not None:
            if self._is_op(tok, ";;") or self._kw(tok) == "esac":
                break
            ao = self.parse_andor()
            seq.items.append((ao, False))
            self.skip_seps()
        if self._is_op(self.peek(), ";;"):
            self.i += 1
        return seq


@dataclass
class _Wrapped:
    node: object
    redirs: list[Redir]


def parse(src: str) -> Seq:
    return Parser(tokenize(src)).parse_script()


# ============================================================== evaluator

_VAR_RE = re.compile(r"\$(\{([^}]*)\}|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])")


@dataclass
class Proc:
    stdin: bytes = b""
    out: bytearray = field(default_factory=bytearray)
    err: bytearray = field(default_factory=bytearray)

    def write(self, s: str | bytes) -> None:
        self.out += s.encode("utf-8", "surrogateescape") if isinstance(s, str) else s

    def error(self, s: str | bytes) -> None:
        self.err += s.encode("utf-8", "surrogateescape") if isinstance(s, str) else s


class Interpreter:
    MAX_DEPTH = 6
    MAX_LOOP = 40

    def __init__(self, sh: "ShellSession") -> None:
        self.sh = sh
        self.depth = 0

    # ----------------------------------------------------------- expansion
    def _var(self, name: str) -> str:
        sh = self.sh
        if name == "?":
            return str(sh.status)
        if name == "$":
            return "1337"
        if name in ("@", "*"):
            return " ".join(sh.positional)
        if name == "#":
            return str(len(sh.positional))
        if name.isdigit():
            idx = int(name)
            if idx == 0:
                return sh.arg0
            return sh.positional[idx - 1] if idx <= len(sh.positional) else ""
        return sh.vars.get(name, "")

    def _expand_vars(self, text: str) -> str:
        def repl(m: re.Match[str]) -> str:
            g = m.group(2) if m.group(2) is not None else m.group(1)
            if m.group(2) is not None:
                inner = g
                for op in (":-", ":=", "-", ":+", "+"):
                    if op in inner:
                        name, _, default = inner.partition(op)
                        val = self.sh.vars.get(name, "")
                        if op in (":-", ":="):
                            return val if val else default
                        if op == "-":
                            return val if name in self.sh.vars else default
                        return default if val else ""
                if inner.startswith("#"):
                    return str(len(self._var(inner[1:])))
                if ":" in inner and re.match(r"^\w+:\d+(:\d+)?$", inner):
                    name, off, *ln = inner.split(":")
                    v = self._var(name)
                    s = int(off)
                    return v[s:s + int(ln[0])] if ln else v[s:]
                return self._var(inner)
            return self._var(g)
        return _VAR_RE.sub(repl, text)

    async def expand_word(self, w: Word) -> list[str]:
        """Expand to zero or more fields (var/cmd substitution, splitting, globbing)."""
        fields: list[list[tuple[str, bool]]] = [[]]   # each field is list of (text, protected)

        def add(text: str, protect: bool) -> None:
            fields[-1].append((text, protect))

        for kind, text in w.parts:
            if kind == "lit":
                text = text.replace("\\$", "\x00")   # escaped dollar from dq handling
                if text.startswith("~") and not fields[-1]:
                    text = self.sh.home + text[1:]
                expanded = self._expand_vars(text).replace("\x00", "$")
                # unquoted expansions are subject to word splitting
                if expanded != text and re.search(r"\s", expanded):
                    pieces = expanded.split()
                    for idx, piece in enumerate(pieces):
                        if idx:
                            fields.append([])
                        add(piece, False)
                    if expanded.endswith((" ", "\t")):
                        fields.append([])
                else:
                    add(expanded, False)
            elif kind == "sq":
                add(text, True)
            elif kind == "dq":
                add(self._expand_vars(text.replace("\\$", "\x00")).replace("\x00", "$"), True)
            elif kind in ("cmd", "dqcmd"):
                out = await self.command_subst(text)
                if kind == "cmd":
                    pieces = out.split()
                    for idx, piece in enumerate(pieces):
                        if idx:
                            fields.append([])
                        add(piece, False)
                else:
                    add(out, True)
        results: list[str] = []
        for fld in fields:
            if not fld and not w.quoted:
                continue
            text = "".join(t for t, _ in fld)
            unquoted_glob = any(c in text for c in "*?[") and not all(p for _, p in fld)
            if unquoted_glob:
                matches = self.sh.fs.glob(text, self.sh.cwd)
                if matches:
                    results.extend(matches)
                    continue
            results.append(text)
        return results

    async def command_subst(self, src: str) -> str:
        if self.depth >= self.MAX_DEPTH:
            return ""
        proc = Proc()
        self.depth += 1
        try:
            tree = parse(src)
            await self.run_seq(tree, proc)
        except (Incomplete, ShellSyntaxError):
            return ""
        finally:
            self.depth -= 1
        self.sh.terminal += proc.err
        return proc.out.decode("utf-8", "replace").rstrip("\n")

    # ----------------------------------------------------------- execution
    async def run_seq(self, seq: Seq, proc: Proc) -> int:
        status = self.sh.status
        for ao, bg in seq.items:
            status = await self.run_andor(ao, proc)
            self.sh.status = status
        return status

    async def run_andor(self, ao: AndOr, proc: Proc) -> int:
        status = await self.run_pipeline(ao.first, proc)
        self.sh.status = status
        for op, pl in ao.rest:
            if (op == "&&" and status == 0) or (op == "||" and status != 0):
                status = await self.run_pipeline(pl, proc)
                self.sh.status = status
        return status

    async def run_pipeline(self, pl: Pipeline, proc: Proc) -> int:
        data = proc.stdin
        status = 0
        for idx, cmd in enumerate(pl.cmds):
            last = idx == len(pl.cmds) - 1
            stage = Proc(stdin=data)
            status = await self.run_node(cmd, stage)
            self.sh.terminal += stage.err
            if last:
                proc.out += stage.out
            else:
                data = bytes(stage.out)
        return (0 if status else 1) if pl.negate else status

    async def run_node(self, node, proc: Proc) -> int:
        self.sh.tick()
        if isinstance(node, Simple):
            return await self.run_simple(node, proc)
        if isinstance(node, _Wrapped):
            return await self._with_redirections(node.redirs, proc, lambda p: self.run_node(node.node, p))
        if isinstance(node, Group):
            if node.subshell:
                saved = (dict(self.sh.vars), self.sh.cwd)
                st = await self.run_seq(node.body, proc)
                self.sh.vars, self.sh.cwd = saved
                return st
            return await self.run_seq(node.body, proc)
        if isinstance(node, If):
            for cond, body in node.branches:
                if await self.run_seq(cond, Proc(stdin=proc.stdin, out=proc.out, err=proc.err)) == 0:
                    return await self.run_seq(body, proc)
            if node.other is not None:
                return await self.run_seq(node.other, proc)
            return 0
        if isinstance(node, While):
            status, n = 0, 0
            while n < self.MAX_LOOP:
                n += 1
                c = await self.run_seq(node.cond, Proc(stdin=proc.stdin, out=proc.out, err=proc.err))
                if (c == 0) == node.until:
                    break
                try:
                    status = await self.run_seq(node.body, proc)
                except BreakLoop as b:
                    if b.n > 1:
                        raise BreakLoop(b.n - 1)
                    break
                except ContinueLoop as c2:
                    if c2.n > 1:
                        raise ContinueLoop(c2.n - 1)
            return status
        if isinstance(node, For):
            items: list[str] = []
            if node.words is None:
                items = list(self.sh.positional)
            else:
                for w in node.words:
                    items.extend(await self.expand_word(w))
            status = 0
            for item in items[: self.MAX_LOOP]:
                self.sh.vars[node.var] = item
                try:
                    status = await self.run_seq(node.body, proc)
                except BreakLoop as b:
                    if b.n > 1:
                        raise BreakLoop(b.n - 1)
                    break
                except ContinueLoop as c2:
                    if c2.n > 1:
                        raise ContinueLoop(c2.n - 1)
            return status
        if isinstance(node, Case):
            word = "".join(await self.expand_word(node.word))
            import fnmatch
            for pats, body in node.items:
                for pw in pats:
                    for pat in await self.expand_word(pw) or [""]:
                        if fnmatch.fnmatchcase(word, pat):
                            return await self.run_seq(body, proc)
            return 0
        if isinstance(node, FuncDef):
            self.sh.functions[node.name] = node.body
            return 0
        raise ShellSyntaxError("unsupported construct")

    async def _with_redirections(self, redirs: list[Redir], proc: Proc, runner) -> int:
        inner = Proc(stdin=proc.stdin)
        for r in redirs:
            if r.op in ("<<", "<<-"):
                body = r.body if r.quoted_delim else self._expand_vars(r.body)
                inner.stdin = body.encode("utf-8", "surrogateescape")
            elif r.op == "<" and r.target is not None:
                path = "".join(await self.expand_word(r.target))
                try:
                    node = self.sh.fs.lookup(self.sh.fs.normpath(path, self.sh.cwd, self.sh.home))
                    if node is None:
                        raise FSError("No such file or directory")
                    inner.stdin = node.content
                except FSError as e:
                    proc.error(f"sh: {path}: {e}\n")
                    return 1
        status = await runner(inner)
        out, err = bytes(inner.out), bytes(inner.err)
        for r in redirs:
            if r.op in (">", ">>") and r.target is not None:
                path = "".join(await self.expand_word(r.target))
                data = out if r.fd == 1 else err
                if r.fd == 1:
                    out = b""
                else:
                    err = b""
                if path == "/dev/null":
                    continue
                if path in ("/dev/stderr",):
                    err += data
                    continue
                if path in ("/dev/stdout",):
                    out += data
                    continue
                try:
                    p = self.sh.fs.normpath(path, self.sh.cwd, self.sh.home)
                    self.sh.fs.write(p, data, append=(r.op == ">>"))
                    self.sh.note_write(p)
                except FSError as e:
                    proc.error(f"sh: can't create {path}: {e}\n")
                    status = 1
            elif r.op == ">&" and r.target is not None:
                tgt = "".join(await self.expand_word(r.target))
                if r.fd == 2 and tgt == "1":
                    out, err = out + err, b""
                elif r.fd == 1 and tgt == "2":
                    err, out = err + out, b""
        proc.out += out
        proc.err += err
        return status

    async def run_simple(self, s: Simple, proc: Proc) -> int:
        sh = self.sh
        argv: list[str] = []
        for w in s.words:
            argv.extend(await self.expand_word(w))
        temp_env: dict[str, str] = {}
        for name, w in s.assigns:
            val = "".join(await self.expand_word(w)) if w.parts != [("lit", "")] else ""
            temp_env[name] = val
        if not argv:
            sh.vars.update(temp_env)
            if s.redirs:
                return await self._with_redirections(s.redirs, proc, lambda p: _noop())
            return 0

        async def runner(p: Proc) -> int:
            saved = {k: sh.vars.get(k) for k in temp_env}
            sh.vars.update(temp_env)
            try:
                return await self.dispatch(argv, p)
            finally:
                for k, v in saved.items():
                    if v is None:
                        sh.vars.pop(k, None)
                    else:
                        sh.vars[k] = v

        if s.redirs:
            return await self._with_redirections(s.redirs, proc, runner)
        return await runner(proc)

    async def dispatch(self, argv: list[str], proc: Proc) -> int:
        sh = self.sh
        name = argv[0]
        sh.executed.append(name.rsplit("/", 1)[-1])
        if name in sh.functions:
            if self.depth >= self.MAX_DEPTH:
                return 1
            saved = sh.positional
            sh.positional = argv[1:]
            self.depth += 1
            try:
                return await self.run_node(sh.functions[name], proc)
            except ReturnFunc as r:
                return r.status
            finally:
                self.depth -= 1
                sh.positional = saved
        return await sh.run_command(argv, proc)


async def _noop() -> int:
    return 0
