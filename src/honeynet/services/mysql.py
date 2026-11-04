"""MySQL honeypot: protocol-10 handshake, offline cracking of weak passwords from the
mysql_native_password scramble, then a tiny query emulator that logs everything."""

from __future__ import annotations

import hashlib
import os
import re
import struct

from ..common.events import AUTH_ATTEMPT, DB_QUERY, EXPLOIT, SESSION_CLOSE, SESSION_OPEN
from ..common.sanitize import sanitize_text
from .auth_policy import ALLOWED_USERS, WEAK_PASSWORDS, decide
from .base import Connection, TCPService, register

SERVER_VERSION = "5.7.42-0ubuntu0.18.04.1"
MAX_PACKET = 1 << 20

CLIENT_LONG_PASSWORD, CLIENT_FOUND_ROWS, CLIENT_LONG_FLAG, CLIENT_CONNECT_WITH_DB = 1, 2, 4, 8
CLIENT_PROTOCOL_41, CLIENT_TRANSACTIONS, CLIENT_SECURE_CONNECTION = 1 << 9, 1 << 13, 1 << 15
CLIENT_MULTI_STATEMENTS, CLIENT_MULTI_RESULTS, CLIENT_PLUGIN_AUTH = 1 << 16, 1 << 17, 1 << 19
CLIENT_CONNECT_ATTRS, CLIENT_PLUGIN_AUTH_LENENC = 1 << 20, 1 << 21
SERVER_CAPS = (CLIENT_LONG_PASSWORD | CLIENT_FOUND_ROWS | CLIENT_LONG_FLAG | CLIENT_CONNECT_WITH_DB | CLIENT_PROTOCOL_41 |
               CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_MULTI_STATEMENTS | CLIENT_MULTI_RESULTS |
               CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_ATTRS | CLIENT_PLUGIN_AUTH_LENENC)


# ------------------------------------------------------------------ packet helpers

def lenenc_int(n: int) -> bytes:
    if n < 251:
        return bytes([n])
    if n < 1 << 16:
        return b"\xfc" + struct.pack("<H", n)
    if n < 1 << 24:
        return b"\xfd" + struct.pack("<I", n)[:3]
    return b"\xfe" + struct.pack("<Q", n)


def lenenc_str(s: bytes | None) -> bytes:
    if s is None:
        return b"\xfb"
    return lenenc_int(len(s)) + s


def read_lenenc(buf: bytes, off: int) -> tuple[int | None, int]:
    first = buf[off]
    if first < 0xFB:
        return first, off + 1
    if first == 0xFB:
        return None, off + 1
    if first == 0xFC:
        return struct.unpack_from("<H", buf, off + 1)[0], off + 3
    if first == 0xFD:
        return int.from_bytes(buf[off + 1: off + 4], "little"), off + 4
    return struct.unpack_from("<Q", buf, off + 1)[0], off + 9


def native_scramble(password: str, salt: bytes) -> bytes:
    """mysql_native_password client response for a candidate password."""
    if not password:
        return b""
    h1 = hashlib.sha1(password.encode("utf-8", "surrogateescape")).digest()
    h2 = hashlib.sha1(h1).digest()
    h3 = hashlib.sha1(salt + h2).digest()
    return bytes(a ^ b for a, b in zip(h1, h3))


def pkt(seq: int, payload: bytes) -> bytes:
    return struct.pack("<I", len(payload))[:3] + bytes([seq & 0xFF]) + payload


def ok_packet(seq: int, affected: int = 0) -> bytes:
    return pkt(seq, b"\x00" + lenenc_int(affected) + lenenc_int(0) + struct.pack("<HH", 2, 0))


def err_packet(seq: int, code: int, state: str, msg: str) -> bytes:
    return pkt(seq, b"\xff" + struct.pack("<H", code) + b"#" + state.encode() + msg.encode("utf-8", "replace"))


def eof_packet(seq: int) -> bytes:
    return pkt(seq, b"\xfe" + struct.pack("<HH", 0, 2))


def column_def(seq: int, name: str) -> bytes:
    nm = name.encode()
    payload = (lenenc_str(b"def") + lenenc_str(b"") + lenenc_str(b"") + lenenc_str(b"") + lenenc_str(nm) + lenenc_str(nm)
               + b"\x0c" + struct.pack("<H", 0x21) + struct.pack("<I", 255) + b"\xfd" + struct.pack("<H", 0) + b"\x00\x00\x00")
    return pkt(seq, payload)


def result_set(columns: list[str], rows: list[list[str | None]], seq0: int = 1) -> bytes:
    out = pkt(seq0, lenenc_int(len(columns)))
    seq = seq0 + 1
    for c in columns:
        out += column_def(seq, c); seq += 1
    out += eof_packet(seq); seq += 1
    for r in rows:
        out += pkt(seq, b"".join(lenenc_str(None if v is None else v.encode("utf-8", "replace")) for v in r)); seq += 1
    out += eof_packet(seq)
    return out


# ------------------------------------------------------------------ query emulation

FAKE_DBS = ["information_schema", "mysql", "performance_schema", "sys", "app_prod"]
FAKE_USERS = [["1", "admin", "5f4dcc3b5aa765d61d8327deb882cf99", "admin@example.com"],
              ["2", "jsmith", "e10adc3949ba59abbe56e057f20f883e", "j.smith@example.com"],
              ["3", "backup", "25d55ad283aa400af464c76d713c07ad", "backup@example.com"]]

MYSQL_RULES = [
    ("mysql-file-write", re.compile(r"into\s+(out|dump)file", re.I), "file-write", "T1105"),
    ("mysql-file-read", re.compile(r"load_file\s*\(|load\s+data\s+(local\s+)?infile", re.I), "file-read", ""),
    ("mysql-udf-install", re.compile(r"create\s+(or\s+replace\s+)?function\s+\w+\s+returns.*soname", re.I | re.S), "udf-rce", ""),
    ("mysql-sys-exec", re.compile(r"\b(sys_exec|sys_eval|xp_cmdshell)\s*\(", re.I), "rce", ""),
    ("mysql-privilege-change", re.compile(r"^\s*(grant|create\s+user|alter\s+user|set\s+password)\b", re.I), "persistence", ""),
    ("mysql-drop-database", re.compile(r"^\s*drop\s+(database|schema)\b", re.I), "destructive", ""),
    ("mysql-ransom-note", re.compile(r"(bitcoin|btc|ransom|recover|your\s+data\s+(has|have)\s+been)", re.I), "ransom", ""),
]


def answer_query(q: str, seq: int, user: str) -> bytes:
    s = re.sub(r"/\*.*?\*/", " ", q, flags=re.S).strip().rstrip(";").strip()
    low = s.lower()
    if low.startswith("select") and ("into outfile" in low or "into dumpfile" in low or "load_file" in low):
        return err_packet(seq, 1290, "HY000", "The MySQL server is running with the --secure-file-priv option so it cannot execute this statement")
    if low in ("select version()", "select @@version"):
        return result_set(["version()"], [[SERVER_VERSION]])
    if low.startswith("select @@version_comment"):
        return result_set(["@@version_comment"], [["(Ubuntu)"]])
    if low in ("select user()", "select current_user()", "select current_user"):
        return result_set(["user()"], [[f"{user}@localhost"]])
    if low in ("select database()",):
        return result_set(["database()"], [[None]])
    if low.startswith("select @@") or low.startswith("select @@global"):
        return result_set([s[7:].strip()[:40] or "v"], [["0" if "secure_file_priv" not in low else None]])
    if re.fullmatch(r"select\s+\d+", low):
        return result_set([s[7:]], [[s[7:]]])
    if low.startswith("select sleep"):
        return result_set(["sleep(1)"], [["0"]])
    if low in ("show databases", "show schemas"):
        return result_set(["Database"], [[d] for d in FAKE_DBS])
    if low.startswith("show tables"):
        return result_set(["Tables_in_app_prod"], [["users"], ["orders"], ["sessions"]])
    if low.startswith("show grants"):
        return result_set([f"Grants for {user}@localhost"], [[f"GRANT ALL PRIVILEGES ON *.* TO '{user}'@'localhost' WITH GRANT OPTION"]])
    if low.startswith("show variables") or low.startswith("show global variables"):
        return result_set(["Variable_name", "Value"], [["version", SERVER_VERSION], ["version_comment", "(Ubuntu)"],
                                                       ["secure_file_priv", "/var/lib/mysql-files/"], ["datadir", "/var/lib/mysql/"],
                                                       ["hostname", "db01"], ["port", "3306"]])
    if low.startswith("show processlist") or low.startswith("show full processlist"):
        return result_set(["Id", "User", "Host", "db", "Command", "Time", "State", "Info"],
                          [["8", user, "localhost", None, "Query", "0", "starting", "show processlist"]])
    if low.startswith("show status"):
        return result_set(["Variable_name", "Value"], [["Uptime", "3201433"], ["Threads_connected", "1"]])
    if re.match(r"select\s+.*\s+from\s+(app_prod\.)?users", low):
        return result_set(["id", "username", "password", "email"], FAKE_USERS)
    if re.match(r"(select|show|describe|desc|explain)\b", low):
        return result_set(["result"], [])
    if low.startswith("use "):
        return ok_packet(seq)
    return ok_packet(seq, affected=0)


@register
class MySQLService(TCPService):
    name = "mysql"
    default_ports = [3306]

    async def _read_packet(self, conn: Connection, timeout: float | None = None) -> tuple[int, bytes] | None:
        head = await conn.readexactly(4, timeout)
        length = int.from_bytes(head[:3], "little")
        if length > MAX_PACKET:
            return None
        payload = await conn.readexactly(length, timeout) if length else b""
        return head[3], payload

    async def handle(self, conn: Connection) -> None:
        salt = os.urandom(20)
        salt = bytes((b % 94) + 33 for b in salt)       # printable, no NUL
        tid = int.from_bytes(os.urandom(2), "big")
        hs = (b"\x0a" + SERVER_VERSION.encode() + b"\x00" + struct.pack("<I", tid) + salt[:8] + b"\x00"
              + struct.pack("<H", SERVER_CAPS & 0xFFFF) + b"\x21" + struct.pack("<H", 2)
              + struct.pack("<H", SERVER_CAPS >> 16) + bytes([21]) + b"\x00" * 10 + salt[8:20] + b"\x00"
              + b"mysql_native_password\x00")
        await conn.send(pkt(0, hs))
        got = await self._read_packet(conn, 20)
        if got is None:
            return
        seq, payload = got
        if len(payload) < 33:
            conn.emit("probe", proto_guess="mysql-short-handshake", first_bytes_hex=payload[:48].hex())
            return
        caps = struct.unpack_from("<I", payload, 0)[0]
        off = 32
        end = payload.find(b"\x00", off)
        if end < 0:
            return
        user = payload[off:end].decode("utf-8", "replace")
        off = end + 1
        try:
            if caps & CLIENT_PLUGIN_AUTH_LENENC:
                n, off = read_lenenc(payload, off)
                resp = payload[off: off + (n or 0)]
                off += n or 0
            elif caps & CLIENT_SECURE_CONNECTION:
                n = payload[off]
                resp = payload[off + 1: off + 1 + n]
                off += 1 + n
            else:
                end = payload.find(b"\x00", off)
                resp = payload[off:end]
                off = end + 1
            db = plugin = ""
            if caps & CLIENT_CONNECT_WITH_DB:
                end = payload.find(b"\x00", off)
                db = payload[off:end].decode("utf-8", "replace")
                off = end + 1
            if caps & CLIENT_PLUGIN_AUTH:
                end = payload.find(b"\x00", off)
                plugin = payload[off:end].decode("ascii", "replace")
        except (IndexError, struct.error):
            resp, db, plugin = b"", "", ""

        # offline "cracking" of the scramble against well-known weak passwords (and empty)
        cracked: str | None = None
        if not resp:
            cracked = ""
        else:
            for cand in WEAK_PASSWORDS:
                if native_scramble(cand, salt) == resp:
                    cracked = cand
                    break
        ok = False
        if cracked is not None:
            # weak password + common user => in; empty/unknown => same deterministic roll as SSH
            ok = decide(conn.ip, user, cracked or "(empty)", self.settings.ssh_accept_pct)
        conn.emit(AUTH_ATTEMPT, username=user, password=cracked if cracked is not None else "",
                  password_recovered=cracked is not None, method="mysql_native_password", success=ok, database=db,
                  hash=f"$mysqlna${salt.hex()}*{resp.hex()}" if resp else "", client_plugin=plugin, caps=caps)
        if not ok:
            await conn.send(err_packet(seq + 1, 1045, "28000",
                                       f"Access denied for user '{user}'@'{conn.ip}' (using password: {'YES' if resp else 'NO'})"))
            return
        conn.emit(SESSION_OPEN, username=user, password=cracked or "", method="mysql", client_version=plugin)
        await conn.send(ok_packet(seq + 1))
        queries = 0
        try:
            while queries < 200:
                got = await self._read_packet(conn)
                if got is None:
                    break
                _, body = got
                if not body:
                    continue
                cmd, arg = body[0], body[1:]
                if cmd == 0x01:     # QUIT
                    break
                if cmd == 0x03:     # QUERY
                    queries += 1
                    q = arg.decode("utf-8", "replace")
                    conn.emit(DB_QUERY, engine="mysql", query=sanitize_text(q, 4000), user=user)
                    for rule, rx, kind, _t in MYSQL_RULES:
                        if rx.search(q):
                            conn.emit(EXPLOIT, rule=rule, cve="", category=kind, severity=3,
                                      snippet=sanitize_text(q, 200), method="mysql")
                    await conn.send(answer_query(q, 1, user))
                elif cmd in (0x0E, 0x02, 0x1B):    # PING, INIT_DB, SET_OPTION
                    await conn.send(ok_packet(1))
                elif cmd == 0x04:                  # FIELD_LIST
                    await conn.send(eof_packet(1))
                else:
                    conn.emit(DB_QUERY, engine="mysql", query=f"<command 0x{cmd:02x}>", user=user)
                    await conn.send(err_packet(1, 1047, "08S01", "Unknown command"))
        finally:
            conn.emit(SESSION_CLOSE, duration=round(conn.duration, 2), commands=queries, username=user, downloads=0,
                      reason="closed")
