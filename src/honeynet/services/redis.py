"""Redis honeypot: an 'open' Redis instance speaking RESP.  Logs every command and flags the
classic abuse patterns (CONFIG SET dir/dbfilename, SSH-key and cron injection, rogue
replication, MODULE LOAD, Lua sandbox escapes)."""

from __future__ import annotations

import asyncio
import re
import time

from ..common.events import AUTH_ATTEMPT, DB_QUERY, EXPLOIT, SESSION_CLOSE, SESSION_OPEN, DOWNLOAD_ATTEMPT
from ..common.sanitize import sanitize_text
from .base import Connection, TCPService, register
from .http_rules import extract_payload_urls

MAX_ARGS = 256
MAX_BULK = 512 * 1024
MAX_STORE_BYTES = 2 * 1024 * 1024
VERSION = "5.0.7"

SSH_KEY_RE = re.compile(r"ssh-(rsa|ed25519|dss)|ecdsa-sha2")
CRON_RE = re.compile(r"(\*\s+){4}\*|/dev/tcp/|bash\s+-i|\b(wget|curl|tftp|python|perl|nc)\b.*(\||;|sh)", re.I | re.S)


class RespError(Exception):
    pass


def simple(s: str) -> bytes:
    return f"+{s}\r\n".encode()


def error(s: str) -> bytes:
    return f"-{s}\r\n".encode()


def integer(n: int) -> bytes:
    return f":{n}\r\n".encode()


def bulk(b: bytes | str | None) -> bytes:
    if b is None:
        return b"$-1\r\n"
    if isinstance(b, str):
        b = b.encode("utf-8", "surrogateescape")
    return b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"


def array(items: list[bytes]) -> bytes:
    return b"*" + str(len(items)).encode() + b"\r\n" + b"".join(items)


async def read_command(conn: Connection) -> list[bytes] | None:
    """Parse one RESP array or inline command. Returns None on EOF."""
    timeout = conn.svc.settings.max_idle_seconds
    line = await _readline(conn, timeout)
    if line is None:
        return None
    if not line:
        return []
    if line[:1] == b"*":
        try:
            n = int(line[1:])
        except ValueError:
            raise RespError("Protocol error: invalid multibulk length")
        if n < 0:
            return []
        if n > MAX_ARGS:
            raise RespError("Protocol error: invalid multibulk length")
        args = []
        total = 0
        for _ in range(n):
            hdr = await _readline(conn, timeout)
            if hdr is None or hdr[:1] != b"$":
                raise RespError("Protocol error: expected '$'")
            try:
                ln = int(hdr[1:])
            except ValueError:
                raise RespError("Protocol error: invalid bulk length")
            if ln < 0 or ln > MAX_BULK:
                raise RespError("Protocol error: invalid bulk length")
            total += ln
            if total > 4 * MAX_BULK:
                raise RespError("Protocol error: too big")
            data = await conn.readexactly(ln + 2, timeout)
            args.append(data[:-2])
        return args
    return line.split()


async def _readline(conn: Connection, timeout: float) -> bytes | None:
    try:
        data = await asyncio.wait_for(conn.reader.readuntil(b"\n"), timeout)
    except asyncio.IncompleteReadError:
        return None
    except asyncio.LimitOverrunError:
        raise RespError("Protocol error: too big inline request")
    conn.bytes_in += len(data)
    return data.rstrip(b"\r\n")


def fake_info() -> str:
    up = 3201433
    return (f"# Server\r\nredis_version:{VERSION}\r\nredis_mode:standalone\r\nos:Linux 4.19.0-21-amd64 x86_64\r\narch_bits:64\r\n"
            f"tcp_port:6379\r\nuptime_in_seconds:{up}\r\nuptime_in_days:{up // 86400}\r\n# Clients\r\nconnected_clients:1\r\n"
            "# Memory\r\nused_memory:871256\r\nused_memory_human:850.84K\r\n# Persistence\r\nloading:0\r\nrdb_last_save_time:1730000000\r\n"
            "# Replication\r\nrole:master\r\nconnected_slaves:0\r\n# Keyspace\r\ndb0:keys=2,expires=0,avg_ttl=0\r\n")


@register
class RedisService(TCPService):
    name = "redis"
    default_ports = [6379]

    async def handle(self, conn: Connection) -> None:
        store: dict[bytes, bytes] = {b"session:1042": b"eyJ1IjoiYWRtaW4ifQ==", b"counter": b"41"}
        config = {"dir": "/var/lib/redis", "dbfilename": "dump.rdb", "requirepass": "", "port": "6379", "bind": "0.0.0.0",
                  "protected-mode": "no", "maxmemory": "0", "appendonly": "no", "save": "3600 1 300 100 60 10000"}
        size = 0
        cmds = 0
        opened = False
        try:
            while cmds < 500:
                try:
                    args = await read_command(conn)
                except RespError as e:
                    await conn.send(error(f"ERR {e}"))
                    conn.emit("probe", proto_guess="redis-protocol-error", first_bytes="", error=str(e))
                    return
                if args is None:
                    return
                if not args:
                    continue
                cmds += 1
                if not opened:
                    opened = True
                    conn.emit(SESSION_OPEN, username="", password="", method="redis-open", client_version="")
                name = args[0].decode("utf-8", "replace").lower()
                argstr = " ".join(a.decode("utf-8", "replace") for a in args[1:])
                shown = " ".join(a.decode("utf-8", "replace") for a in args[:12])
                conn.emit(DB_QUERY, engine="redis", command=name, query=sanitize_text(shown, 2000), nargs=len(args) - 1)
                self._detect(conn, name, args, argstr)
                reply, quit_ = self._execute(conn, name, args, store, config)
                if name == "set" and len(args) >= 3:
                    size += len(args[2])
                    if size > MAX_STORE_BYTES:
                        store.clear(); size = 0
                await conn.send(reply)
                if quit_:
                    return
        finally:
            conn.emit(SESSION_CLOSE, duration=round(conn.duration, 2), commands=cmds, username="", downloads=0, reason="closed")

    # ------------------------------------------------------------- detection
    def _detect(self, conn: Connection, name: str, args: list[bytes], argstr: str) -> None:
        def hit(rule: str, category: str, snippet: str, cve: str = "", sev: int = 3) -> None:
            conn.emit(EXPLOIT, rule=rule, cve=cve, category=category, severity=sev, snippet=sanitize_text(snippet, 300),
                      method="redis")

        low = [a.decode("utf-8", "replace") for a in args]
        if name == "auth":
            user = low[1] if len(low) > 2 else "default"
            pw = low[-1] if len(low) > 1 else ""
            conn.emit(AUTH_ATTEMPT, username=user, password=pw, method="redis-auth", success=False)
        if name == "config" and len(low) >= 4 and low[1].lower() == "set":
            key, val = low[2].lower(), low[3]
            if key == "dir":
                kind = "cron" if "cron" in val else "ssh" if ".ssh" in val else "webshell" if "/www" in val or "html" in val else "path"
                hit("redis-config-dir-write", "persistence", f"dir={val} ({kind})")
            elif key == "dbfilename":
                hit("redis-config-dbfilename", "persistence", f"dbfilename={val}")
            elif key in ("slaveof", "replicaof", "appendfilename"):
                hit("redis-config-set-" + key, "exploit", f"{key}={val}")
        if name in ("slaveof", "replicaof") and len(low) >= 3 and low[1].lower() != "no":
            hit("redis-replication-rce", "rce", f"{low[1]}:{low[2]}", sev=3)
        if name == "module":
            hit("redis-module-load", "rce", argstr)
        if name in ("eval", "evalsha") and re.search(r"os\.execute|io\.popen|package\.loadlib|loadstring|cmsgpack|struct\.", argstr):
            hit("redis-lua-sandbox-escape", "rce", argstr, cve="CVE-2022-0543")
        if name in ("set", "append", "setex", "lpush", "rpush", "sadd", "hset") and len(args) >= 3:
            val = " ".join(low[2:])
            if SSH_KEY_RE.search(val):
                hit("redis-ssh-key-inject", "persistence", val[:200])
            if CRON_RE.search(val):
                hit("redis-cron-payload", "rce", val[:300])
                for u in extract_payload_urls(val):
                    conn.emit(DOWNLOAD_ATTEMPT, url=sanitize_text(u, 2048), via="redis-payload", host="", fetched=False,
                              scheme=u.split(":", 1)[0].lower())
        if name in ("flushall", "flushdb"):
            hit("redis-flush", "destructive", name, sev=2)
        if name in ("save", "bgsave") :
            hit("redis-save-after-config", "persistence", name, sev=1)
        if name.startswith("system.") or name in ("module", "debug"):
            hit("redis-module-command", "rce", name)

    # ------------------------------------------------------------- execution
    def _execute(self, conn: Connection, name: str, args: list[bytes], store: dict[bytes, bytes],
                 config: dict[str, str]) -> tuple[bytes, bool]:
        n = len(args)
        if name == "ping":
            return (bulk(args[1]) if n > 1 else simple("PONG")), False
        if name == "quit":
            return simple("OK"), True
        if name == "echo" and n > 1:
            return bulk(args[1]), False
        if name == "auth":
            return error("ERR Client sent AUTH, but no password is set"), False
        if name == "info":
            return bulk(fake_info()), False
        if name == "select":
            return simple("OK"), False
        if name == "dbsize":
            return integer(len(store)), False
        if name in ("flushall", "flushdb"):
            store.clear()
            return simple("OK"), False
        if name == "keys":
            pat = args[1].decode("utf-8", "replace") if n > 1 else "*"
            rx = re.compile("^" + re.escape(pat).replace(r"\*", ".*").replace(r"\?", ".") + "$")
            return array([bulk(k) for k in store if rx.match(k.decode("utf-8", "replace"))][:200]), False
        if name == "scan":
            return array([bulk("0"), array([bulk(k) for k in list(store)[:100]])]), False
        if name == "set" and n >= 3:
            store[args[1]] = args[2][:MAX_BULK]
            return simple("OK"), False
        if name == "setex" and n >= 4:
            store[args[1]] = args[3]
            return simple("OK"), False
        if name == "get" and n >= 2:
            return bulk(store.get(args[1])), False
        if name == "mget":
            return array([bulk(store.get(k)) for k in args[1:]]), False
        if name in ("del", "unlink"):
            return integer(sum(1 for k in args[1:] if store.pop(k, None) is not None)), False
        if name == "exists":
            return integer(sum(1 for k in args[1:] if k in store)), False
        if name == "type" and n >= 2:
            return simple("string" if args[1] in store else "none"), False
        if name in ("ttl", "pttl"):
            return integer(-1 if (n >= 2 and args[1] in store) else -2), False
        if name in ("expire", "pexpire", "persist"):
            return integer(1), False
        if name == "incr" and n >= 2:
            try:
                v = int(store.get(args[1], b"0")) + 1
            except ValueError:
                return error("ERR value is not an integer or out of range"), False
            store[args[1]] = str(v).encode()
            return integer(v), False
        if name == "append" and n >= 3:
            store[args[1]] = store.get(args[1], b"") + args[2]
            return integer(len(store[args[1]])), False
        if name == "config" and n >= 3:
            sub = args[1].decode("utf-8", "replace").lower()
            if sub == "get":
                pat = args[2].decode("utf-8", "replace").lower()
                rx = re.compile("^" + re.escape(pat).replace(r"\*", ".*") + "$")
                out: list[bytes] = []
                for k, v in config.items():
                    if rx.match(k):
                        out += [bulk(k), bulk(v)]
                return array(out), False
            if sub == "set" and n >= 4:
                config[args[2].decode("utf-8", "replace").lower()] = args[3].decode("utf-8", "replace")[:500]
                return simple("OK"), False
            if sub in ("rewrite", "resetstat"):
                return simple("OK"), False
        if name in ("save", "bgrewriteaof"):
            return simple("OK"), False
        if name == "bgsave":
            return simple("Background saving started"), False
        if name in ("slaveof", "replicaof"):
            return simple("OK"), False
        if name == "client" and n >= 2:
            sub = args[1].decode("utf-8", "replace").lower()
            if sub in ("setname",):
                conn.emit("client.fingerprint", client_name=sanitize_text(args[2] if n > 2 else b"", 80))
                return simple("OK"), False
            if sub == "getname":
                return bulk(None), False
            if sub == "id":
                return integer(7), False
            if sub == "list":
                return bulk(f"id=7 addr={conn.ip}:{conn.port} fd=8 name= age=1 idle=0 flags=N db=0 cmd=client"), False
            return simple("OK"), False
        if name == "command":
            return array([]), False
        if name == "module" and n >= 2:
            if args[1].lower() == b"list":
                return array([]), False
            return error("ERR Error loading the extension. Please check the server logs."), False
        if name in ("eval", "evalsha"):
            return bulk(None), False
        if name == "time":
            t = time.time()
            return array([bulk(str(int(t))), bulk(str(int((t % 1) * 1e6)))]), False
        if name == "shutdown":
            return error("ERR Errors trying to SHUTDOWN. Check logs."), False
        if name == "debug":
            return error("ERR DEBUG command not allowed. If the enable-debug-command option is set to \"local\", you can run it from a local connection."), False
        tail = " ".join(f"'{a.decode('utf-8', 'replace')[:30]}'" for a in args[1:5])
        return error(f"ERR unknown command '{sanitize_text(args[0], 40)}', with args beginning with: {tail}"), False
