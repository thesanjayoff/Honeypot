from __future__ import annotations

import json
import stat
import sys

import pytest

from honeynet.common.events import EventWriter, parse_event
from honeynet.common.netutil import is_public, normalize_ip
from honeynet.common.quarantine import Quarantine, QuarantineFull
from honeynet.common.redact import Redactor
from honeynet.common.sanitize import (csv_safe, defang, escape_controls, neutralize_chat, sanitize_obj,
                                      sanitize_text)


# ------------------------------------------------------------------ sanitisation

def test_escape_controls_makes_terminal_sequences_visible():
    assert escape_controls("a\x1b[31mred\x1b[0m") == "a\\x1b[31mred\\x1b[0m"
    assert escape_controls("line1\nline2\r\t") == "line1\\nline2\\r\\t"
    assert escape_controls("\x00\x07\x7f\x9b") == "\\x00\\x07\\x7f\\x9b"
    # bidi override / zero-width characters used for spoofing
    assert "‮" not in escape_controls("evil‮txt.exe")
    assert "​" not in escape_controls("a​b")


def test_sanitize_text_bounds_and_types():
    out = sanitize_text("A" * 5000, 100)
    assert out.startswith("A" * 100) and out.endswith("...[+4900]")
    assert sanitize_text(b"\xff\xfeabc\x1b") == "\\xff\\xfeabc\\x1b"
    assert sanitize_text(None) == "None"
    assert sanitize_text("\ud800 lone surrogate")  # must not raise on encode


def test_sanitize_obj_limits_depth_keys_and_items():
    deep = cur = {}
    for _ in range(20):
        cur["x"] = {}
        cur = cur["x"]
    out = json.dumps(sanitize_obj(deep))
    assert "max-depth" in out
    obj = sanitize_obj({"k\x1b<script>": "v", **{f"i{i}": i for i in range(200)}})
    assert all(k.replace("_", "").replace("-", "").replace(".", "").isalnum() for k in obj)
    assert len(obj) <= 66


def test_csv_and_chat_neutralisation():
    assert csv_safe("=HYPERLINK(\"http://x\")").startswith("'=")
    assert csv_safe("+1+1").startswith("'+")
    assert csv_safe("@SUM(A1)").startswith("'@")
    msg = neutralize_chat("@everyone <@123> [x](http://evil) `rm`")
    assert "@everyone" not in msg and "<@" not in msg and "](" not in msg and "http://" not in msg
    assert defang("http://1.2.3.4/x") == "hxxp://1[.]2[.]3[.]4/x"


# ----------------------------------------------------------------- redaction

def test_redactor_scrubs_admin_ip_and_secrets():
    r = Redactor(["203.0.113.50", "198.51.100.0/24"], ["s3cr3t-token-value"])
    assert r.is_ignored("203.0.113.50") and r.is_ignored("198.51.100.9") and not r.is_ignored("203.0.113.51")
    text = r.scrub("from 203.0.113.50 using s3cr3t-token-value (not 203.0.113.501)")
    assert "203.0.113.50 " not in text and "s3cr3t" not in text and "203.0.113.501" in text
    assert r.scrub_obj({"a": ["x 203.0.113.50"]}) == {"a": ["x [REDACTED-IP]"]}


def test_event_writer_drops_ignored_sources_and_scrubs(tmp_path):
    w = EventWriter("ssh", tmp_path, redactor=Redactor(["203.0.113.50"], ["topsecretkey"]))
    assert w.emit("auth.attempt", "203.0.113.50", username="me") is None
    ev = w.emit("auth.attempt", "192.0.2.9", username="x", note="proxy 203.0.113.50 topsecretkey")
    assert ev and "203.0.113.50" not in ev.to_json() and "topsecretkey" not in ev.to_json()
    lines = (tmp_path / "ssh" / "events.jsonl").read_text().splitlines()
    assert len(lines) == 1 and w.dropped_ignored == 1


# --------------------------------------------------------------- event parsing

def good(**over):
    base = {"v": 1, "id": "abcd1234", "ts": 1730000000.5, "service": "ssh", "event": "auth.attempt",
            "src_ip": "192.0.2.1", "src_port": 4444, "dst_port": 22, "session": "s1", "data": {"username": "root"}}
    base.update(over)
    return json.dumps(base)


def test_parse_event_roundtrip_and_rejections():
    ev = parse_event(good())
    assert ev and ev.src_ip == "192.0.2.1" and ev.data["username"] == "root" and ev.session == "s1"
    assert parse_event(good(src_ip="not-an-ip")) is None
    assert parse_event(good(service="BAD SERVICE")) is None
    assert parse_event(good(event="x" * 80)) is None
    assert parse_event(good(ts="yesterday")) is None
    assert parse_event(good(ts=12)) is None
    assert parse_event("garbage") is None and parse_event("[1,2]") is None and parse_event("") is None
    assert parse_event("{" * 200000) is None
    assert parse_event(good(src_port=99999)).src_port is None
    assert parse_event(good(session="../../etc")).session is None


def test_parse_event_resanitises_hostile_data():
    ev = parse_event(good(data={"cmd": "ls\x1b]0;pwned\x07", "html": "<img src=x onerror=1>"}))
    assert "\x1b" not in ev.data["cmd"] and "\x07" not in ev.data["cmd"]
    assert ev.data["html"] == "<img src=x onerror=1>"      # stored verbatim-but-safe; escaped at render time


def test_event_writer_flood_protection(tmp_path):
    w = EventWriter("http", tmp_path, max_per_ip_minute=5)
    written = [w.emit("http.request", "192.0.2.5", path="/x") for _ in range(50)]
    assert sum(1 for e in written if e) == 5


def test_normalize_and_public_ip():
    assert normalize_ip("::ffff:192.0.2.1") == "192.0.2.1"
    assert normalize_ip("junk") is None
    assert not is_public("10.1.2.3") and not is_public("127.0.0.1") and is_public("8.8.8.8")
    assert not is_public("192.0.2.1") and is_public("192.0.2.1", allow_test_nets=True)


# ------------------------------------------------------------------ quarantine

def test_quarantine_hash_naming_dedup_and_permissions(tmp_path):
    q = Quarantine(tmp_path / "q", max_file_bytes=1000, max_total_bytes=10_000)
    a = q.store(b"hello malware", {"src_ip": "192.0.2.1"})
    b = q.store(b"hello malware", {"src_ip": "192.0.2.2"})
    assert a.sha256 == b.sha256 and a.is_new and not b.is_new
    assert a.path.name == a.sha256 and a.path.parent.name == a.sha256[:2]
    assert q.meta(a.sha256)["count"] == 2 and len(q.meta(a.sha256)["sources"]) == 2
    if sys.platform != "win32":
        mode = stat.S_IMODE(a.path.stat().st_mode)
        assert mode & 0o111 == 0 and mode == 0o440
    assert q.read(a.sha256) == b"hello malware"


def test_quarantine_caps(tmp_path):
    q = Quarantine(tmp_path / "q", max_file_bytes=100, max_total_bytes=150)
    big = q.store(b"A" * 500)
    assert big.truncated and big.size == 100
    with pytest.raises(QuarantineFull):
        q.store(b"B" * 100)
    with pytest.raises(ValueError):
        q.path_for("../../etc/passwd")


def test_quarantine_streaming_writer_abort(tmp_path):
    q = Quarantine(tmp_path / "q")
    w = q.writer({"url": "http://x"})
    w.write(b"abc")
    w.abort()
    assert not list(q.iter_hashes())
