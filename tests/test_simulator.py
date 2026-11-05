from __future__ import annotations

import contextlib
import json

import pytest

from conftest import read_events, running
from honeynet.analysis import analyze_file, get_backend
from honeynet.common.netutil import is_test_net, loopback_alias
from honeynet.common.quarantine import Quarantine
from honeynet.simulator.live import LiveAttacker, drop_script
from honeynet.analysis.fixtures import all_fixtures


def test_alias_maps_loopback_aliases_to_documentation_ranges():
    seen = {loopback_alias(f"127.77.{a}.{b}") for a in range(4) for b in range(1, 250)}
    assert all(is_test_net(ip) for ip in seen) and len(seen) > 300
    assert loopback_alias("127.77.1.5") == loopback_alias("127.77.1.5")
    assert loopback_alias("127.0.0.1") == "127.0.0.1" and loopback_alias("8.8.8.8") == "8.8.8.8" and loopback_alias("not-an-ip") == "not-an-ip"


def test_attacker_refuses_non_loopback_targets():
    with pytest.raises(SystemExit):
        LiveAttacker("8.8.8.8", {"ssh": [22]})


def test_drop_script_rebuilds_the_fixture_exactly():
    # replay the echo -ne chunks the way a shell would and compare with the fixture
    data = all_fixtures()["mirai_like_x86_64.elf"]
    out = b""
    for cmd in drop_script("mirai_like_x86_64.elf", "/tmp/x")[1:]:
        hexes = cmd.split("'")[1].split("\\x")[1:]
        out += bytes(int(h, 16) for h in hexes)
    assert out == data


async def test_live_attacker_drives_real_services_end_to_end(settings):
    names = ("ssh", "telnet", "http", "mysql", "redis")
    async with contextlib.AsyncExitStack() as stack:
        for n in names:
            await stack.enter_async_context(running(settings, n))
        atk = LiveAttacker("127.0.0.1", settings.ports, seed=3, sources=40)
        stats = await atk.run(duration=14, rate_per_min=300)

    assert sum(v for k, v in stats.items() if k != "errors") >= 25
    assert stats.get("errors", 0) <= 3, stats

    ev = {n: read_events(settings, n) for n in names}
    kinds = {n: {e["event"] for e in ev[n]} for n in names}
    assert {"conn.open", "auth.attempt"} <= kinds["ssh"] and "cmd.input" in kinds["ssh"] | kinds["telnet"]
    assert "exploit.attempt" in kinds["http"] and "http.request" in kinds["http"]
    assert "conn.open" in kinds["mysql"] and "conn.open" in kinds["redis"]

    # every "attacker" is a documentation-range alias, never the real loopback address
    ips = {e["src_ip"] for n in names for e in ev[n]}
    assert len(ips) >= 5 and all(is_test_net(ip) for ip in ips), ips

    # the harmless droppers were captured, never executed, and the analyser can read them
    q = Quarantine(settings.quarantine_dir)
    hashes = list(q.iter_hashes())
    assert hashes
    be = get_backend("builtin")
    for sha in hashes:
        rep = analyze_file(q.path_for(sha), be)
        json.dumps(rep)
        assert rep["static_only"] is True and rep["sha256"] == sha
