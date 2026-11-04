"""IOC extraction from text / strings (used for samples *and* attacker command lines).

Types: url, ip, endpoint (ip:port or host:port), domain, wallet, pool, credential, path, mutex,
registry, ssh_key, cron, command, useragent.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Iterable

from ..common.netutil import is_test_net
from ..common.sanitize import sanitize_text

TLDS = ("com net org info biz ru cn tk top xyz cc io pw su ws me us uk de fr nl br in ir kr jp vn id tr ua pl it es ca au "
        "club site online live icu shop work space tech pro name mobi onion invalid test example local to ga ml cf gq la "
        "su by kz eu ch se no fi dk cz sk ro bg gr hu pt mx ar cl co za ng ke tw hk sg my th ph pk bd lk np ae sa il "
        "cyou fun win bid loan download stream racing party review trade date faith cricket science accountant men").split()
_TLD_RE = "|".join(sorted(set(TLDS), key=len, reverse=True))
DOMAIN_RE = re.compile(rf"(?<![\w.@/-])((?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{_TLD_RE}))(?![\w-])(?::(\d{{1,5}}))?", re.I)
URL_RE = re.compile(r"\b((?:https?|ftp|tftp|stratum\+(?:tcp|ssl|tls)|stratum2\+tcp|socks[45]h?|redis|mysql)://[^\s'\"<>\\^`{|}]{3,512})", re.I)
IPV4_RE = re.compile(r"(?<![\w.\-])((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))(?![\w\-]|\.\d)(?::(\d{1,5}))?")
BTC_RE = re.compile(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
BECH32_RE = re.compile(r"\b(bc1[ac-hj-np-z02-9]{11,71})\b")
ETH_RE = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")
XMR_RE = re.compile(r"\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b")
LTC_RE = re.compile(r"\b([LM][a-km-zA-HJ-NP-Z1-9]{26,33})\b")
DOGE_RE = re.compile(r"\b(D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32})\b")
TRX_RE = re.compile(r"\b(T[1-9A-HJ-NP-Za-km-z]{33})\b")
PATH_RE = re.compile(r"(?<![\w/.\-])(/(?:tmp|var/tmp|var/run|var/lock|dev/shm|run|etc|root|home/[\w.\-]+|usr/(?:bin|sbin|local/bin)|opt|"
                     r"proc/self|mnt|var/spool/cron|var/log|bin|sbin|lib)/[\w.\-/%@+~]{1,120})")
WINPATH_RE = re.compile(r"\b([A-Za-z]:\\(?:[\w .\-$%]+\\)*[\w .\-$%]{1,64})")
MUTEX_RE = re.compile(r"\b((?:Global|Local)\\[\w\-{}.]{4,64})")
LOCKFILE_RE = re.compile(r"(?<![\w/.\-])((?:/[\w.\-]+)+\.(?:pid|lock|lck))\b")
REGISTRY_RE = re.compile(r"\b(HKEY_[A-Z_]+\\[\w\\ .\-{}]{3,120}|Software\\Microsoft\\Windows\\CurrentVersion\\Run\w*)")
SSHKEY_RE = re.compile(r"\b(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+)\s+(AAAA[0-9A-Za-z+/=]{20,})(?:\s+([\w@.\-]{1,64}))?")
CRON_RE = re.compile(r"(?m)^\s*((?:\*(?:/\d+)?|[\d,\-]+(?:/\d+)?)(?:\s+(?:\*(?:/\d+)?|[\d,\-]+(?:/\d+)?|\*)){4}\s+\S.{0,250})$")
CMD_RE = re.compile(r"(?i)((?:busybox\s+)?(?:wget|curl|tftp|ftpget)\b[^\n;|&]{0,200}?(?:(?:;|&&|\|\||\|)\s*(?:cd\s+\S+\s*(?:;|&&)\s*)?(?:chmod|sh\b|bash\b|\./|/bin/(?:ba)?sh|python|perl)[^\n]{0,100}))")
UA_RE = re.compile(r"(?i)user-agent:\s*([^\r\n]{10,200})")
CRED_PATTERNS = [
    (re.compile(r"\b(?:https?|ftp|tftp|redis|mysql|stratum\+\w+)://([^:@/\s'\"]{1,64}):([^@/\s'\"]{1,128})@"), "url-userinfo"),
    (re.compile(r"sshpass\s+-p\s*['\"]?([^\s'\"]{1,64})"), "sshpass"),
    (re.compile(r"echo\s+['\"]?([\w.\-]{1,32}):([^\s'\"|]{1,64})['\"]?\s*\|\s*chpasswd"), "chpasswd"),
    (re.compile(r"mysql\s+[^\n]*?-u\s*['\"]?([\w.\-]{1,32})['\"]?\s+-p['\"]?([^\s'\"]{1,64})"), "mysql-cli"),
    (re.compile(r"curl\s+[^\n]*?(?:-u|--user)\s+['\"]?([^\s:'\"]{1,64}):([^\s'\"]{1,64})"), "curl-user"),
    (re.compile(r"wget\s+[^\n]*?--(?:http-)?user[= ]['\"]?([^\s'\"]{1,64})['\"]?\s+--(?:http-)?password[= ]['\"]?([^\s'\"]{1,64})"), "wget-user"),
    (re.compile(r"redis-cli\s+[^\n]*?-a\s+['\"]?([^\s'\"]{1,64})"), "redis-cli"),
    (re.compile(r"(?:^|\s)-u\s+(\S{3,120})\s+-p\s+(\S{1,64})"), "miner-cli"),
    (re.compile(r"--user[= ](\S{3,120})\s+--pass(?:word)?[= ](\S{1,64})"), "miner-cli"),
]
NOISE_PATHS = {"/etc/localtime", "/etc/ld.so.cache", "/etc/nsswitch.conf", "/etc/hosts", "/etc/host.conf", "/lib/ld-linux.so.2",
               "/etc/gai.conf", "/usr/bin/env", "/etc/ld.so.conf", "/bin/sh", "/bin/bash", "/bin/ash", "/bin/dash", "/usr/bin/sh",
               "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/tty", "/proc/self", "/etc/passwd", "/etc/shadow",
               "/etc/resolv.conf", "/etc/profile", "/etc/issue", "/etc/os-release", "/proc/cpuinfo", "/proc/meminfo"}
NOISE_DOMAINS = {"w3.org", "gnu.org", "kernel.org", "apache.org", "mozilla.org", "openssl.org", "ietf.org", "debian.org",
                 "ubuntu.com", "redhat.com", "microsoft.com", "github.com", "gcc.gnu.org", "sourceforge.net", "example.com",
                 "example.org", "example.net", "libc.so", "busybox.net", "uclibc.org", "musl-libc.org", "xmlsoft.org"}
FILE_EXT_TLDS = {"in", "id", "pl", "sh", "py", "so", "me", "cc", "it", "to"}
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


@dataclass
class IOC:
    type: str
    value: str
    confidence: float = 0.5
    scope: str = ""            # public | private | documentation (for ip/endpoint)
    context: str = ""
    offset: int | None = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["value"] = sanitize_text(d["value"], 512)
        d["context"] = sanitize_text(d["context"], 200)
        return d


# ------------------------------------------------------------------ validators

def _b58decode(s: str) -> bytes | None:
    n = 0
    for ch in s:
        i = B58.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def b58check_ok(addr: str, versions: tuple[int, ...]) -> bool:
    raw = _b58decode(addr)
    if not raw or len(raw) != 25 or raw[0] not in versions:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def bech32_ok(addr: str) -> bool:
    if addr.lower() != addr:
        return False
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        return False
    hrp, data = addr[:pos], addr[pos + 1:]
    try:
        vals = [BECH32_CHARSET.index(c) for c in data]
    except ValueError:
        return False
    exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    return _bech32_polymod(exp + vals) in (1, 0x2BC830A3)


def _ip_scope(ip: str) -> str | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.is_loopback or a.is_unspecified or a.is_multicast or a.is_reserved or ip.startswith("255."):
        return None
    if is_test_net(ip):
        return "documentation"
    if a.is_private or a.is_link_local:
        return "private"
    return "public"


# ------------------------------------------------------------------ extraction

def extract_iocs(text: str, *, source: str = "text", base_offset: int | None = None, max_items: int = 400) -> list[IOC]:
    out: dict[tuple[str, str], IOC] = {}

    def add(t: str, v: str, conf: float, scope: str = "", ctx: str = "", extra: dict | None = None, pos: int | None = None) -> None:
        key = (t, v)
        off = (base_offset + pos) if (base_offset is not None and pos is not None) else None
        if key in out:
            if conf > out[key].confidence:
                out[key].confidence = conf
            return
        if len(out) < max_items:
            out[key] = IOC(t, v, conf, scope, ctx or source, off, extra or {})

    url_spans: list[tuple[int, int]] = []
    for m in URL_RE.finditer(text):
        raw = m.group(1).rstrip(".,;)'\"]")
        url_spans.append((m.start(), m.end()))
        low = raw.lower()
        if low.startswith("stratum"):
            add("pool", raw, 0.9, ctx="mining pool url", pos=m.start())
        else:
            add("url", raw, 0.8, ctx="url", pos=m.start())
        host = re.sub(r"^[a-z0-9+]+://([^/@]*@)?", "", raw, flags=re.I).split("/", 1)[0].split("?", 1)[0]
        hostname, _, port = host.partition(":")
        if _ip_scope(hostname):
            add("ip", hostname, 0.7, _ip_scope(hostname) or "", "host of url", pos=m.start())
            if port.isdigit():
                add("endpoint", f"{hostname}:{port}", 0.8, _ip_scope(hostname) or "", "host:port of url", pos=m.start())
        elif hostname and DOMAIN_RE.fullmatch(hostname) and hostname.lower() not in NOISE_DOMAINS:
            add("domain", hostname.lower(), 0.7, ctx="host of url", pos=m.start())

    def in_url(pos: int) -> bool:
        return any(a <= pos < b for a, b in url_spans)

    for m in IPV4_RE.finditer(text):
        scope = _ip_scope(m.group(1))
        if scope is None:
            continue
        port = m.group(2)
        if port and not (0 < int(port) < 65536):
            port = None
        if in_url(m.start()):
            continue
        conf = 0.6 if scope in ("public", "documentation") else 0.2
        add("ip", m.group(1), conf, scope, pos=m.start())
        if port:
            add("endpoint", f"{m.group(1)}:{port}", min(0.9, conf + 0.2), scope, pos=m.start())

    for m in DOMAIN_RE.finditer(text):
        if in_url(m.start()):
            continue
        dom = m.group(1).lower()
        tld = dom.rsplit(".", 1)[-1]
        if dom in NOISE_DOMAINS or any(dom.endswith("." + n) for n in NOISE_DOMAINS) or len(dom) < 6:
            continue
        if tld in FILE_EXT_TLDS and dom.count(".") == 1 and len(dom.split(".")[0]) < 8:
            continue            # config.in, setup.py style filenames
        add("domain", dom, 0.55, pos=m.start())
        if m.group(2):
            add("endpoint", f"{dom}:{m.group(2)}", 0.7, pos=m.start())

    for rx, coin, versions in ((BTC_RE, "bitcoin", (0, 5)), (LTC_RE, "litecoin", (0x30, 0x32)), (DOGE_RE, "dogecoin", (0x1E,)),
                               (TRX_RE, "tron", (0x41,))):
        for m in rx.finditer(text):
            if b58check_ok(m.group(1), versions):
                add("wallet", m.group(1), 0.9, ctx=coin, extra={"coin": coin}, pos=m.start())
    for m in BECH32_RE.finditer(text):
        if bech32_ok(m.group(1)):
            add("wallet", m.group(1), 0.9, ctx="bitcoin", extra={"coin": "bitcoin"}, pos=m.start())
    for m in ETH_RE.finditer(text):
        add("wallet", m.group(1), 0.7, ctx="ethereum", extra={"coin": "ethereum"}, pos=m.start())
    for m in XMR_RE.finditer(text):
        add("wallet", m.group(1), 0.9, ctx="monero", extra={"coin": "monero"}, pos=m.start())

    for rx, kind in CRED_PATTERNS:
        for m in rx.finditer(text):
            groups = [g for g in m.groups() if g is not None]
            if len(groups) == 2:
                user, pw = groups
                if re.fullmatch(r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}(\.\S+)?", user) or BTC_RE.fullmatch(user.split(".")[0]):
                    add("wallet", user.split(".")[0], 0.85, ctx="mining user", extra={"coin": "monero"}, pos=m.start())
                    continue
                add("credential", f"{user}:{pw}", 0.8, ctx=kind, extra={"user": user, "password": pw}, pos=m.start())
            elif groups:
                add("credential", f":{groups[0]}", 0.6, ctx=kind, extra={"password": groups[0]}, pos=m.start())

    for m in PATH_RE.finditer(text):
        p = m.group(1).rstrip("/.,;")
        if p not in NOISE_PATHS and len(p) > 5:
            hidden = "/." in p
            add("path", p, 0.7 if hidden else 0.45, ctx="hidden path" if hidden else "path", pos=m.start())
    for m in WINPATH_RE.finditer(text):
        add("path", m.group(1), 0.5, ctx="windows path", pos=m.start())
    for m in MUTEX_RE.finditer(text):
        add("mutex", m.group(1), 0.7, ctx="named object", pos=m.start())
    for m in LOCKFILE_RE.finditer(text):
        add("mutex", m.group(1), 0.4, ctx="lock/pid file", pos=m.start())
    for m in REGISTRY_RE.finditer(text):
        add("registry", m.group(1).strip(), 0.7, pos=m.start())
    for m in SSHKEY_RE.finditer(text):
        try:
            fp = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(m.group(2) + "==")).digest()).decode().rstrip("=")
        except (ValueError, TypeError):
            continue
        add("ssh_key", fp, 0.8, ctx=f"{m.group(1)} {m.group(3) or ''}".strip(), extra={"type": m.group(1), "comment": m.group(3) or ""}, pos=m.start())
    for m in CRON_RE.finditer(text):
        add("cron", m.group(1).strip(), 0.7, pos=m.start())
    for m in CMD_RE.finditer(text):
        add("command", m.group(1).strip()[:300], 0.8, ctx="download-and-execute", pos=m.start())
    for m in UA_RE.finditer(text):
        add("useragent", m.group(1).strip(), 0.3, pos=m.start())
    return list(out.values())


def merge_iocs(groups: Iterable[Iterable[IOC]]) -> list[IOC]:
    merged: dict[tuple[str, str], IOC] = {}
    for g in groups:
        for i in g:
            k = (i.type, i.value)
            if k not in merged or i.confidence > merged[k].confidence:
                merged[k] = i
    return sorted(merged.values(), key=lambda i: (-i.confidence, i.type, i.value))
