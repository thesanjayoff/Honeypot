"""Family labelling: weighted, explainable signals -> label + confidence + reasons.

This is deliberately transparent rather than clever: every signal carries a weight and a human
readable reason, the score is turned into a confidence with ``1 - 0.5**(score/2)`` and the
top candidates are reported so an analyst can disagree with the label.  Labels are *families of
behaviour* ("Mirai-style bot") not attributions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable

from .behaviors import Behavior
from .iocs import IOC

MIN_SCORE = 2.5
MAX_CONF = 0.97


@dataclass
class Features:
    kind: str                       # elf | pe | script | php | python | perl | text | data ...
    arch: str = ""
    text: str = ""                  # printable content (script text or joined binary strings), original case
    behaviors: dict[str, Behavior] = field(default_factory=dict)
    iocs: list[IOC] = field(default_factory=list)
    cred_hits: int = 0
    syscalls: set[str] = field(default_factory=set)
    static: bool = False
    stripped: bool = True
    packed: bool = False
    size: int = 0
    lines: int = 0

    def b(self, bid: str) -> bool:
        return bid in self.behaviors

    def ioc(self, typ: str) -> list[IOC]:
        return [i for i in self.iocs if i.type == typ]


@lru_cache(maxsize=512)
def _rx(p: str) -> re.Pattern[str]:
    return re.compile(p, re.I)


def has(f: Features, pattern: str) -> str | None:
    m = _rx(pattern).search(f.text)
    return m.group(0)[:60] if m else None


Signal = tuple[float, Callable[[Features], str | None]]


def S(weight: float, fn: Callable[[Features], str | None]) -> Signal:
    return weight, fn


def _txt(pattern: str, reason: str) -> Callable[[Features], str | None]:
    return lambda f: (f"{reason} ({hit!r})" if (hit := has(f, pattern)) else None)


def _beh(bid: str, reason: str) -> Callable[[Features], str | None]:
    return lambda f: reason if f.b(bid) else None


def _elf(fn: Callable[[Features], str | None]) -> Callable[[Features], str | None]:
    return lambda f: fn(f) if f.kind == "elf" else None


@dataclass
class Family:
    id: str
    name: str
    kind: str          # bot | miner | downloader | backdoor | webshell | implant | tool
    signals: list[Signal]
    description: str


def _syscalls_all(*names: str) -> Callable[[Features], str | None]:
    return lambda f: (f"syscalls {', '.join(names)} present" if set(names) <= f.syscalls else None)


def _is_iot_elf(f: Features) -> str | None:
    if f.kind == "elf" and f.static and f.arch in ("mips", "arm", "aarch64", "ppc", "sh4", "m68k", "sparc", "x86_64", "x86"):
        return f"statically linked {f.arch} ELF" + (" (stripped)" if f.stripped else "")
    return None


def _script(f: Features) -> bool:
    return f.kind in ("script", "python", "perl", "php", "text")


FAMILIES: list[Family] = [
    Family("mirai_like", "Mirai-style IoT bot", "bot", [
        S(2.5, lambda f: f"embeds a default-credential dictionary ({f.cred_hits} well-known user/password words)" if f.cred_hits >= 8 and f.kind == "elf" else None),
        S(1.0, lambda f: f"embeds a small credential list ({f.cred_hits} words)" if 4 <= f.cred_hits < 8 and f.kind == "elf" else None),
        S(2.0, _elf(_txt(r"/dev/(?:misc/)?watchdog", "opens the hardware watchdog (anti-reboot)"))),
        S(3.0, _elf(_txt(r"TSource Engine Query", "Valve/Source query flood payload"))),
        S(1.5, _elf(_txt(r"applet not found", "BusyBox applet-probe marker"))),
        S(1.0, _elf(_txt(r"/bin/busybox\s+\w+", "uses /bin/busybox as a shell/FS toolbox"))),
        S(1.0, _elf(_txt(r"/proc/net/tcp", "walks /proc/net/tcp (finds the process behind a port)"))),
        S(2.0, _elf(_txt(r"cdn-cgi|\bHTTP flood\b|Cloudflare", "HTTP flood with anti-DDoS-protection bypass"))),
        S(1.5, lambda f: "kills other processes by inspecting /proc/<pid>/exe (killer)" if f.kind == "elf" and f.b("killer-processes") and f.b("sys-process-kill") else None),
        S(1.0, _elf(lambda f: "forks/daemonizes and opens sockets" if {"fork", "socket", "connect"} <= f.syscalls else None)),
        S(1.0, _elf(lambda f: "raw sockets used for spoofed/SYN floods" if f.b("sys-raw-socket") else None)),
        S(1.0, _is_iot_elf),
        S(1.0, _elf(_beh("ddos-flood", "contains DDoS flood strings"))),
        S(1.0, _elf(_beh("scan-telnet-login", "contains telnet login-scanner strings"))),
        S(-2.0, lambda f: "contains Gafgyt-style text command protocol" if f.kind == "elf" and has(f, r"\bLOLNOGTFO\b|\bGETLOCALIP\b|\bSCANNER (?:ON|OFF)\b") else None),
    ], "Telnet/SSH-scanning worm with a credential dictionary, flood attack modules and a process killer."),

    Family("gafgyt_like", "Gafgyt/Bashlite-style bot", "bot", [
        S(3.0, _txt(r"\bLOLNOGTFO\b", "Gafgyt kill-switch command")),
        S(2.5, _txt(r"\bGETLOCALIP\b", "Gafgyt GETLOCALIP command")),
        S(2.0, _txt(r"\bSCANNER (?:ON|OFF)\b", "scanner toggle command")),
        S(1.5, _txt(r"\bKILLATTK\b", "attack-stop command")),
        S(1.0, _txt(r"\bPONG!?\b", "PING/PONG keep-alive")),
        S(1.5, lambda f: "UDP/TCP/JUNK/HOLD/STD flood command names" if len(_rx(r"\b(?:UDP|TCP|JUNK|HOLD|STD|VSE|XMAS|ACK|SYN)\b").findall(f.text)) >= 4 else None),
        S(1.5, _beh("scan-credential-dictionary", "default-credential dictionary")),
        S(1.0, _beh("persist-watchdog", "watchdog handling")),
        S(1.0, _beh("ddos-flood", "flood attack strings")),
        S(1.0, _beh("propagation-multiarch", "multi-architecture payload names")),
    ], "Line-based text C2 protocol (PING/PONG, SCANNER ON/OFF), UDP/TCP floods and telnet scanning."),

    Family("irc_bot", "IRC-controlled bot (Kaiten/Tsunami/perl bot)", "bot", [
        S(2.0, _txt(r"\bPRIVMSG\b", "IRC PRIVMSG handling")),
        S(1.5, _txt(r"\bJOIN #\S+|JOIN %s", "joins an IRC channel")),
        S(1.0, _txt(r"\bNICK\b.{0,20}\bUSER\b|NICK %s", "IRC registration")),
        S(1.5, _txt(r"tsunami|kaiten|ballast|perlbot|shellbot|dbot", "bot-family name")),
        S(1.0, _beh("c2-commands", "bot command keywords")),
        S(1.0, lambda f: "IRC server endpoint (:6667/6697/ircs)" if any(re.search(r":(?:666\d|6697|7000)$", i.value) for i in f.ioc("endpoint")) else None),
        S(1.0, _beh("ddos-flood", "flood commands")),
    ], "Connects to an IRC channel and executes channel commands (scan, flood, shell)."),

    Family("cryptominer", "Cryptocurrency miner", "miner", [
        S(3.0, lambda f: "mining pool URL/endpoint in strings" if f.ioc("pool") else None),
        S(3.0, _txt(r"\bxmrig\b|\bcpuminer\b|\bminerd\b|\bkdevtmpfsi\b|\bkinsing\b", "known miner name")),
        S(2.0, _txt(r"cryptonight|randomx|ghostrider|donate-level|\bhashrate\b", "mining algorithm / option")),
        S(2.0, lambda f: "wallet address(es) embedded" if any(i.type == "wallet" and i.confidence >= 0.7 for i in f.iocs) else None),
        S(1.5, _beh("mining-hugepages", "hugepages / MSR tuning")),
        S(1.0, _beh("killer-processes", "kills competing miners")),
        S(1.0, _beh("persist-cron", "cron persistence")),
        S(0.5, _txt(r"\bmoneroocean\b|\bsupportxmr\b|\bnanopool\b|\bminexmr\b|\bnicehash\b|\bc3pool\b", "public mining pool name")),
    ], "Resource-hijacking payload that runs or installs a CPU miner."),

    Family("downloader_script", "Shell downloader / dropper script", "downloader", [
        S(2.5, lambda f: "downloads and executes a second stage" if _script(f) and f.b("propagation-download-exec") else None),
        S(1.5, lambda f: "iterates over CPU architectures (multi-arch IoT dropper)" if _script(f) and f.b("propagation-multiarch") else None),
        S(1.0, lambda f: "uses several fetch tools (wget/curl/tftp/ftpget) as fallbacks" if _script(f) and len(set(_rx(r"\b(wget|curl|tftp|ftpget|busybox wget)\b").findall(f.text))) >= 2 else None),
        S(1.0, lambda f: "changes into a writable directory (/tmp, /var/run, /dev/shm)" if _script(f) and has(f, r"cd\s+(?:/tmp|/var/run|/dev/shm|/mnt|/var/tmp)") else None),
        S(1.0, lambda f: "chmod +x then runs the dropped file" if _script(f) and has(f, r"chmod\s+(?:\+x|[0-7]*7[0-7]*)") else None),
        S(1.0, lambda f: "removes traces after running" if _script(f) and f.b("self-delete") else None),
        S(1.0, lambda f: "script is short and mostly download commands" if _script(f) and 0 < f.lines <= 40 and f.ioc("url") else None),
        S(0.5, lambda f: "contains URL(s) to fetch payloads" if _script(f) and f.ioc("url") else None),
    ], "Small shell script that fetches and runs binaries for several architectures."),

    Family("reverse_shell", "Reverse shell", "backdoor", [
        S(3.0, _beh("reverse-shell", "reverse-shell construct")),
        S(1.0, lambda f: "connects to a hard-coded endpoint" if f.ioc("endpoint") or f.ioc("ip") else None),
        S(1.0, _txt(r"\bsh\s+-i\b|/bin/sh\b|/bin/bash\b", "spawns an interactive shell")),
        S(0.5, lambda f: "short payload" if f.size < 4096 else None),
    ], "Connects back to an attacker host and attaches a shell."),

    Family("php_webshell", "PHP web shell", "webshell", [
        S(3.0, lambda f: "PHP code executing request input" if f.kind == "php" and f.b("webshell") else None),
        S(1.0, lambda f: "PHP file" if f.kind == "php" else None),
        S(1.0, _txt(r"base64_decode|gzinflate|str_rot13|eval\s*\(", "obfuscation / dynamic evaluation")),
        S(1.0, _txt(r"\bFilesMan\b|\bc99\b|\br57\b|\bWSO\b|\bb374k\b", "known web-shell name")),
    ], "Server-side script giving the attacker remote command execution."),

    Family("ssh_key_implant", "SSH key / persistence implant", "implant", [
        S(3.0, lambda f: "installs an SSH public key" if f.ioc("ssh_key") else None),
        S(1.5, _beh("persist-ssh-key", "writes authorized_keys")),
        S(1.0, _txt(r"chmod\s+(?:-R\s+)?(?:700|600)\s+\S*\.ssh", "tightens .ssh permissions")),
        S(1.0, _txt(r"chattr\s+\+[ia]", "locks the file against removal (chattr)")),
        S(0.5, lambda f: "short script" if _script(f) and f.lines <= 10 else None),
    ], "Adds the attacker's SSH key for persistent, password-less access."),

    Family("credential_stealer", "Credential harvester", "tool", [
        S(2.0, _beh("credential-access", "reads credential stores")),
        S(1.0, _txt(r"\bscp\b|\bcurl\b.*(?:-F|--data|--upload)|\bnc\b.*<", "exfiltrates data")),
        S(1.0, _txt(r"\.ssh/id_rsa|\.aws/credentials|\.git-credentials", "targets key / token files")),
    ], "Collects passwords, keys or tokens from the host."),

    Family("scanner_tool", "Network scanner / brute-forcer", "tool", [
        S(2.0, _beh("scan-tools", "scanner tooling")),
        S(1.5, _beh("sys-scan-pattern", "asynchronous connect-scan loop")),
        S(1.5, _beh("scan-credential-dictionary", "credential dictionary")),
        S(1.0, _beh("scan-telnet-login", "telnet login logic")),
    ], "Scans for hosts and tries logins; lacks the flood/bot features of a full botnet client."),
]

FAMILY_BY_ID = {f.id: f for f in FAMILIES}


@dataclass
class FamilyResult:
    id: str
    name: str
    kind: str
    confidence: float
    score: float
    reasons: list[str]
    description: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "kind": self.kind, "confidence": round(self.confidence, 2),
                "score": round(self.score, 2), "reasons": self.reasons, "description": self.description}


def confidence_from_score(score: float) -> float:
    return min(MAX_CONF, max(0.0, 1 - 0.5 ** (score / 2)))


def score_families(f: Features) -> list[FamilyResult]:
    results: list[FamilyResult] = []
    for fam in FAMILIES:
        score = 0.0
        reasons: list[str] = []
        for weight, fn in fam.signals:
            try:
                r = fn(f)
            except Exception:                      # noqa: BLE001 - one bad signal must not kill the report
                r = None
            if r:
                score += weight
                if weight > 0:
                    reasons.append(r)
        if score > 0:
            results.append(FamilyResult(fam.id, fam.name, fam.kind, confidence_from_score(score), score, reasons, fam.description))
    results.sort(key=lambda r: -r.score)
    return results


def label(f: Features) -> tuple[FamilyResult, list[FamilyResult]]:
    ranked = score_families(f)
    if ranked and ranked[0].score >= MIN_SCORE:
        top = ranked[0]
        # when two families are close, say so instead of pretending certainty
        if len(ranked) > 1 and ranked[1].score >= MIN_SCORE and ranked[0].score - ranked[1].score < 1.0:
            top.reasons.append(f"also resembles {ranked[1].name} (score {ranked[1].score:.1f} vs {top.score:.1f})")
            top.confidence = min(top.confidence, 0.6)
        return top, ranked[1:4]
    kind = f.kind
    name = {"elf": "Unclassified ELF binary", "pe": "Unclassified Windows binary"}.get(kind, "Unclassified file")
    reasons = ["no family reached the scoring threshold"]
    if f.packed:
        reasons.append("sample looks packed/obfuscated - static features are limited")
    if f.behaviors:
        reasons.append("behaviours seen: " + ", ".join(sorted(f.behaviors)[:5]))
    return FamilyResult("unknown", name, "unknown", 0.0, ranked[0].score if ranked else 0.0, reasons), ranked[:3]
