"""Behaviour detection: string rules + syscall/import rules over the disassembly."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from ..services.auth_policy import ALLOWED_USERS, WEAK_PASSWORDS
from .syscalls import SyscallSite

MAX_EVIDENCE = 6


@dataclass
class Evidence:
    kind: str                       # string | syscall | import | ioc
    detail: str
    offset: int | None = None       # file offset (strings)
    address: int | None = None      # virtual address (syscall sites)
    line: int | None = None         # script line
    snippet: str | None = None      # key into report["snippets"]
    pseudocode: str | None = None   # key of decompiler output, when the backend provides it


@dataclass
class Behavior:
    id: str
    category: str
    title: str
    severity: int                   # 1..5
    confidence: float
    description: str
    mitre: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SRule:
    id: str
    category: str
    title: str
    severity: int
    mitre: list[str]
    patterns: list[str]
    description: str
    min_hits: int = 1


S = SRule
STRING_RULES: list[SRule] = [
    S("persist-cron", "persistence", "Cron-based persistence", 3, ["T1053.003"],
      [r"crontab\b", r"/etc/cron", r"/var/spool/cron", r"(?:\*|\d+)(?:/\d+)?\s+\*\s+\*\s+\*\s+\*\s+\S+"],
      "Installs or edits cron entries so the payload re-runs periodically."),
    S("persist-rclocal", "persistence", "Init/rc.local persistence", 3, ["T1037.004"],
      [r"/etc/rc\.local", r"/etc/init\.d/", r"/etc/inittab", r"update-rc\.d", r"chkconfig", r"rc\d?\.d/S\d"],
      "Writes startup scripts so the payload survives a reboot."),
    S("persist-systemd", "persistence", "systemd service persistence", 3, ["T1543.002"],
      [r"systemctl\s+(?:enable|daemon-reload)", r"/etc/systemd/system", r"WantedBy=", r"\[Service\]"],
      "Registers a systemd unit for persistence."),
    S("persist-shell-profile", "persistence", "Shell profile persistence", 2, ["T1546.004"],
      [r"\.bashrc\b", r"\.bash_profile\b", r"/etc/profile\b", r"\.profile\b"],
      "Modifies shell start-up files."),
    S("persist-ssh-key", "persistence", "SSH authorized_keys implant", 4, ["T1098.004"],
      [r"authorized_keys", r"ssh-(?:rsa|ed25519)\s+AAAA"], "Adds an attacker SSH key for persistent access."),
    S("persist-registry", "persistence", "Windows registry/scheduled-task persistence", 3, ["T1547.001", "T1053.005"],
      [r"CurrentVersion\\Run", r"schtasks", r"\bsc\s+create\b"], "Windows autorun persistence."),
    S("persist-watchdog", "persistence", "Hardware watchdog handling (anti-reboot)", 2, [],
      [r"/dev/(?:misc/)?watchdog"], "Opens the watchdog device - typical of IoT bots that keep the device from rebooting."),
    S("scan-telnet-login", "scanning_propagation", "Telnet login brute force", 4, ["T1110.001", "T1021"],
      [r"ogin:?", r"assword:?", r"ncorrect", r"applet not found", r"/bin/busybox\s+\w+"],
      "Contains telnet prompt matching strings used by worm scanners.", 3),
    S("scan-proc-net", "scanning_propagation", "Reads /proc/net to learn network state", 2, ["T1016"],
      [r"/proc/net/(?:tcp|route|arp)"], "Reads kernel network tables (common in scanners and killers)."),
    S("scan-tools", "scanning_propagation", "Uses/mentions network scanners", 3, ["T1046"],
      [r"\bmasscan\b", r"\bzmap\b", r"\bnmap\b", r"\bzgrab\b", r"scanner", r"sshscan", r"\bpnscan\b"], "Network scanning tooling."),
    S("propagation-download-exec", "scanning_propagation", "Download-and-execute chain", 4, ["T1105", "T1059.004"],
      [r"\b(?:wget|curl|tftp|ftpget)\b.*(?:chmod|\|\s*(?:ba)?sh|sh\s+\S+|\./\S+)"],
      "Downloads a second stage and runs it (dropper / worm propagation)."),
    S("propagation-multiarch", "scanning_propagation", "Fetches payloads for many CPU architectures", 4, ["T1105"],
      [r"\b(?:mips|mipsel|mpsl|arm[5-7]?|x86_64|x86|i[3-6]86|sh4|ppc|powerpc|m68k|spc|sparc|arc|aarch64)\b"],
      "Iterates over architecture names - the signature of IoT worm droppers.", 4),
    S("killer-processes", "killer", "Kills other processes / competing malware", 4, ["T1562", "T1489"],
      [r"\bkillall\b", r"\bpkill\b", r"kill\s+-9", r"/proc/%d/(?:exe|cmdline|maps|stat)", r"/proc/\d+/(?:exe|cmdline)",
       r"\b(?:xmrig|kinsing|kdevtmpfsi|minerd|cpuminer|mirai|gafgyt|qbot|bashlite|tsunami|kaiten|sysupdate|networkservice)\b"],
      "Terminates processes (often rival bots/miners) and inspects /proc.", 2),
    S("hide-process", "process_hiding", "Process hiding / masquerading", 3, ["T1036.004", "T1014"],
      [r"LD_PRELOAD", r"/etc/ld\.so\.preload", r"\[kworker[^\]]*\]", r"\[ksoftirqd[^\]]*\]", r"mount\s+--bind\s+/proc", r"rootkit",
       r"PR_SET_NAME", r"/proc/self/exe"], "Renames/hides the process or hooks libc."),
    S("mining-stratum", "mining", "Cryptocurrency mining", 4, ["T1496"],
      [r"stratum\+(?:tcp|ssl|tls)://", r"\bxmrig\b", r"cryptonight", r"randomx", r"donate-level", r"\bmonero\b", r"hashrate",
       r"\bcpuminer\b", r"\bminerd\b", r"nicehash", r"--coin", r"\bnanopool\b", r"\bminexmr\b", r"supportxmr", r"moneroocean"],
      "Mining software/pool configuration (resource hijacking).", 1),
    S("mining-hugepages", "mining", "Prepares host for mining (hugepages/MSR)", 3, ["T1496"],
      [r"vm\.nr_hugepages", r"/sys/kernel/mm/hugepages", r"/dev/cpu/\d*/?msr", r"\bwrmsr\b"], "Tunes CPU for hashing."),
    S("ddos-flood", "ddos", "DDoS flood capability", 5, ["T1498", "T1499"],
      [r"TSource Engine Query", r"\bUDPFLOOD\b|udp flood|syn flood|ack flood|tcp flood|http flood", r"\bGET / HTTP/1\.[01]",
       r"\bHOLD\b", r"\bJUNK\b", r"(?<![A-Za-z])STD(?![A-Za-z])", r"\bKILLATTK\b", r"Content-Length: \d+\r?\n.*Connection: keep-alive"],
      "Strings used by flood attack modules (Valve query flood, HTTP/UDP/TCP floods).", 2),
    S("c2-commands", "c2_communication", "Bot command protocol strings", 3, ["T1071"],
      [r"\bGETLOCALIP\b", r"\bSCANNER (?:ON|OFF)\b", r"\bPONG!?\b", r"\bLOLNOGTFO\b", r"PRIVMSG", r"JOIN #\S+", r"NOTICE %s :"],
      "Command-and-control protocol keywords (Gafgyt/IRC style).", 2),
    S("anti-analysis", "anti_analysis", "Anti-debugging / sandbox checks", 3, ["T1622", "T1497"],
      [r"TracerPid", r"/proc/self/status", r"IsDebuggerPresent", r"\b(?:vmware|virtualbox|vbox|qemu|cuckoo|sandbox)\b", r"\b(?:gdb|strace|ltrace)\b"],
      "Checks for debuggers or virtualised analysis environments."),
    S("self-delete", "evasion", "Deletes itself / cleans traces", 3, ["T1070.004", "T1070.003"],
      [r"rm\s+-(?:rf?|fr)\s+\$?0", r"rm\s+-(?:rf?|fr)\s+/tmp", r"history\s+-c", r"unset\s+HISTFILE", r"HISTSIZE=0", r"/var/log/(?:wtmp|btmp|lastlog|auth\.log)",
       r"\bshred\b"], "Removes the payload or shell history after running."),
    S("firewall-tamper", "defense_evasion", "Disables firewall / security controls", 4, ["T1562.001", "T1562.004"],
      [r"iptables\s+-F", r"ufw\s+disable", r"setenforce\s+0", r"systemctl\s+(?:stop|disable)\s+(?:firewalld|iptables|ufw)", r"service\s+iptables\s+stop",
       r"chattr\s+-i", r"\bSELINUX=disabled"], "Weakens host defences."),
    S("reverse-shell", "reverse_shell", "Reverse shell", 5, ["T1059.004", "T1095"],
      [r"/dev/tcp/", r"bash\s+-i\s*>?&", r"\bnc\b.*\s-e\s", r"\bncat\b.*--exec", r"pty\.spawn", r"socat\b.*exec", r"\bmkfifo\b"],
      "Connects back to an attacker-controlled host and spawns a shell."),
    S("webshell", "webshell", "Web shell", 5, ["T1505.003"],
      [r"eval\s*\(\s*(?:(?:base64_decode|gzinflate|str_rot13)\s*\(\s*)?\$_(?:POST|GET|REQUEST|COOKIE)", r"(?:system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*\$_(?:POST|GET|REQUEST)",
       r"base64_decode\s*\(", r"assert\s*\(\s*\$_", r"preg_replace\s*\(.*/e['\"]", r"\bFilesMan\b|\bc99shell\b|\br57shell\b|\bWSO\b"],
      "PHP/JSP code that executes attacker-supplied input.", 1),
    S("credential-access", "credential_access", "Harvests credentials", 3, ["T1003.008", "T1552.001"],
      [r"/etc/shadow", r"/etc/passwd", r"\.ssh/id_rsa", r"\.aws/credentials", r"\.bash_history", r"wp-config\.php", r"\.git-credentials"],
      "Reads credential stores."),
    S("discovery", "discovery", "System discovery", 1, ["T1082", "T1033", "T1057"],
      [r"uname\s+-[amrs]", r"/proc/cpuinfo", r"/proc/meminfo", r"\bwhoami\b", r"\bnproc\b", r"lscpu"], "Collects host information."),
    S("destructive", "impact", "Destructive commands", 4, ["T1485", "T1561"],
      [r"dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/", r"rm\s+-rf\s+/(?:\s|\*|$)", r"\bmkfs\.", r"> /dev/sd[a-z]"], "Wipes data or disks."),
]


@dataclass
class SysRule:
    id: str
    category: str
    title: str
    severity: int
    mitre: list[str]
    all_of: set[str]
    description: str
    any_of: set[str] = field(default_factory=set)


SYS_RULES: list[SysRule] = [
    SysRule("sys-network-client", "c2_communication", "Outbound network connections", 2, ["T1071"], {"socket", "connect"},
            "Creates sockets and connects out (C2 or scanning)."),
    SysRule("sys-listener", "c2_communication", "Listens for inbound connections", 3, ["T1571"], {"socket", "bind", "listen"},
            "Opens a listening socket (bind shell / backdoor / local control port).", {"accept", "accept4"}),
    SysRule("sys-daemonize", "process_hiding", "Daemonizes (fork + setsid)", 2, ["T1564"], {"fork", "setsid"},
            "Detaches from the terminal and keeps running in the background.", set()),
    SysRule("sys-process-kill", "killer", "Sends kill signals to processes", 3, ["T1489"], {"kill"},
            "Calls kill(2) - used to terminate rival malware or stale instances."),
    SysRule("sys-anti-debug", "anti_analysis", "ptrace anti-debugging", 3, ["T1622"], {"ptrace"},
            "Uses ptrace (self-attach trick or tracing other processes)."),
    SysRule("sys-rename-process", "process_hiding", "Renames its own process (prctl)", 3, ["T1036.004"], {"prctl"},
            "prctl(PR_SET_NAME) is used to masquerade as a harmless process."),
    SysRule("sys-reverse-shell", "reverse_shell", "Reverse-shell syscall pattern", 5, ["T1059.004"], {"socket", "connect", "execve"},
            "connect + dup2/dup3 + execve: redirects a shell onto a network socket.", {"dup2", "dup3"}),
    SysRule("sys-scan-pattern", "scanning_propagation", "Mass-scanning socket pattern", 4, ["T1046"],
            {"socket", "connect", "fcntl"}, "Non-blocking connect + select/poll loop - an asynchronous port scanner.",
            {"select", "poll", "ppoll", "epoll_wait"}),
    SysRule("sys-execute", "execution", "Executes other programs", 2, ["T1059.004"], {"execve"}, "Calls execve."),
    SysRule("sys-reboot", "impact", "Can reboot/halt the system", 2, ["T1529"], {"reboot"}, "Calls reboot(2)."),
]

IMPORT_TO_SYS = {
    "socket": "socket", "connect": "connect", "bind": "bind", "listen": "listen", "accept": "accept", "accept4": "accept4",
    "fork": "fork", "vfork": "fork", "setsid": "setsid", "daemon": "setsid", "kill": "kill", "killpg": "kill", "ptrace": "ptrace",
    "prctl": "prctl", "execve": "execve", "execv": "execve", "execl": "execve", "execlp": "execve", "execvp": "execve",
    "system": "execve", "popen": "execve", "dup2": "dup2", "dup3": "dup3", "fcntl": "fcntl", "select": "select", "poll": "poll",
    "epoll_wait": "epoll_wait", "reboot": "reboot",
}

DEFAULT_CRED_WORDS = {w.lower() for w in (WEAK_PASSWORDS | ALLOWED_USERS) if len(w) >= 3}


def credential_dictionary_hits(strings: list[tuple[int, str]]) -> list[tuple[int, str]]:
    hits = []
    seen = set()
    for off, s in strings:
        t = s.strip().lower()
        if t in DEFAULT_CRED_WORDS and t not in seen and len(t) <= 24:
            seen.add(t)
            hits.append((off, s.strip()))
    return hits


def _match_strings(rule: SRule, strings: list[tuple[int, str]]) -> tuple[list[Evidence], int]:
    ev: list[Evidence] = []
    hit_patterns = 0
    for pat in rule.patterns:
        rx = re.compile(pat, re.I | re.S)
        found = False
        for off, s in strings:
            m = rx.search(s)
            if m:
                found = True
                if len(ev) < MAX_EVIDENCE:
                    ev.append(Evidence("string", m.group(0)[:160], offset=off))
                break
        hit_patterns += int(found)
    return ev, hit_patterns


def _match_text(rule: SRule, text: str) -> tuple[list[Evidence], int]:
    ev: list[Evidence] = []
    hit_patterns = 0
    for pat in rule.patterns:
        rx = re.compile(pat, re.I)
        m = rx.search(text)
        if m:
            hit_patterns += 1
            if len(ev) < MAX_EVIDENCE:
                ev.append(Evidence("string", m.group(0)[:160], offset=m.start(), line=text.count("\n", 0, m.start()) + 1))
    return ev, hit_patterns


PE_IMPORT_RULES: list[tuple[str, str, str, int, list[str], set[str], str]] = [
    ("pe-download", "execution", "Downloads files via Win32 APIs", 3, ["T1105"],
     {"urldownloadtofilea", "urldownloadtofilew", "internetreadfile", "winhttpreaddata", "internetopenurla"}, "Fetches remote content."),
    ("pe-injection", "defense_evasion", "Process injection APIs", 4, ["T1055"],
     {"writeprocessmemory", "createremotethread", "virtualallocex", "ntunmapviewofsection", "queueuserapc"}, "Writes into other processes."),
    ("pe-persistence", "persistence", "Registry / service persistence APIs", 3, ["T1547.001", "T1543.003"],
     {"regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw", "createservicea", "createservicew"}, "Autorun registry/service."),
    ("pe-anti-debug", "anti_analysis", "Anti-debugging APIs", 3, ["T1622"],
     {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstringa"}, "Debugger detection."),
    ("pe-crypto", "impact", "Bulk file encryption APIs", 3, ["T1486"],
     {"cryptencrypt", "bcryptencrypt", "cryptgenkey", "cryptacquirecontexta", "cryptacquirecontextw"}, "Possible ransomware / crypto use."),
    ("pe-network", "c2_communication", "Winsock networking", 2, ["T1071"],
     {"wsastartup", "connect", "send", "recv", "internetopena", "internetopenw", "httpsendrequesta"}, "Network communication."),
]


def pe_import_behaviors(imports: set[str]) -> list[Behavior]:
    low = {i.lower() for i in imports}
    out = []
    for bid, cat, title, sev, mitre, names, desc in PE_IMPORT_RULES:
        hit = sorted(low & names)
        if len(hit) >= (2 if bid == "pe-network" else 1):
            out.append(Behavior(bid, cat, title, sev, 0.7, desc, list(mitre), [Evidence("import", h) for h in hit[:MAX_EVIDENCE]]))
    return out


COMMON_WORDS = {"root", "admin", "password", "123456", "12345", "1234", "12345678", "default", "pass", "test", "guest", "support",
                "changeme", "1111", "0000", "system", "service", "ubuntu", "oracle", "qwerty", "letmein", "welcome", "admin123",
                "user", "administrator", "debian", "git", "dev", "tech", "operator", "supervisor", "postgres", "vagrant", "pi"}
WORM_WORDS = {w for w in DEFAULT_CRED_WORDS if w not in COMMON_WORDS}


def qualify_cred_hits(hits: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Ordinary words like root/user/test appear in benign files; a worm dictionary also has factory-only
    passwords (vizxv, xc3511, juantech, ...).  Require at least two of those before calling it a dictionary."""
    return hits if sum(1 for _, w in hits if w.lower() in WORM_WORDS) >= 2 else []


def cred_words_from(strings: list[tuple[int, str]], text: str | None) -> list[tuple[int, str]]:
    return qualify_cred_hits(credential_dictionary_hits(
        strings if text is None else [(m.start(), m.group()) for m in re.finditer(r"[\w.@-]{3,24}", text)]))


def detect_behaviors(*, strings: list[tuple[int, str]], text: str | None, sites: list[SyscallSite],
                     imports: set[str], cred_words: list[tuple[int, str]] | None = None) -> list[Behavior]:
    out: dict[str, Behavior] = {}

    for rule in STRING_RULES:
        if rule.id == "propagation-multiarch":
            ev, n = _arch_hits(strings, text)
        elif text is not None:
            ev, n = _match_text(rule, text)
        else:
            ev, n = _match_strings(rule, strings)
        if n >= rule.min_hits and ev:
            conf = min(0.95, 0.45 + 0.12 * n)
            out[rule.id] = Behavior(rule.id, rule.category, rule.title, rule.severity, round(conf, 2), rule.description,
                                    list(rule.mitre), ev)

    creds = cred_words if cred_words is not None else cred_words_from(strings, text)
    if len(creds) >= 8:
        ev = [Evidence("string", w, offset=o) for o, w in creds[:MAX_EVIDENCE]]
        out["scan-credential-dictionary"] = Behavior(
            "scan-credential-dictionary", "scanning_propagation", "Built-in default-credential dictionary", 4,
            round(min(0.95, 0.5 + len(creds) * 0.03), 2),
            f"{len(creds)} well-known default usernames/passwords embedded - used to brute-force telnet/SSH devices.",
            ["T1110.001", "T1078.001"], ev)

    names: dict[str, list[Evidence]] = {}
    for s in sites:
        names.setdefault(s.name, []).append(Evidence("syscall", f"{s.name}({s.number})", address=s.address))
    for imp in imports:
        n = IMPORT_TO_SYS.get(imp)
        if n:
            names.setdefault(n, []).append(Evidence("import", imp))
    for rule in SYS_RULES:
        if rule.all_of <= names.keys() and (not rule.any_of or rule.any_of & names.keys()):
            ev: list[Evidence] = []
            for n in sorted(rule.all_of | (rule.any_of & names.keys())):
                ev.extend(names[n][:2])
            beh = Behavior(rule.id, rule.category, rule.title, rule.severity, 0.7, rule.description, list(rule.mitre), ev[:MAX_EVIDENCE + 2])
            out[rule.id] = beh

    # raw sockets (SOCK_RAW == 3) = packet crafting
    raw = [s for s in sites if s.name == "socket" and len(s.args) > 1 and s.args[1] in (3, 0x803, 0x3)]
    if raw:
        out["sys-raw-socket"] = Behavior(
            "sys-raw-socket", "ddos", "Raw sockets (packet crafting)", 4, 0.75,
            "socket(AF_INET, SOCK_RAW, ...) - needed for SYN scanners and spoofed floods.", ["T1498", "T1046"],
            [Evidence("syscall", f"socket(args={s.args})", address=s.address) for s in raw[:3]])

    # killer = kill + /proc walking is much stronger than either alone
    if "sys-process-kill" in out and "killer-processes" in out:
        out["killer-processes"].severity = 5
        out["killer-processes"].confidence = max(out["killer-processes"].confidence, 0.85)
    for b in pe_import_behaviors(imports):
        out.setdefault(b.id, b)
    return sorted(out.values(), key=lambda b: (-b.severity, -b.confidence, b.id))


ARCH_WORDS = {"mips", "mipsel", "mpsl", "arm", "arm5", "arm6", "arm7", "x86", "x86_64", "i586", "i686", "sh4", "ppc", "powerpc",
              "m68k", "spc", "sparc", "arc", "aarch64"}


def _arch_hits(strings: list[tuple[int, str]], text: str | None) -> tuple[list[Evidence], int]:
    found: dict[str, Evidence] = {}
    if text is not None:
        for m in re.finditer(r"\b[a-z0-9_]+\b", text, re.I):
            w = m.group(0).lower()
            if w in ARCH_WORDS and w not in found:
                found[w] = Evidence("string", w, offset=m.start(), line=text.count("\n", 0, m.start()) + 1)
    else:
        for off, s in strings:
            w = s.strip().lower()
            if w in ARCH_WORDS and w not in found:
                found[w] = Evidence("string", w, offset=off)
    distinct = len(found)
    return list(found.values())[:MAX_EVIDENCE], (4 if distinct >= 4 else 0)
