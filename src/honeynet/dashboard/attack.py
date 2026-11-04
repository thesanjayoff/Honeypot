"""MITRE ATT&CK (Enterprise) technique mapping for what attackers do on the honeypots.

Technique ids/names are from the public ATT&CK knowledge base (https://attack.mitre.org/).  The
rules below are original; they map *observed behaviour* (a command line, an exploit rule, an
authentication attempt) to techniques so the dashboard can show a coverage matrix.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

TACTICS = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
           "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]

# id -> (name, tactic)
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1595.002": ("Vulnerability Scanning", "Reconnaissance"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.004": ("Brute Force: Credential Stuffing", "Credential Access"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1059.006": ("Command and Scripting Interpreter: Python", "Execution"),
    "T1059.008": ("Command and Scripting Interpreter: Network Device CLI", "Execution"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "Persistence"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "Persistence"),
    "T1037.004": ("Boot or Logon Initialization Scripts: RC Scripts", "Persistence"),
    "T1546.004": ("Event Triggered Execution: Unix Shell Configuration Modification", "Persistence"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation"),
    "T1070.002": ("Indicator Removal: Clear Linux or Mac System Logs", "Defense Evasion"),
    "T1070.003": ("Indicator Removal: Clear Command History", "Defense Evasion"),
    "T1070.004": ("Indicator Removal: File Deletion", "Defense Evasion"),
    "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "T1222.002": ("File and Directory Permissions Modification: Linux and Mac", "Defense Evasion"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", "Defense Evasion"),
    "T1036.004": ("Masquerading: Masquerade Task or Service", "Defense Evasion"),
    "T1003.008": ("OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access"),
    "T1552.003": ("Unsecured Credentials: Bash History", "Credential Access"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1033": ("System Owner/User Discovery", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1016": ("System Network Configuration Discovery", "Discovery"),
    "T1049": ("System Network Connections Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1087.001": ("Account Discovery: Local Account", "Discovery"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1095": ("Non-Application Layer Protocol", "Command and Control"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1005": ("Data from Local System", "Collection"),
    "T1496": ("Resource Hijacking", "Impact"),
    "T1489": ("Service Stop", "Impact"),
    "T1485": ("Data Destruction", "Impact"),
    "T1529": ("System Shutdown/Reboot", "Impact"),
    "T1499": ("Endpoint Denial of Service", "Impact"),
}


@dataclass(frozen=True)
class Rule:
    technique: str
    pattern: re.Pattern[str]


def _r(tid: str, pat: str) -> Rule:
    return Rule(tid, re.compile(pat, re.I))


_CMD = r"(?:^|[;&|`(]|\$\()\s*(?:sudo\s+|busybox\s+|/\S*/)?"

COMMAND_RULES: list[Rule] = [
    _r("T1082", _CMD + r"(?:uname|lscpu|nproc|free|dmesg|lsb_release|hostnamectl|arch|getconf|lsmod|df|mount)\b|/proc/(?:cpuinfo|meminfo|version|mounts)|/etc/(?:os-release|issue|lsb-release)"),
    _r("T1082", _CMD + r"cat\s+/proc/(?:cpuinfo|meminfo|version)"),
    _r("T1033", _CMD + r"(?:whoami|id|w|who|last|lastlog|users|logname)\b"),
    _r("T1087.001", r"(?:cat|grep|less|head|tail|awk|cut)\s+[^;|&]*/etc/passwd|getent\s+passwd"),
    _r("T1057", _CMD + r"(?:ps|top|htop|pgrep|pstree)\b"),
    _r("T1016", _CMD + r"(?:ifconfig|ip\s+(?:a|addr|address|r|route|link)|route|arp|hostname\s+-I|iwconfig)\b|/etc/resolv\.conf|/proc/net/(?:route|arp|dev)"),
    _r("T1049", _CMD + r"(?:netstat|ss|lsof\s+-i)\b|/proc/net/(?:tcp|udp)"),
    _r("T1083", _CMD + r"(?:ls|find|locate|tree|stat|dir)\b"),
    _r("T1046", _CMD + r"(?:nmap|masscan|zmap|zgrab|nc\s+-z|netcat\s+-z)\b"),
    _r("T1105", _CMD + r"(?:wget|curl|tftp|ftpget|ftp|scp|rsync|fetch|lwp-download|aria2c)\b[^|;&]*(?:https?://|ftp://|\d+\.\d+\.\d+\.\d+|-g\b|-r\b)"),
    _r("T1105", _CMD + r"busybox\s+(?:wget|tftp|ftpget)\b"),
    _r("T1222.002", _CMD + r"(?:chmod|chown|chattr|setfacl)\b"),
    _r("T1053.003", _CMD + r"crontab\b|/etc/cron|/var/spool/cron|\bcron\.d\b|\banacron\b|\bat\s+(?:now|\d)"),
    _r("T1098.004", r"authorized_keys|\.ssh/(?:id_rsa|config)|ssh-(?:rsa|ed25519)\s+AAAA"),
    _r("T1136.001", _CMD + r"(?:useradd|adduser|usermod|passwd|chpasswd)\b"),
    _r("T1543.002", r"systemctl\s+(?:enable|daemon-reload)|/etc/systemd/system|\.service\b.*\[Unit\]"),
    _r("T1037.004", r"/etc/rc\.local|/etc/init\.d/|update-rc\.d|/etc/inittab|rc\d\.d/S"),
    _r("T1546.004", r"\.bashrc|\.bash_profile|/etc/profile\b|\.profile\b|\.zshrc"),
    _r("T1548.003", _CMD + r"sudo\b|su\s+-"),
    _r("T1003.008", r"/etc/shadow|/etc/passwd(?!\s*$)|unshadow|john\b|hashcat"),
    _r("T1552.001", r"\.aws/credentials|\.git-credentials|id_rsa|\.netrc|wp-config\.php|\.env\b|grep\s+-[a-z]*r[a-z]*\s+[^;|&]*pass"),
    _r("T1552.003", r"\.bash_history|\bhistory\b(?!\s+-[cw])"),
    _r("T1070.003", r"history\s+-[cw]|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|export\s+HISTCONTROL|ln\s+-sf\s+/dev/null\s+\S*history"),
    _r("T1070.002", r"/var/log/(?:wtmp|btmp|lastlog|auth\.log|secure|syslog|messages)|>\s*/var/log|rm\s+[^;|&]*/var/log|\bshred\b|\blogrotate\b.*-f"),
    _r("T1070.004", _CMD + r"(?:rm|unlink|shred)\s+(?:-[a-z]+\s+)*\S+"),
    _r("T1140", r"base64\s+(?:-d|--decode)|echo\s+-e\s+['\"]?\\x|xxd\s+-r|openssl\s+enc\s+-d|\|\s*(?:gunzip|zcat|bzcat|xz\s+-d)|printf\s+['\"]\\x"),
    _r("T1059.004", r"\|\s*(?:ba|da|z)?sh\b|(?:^|[;&])\s*(?:ba|da|z)?sh\s+(?:-c\s+|\S+\.sh)|\./\S+"),
    _r("T1059.006", _CMD + r"python[23]?\s+(?:-c|\S+\.py)|\bperl\s+-e\b"),
    _r("T1496", r"xmrig|minerd|cpuminer|stratum\+|kdevtmpfsi|kinsing|cryptonight|\bmonero\b|nanopool|nicehash|moneroocean"),
    _r("T1562.001", r"setenforce\s+0|service\s+\S+\s+stop|systemctl\s+(?:stop|disable|mask)|killall\s+(?:-9\s+)?(?:auditd|syslog|rsyslog|firewalld|clamd|falcon|osqueryd)|ufw\s+disable|apparmor"),
    _r("T1562.004", r"iptables\s+-[FXP]|ufw\s+disable|nft\s+flush|firewall-cmd\s+--(?:remove|permanent)"),
    _r("T1489", _CMD + r"(?:killall|pkill|kill\s+-9|kill\s+-KILL|xkill)\b"),
    _r("T1036.004", r"\[kworker[^\]]*\]|\[ksoftirqd|\[migration|exec\s+-a\s+\S+|prctl|\.systemd-?\w*|\bkdevtmp|\bsshd:\s"),
    _r("T1021.004", _CMD + r"ssh\s+(?:-[a-zA-Z]\s+\S+\s+)*\S+@\S+|sshpass\b|\bscp\s+[^;|&]*@"),
    _r("T1095", r"/dev/tcp/|/dev/udp/|\bnc\b[^;|&]*\s-e\b|\bncat\b[^;|&]*--exec|bash\s+-i\s*>&|socat\b[^;|&]*exec|mkfifo\b[^;|&]*\bnc\b"),
    _r("T1048", r"curl\s+[^;|&]*(?:-F|--data|-d|-T|--upload-file)\s|scp\s+\S+\s+\S+@|nc\s+\S+\s+\d+\s*<|ftpput|tftp\s+-p"),
    _r("T1529", _CMD + r"(?:reboot|shutdown|poweroff|halt|init\s+[06])\b"),
    _r("T1485", r"rm\s+-[a-z]*r[a-z]*f?[a-z]*\s+/(?:\s|\*|$)|dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/|mkfs\.|>\s*/dev/sd"),
    _r("T1005", _CMD + r"(?:cat|tar|zip|7z)\s+[^;|&]*(?:/home|/root|/etc|/var/www|\.sql|\.db|\.conf)"),
    _r("T1499", r"\b(?:ddos|udpflood|syn\s*flood|slowloris|hping3?)\b"),
]

EXPLOIT_CATEGORY_MAP = {
    "traversal": ["T1190", "T1083"], "sqli": ["T1190"], "xss": ["T1190"], "rce": ["T1190", "T1059.004"],
    "cmdi": ["T1190", "T1059.004"], "cve": ["T1190"], "scanner": ["T1595.002"], "recon": ["T1595.002"],
    "webshell": ["T1190", "T1059.004"], "file-upload": ["T1190", "T1105"], "auth": ["T1110.001"],
    "destructive": ["T1485"], "persistence": ["T1053.003"], "ssrf": ["T1190"], "lfi": ["T1190", "T1083"],
    "info": ["T1595.002"], "ssh-key": ["T1098.004"], "cron": ["T1053.003"], "module-load": ["T1190"], "replication": ["T1190", "T1105"],
}


def map_command(text: str) -> list[tuple[str, str]]:
    """-> [(technique, matched evidence)] for a command line."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for rule in COMMAND_RULES:
        m = rule.pattern.search(text)
        if m and rule.technique not in seen:
            seen.add(rule.technique)
            out.append((rule.technique, text[max(0, m.start()):m.end()][:120].strip()))
    return out


def map_event(event: str, data: dict) -> list[tuple[str, str]]:
    """Techniques implied by a non-command event."""
    out: list[tuple[str, str]] = []
    if event == "auth.attempt":
        if data.get("success"):
            out.append(("T1078", f"login as {str(data.get('username', ''))[:40]}"))
        out.append(("T1110.001", f"{str(data.get('username', ''))[:30]}:{str(data.get('password', ''))[:30]}"))
    elif event == "exploit.attempt":
        cat = str(data.get("category", ""))
        for t in EXPLOIT_CATEGORY_MAP.get(cat, ["T1190"]):
            out.append((t, f"{data.get('rule', '')} {data.get('cve', '')}".strip()))
    elif event == "probe":
        out.append(("T1595", str(data.get("proto_guess", ""))[:60]))
    elif event == "download.attempt":
        out.append(("T1105", str(data.get("url", ""))[:120]))
    elif event in ("file.exec_attempt",):
        out.append(("T1059.004", str(data.get("path", ""))[:100]))
    elif event == "cron.install":
        out.append(("T1053.003", str(data.get("crontab", ""))[:100]))
    elif event == "net.outbound_attempt":
        out.append(("T1021.004" if data.get("tool") in ("ssh", "scp") else "T1071.001", str(data.get("target", ""))[:100]))
    elif event == "sftp.open" and data.get("write"):
        out.append(("T1105", str(data.get("path", ""))[:100]))
    return out


def technique_info(tid: str) -> dict:
    name, tactic = TECHNIQUES.get(tid, (tid, "Unknown"))
    return {"id": tid, "name": name, "tactic": tactic, "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"}
