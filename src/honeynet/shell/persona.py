"""Personas: what the fake machine claims to be (hostname, kernel, files...)."""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field

from .fakefs import BaseTree, Node

EPOCH_BOOT = time.time() - 86400 * 37 - 5231  # pretend uptime ~37 days


def elf_stub(machine: int, bits: int = 64, little: bool = True, size: int = 2048) -> bytes:
    """A syntactically valid ELF header + padding. Never executable content."""
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1 if little else 2, 1, 0]) + b"\x00" * 8
    e = "<" if little else ">"
    if bits == 64:
        hdr = ident + struct.pack(e + "HHIQQQIHHHHHH", 2, machine, 1, 0x401000, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    else:
        hdr = ident + struct.pack(e + "HHIIIIIHHHHHH", 2, machine, 1, 0x8000, 52, 0, 0, 52, 32, 1, 40, 0, 0)
    return hdr + b"\x00" * max(0, size - len(hdr))


@dataclass
class Persona:
    name: str
    hostname: str
    os_pretty: str
    kernel_release: str
    kernel_version: str
    machine: str                       # uname -m
    elf_machine: int
    elf_bits: int
    prompt_root: str
    prompt_user: str
    login_banner: str                  # shown before login (telnet) / ssh pre-auth
    motd: str
    busybox: bool
    cpu_model: str
    cpu_cores: int
    mem_total_kb: int
    users: list[tuple[str, int, str, str]] = field(default_factory=list)  # name, uid, home, shell
    processes: list[tuple[int, str, str]] = field(default_factory=list)   # pid, user, cmdline
    extra_files: dict[str, str] = field(default_factory=dict)
    commands: set[str] = field(default_factory=set)

    @property
    def uname_a(self) -> str:
        return (f"Linux {self.hostname} {self.kernel_release} {self.kernel_version} {self.machine} "
                f"{'GNU/Linux' if not self.busybox else 'GNU/Linux'}")


COMMON_BINS = (
    "sh bash ash cat ls cd pwd echo printf mkdir rm rmdir touch cp mv chmod chown ln head tail wc grep awk sed cut "
    "sort uniq tr id whoami uname hostname uptime date w who last ps top free df mount lscpu nproc ifconfig ip "
    "netstat ss env export history sleep kill pkill killall nohup busybox wget curl tftp ftpget base64 dd crontab "
    "service systemctl iptables sudo su passwd exit reboot shutdown which uname dmesg lsmod chattr tar gzip gunzip "
    "unzip find xargs test python python3 perl php nc ping basename dirname stat file strings md5sum sha256sum "
    "tee clear reset stty ulimit getconf lsb_release arch sync swapon free"
).split()


def _debian_persona() -> Persona:
    return Persona(
        name="debian", hostname="svr04", os_pretty="Debian GNU/Linux 10 (buster)",
        kernel_release="4.19.0-21-amd64", kernel_version="#1 SMP Debian 4.19.249-2 (2022-06-30)",
        machine="x86_64", elf_machine=0x3E, elf_bits=64,
        prompt_root="root@svr04:{cwd}# ", prompt_user="{user}@svr04:{cwd}$ ",
        login_banner="", motd=(
            "\nThe programs included with the Debian GNU/Linux system are free software;\n"
            "the exact distribution terms for each program are described in the\n"
            "individual files in /usr/share/doc/*/copyright.\n\n"
            "Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent\n"
            "permitted by applicable law.\n"),
        busybox=False, cpu_model="Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz", cpu_cores=2,
        mem_total_kb=4046432,
        users=[("root", 0, "/root", "/bin/bash"), ("daemon", 1, "/usr/sbin", "/usr/sbin/nologin"),
               ("www-data", 33, "/var/www", "/usr/sbin/nologin"), ("sshd", 104, "/run/sshd", "/usr/sbin/nologin"),
               ("admin", 1000, "/home/admin", "/bin/bash"), ("ubuntu", 1001, "/home/ubuntu", "/bin/bash")],
        processes=[(1, "root", "/sbin/init"), (312, "root", "/usr/sbin/cron -f"),
                   (344, "root", "/usr/sbin/rsyslogd -n"), (402, "root", "/usr/sbin/sshd -D"),
                   (517, "www-data", "nginx: worker process"), (518, "root", "nginx: master process /usr/sbin/nginx")],
        commands=set(COMMON_BINS),
    )


def _iot_persona() -> Persona:
    return Persona(
        name="iot", hostname="dvr", os_pretty="Linux (BusyBox v1.22.1)",
        kernel_release="3.10.0", kernel_version="#7 SMP PREEMPT Tue Mar 12 17:12:04 CST 2019",
        machine="armv7l", elf_machine=0x28, elf_bits=32,
        prompt_root="# ", prompt_user="$ ",
        login_banner="\r\nWelcome to DVR\r\n", motd="",
        busybox=True, cpu_model="ARMv7 Processor rev 5 (v7l)", cpu_cores=1, mem_total_kb=125312,
        users=[("root", 0, "/root", "/bin/sh"), ("admin", 1000, "/home/admin", "/bin/sh")],
        processes=[(1, "root", "init"), (2, "root", "[kthreadd]"), (96, "root", "/usr/sbin/telnetd"),
                   (132, "root", "/bin/watchdog"), (205, "root", "/usr/bin/dvrapp"),
                   (211, "root", "/usr/sbin/httpd -p 80")],
        commands=set(COMMON_BINS) - {"python", "python3", "php", "perl", "sudo", "lsb_release", "systemctl", "unzip"},
    )


PERSONAS = {"debian": _debian_persona, "iot": _iot_persona}


def get_persona(name: str) -> Persona:
    return PERSONAS.get(name, _debian_persona)()


def _passwd(p: Persona) -> str:
    return "".join(f"{n}:x:{uid}:{uid}:{n}:{home}:{sh}\n" for n, uid, home, sh in p.users)


def _shadow(p: Persona) -> str:
    return "".join(f"{n}:$6$rounds=5000$x7Qf1aZk$Zr0D8e2c1ZqkG0zq6mE0Lw5uKq1Rz0g3sQJvY8d.k:19000:0:99999:7:::\n"
                   for n, *_ in p.users)


def _cpuinfo(p: Persona) -> str:
    out = []
    for i in range(p.cpu_cores):
        out.append(f"processor\t: {i}\nmodel name\t: {p.cpu_model}\ncpu MHz\t\t: 2399.998\ncache size\t: 35840 KB\n"
                   f"cpu cores\t: {p.cpu_cores}\nbogomips\t: 4799.99\n\n")
    return "".join(out)


def _meminfo(p: Persona) -> str:
    t = p.mem_total_kb
    return (f"MemTotal:       {t:8d} kB\nMemFree:        {t // 3:8d} kB\nMemAvailable:   {t // 2:8d} kB\n"
            f"Buffers:        {t // 40:8d} kB\nCached:         {t // 5:8d} kB\nSwapTotal:      {0 if p.busybox else 1048572:8d} kB\n"
            f"SwapFree:       {0 if p.busybox else 1048572:8d} kB\n")


def build_base(p: Persona) -> BaseTree:
    now = time.time() - 86400 * 90
    nodes: dict[str, Node] = {}

    def d(path: str, mode: int = 0o755) -> None:
        nodes[path] = Node("d", mode, mtime=now)

    def f(path: str, content: str | bytes, mode: int = 0o644, uid: int = 0) -> None:
        data = content.encode() if isinstance(content, str) else content
        nodes[path] = Node("f", mode, uid=uid, gid=uid, mtime=now, content=data)

    for path in ("/", "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin", "/usr/local", "/usr/local/bin", "/etc",
                 "/etc/init.d", "/etc/cron.d", "/etc/ssh", "/var", "/var/log", "/var/run", "/var/tmp", "/var/www",
                 "/var/spool", "/var/spool/cron", "/dev", "/proc", "/proc/net", "/sys", "/root", "/home", "/mnt",
                 "/opt", "/lib", "/run", "/srv", "/media"):
        d(path)
    nodes["/tmp"] = Node("d", 0o1777, mtime=now)
    nodes["/root"].mode = 0o700
    d("/root/.ssh", 0o700)
    for n, uid, home, _sh in p.users:
        if home.startswith("/home/"):
            d(home)
            nodes[home].uid = nodes[home].gid = uid

    f("/etc/passwd", _passwd(p))
    f("/etc/shadow", _shadow(p), 0o640)
    f("/etc/group", "root:x:0:\ndaemon:x:1:\nadmin:x:1000:\nwww-data:x:33:\n")
    f("/etc/hostname", p.hostname + "\n")
    f("/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{p.hostname}\n::1\tlocalhost ip6-localhost\n")
    f("/etc/resolv.conf", "nameserver 8.8.8.8\nnameserver 1.1.1.1\n")
    f("/etc/issue", f"{p.os_pretty} \\n \\l\n\n")
    f("/etc/motd", p.motd)
    f("/etc/os-release", f'PRETTY_NAME="{p.os_pretty}"\nNAME="{p.os_pretty.split()[0]}"\nID={p.os_pretty.split()[0].lower()}\n')
    f("/etc/crontab", "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
                      "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n")
    f("/etc/rc.local", "#!/bin/sh -e\n#\n# rc.local\n#\nexit 0\n", 0o755)
    f("/etc/fstab", "/dev/sda1 / ext4 defaults 0 1\n")
    f("/etc/ssh/sshd_config", "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nSubsystem sftp /usr/lib/openssh/sftp-server\n")
    f("/etc/inittab", "::sysinit:/etc/init.d/rcS\n::respawn:/sbin/getty -L ttyS0 115200 vt100\n")
    f("/proc/cpuinfo", _cpuinfo(p))
    f("/proc/meminfo", _meminfo(p))
    f("/proc/version", f"Linux version {p.kernel_release} (gcc version 8.3.0) {p.kernel_version}\n")
    f("/proc/uptime", "3201433.77 6319823.12\n")
    f("/proc/loadavg", "0.08 0.03 0.01 1/187 9921\n")
    f("/proc/mounts", "/dev/root / ext4 rw,relatime 0 0\nproc /proc proc rw 0 0\nsysfs /sys sysfs rw 0 0\n"
                      "tmpfs /tmp tmpfs rw 0 0\ndevtmpfs /dev devtmpfs rw 0 0\n")
    f("/proc/net/tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
    f("/proc/net/dev", "Inter-|   Receive\n face |bytes    packets\n    lo: 0 0\n  eth0: 91773412 71203\n")
    f("/root/.bashrc", "# ~/.bashrc: executed by bash(1) for non-login shells.\nalias ll='ls -l'\n")
    f("/root/.profile", "# ~/.profile\n")
    f("/root/.bash_history", "ls\ncd /var/www\nexit\n")
    f("/var/log/auth.log", "")
    f("/var/log/syslog", "")
    f("/var/log/messages", "")
    f("/var/log/wtmp", "", 0o664)
    f("/var/www/index.html", "<html><body><h1>It works!</h1></body></html>\n")
    for dev in ("null", "zero", "random", "urandom", "tty", "console"):
        nodes[f"/dev/{dev}"] = Node("c", 0o666, mtime=now)
    nodes["/dev/watchdog"] = Node("c", 0o600, mtime=now)
    if p.busybox:
        nodes["/dev/misc"] = Node("d", 0o755, mtime=now)
        nodes["/dev/misc/watchdog"] = Node("c", 0o600, mtime=now)

    stub = elf_stub(p.elf_machine, p.elf_bits)
    for cmd in sorted(p.commands):
        loc = "/bin" if cmd in ("sh", "bash", "ash", "cat", "ls", "echo", "busybox", "ps", "kill", "chmod", "rm",
                                "mkdir", "cp", "mv", "uname", "date", "grep", "sed", "mount", "ping", "sleep",
                                "tar", "gzip", "touch", "pwd", "su", "hostname", "dd", "df", "netstat", "ln") else "/usr/bin"
        nodes[f"{loc}/{cmd}"] = Node("f", 0o755, mtime=now, content=stub)
    nodes["/bin/busybox"] = Node("f", 0o755, mtime=now, content=stub)
    for path, content in p.extra_files.items():
        f(path, content)
    return BaseTree(nodes)
