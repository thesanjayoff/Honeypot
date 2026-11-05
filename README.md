# honeynet

A personal honeypot network with a private attack dashboard. Medium-interaction SSH, Telnet, HTTP, MySQL and Redis honeypots, a static-analysis pipeline for anything attackers upload, and a dashboard with a live map, session replay, sample reports, ATT&CK mapping, blocklist/IOC exports and alerts.

Python 3.11+, asyncio, FastAPI + SQLite, no external services required. One user, one box, no accounts.

> **Run it on an isolated, disposable VPS only.** Never on a home or office network, and never on a machine that holds anything you care about. The whole point is to be attacked.

## Try it locally (test mode)

Test mode never listens on anything but loopback, maps source addresses into the RFC 5737 documentation ranges, uses simulated geo data and needs no password.

```powershell
python -m venv .venv
.venv\Scripts\pip install -e ".[dev]"          # Linux/macOS: .venv/bin/pip

.venv\Scripts\python -m honeynet demo           # dashboard filled with synthetic traffic -> http://127.0.0.1:8088/
.venv\Scripts\python -m honeynet dev            # real honeypots + analyzer + dashboard, attacked by a live simulator
.venv\Scripts\python -m pytest tests -q         # ~165 tests, about 100 s
```

`dev` starts the real services on loopback ports (12222, 12323, 18080, 13306, 16379) and drives them with real protocol clients (SSH logins and shell sessions, Telnet, WordPress/phpMyAdmin/router probes with exploit payloads, MySQL and Redis attacks, harmless fake "malware" uploads). Data goes to `.devdata/` (git-ignored, delete it any time). Options: `--rate 60` attacks per minute, `--no-attacks`, `--backfill 0`, `--port 9000`.

## What is in the box

| Piece | What it does |
|---|---|
| `services/ssh`, `telnet` | Fake shell over a fake filesystem. Logs credentials, commands, client fingerprints (SSH version, HASSH-style KEX hash), session transcripts. Every file an attacker creates in the fake shell, uploads over SFTP/SCP, or downloads with `wget`/`curl`/`tftp` (real fetch only via the optional fetcher) lands in the quarantine. |
| `services/http` | Fake WordPress, phpMyAdmin and a router admin panel. Detects SQLi, XSS, path traversal, command injection, Log4Shell, Shellshock, webshell probing, known CVE paths. |
| `services/mysql`, `redis` | Handshake/auth capture, query and command logging, `CONFIG SET dir` / `SLAVEOF` / module-load abuse detection. |
| `analysis/` | Static analysis of every captured binary (see below). |
| `dashboard/` | FastAPI backend + dependency-free single-page frontend. |
| `fetcher.py` | Optional sandboxed downloader for attacker payload URLs (stored, never executed). |
| `simulator/` | Synthetic traffic and the live attack simulator used by `demo` and `dev`. |

Every honeypot service is its own container and writes append-only JSONL to its own events directory. The dashboard tails those files; nothing ever talks to a honeypot at runtime.

### Reverse-engineering module

Every captured file goes to the quarantine under its SHA-256 name (never executed, never given an exec bit) and the analyzer container, which has **no network**, processes it:

- hashes, file type, size, **MalwareBazaar lookup by hash only** (optional, off by default; the file itself is never uploaded)
- strings, imports/exports, sections, entropy, packer heuristics (UPX etc.)
- IOCs: IPs, domains, URLs, wallet addresses, credentials, C2 patterns
- behaviours derived from the disassembly (persistence, anti-debug, scanning loops, self-deletion, miner/DDoS/botnet indicators, syscall sites)
- family label with confidence and the reasons behind it
- a per-sample report in which each finding links to the disassembled snippet (and decompiled text when the backend can produce it) that supports it

**Static analysis only.** Samples are parsed, never run. IOCs flow back into the dashboard (IOC page, `/api/export/*`) and the blocklist.

The tool sits behind a small adapter interface (`analysis/model.py: AnalysisBackend`). Two implementations ship:

- `builtin` (default): capstone + pyelftools + pefile.
- `command`: runs *your* reverse-engineering CLI headless as a subprocess (no shell, scrubbed environment, no network in the analyzer container, time-boxed). Point it at a wrapper that implements:

  ```
  <cmd> inspect <file>             -> JSON object (honeynet.analysis.model.BinaryInfo.to_dict())
  <cmd> disasm  <file> --max N     -> JSON list of {address,size,mnemonic,op_str,bytes}
  <cmd> pseudo  <file> <address>   -> decompiler text, exit status 3 = unsupported
  ```

  Set `analysis_backend: command` and `analysis_command: "/opt/tools/mytool"` in `config/honeynet.yml` (or the env vars `HONEYNET_ANALYSIS_BACKEND` / `HONEYNET_ANALYSIS_COMMAND`). The program must exist inside the analyzer image, so extend the `analyzer` target in `docker/Dockerfile`. The spec's `[RE_TOOL]` placeholder was never filled in, so nothing is hard-wired to a particular product.

Try it on harmless files only: `python -m honeynet analyze --once` after dropping a file into `<data>/quarantine/`. The test suite uses self-made fixtures (tiny ELF/PE files built in the tests), not real malware.

### Dashboard

Live attack map and event feed (SSE), time series, top countries/ASNs/usernames/passwords/commands/URLs/user agents, per-IP profiles, session replay (control characters shown as visible escapes, never interpreted), samples with full analysis report, IOC table, MITRE ATT&CK matrix coverage, alerts, light/dark theme, a table view for every chart.

- **Enrichment**: offline GeoLite2 (City + ASN `.mmdb` in `./geoip`, free MaxMind account). Optional AbuseIPDB reputation toggle (`HONEYNET_ABUSEIPDB_ENABLED=1` + key): only IP addresses are sent.
- **Exports** (`/api/export/...` and `python -m honeynet export ...`): blocklist as txt/csv/json/ipset/iptables/nft/ufw/pf, IOC feeds as JSON/CSV, C2 indicators, daily summary in Markdown/HTML. Your own IPs and any secrets are redacted from everything.
- **Alerts** (webhook and/or SMTP): first sighting of a sample, first sighting of a new exploit signature, traffic spikes vs. the 6 h baseline. Cooldowns prevent floods.

## Deploy to a VPS

1. **Get a throw-away VPS** (Debian 12 / Ubuntu 22.04+, 1 GB RAM is fine) that has no private networking into anything of yours. Use SSH keys for your own login. Note your own public IP.
2. **Copy the repo** to it (`git clone`, or `scp -r`), then, as root in the repo directory:

   ```bash
   sudo deploy/deploy.sh prepare
   ```

   It asks you to type `isolated-vps`, installs Docker, writes `.env` (admin SSH port, your IP list, dashboard password), creates `/srv/honeynet/...` owned by the unprivileged container user, mounts the quarantine on a `noexec,nosuid,nodev` loop filesystem, moves your **real sshd to the admin port (default 22022) while keeping 22 open**, and applies the host firewall with a **180 s automatic rollback**.
3. **From a second terminal** log in on the new port: `ssh -p 22022 you@server`. If it works, type `works` in the first terminal to keep the firewall. If you do nothing, the firewall rolls itself back.
4. Reconnect on the admin port, then:

   ```bash
   sudo deploy/deploy.sh up
   ```

   You must type `free-port-22`. sshd stops listening on 22, the final firewall is applied (again with a rollback timer), images are built and `docker compose up -d` starts the five honeypots, the analyzer and the dashboard. A systemd unit re-applies the firewall on boot and whenever Docker restarts.
5. **Open the dashboard through an SSH tunnel** (it is published on `127.0.0.1` on the server only):

   ```bash
   ssh -N -L 8088:127.0.0.1:8088 -p 22022 you@server     # then browse to http://127.0.0.1:8088/
   ```

6. Optional: put the GeoLite2 `.mmdb` files in `./geoip/` and `docker compose restart dashboard`. Fill in the AbuseIPDB / MalwareBazaar / webhook / SMTP values in `.env` and `docker compose up -d dashboard` again.

Helpers: `deploy/deploy.sh status | logs [service] | down | tunnel`. Firewall on its own: `deploy/firewall.sh apply|confirm|status|remove`.

### Safety model

- **Network isolation.** Honeypots publish only their own ports. `deploy/firewall.sh` sets a default-deny INPUT policy, rate-limits new connections per source, allows the admin SSH port only from `ADMIN_IPS` (if set), and in `DOCKER-USER` drops all new outbound connections from the honeypot subnet. Containers cannot reach each other (ICC off), and the host's default-deny INPUT policy drops what they send to it. The only egress is opt-in: the fetcher (`ENABLE_FETCHER=1`, a handful of ports, rate-limited, token-protected, size-capped, internal-address targets refused) and the dashboard to hosts listed in `DASHBOARD_EGRESS_HOSTS`.
- **Container hardening.** Non-root uid 10001, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, tmpfs `/tmp` with `noexec`, memory/CPU/pid limits, log rotation. Each honeypot can write only its own events directory and the quarantine.
- **Samples are never executed.** The analyzer container has `network_mode: none`, a read-only quarantine mount and no exec permission on it; files are parsed in a child process with time, memory and size limits.
- **Attacker input is hostile.** Everything is sanitised at log time (control characters, length caps, log-injection newlines), re-validated when read, and rendered in the UI with DOM text nodes only (strict CSP, no inline script/style, no HTML parsing from data). Terminal escape sequences in replays are shown as `\x1b` style escapes. Session length, file size, connection counts and per-IP event rates are capped.
- **Dashboard is private.** Loopback only, password required (PBKDF2, throttled logins, signed cookie), Host allow-list, CSRF check, no wildcard CORS. There is no multi-user model.
- **Your data stays out.** `ADMIN_IPS` traffic is dropped before logging; known secrets and your IPs are scrubbed from logs, reports and every export.

### Things worth knowing

- Port 22/23/80 on the VPS belong to the honeypots. Do not run anything else there.
- Disk usage is bounded (`max_quarantine_bytes`, `max_events_dir_bytes`, `retention_days`), but check `df -h` now and then.
- Docker, the compose file, the firewall script and `deploy.sh` were written against Docker Engine + iptables on Debian/Ubuntu but have so far only been syntax-checked, not run on a real VPS. Run `prepare` from a provider console session you can fall back on the first time.
- Settings live in `config/honeynet.yml` (non-secret) and `.env` (secrets). Most keys can also be set as `HONEYNET_<KEY>` environment variables (see `_ENV_MAP` in `src/honeynet/common/config.py`); secrets are only ever read from the environment, never from YAML.

## Layout

```
src/honeynet/{common,shell,services,analysis,dashboard,simulator}
docker/Dockerfile          one build file, targets: honeypot, analyzer, dashboard, fetcher
docker-compose.yml         hardened services and networks
deploy/deploy.sh           two-phase VPS setup
deploy/firewall.sh         host firewall with lock-out protection
config/honeynet.example.yml, .env.example
tests/                     pytest suite (parsing, sanitisation, shell, services, analysis adapter, exports, dashboard API, frontend safety)
```
