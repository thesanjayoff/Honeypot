#!/usr/bin/env bash
# deploy/deploy.sh - set up the honeypot network on a fresh, ISOLATED VPS (Debian / Ubuntu), in two safe steps.
#
#   sudo deploy/deploy.sh prepare   check the box, install Docker, write .env, create data dirs (noexec quarantine),
#                                   move your real sshd to an admin port (port 22 stays open meanwhile) and apply the
#                                   firewall with an automatic rollback if you cannot log in again.
#   sudo deploy/deploy.sh up        after you proved you can log in on the admin port: free port 22, finalise the
#                                   firewall, build the images and start the honeypots, analyzer and dashboard.
#   sudo deploy/deploy.sh status | logs [service] | down | tunnel
#
# Never run this on your home or office network, or on a machine that holds anything you care about:
# the whole point is to be attacked.  Every step that changes ssh or the firewall asks first.
# Add --yes to skip the routine questions (the typed confirmations stay).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
ENV_FILE="$ROOT/.env"
YES=0
COMPOSE=(docker compose)

say()  { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

ask() {            # ask "question" [default y|n]  -> returns 0 for yes
  local q="$1" d="${2:-y}" a
  if [ "$YES" = 1 ]; then return 0; fi
  read -r -p "$q [$([ "$d" = y ] && echo Y/n || echo y/N)] " a || a=""
  a="${a:-$d}"
  [[ "$a" =~ ^[Yy] ]]
}
typed() {          # typed "word" "why"   - the user must type the word exactly
  local w="$1" a
  printf '%s\n' "$2"
  read -r -p "Type '$w' to continue: " a || a=""
  [ "$a" = "$w" ] || die "not confirmed, nothing changed"
}

envval() { local v=""; [ -f "$ENV_FILE" ] && v="$(grep -E "^$1=" "$ENV_FILE" | tail -n1 | cut -d= -f2- || true)"; v="${v%\'}"; v="${v#\'}"; echo "${v:-${2:-}}"; }
set_env() {        # set_env KEY VALUE   (keeps every other line; VALUE is written as given)
  local k="$1" v="$2" tmp
  tmp="$(mktemp)"
  { grep -v "^$k=" "$ENV_FILE" 2>/dev/null || true; printf '%s=%s\n' "$k" "$v"; } > "$tmp"
  cat "$tmp" > "$ENV_FILE"; rm -f "$tmp"; chmod 600 "$ENV_FILE"
}

need_root() { [ "$(id -u)" = 0 ] || die "run as root (sudo)"; }
data_dir()  { envval HONEYNET_DATA /srv/honeynet; }
ssh_unit()  { if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then echo ssh; else echo sshd; fi; }
client_ip() { local c="${SSH_CONNECTION:-}"; echo "${c%% *}"; }
client_port_on_server() { echo "${SSH_CONNECTION:-}" | awk '{print $4}'; }

# ------------------------------------------------------------------------------------------ preflight
preflight() {
  need_root
  [ "$(uname -s)" = Linux ] || die "Linux only"
  have systemctl || die "systemd is required"
  cat <<'BANNER'

  honeynet deployment
  -------------------
  This turns the machine into bait: it will accept hostile connections on ports 22, 23, 80, 3306 and 6379.
  Only do this on a throw-away VPS that is NOT connected to your home or office network and holds no secrets.
BANNER
  typed "isolated-vps" "I confirm this is a disposable VPS, not a home/office machine or a server with real data."
}

install_docker() {
  if have docker && docker compose version >/dev/null 2>&1; then say "docker + compose plugin present"; return; fi
  have apt-get || die "install Docker Engine and the compose plugin yourself, then re-run"
  ask "Install docker.io, docker-compose-v2 and iptables from the distribution repositories?" y || die "Docker is required"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 iptables python3 e2fsprogs
  systemctl enable --now docker
  docker compose version >/dev/null 2>&1 || die "docker compose plugin missing (package docker-compose-v2 / docker-compose-plugin)"
}

# ------------------------------------------------------------------------------------------ .env + dirs
setup_env() {
  [ -f "$ENV_FILE" ] || { cp "$ROOT/.env.example" "$ENV_FILE"; chmod 600 "$ENV_FILE"; say "created .env from .env.example"; }
  [ -f "$ROOT/config/honeynet.yml" ] || { cp "$ROOT/config/honeynet.example.yml" "$ROOT/config/honeynet.yml"; say "created config/honeynet.yml"; }
  mkdir -p "$ROOT/geoip"

  local port ips me cur
  cur="$(envval ADMIN_SSH_PORT 22022)"
  if [ "$YES" != 1 ]; then
    read -r -p "Admin SSH port for YOUR access (real sshd will move here) [$cur]: " port || port=""
    port="${port:-$cur}"
  else port="$cur"; fi
  [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -gt 1023 ] && [ "$port" -lt 65536 ] || die "pick a port between 1024 and 65535"
  [ "$port" != 22 ] || die "the admin port must not be 22 (the honeypot takes it)"
  set_env ADMIN_SSH_PORT "$port"

  me="$(client_ip)"; cur="$(envval ADMIN_IPS)"
  if [ -z "$cur" ] && [ -n "$me" ]; then cur="$me"; fi
  if [ "$YES" != 1 ]; then
    echo "Your own address(es), comma separated. Only these may reach the admin port, and none of their traffic is logged."
    echo "Leave empty ONLY if your address changes often (the admin port is then open to everyone, rate limited, key-only advised)."
    read -r -p "ADMIN_IPS [$cur]: " ips || ips=""
    ips="${ips:-$cur}"
  else ips="$cur"; fi
  set_env ADMIN_IPS "$ips"
  [ -n "$ips" ] || warn "ADMIN_IPS is empty: the admin SSH port will be reachable from anywhere (rate limited). Use key-only logins."

  if [ -z "$(envval HONEYNET_DASHBOARD_PASSWORD_HASH)" ]; then
    say "dashboard password"
    docker build -q -f docker/Dockerfile --target dashboard -t honeynet/dashboard:local .
    local h
    h="$(docker run --rm -it honeynet/dashboard:local hash-password | tail -n1 | tr -d '\r')"
    [ -n "$h" ] && [[ "$h" == *'$'* ]] || die "no password hash produced"
    set_env HONEYNET_DASHBOARD_PASSWORD_HASH "'$h'"
  fi

  if [ "$(envval ENABLE_FETCHER 0)" != 1 ] && ask "Let the sandboxed fetcher download attacker payload URLs (stored, never run)? Needs narrow outbound access." n; then
    set_env ENABLE_FETCHER 1
    set_env FETCHER_URL "http://fetcher:8099"
    [ -n "$(envval HONEYNET_FETCHER_TOKEN)" ] || set_env HONEYNET_FETCHER_TOKEN "$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n')"
  fi
}

setup_dirs() {
  local d svc q size
  d="$(data_dir)"
  say "data directories under $d"
  mkdir -p "$d"
  for svc in ssh telnet http mysql redis; do mkdir -p "$d/events/$svc"; done
  mkdir -p "$d/quarantine" "$d/analysis" "$d/db" "$d/reports" "$d/keys"
  q="$d/quarantine"
  if ! mountpoint -q "$q"; then
    size="${QUARANTINE_SIZE:-3G}"
    if ask "Mount a $size loop filesystem (noexec,nosuid,nodev) for the quarantine so captured files can never be executed?" y; then
      have mkfs.ext4 || die "mkfs.ext4 missing (apt install e2fsprogs)"
      [ -f "$d/quarantine.img" ] || { truncate -s "$size" "$d/quarantine.img"; mkfs.ext4 -q -m 0 -L hn-quarantine "$d/quarantine.img"; }
      grep -q "$d/quarantine.img" /etc/fstab || echo "$d/quarantine.img $q ext4 loop,noexec,nosuid,nodev,nofail 0 0" >> /etc/fstab
      mount "$q"
    else
      warn "quarantine is a plain directory: noexec is NOT enforced by the filesystem"
    fi
  fi
  chown -R 10001:10001 "$d"
  chmod 750 "$d" "$d"/events "$d"/events/* "$d/analysis" "$d/db" "$d/reports"
  chmod 770 "$q" 2>/dev/null || true
  chmod 700 "$d/keys"
}

# ------------------------------------------------------------------------------------------ sshd
SSHD_DROPIN=/etc/ssh/sshd_config.d/10-honeynet-admin.conf

sshd_check_include() {
  grep -Eq '^\s*Include\s+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config || die "/etc/ssh/sshd_config has no 'Include /etc/ssh/sshd_config.d/*.conf'; add it (OpenSSH 8.2+) and re-run"
  mkdir -p /etc/ssh/sshd_config.d
}

sshd_use_service_not_socket() {            # Ubuntu 22.10+/24.04 start sshd from ssh.socket, which ignores Port directives
  if systemctl is-enabled ssh.socket >/dev/null 2>&1 || systemctl is-active ssh.socket >/dev/null 2>&1; then
    say "disabling ssh.socket so the Port setting is honoured"
    systemctl disable --now ssh.socket
    systemctl enable --now "$(ssh_unit)".service
  fi
}

sshd_apply() {       # sshd_apply "22 22022"  or "22022"
  local ports="$1" p
  { echo "# managed by honeynet deploy.sh - your real sshd lives here, the honeypot owns port 22"; for p in $ports; do echo "Port $p"; done; } > "$SSHD_DROPIN"
  if [ "$ports" = "$(envval ADMIN_SSH_PORT)" ]; then
    # the main config and other drop-ins must not also open port 22
    local f
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
      [ "$f" = "$SSHD_DROPIN" ] && continue
      if grep -Eq '^\s*Port\s' "$f" 2>/dev/null; then
        cp -n "$f" "$f.honeynet-backup"
        sed -i -E 's/^(\s*)Port\s/\1#Port /' "$f"
      fi
    done
  fi
  sshd -t || { rm -f "$SSHD_DROPIN"; die "sshd rejected the configuration; nothing was reloaded"; }
  systemctl reload "$(ssh_unit)"
}

wait_listen() { local port="$1" i; for i in 1 2 3 4 5 6 7 8 9 10; do ss -ltn 2>/dev/null | grep -q ":$port " && return 0; sleep 1; done; return 1; }

# ------------------------------------------------------------------------------------------ commands
cmd_prepare() {
  preflight
  install_docker
  setup_env
  setup_dirs
  local port; port="$(envval ADMIN_SSH_PORT)"
  [ -s /root/.ssh/authorized_keys ] || [ -n "${SUDO_USER:-}" ] || warn "no SSH key found for root; prefer key-only logins before exposing the admin port"

  say "moving your real sshd: it will listen on 22 AND $port for now"
  sshd_check_include
  sshd_use_service_not_socket
  sshd_apply "22 $port"
  wait_listen "$port" || die "sshd is not listening on $port"

  say "applying the firewall with an automatic rollback in 180 seconds"
  "$ROOT/deploy/firewall.sh" apply --extra-admin-port 22 --confirm-timeout 180
  local host; host="$(hostname -I 2>/dev/null | awk '{print $1}')"
  cat <<MSG

  ------------------------------------------------------------------------------
  Open a SECOND terminal now and log in on the new port:

      ssh -p $port ${SUDO_USER:-root}@${host:-<this-server>}

  If that works, come back here.  If you do nothing, the firewall rolls back by itself.
  ------------------------------------------------------------------------------
MSG
  read -r -p "Type 'works' once the second login succeeded: " a || a=""
  if [ "$a" = works ]; then
    "$ROOT/deploy/firewall.sh" confirm
    say "prepared. Next:  sudo deploy/deploy.sh up"
  else
    warn "not confirmed - the firewall will roll back shortly; sshd still listens on 22 and $port. Re-run prepare when ready."
    exit 1
  fi
}

cmd_up() {
  preflight
  have docker || die "run 'prepare' first"
  [ -f "$ENV_FILE" ] || die "run 'prepare' first"
  local port; port="$(envval ADMIN_SSH_PORT)"
  [ -n "$(envval HONEYNET_DASHBOARD_PASSWORD_HASH)" ] || die "HONEYNET_DASHBOARD_PASSWORD_HASH is empty; run 'prepare'"
  wait_listen "$port" || die "sshd does not listen on admin port $port; run 'prepare'"
  if [ -n "${SSH_CONNECTION:-}" ] && [ "$(client_port_on_server)" = 22 ]; then
    die "you are logged in on port 22, which is about to become the honeypot. Log in on port $port and run this again."
  fi
  typed "free-port-22" "sshd stops listening on 22 and the honeypot takes it. Make sure 'ssh -p $port ...' works from your machine."

  sshd_apply "$port"
  say "applying the final firewall (rollback in 120 s unless confirmed)"
  "$ROOT/deploy/firewall.sh" apply --confirm-timeout 120
  "$ROOT/deploy/firewall.sh" confirm      # we are on the admin port already; the rules were validated against this session

  install_firewall_unit

  say "building images"
  local -a profile=()
  [ "$(envval ENABLE_FETCHER 0)" = 1 ] && profile=(--profile fetcher)
  "${COMPOSE[@]}" "${profile[@]}" build
  say "starting the honeypots, analyzer and dashboard"
  "${COMPOSE[@]}" "${profile[@]}" up -d
  # the firewall egress rules reference the docker networks, so re-apply now that they exist
  "$ROOT/deploy/firewall.sh" apply --quiet
  "$ROOT/deploy/firewall.sh" confirm >/dev/null
  sleep 8
  "${COMPOSE[@]}" "${profile[@]}" ps
  cmd_tunnel
}

install_firewall_unit() {
  cat > /etc/systemd/system/honeynet-firewall.service <<UNIT
[Unit]
Description=honeynet host firewall (DOCKER-USER egress rules)
After=docker.service network-online.target
Wants=network-online.target
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$ROOT/deploy/firewall.sh apply --quiet
ExecStartPost=$ROOT/deploy/firewall.sh confirm
ExecStop=$ROOT/deploy/firewall.sh remove

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable honeynet-firewall.service >/dev/null
  say "firewall will be re-applied on boot and whenever Docker restarts"
}

cmd_status() {
  "${COMPOSE[@]}" --profile fetcher ps 2>/dev/null || "${COMPOSE[@]}" ps
  echo; "$ROOT/deploy/firewall.sh" status | head -30
}
cmd_logs()   { "${COMPOSE[@]}" --profile fetcher logs --tail 100 -f "$@"; }
cmd_down()   { ask "Stop all honeynet containers (data is kept)?" y && "${COMPOSE[@]}" --profile fetcher down; }
cmd_tunnel() {
  local port dp; port="$(envval ADMIN_SSH_PORT)"; dp="$(envval DASHBOARD_PORT 8088)"
  cat <<MSG

  Dashboard (private, loopback only). From YOUR computer:

      ssh -N -L ${dp}:127.0.0.1:${dp} -p ${port} ${SUDO_USER:-root}@<server-address>

  then open  http://127.0.0.1:${dp}/  and sign in with the password you chose.
MSG
}

# ------------------------------------------------------------------------------------------ main
args=()
for a in "$@"; do [ "$a" = "--yes" ] && YES=1 || args+=("$a"); done
set -- "${args[@]:-}"
case "${1:-}" in
  prepare) cmd_prepare ;;
  up)      cmd_up ;;
  status)  cmd_status ;;
  logs)    shift; cmd_logs "$@" ;;
  down)    cmd_down ;;
  tunnel)  cmd_tunnel ;;
  *)       sed -n '2,16p' "${BASH_SOURCE[0]}"; exit 2 ;;
esac
