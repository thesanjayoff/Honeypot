#!/usr/bin/env bash
# deploy/firewall.sh - host firewall for the honeypot VPS (iptables + Docker's DOCKER-USER chain)
#
#   firewall.sh apply [--confirm-timeout SECONDS] [--extra-admin-port PORT] [--force] [--quiet]
#   firewall.sh confirm        cancel the automatic rollback started by --confirm-timeout
#   firewall.sh status
#   firewall.sh remove
#
# What it enforces
#   INPUT           default deny.  Only: loopback, established traffic, ICMP echo (rate-limited) and your admin SSH port
#                   (from ADMIN_IPS only when set, otherwise from anywhere with a per-source rate limit).
#                   Docker bridge subnets can never reach host services.
#   DOCKER-USER     * new connections to the honeypot ports are rate-limited per source address
#                   * containers on the honeypot network (dmz) may not open ANY new outbound connection
#                   * optional: the fetcher container gets narrow egress (public IPs only, tcp 80/443/8080/8443, rate-limited,
#                     DNS to two fixed resolvers); the dashboard gets tcp egress to DASHBOARD_EGRESS_HOSTS only
#   IPv6            Docker's IPv6 is off, so forwarding is dropped; the host only answers loopback, ND/ping and admin SSH.
#
# Lock-out protection: use --confirm-timeout 120 the first time.  If you cannot log in again, the previous rules are
# restored automatically after that many seconds.  When everything works, run:  firewall.sh confirm
#
# Settings are read from .env in the repository root (ADMIN_SSH_PORT, ADMIN_IPS, ENABLE_FETCHER, DASHBOARD_EGRESS_*).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"
STATE=/var/lib/honeynet
IN_CHAIN=HONEYNET-IN
FWD_CHAIN=HONEYNET-FWD

DMZ=172.28.10.0/24
EGRESS=172.28.20.0/24
ADMIN_NET=172.28.30.0/24
FETCH=172.28.40.0/24
DOCKER_SUPERNET=172.28.0.0/16
HONEYPOT_PORTS=2222,2323,8080,3306,6379          # container-side ports (after Docker's DNAT)
DNS_SERVERS=(1.1.1.1 9.9.9.9)

say() { [ "${QUIET:-0}" = 1 ] || echo "firewall: $*"; }
die() { echo "firewall: ERROR: $*" >&2; exit 1; }

envval() {   # envval KEY [default]  - read KEY from .env without sourcing it (the password hash contains dollar signs)
  local v=""
  [ -f "$ENV_FILE" ] && v="$(grep -E "^$1=" "$ENV_FILE" | tail -n1 | cut -d= -f2- || true)"
  v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
  echo "${v:-${2:-}}"
}

need_root() { [ "$(id -u)" = 0 ] || die "run as root"; }
have() { command -v "$1" >/dev/null 2>&1; }

ipt()  { iptables -w 5 "$@"; }
ip6t() { ip6tables -w 5 "$@"; }

new_chain() {   # new_chain <tool> <chain> : create or flush
  "$1" -N "$2" 2>/dev/null || "$1" -F "$2"
}
jump_once() {   # jump_once <tool> <from-chain> <to-chain> : make it the first rule, exactly once
  while "$1" -D "$2" -j "$3" 2>/dev/null; do :; done
  "$1" -I "$2" 1 -j "$3"
}

valid_addr() { [[ "$1" =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]]; }

# ------------------------------------------------------------------------------------------------ safety checks
current_client() { local c="${SSH_CONNECTION:-}"; echo "${c%% *}"; }

covered_by_admin_list() {   # is $1 inside one of the ADMIN_IPS entries?
  local ip="$1"; shift
  have python3 || return 0
  python3 - "$ip" "$@" <<'PY'
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
for net in sys.argv[2:]:
    try:
        if ip in ipaddress.ip_network(net, strict=False):
            sys.exit(0)
    except ValueError:
        pass
sys.exit(1)
PY
}

# ------------------------------------------------------------------------------------------------ rule builders
build_input() {
  local admin_port="$1"
  local -a admin_ips=("${ADMIN_LIST[@]}")
  new_chain ipt "$IN_CHAIN"
  ipt -A "$IN_CHAIN" -i lo -j ACCEPT
  ipt -A "$IN_CHAIN" -m conntrack --ctstate INVALID -j DROP
  ipt -A "$IN_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ipt -A "$IN_CHAIN" -s "$DOCKER_SUPERNET" -j DROP                       # containers cannot reach host services
  ipt -A "$IN_CHAIN" -p icmp --icmp-type echo-request -m limit --limit 5/second --limit-burst 10 -j ACCEPT
  local port src
  for port in $admin_port $EXTRA_ADMIN_PORTS; do
    if [ "${#admin_ips[@]}" -gt 0 ]; then
      for src in "${admin_ips[@]}"; do
        [[ "$src" == *:* ]] && continue
        ipt -A "$IN_CHAIN" -p tcp -s "$src" --dport "$port" -m conntrack --ctstate NEW \
            -m hashlimit --hashlimit-name "adm$port" --hashlimit-mode srcip --hashlimit-above 30/minute --hashlimit-burst 20 -j DROP
        ipt -A "$IN_CHAIN" -p tcp -s "$src" --dport "$port" -j ACCEPT
      done
    else
      ipt -A "$IN_CHAIN" -p tcp --dport "$port" -m conntrack --ctstate NEW \
          -m hashlimit --hashlimit-name "adm$port" --hashlimit-mode srcip --hashlimit-above 12/minute --hashlimit-burst 8 -j DROP
      ipt -A "$IN_CHAIN" -p tcp --dport "$port" -j ACCEPT
    fi
  done
  ipt -A "$IN_CHAIN" -j DROP
  jump_once ipt INPUT "$IN_CHAIN"
}

build_input6() {
  local admin_port="$1"
  local -a admin_ips=("${ADMIN_LIST[@]}")
  new_chain ip6t "$IN_CHAIN"
  ip6t -A "$IN_CHAIN" -i lo -j ACCEPT
  ip6t -A "$IN_CHAIN" -m conntrack --ctstate INVALID -j DROP
  ip6t -A "$IN_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6t -A "$IN_CHAIN" -p ipv6-icmp -j ACCEPT                              # neighbour discovery / path MTU must keep working
  local port src v6=()
  for src in "${admin_ips[@]}"; do [[ "$src" == *:* ]] && v6+=("$src"); done
  for port in $admin_port $EXTRA_ADMIN_PORTS; do
    if [ "${#admin_ips[@]}" -eq 0 ]; then
      ip6t -A "$IN_CHAIN" -p tcp --dport "$port" -m conntrack --ctstate NEW \
           -m hashlimit --hashlimit-name "adm6$port" --hashlimit-mode srcip --hashlimit-above 12/minute --hashlimit-burst 8 -j DROP
      ip6t -A "$IN_CHAIN" -p tcp --dport "$port" -j ACCEPT
    else
      for src in "${v6[@]}"; do
        ip6t -A "$IN_CHAIN" -p tcp -s "$src" --dport "$port" -j ACCEPT
      done
    fi
  done
  ip6t -A "$IN_CHAIN" -j DROP
  jump_once ip6t INPUT "$IN_CHAIN"
  ip6t -P FORWARD DROP 2>/dev/null || true
}

resolve4() { getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u; }

build_forward() {
  have iptables || die "iptables not found"
  ipt -N DOCKER-USER 2>/dev/null || true                                   # exists once Docker runs; harmless otherwise
  new_chain ipt "$FWD_CHAIN"
  local c="$FWD_CHAIN"

  ipt -A $c -m conntrack --ctstate INVALID -j DROP
  ipt -A $c -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN           # replies to inbound honeypot traffic

  # inbound: per-source limit on new connections to the honeypot services (ports are post-DNAT)
  ipt -A $c -p tcp -m multiport --dports "$HONEYPOT_PORTS" -m conntrack --ctstate NEW \
      -m hashlimit --hashlimit-name hp-src --hashlimit-mode srcip --hashlimit-above 90/minute --hashlimit-burst 60 -j DROP

  # honeypot <-> fetcher requests stay inside the internal "fetch" network
  ipt -A $c -s "$FETCH" -d "$FETCH" -j RETURN

  # --- honeypots: nothing new may leave.  Attempts are logged (rate-limited) - they are interesting.
  ipt -A $c -s "$DMZ" -m conntrack --ctstate NEW -m limit --limit 6/minute -j LOG --log-prefix "honeynet-egress-drop " --log-level 4
  ipt -A $c -s "$DMZ" -j DROP
  ipt -A $c -s "$FETCH" -j DROP

  # --- fetcher (optional): public internet only, a handful of ports, rate-limited
  if [ "$ENABLE_FETCHER" = 1 ]; then
    local d
    for d in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 127.0.0.0/8 224.0.0.0/4 240.0.0.0/4 0.0.0.0/8 \
             192.0.0.0/24 192.0.2.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24; do
      ipt -A $c -s "$EGRESS" -d "$d" -j DROP
    done
    for d in "${DNS_SERVERS[@]}"; do
      ipt -A $c -s "$EGRESS" -d "$d" -p udp --dport 53 -j ACCEPT
      ipt -A $c -s "$EGRESS" -d "$d" -p tcp --dport 53 -j ACCEPT
    done
    ipt -A $c -s "$EGRESS" -p tcp -m multiport --dports 80,443,8080,8443 -m conntrack --ctstate NEW \
        -m hashlimit --hashlimit-name fetch --hashlimit-mode srcip --hashlimit-above 30/minute --hashlimit-burst 10 -j DROP
    ipt -A $c -s "$EGRESS" -p tcp -m multiport --dports 80,443,8080,8443 -m conntrack --ctstate NEW -j ACCEPT
  fi
  ipt -A $c -s "$EGRESS" -j DROP

  # --- dashboard: no egress unless hosts are listed (AbuseIPDB, MalwareBazaar, webhook, SMTP)
  if [ -n "$DASHBOARD_EGRESS_HOSTS" ]; then
    local h a p
    for d in "${DNS_SERVERS[@]}"; do
      ipt -A $c -s "$ADMIN_NET" -d "$d" -p udp --dport 53 -j ACCEPT
      ipt -A $c -s "$ADMIN_NET" -d "$d" -p tcp --dport 53 -j ACCEPT
    done
    for h in $DASHBOARD_EGRESS_HOSTS; do
      for a in $(resolve4 "$h"); do
        ipt -A $c -s "$ADMIN_NET" -d "$a" -p tcp -m multiport --dports "$DASHBOARD_EGRESS_PORTS" -m conntrack --ctstate NEW \
            -m limit --limit 120/minute --limit-burst 30 -j ACCEPT
        say "dashboard egress allowed: $h ($a) tcp/$DASHBOARD_EGRESS_PORTS"
      done
    done
  fi
  ipt -A $c -s "$ADMIN_NET" -m conntrack --ctstate NEW -j DROP

  ipt -A $c -j RETURN
  jump_once ipt DOCKER-USER "$c"
}

# ------------------------------------------------------------------------------------------------ commands
cmd_apply() {
  need_root
  have iptables || die "iptables is not installed"
  local timeout=0 force=0
  EXTRA_ADMIN_PORTS=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --confirm-timeout) timeout="$2"; shift 2 ;;
      --extra-admin-port) EXTRA_ADMIN_PORTS="$EXTRA_ADMIN_PORTS $2"; shift 2 ;;
      --force) force=1; shift ;;
      --quiet) QUIET=1; shift ;;
      *) die "unknown option $1" ;;
    esac
  done

  local admin_port admin_ips_raw
  admin_port="$(envval ADMIN_SSH_PORT 22022)"
  admin_ips_raw="$(envval ADMIN_IPS)"
  ENABLE_FETCHER="$(envval ENABLE_FETCHER 0)"
  DASHBOARD_EGRESS_HOSTS="$(envval DASHBOARD_EGRESS_HOSTS)"
  DASHBOARD_EGRESS_PORTS="$(envval DASHBOARD_EGRESS_PORTS 443)"
  [[ "$admin_port" =~ ^[0-9]+$ ]] && [ "$admin_port" -ge 1 ] && [ "$admin_port" -le 65535 ] || die "bad ADMIN_SSH_PORT '$admin_port'"
  [[ "$DASHBOARD_EGRESS_PORTS" =~ ^[0-9,]+$ ]] || die "bad DASHBOARD_EGRESS_PORTS"

  ADMIN_LIST=()
  local -a p
  if [ -n "$admin_ips_raw" ]; then
    IFS=',' read -ra p <<< "$admin_ips_raw"
    local x
    for x in "${p[@]}"; do
      x="${x// /}"; [ -z "$x" ] && continue
      valid_addr "$x" || die "bad address in ADMIN_IPS: $x"
      ADMIN_LIST+=("$x")
    done
  fi
  local -a admin_ips=("${ADMIN_LIST[@]}")

  local me; me="$(current_client)"
  if [ -n "$me" ] && [ "${#admin_ips[@]}" -gt 0 ] && ! covered_by_admin_list "$me" "${admin_ips[@]}"; then
    echo "firewall: you are connected from $me, which is NOT in ADMIN_IPS (${admin_ips[*]})." >&2
    [ "$force" = 1 ] || die "refusing to lock yourself out; add $me to ADMIN_IPS or pass --force"
  fi
  if [ -n "$me" ] && [ -n "${SSH_CONNECTION:-}" ]; then
    local cur_port; cur_port="$(echo "$SSH_CONNECTION" | awk '{print $4}')"
    if [ "$cur_port" != "$admin_port" ] && ! [[ " $EXTRA_ADMIN_PORTS " == *" $cur_port "* ]]; then
      echo "firewall: this session uses sshd port $cur_port but the firewall will only allow $admin_port${EXTRA_ADMIN_PORTS:+ and$EXTRA_ADMIN_PORTS}." >&2
      [ "$force" = 1 ] || die "use --extra-admin-port $cur_port while you move sshd (deploy.sh does this), or --force"
    fi
  fi

  mkdir -p "$STATE"; chmod 700 "$STATE"
  iptables-save  > "$STATE/iptables.before"  2>/dev/null || true
  have ip6tables && ip6tables-save > "$STATE/ip6tables.before" 2>/dev/null || true
  rm -f "$STATE/confirmed"

  build_input "$admin_port"
  if have ip6tables; then build_input6 "$admin_port"; fi
  build_forward
  say "applied: admin ssh port $admin_port${EXTRA_ADMIN_PORTS:+ (+$EXTRA_ADMIN_PORTS)} from ${admin_ips[*]:-anywhere (rate limited)}; fetcher=$ENABLE_FETCHER"

  if [ "$timeout" -gt 0 ]; then
    say "automatic rollback in ${timeout}s unless you run: $0 confirm"
    setsid "${BASH_SOURCE[0]}" _rollback "$timeout" </dev/null >/dev/null 2>&1 &     # survives a dropped SSH session
  fi
}

cmd_rollback() {   # internal: restore the saved rules unless confirmed in time
  sleep "$1"
  if [ ! -e "$STATE/confirmed" ]; then
    iptables-restore < "$STATE/iptables.before" 2>/dev/null || true
    if have ip6tables; then ip6tables-restore < "$STATE/ip6tables.before" 2>/dev/null || true; fi
    logger -t honeynet-firewall "no confirmation within ${1}s - previous firewall restored" 2>/dev/null || true
  fi
}

cmd_confirm() { need_root; mkdir -p "$STATE"; touch "$STATE/confirmed"; say "confirmed - the new rules stay"; }

cmd_status() {
  need_root
  echo "== INPUT ($IN_CHAIN)";  ipt -S "$IN_CHAIN" 2>/dev/null || echo "(not installed)"
  echo "== DOCKER-USER ($FWD_CHAIN)"; ipt -S "$FWD_CHAIN" 2>/dev/null || echo "(not installed)"
  echo "== packet counters"; ipt -L "$FWD_CHAIN" -n -v 2>/dev/null | head -40 || true
}

cmd_remove() {
  need_root
  local t
  for t in ipt ip6t; do
    have "${t%t}tables" 2>/dev/null || [ "$t" = ipt ] || continue
    while $t -D INPUT -j "$IN_CHAIN" 2>/dev/null; do :; done
    $t -F "$IN_CHAIN" 2>/dev/null && $t -X "$IN_CHAIN" 2>/dev/null || true
  done
  while ipt -D DOCKER-USER -j "$FWD_CHAIN" 2>/dev/null; do :; done
  ipt -F "$FWD_CHAIN" 2>/dev/null && ipt -X "$FWD_CHAIN" 2>/dev/null || true
  say "removed (Docker's own rules are untouched)"
}

case "${1:-}" in
  apply) shift; cmd_apply "$@" ;;
  confirm) cmd_confirm ;;
  status) cmd_status ;;
  remove) cmd_remove ;;
  _rollback) cmd_rollback "${2:-120}" ;;
  *) sed -n '2,22p' "${BASH_SOURCE[0]}"; exit 2 ;;
esac
