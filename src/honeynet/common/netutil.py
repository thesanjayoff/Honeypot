"""IP helpers shared by honeypots, dashboard and exports."""

from __future__ import annotations

import ipaddress
from typing import Iterable

# Documentation ranges are never routable; real attackers don't use them, so the
# simulator uses them.  Exports skip them unless test mode is on.
TEST_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(value.strip())
    except (ValueError, AttributeError):
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def normalize_ip(value: str) -> str | None:
    ip = parse_ip(value)
    return str(ip) if ip else None


def is_test_net(ip: str) -> bool:
    a = parse_ip(ip)
    return bool(a) and any(a in n for n in TEST_NETS if a.version == n.version)


def is_public(ip: str, *, allow_test_nets: bool = False) -> bool:
    """True when the address could plausibly be a real remote attacker/C2."""
    a = parse_ip(ip)
    if a is None:
        return False
    if allow_test_nets and is_test_net(ip):
        return True
    return a.is_global and not a.is_multicast


def parse_networks(items: Iterable[str]) -> list:
    nets = []
    for raw in items:
        raw = raw.strip()
        if not raw:
            continue
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            continue
    return nets


def ip_in(ip: str, nets: list) -> bool:
    a = parse_ip(ip)
    if a is None:
        return False
    return any(a.version == n.version and a in n for n in nets)


_ALIAS_BLOCKS = ("203.0.113.", "198.51.100.", "192.0.2.")


def loopback_alias(ip: str) -> str:
    """Test mode only: loopback aliases ``127.77.x.y`` stand in for distinct remote attackers.

    Maps them onto the documentation ranges (RFC 5737) so a local simulator can look like hundreds of
    different sources while every packet stays on loopback.  Any other address is returned unchanged.
    """
    if not ip.startswith("127.77."):
        return ip
    a = parse_ip(ip)
    if a is None or a.version != 4:
        return ip
    n = ((a.packed[2] << 8) | a.packed[3]) % 762
    return f"{_ALIAS_BLOCKS[n // 254]}{n % 254 + 1}"
