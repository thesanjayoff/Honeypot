"""Which credentials 'work' on the fake login prompts.

Deterministic per (ip, user, password) so a bot that got in once gets in again,
and a fixed set of well-known weak defaults always succeeds - this keeps
automated attackers engaged long enough to show their hand.
"""

from __future__ import annotations

import hashlib

ALLOWED_USERS = {
    "root", "admin", "administrator", "user", "pi", "ubuntu", "test", "guest", "oracle", "postgres", "ftpuser",
    "support", "default", "vagrant", "git", "hadoop", "ubnt", "service", "debian", "operator", "supervisor",
    "tech", "mother", "cisco", "dev", "deploy", "ec2-user",
}

# Well-known factory / worm-dictionary passwords (public knowledge; all are junk on this box).
WEAK_PASSWORDS = {
    "root", "admin", "password", "123456", "12345", "1234", "12345678", "default", "pass", "toor", "raspberry",
    "ubnt", "test", "guest", "support", "changeme", "1111", "0000", "888888", "666666", "54321", "vizxv",
    "xc3511", "juantech", "klv123", "klv1234", "hi3518", "jvbzd", "zlxx.", "xmhdipc", "7ujMko0admin", "anko",
    "system", "service", "ikwb", "dreambox", "realtek", "00000000", "1111111", "ubuntu", "oracle", "qwerty",
    "letmein", "welcome", "admin123", "p@ssw0rd", "Zte521", "cat1029", "tlJwpbo6", "fucker", "meinsm",
}


def decide(ip: str, username: str, password: str, accept_pct: int = 12, *, iot: bool = False) -> bool:
    if not password or not username:
        return False
    u = username.lower()
    if u in ALLOWED_USERS and password in WEAK_PASSWORDS:
        return True
    h = hashlib.sha256(f"honeynet|{ip}|{username}|{password}".encode("utf-8", "surrogateescape")).digest()
    roll = int.from_bytes(h[:4], "big") % 100
    pct = accept_pct * (2 if iot else 1)
    return u in ALLOWED_USERS and roll < pct
