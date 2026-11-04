"""Dashboard authentication: one operator password, signed expiring cookie, login throttling.

No accounts, no registration, no multi-user model.  The password is supplied as a PBKDF2 hash
(``honeynet hash-password``) - a plain ``HONEYNET_DASHBOARD_PASSWORD`` also works but is discouraged.
Outside test mode the dashboard refuses to start without one of them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import threading
import time
from pathlib import Path

from ..common.config import Settings

PBKDF2_ITERATIONS = 400_000
COOKIE_NAME = "hn_session"


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt_hex, hash_hex = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        n = int(iters)
        if not (1000 <= n <= 5_000_000):
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), n)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class Authenticator:
    def __init__(self, s: Settings) -> None:
        self.s = s
        self.configured = bool(s.dashboard_password or s.dashboard_password_hash)
        self.required = self.configured or not s.test_mode
        self._secret = self._load_secret()
        self._revoked: set[str] = set()
        self._fails: dict[str, list[float]] = {}
        self._locked: dict[str, float] = {}
        self._global: list[float] = []
        self._lock = threading.Lock()

    def _load_secret(self) -> bytes:
        if self.s.dashboard_secret:
            return hashlib.sha256(b"honeynet-cookie|" + self.s.dashboard_secret.encode()).digest()
        path = self.s.keys_dir / "dashboard_cookie.key"
        try:
            return path.read_bytes()
        except OSError:
            pass
        key = secrets.token_bytes(32)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
        except OSError:
            pass
        return key

    # ---- password ----
    def check_password(self, password: str) -> bool:
        if self.s.dashboard_password_hash:
            return verify_password(password, self.s.dashboard_password_hash)
        if self.s.dashboard_password:
            return hmac.compare_digest(hashlib.sha256(password.encode()).digest(), hashlib.sha256(self.s.dashboard_password.encode()).digest())
        return False

    def login(self, client: str, password: str) -> tuple[bool, int]:
        """-> (ok, retry_after_seconds).  Throttled per client and globally."""
        now = time.time()
        with self._lock:
            if self._locked.get(client, 0) > now:
                return False, int(self._locked[client] - now) + 1
            self._global = [t for t in self._global if now - t < 60]
            if len(self._global) >= 30:
                return False, 30
            self._global.append(now)
        ok = self.check_password(password[:256])
        with self._lock:
            if ok:
                self._fails.pop(client, None)
                return True, 0
            fl = [t for t in self._fails.get(client, []) if now - t < 900] + [now]
            self._fails[client] = fl
            if len(fl) >= 5:
                self._locked[client] = now + min(3600, 30 * 2 ** (len(fl) - 5))
                return False, int(self._locked[client] - now)
        time.sleep(0.4)                                     # slow down online guessing a little
        return False, 0

    # ---- cookie ----
    def make_cookie(self) -> str:
        exp = int(time.time() + self.s.dashboard_session_hours * 3600)
        nonce = secrets.token_hex(8)
        payload = f"{exp}.{nonce}"
        return f"{payload}.{_b64(hmac.new(self._secret, payload.encode(), hashlib.sha256).digest())}"

    def verify_cookie(self, value: str | None) -> bool:
        if not value or len(value) > 200:
            return False
        try:
            exp_s, nonce, sig = value.split(".")
            payload = f"{exp_s}.{nonce}"
            good = _b64(hmac.new(self._secret, payload.encode(), hashlib.sha256).digest())
            return hmac.compare_digest(sig, good) and int(exp_s) > time.time() and nonce not in self._revoked
        except (ValueError, TypeError):
            return False

    def revoke(self, value: str | None) -> None:
        if value and value.count(".") == 2:
            self._revoked.add(value.split(".")[1])
            if len(self._revoked) > 1000:
                self._revoked.clear()

    def is_authed(self, cookie: str | None) -> bool:
        return (not self.required) or self.verify_cookie(cookie)


def cookie_path(s: Settings) -> Path:
    return s.keys_dir / "dashboard_cookie.key"
