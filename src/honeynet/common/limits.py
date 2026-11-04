"""Connection / rate limiting primitives used by every honeypot service."""

from __future__ import annotations

import time
from collections import defaultdict


class ConnectionLimiter:
    """Global and per-source concurrent connection caps."""

    def __init__(self, max_total: int, max_per_ip: int) -> None:
        self.max_total = max_total
        self.max_per_ip = max_per_ip
        self.total = 0
        self.per_ip: dict[str, int] = defaultdict(int)

    def acquire(self, ip: str) -> bool:
        if self.total >= self.max_total or self.per_ip[ip] >= self.max_per_ip:
            return False
        self.total += 1
        self.per_ip[ip] += 1
        return True

    def release(self, ip: str) -> None:
        self.total = max(0, self.total - 1)
        n = self.per_ip.get(ip, 0) - 1
        if n <= 0:
            self.per_ip.pop(ip, None)
        else:
            self.per_ip[ip] = n


class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = rate_per_sec
        self.burst = burst
        self.tokens = float(burst)
        self.stamp = time.monotonic()

    def allow(self, n: float = 1.0) -> bool:
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.stamp) * self.rate)
        self.stamp = now
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


class SlidingCounter:
    """Counts events per key in a sliding window (used for per-IP fetch quotas)."""

    def __init__(self, window: float) -> None:
        self.window = window
        self.hits: dict[str, list[float]] = defaultdict(list)

    def hit(self, key: str, limit: int) -> bool:
        now = time.monotonic()
        arr = [t for t in self.hits[key] if now - t < self.window]
        if len(arr) >= limit:
            self.hits[key] = arr
            return False
        arr.append(now)
        self.hits[key] = arr
        if len(self.hits) > 50000:
            self.hits.clear()
        return True
