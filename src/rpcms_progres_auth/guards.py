from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    """Sliding one-minute window per key (officer). In-process: use a shared store for >1 replica."""

    def __init__(self, per_minute: int, clock=time.monotonic):
        self._limit = per_minute
        self._clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> float | None:
        """Return None if allowed, else seconds until the caller may retry."""
        now = self._clock()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] >= 60:
                q.popleft()
            if len(q) >= self._limit:
                return max(1.0, 60 - (now - q[0]))
            q.append(now)
            return None


class IdempotencyStore:
    """Remembers *results* (never biometrics) so a retried request cannot trigger a second
    ProGres call. The fingerprint excludes the biometric, so a key reused for a different
    person is caught without storing any biometric-derived value."""

    def __init__(self, ttl_seconds: int, clock=time.monotonic):
        self._ttl = ttl_seconds
        self._clock = clock
        self._items: dict[tuple[str, str], tuple[float, str, dict]] = {}
        self._lock = threading.Lock()

    def get(self, officer: str, key: str):
        with self._lock:
            self._purge()
            item = self._items.get((officer, key))
            return None if item is None else (item[1], item[2])

    def put(self, officer: str, key: str, fingerprint: str, response: dict) -> None:
        with self._lock:
            self._purge()
            self._items[(officer, key)] = (self._clock() + self._ttl, fingerprint, response)

    def _purge(self) -> None:
        now = self._clock()
        for k in [k for k, v in self._items.items() if v[0] <= now]:
            del self._items[k]
