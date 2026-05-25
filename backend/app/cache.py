# backend/app/cache.py
"""
Simple TTL in-memory cache for expensive external API calls.
Avoids re-querying Shodan/VirusTotal/etc. for the same domain within the TTL window.
"""
import asyncio
import time
from typing import Any, Optional


class TTLCache:
    """Async-safe in-memory cache with per-entry TTL."""

    def __init__(self):
        self._store: dict = {}  # key -> (value, expires_at)
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                return None
            return value

    async def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        async with self._lock:
            self._store[key] = (value, time.monotonic() + ttl)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()

    def size(self) -> int:
        return len(self._store)


# Global singleton - import this in main.py and scanner.py
_cache = TTLCache()


async def cache_get(key: str) -> Optional[Any]:
    return await _cache.get(key)


async def cache_set(key: str, value: Any, ttl: int = 3600) -> None:
    await _cache.set(key, value, ttl)


async def cache_delete(key: str) -> None:
    await _cache.delete(key)


# TTL constants
TTL_SHORT  = 300    # 5 min  - VPN status, health checks
TTL_MEDIUM = 3600   # 1 hour - Shodan, VirusTotal, BGPView, threat intel
TTL_LONG   = 86400  # 24h   - WHOIS, cert data, passive DNS
