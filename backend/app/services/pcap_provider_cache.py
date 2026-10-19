"""Bounded passive-query cache; dated exact-target answers, never transferred verdicts.

Redis shares quota cooldowns across workers. A bounded process-local fallback
keeps analysis usable if Redis is unavailable; that weaker scope is disclosed.
No sample bytes, full URLs, or API keys are stored here.
"""
from __future__ import annotations

import hashlib
import asyncio
import json
import time
from collections import OrderedDict

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.config import settings


class ProviderCache:
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.local: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self.redis_retry_at = 0.0

    async def get(self, key: str) -> tuple[dict | None, str]:
        if self.redis_url and time.monotonic() >= self.redis_retry_at:
            try:
                async with asyncio.timeout(0.5):
                    async with Redis.from_url(self.redis_url, socket_connect_timeout=0.3, socket_timeout=0.3) as client:
                        value = await client.get(key)
                if value:
                    return json.loads(value), "shared-redis"
            except (OSError, ValueError, RedisError, TimeoutError):
                self.redis_retry_at = time.monotonic() + 30
        entry = self.local.get(key)
        if entry and entry[0] > time.time():
            self.local.move_to_end(key)
            return json.loads(json.dumps(entry[1])), "process-local"
        self.local.pop(key, None)
        return None, "process-local"

    async def put(self, key: str, value: dict, ttl: int) -> None:
        encoded = json.dumps(value, separators=(",", ":"))
        if len(encoded) > 256_000:
            return
        self.local[key] = (time.time() + ttl, json.loads(encoded))
        self.local.move_to_end(key)
        while len(self.local) > 1024:
            self.local.popitem(last=False)
        if self.redis_url and time.monotonic() >= self.redis_retry_at:
            try:
                async with asyncio.timeout(0.5):
                    async with Redis.from_url(self.redis_url, socket_connect_timeout=0.3, socket_timeout=0.3) as client:
                        await client.set(key, encoded, ex=ttl)
            except (OSError, RedisError, TimeoutError):
                self.redis_retry_at = time.monotonic() + 30


def provider_scope(provider: str) -> str:
    # Rotating credentials invalidates the old cache and old quota window.
    credentials = {name: str(value) for name, value in settings.model_dump().items()
                   if (provider in name or (provider == "malwarebazaar" and "threatfox" in name))
                   and any(part in name for part in ("key", "token", "secret", "username"))}
    digest = hashlib.sha256(json.dumps(credentials, sort_keys=True).encode()).hexdigest()
    return f"pcap:provider:v2:{provider}:{digest}"


cache = ProviderCache(settings.redis_url)
