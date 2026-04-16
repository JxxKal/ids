"""
Redis-Cache für IP-Enrichment-Daten.

Key-Schema: enrichment:{ip}
Value: JSON-serialisiertes Enrichment-Dict
TTL: cache_ttl_s (Standard 3600s)

Bei Redis-Ausfall: stilles Fallback auf No-Cache (kein Crash).
"""
from __future__ import annotations

import logging

import orjson
import redis

log = logging.getLogger(__name__)


class EnrichmentCache:
    def __init__(self, redis_url: str, ttl_s: int) -> None:
        self._ttl = ttl_s
        try:
            self._redis = redis.from_url(redis_url, decode_responses=False, socket_timeout=2)
            self._redis.ping()
            log.info("Redis cache connected: %s", redis_url)
        except Exception as exc:
            log.warning("Redis unavailable: %s – running without cache", exc)
            self._redis = None  # type: ignore[assignment]

    def get(self, ip: str) -> dict | None:
        if self._redis is None:
            return None
        try:
            raw = self._redis.get(f"enrichment:{ip}")
            if raw:
                return orjson.loads(raw)
        except Exception as exc:
            log.debug("Cache get error for %s: %s", ip, exc)
        return None

    def set(self, ip: str, data: dict) -> None:
        if self._redis is None:
            return
        try:
            self._redis.setex(f"enrichment:{ip}", self._ttl, orjson.dumps(data))
        except Exception as exc:
            log.debug("Cache set error for %s: %s", ip, exc)
