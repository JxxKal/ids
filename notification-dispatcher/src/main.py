"""notification-dispatcher — Kafka-Consumer + Plugin-Dispatcher.

Liest enriched-Alerts aus Kafka 'alerts-enriched-push', filtert pro Channel
(severity / rule_prefix / source), throttled, und ruft den passenden Handler.
Result landet in notification_deliveries.

Architektur bewusst plugin-basiert (siehe handlers.py): Phase 2 (Cyjan-Cloud-
Companion-App) registriert nur einen neuen Handler unter type='cyjan-cloud',
bestehende Logik bleibt unverändert.

Channel-Cache wird alle CACHE_TTL_S aus der DB refresht — pro Kafka-Message
keinen Round-trip zur DB.
"""
from __future__ import annotations

import asyncio
import logging
import signal
import time
from dataclasses import dataclass
from typing import Any

import asyncpg
import httpx
import orjson
from confluent_kafka import Consumer, KafkaError, KafkaException

from config import Config
from handlers import DeliveryResult, DispatcherContext, dispatch_to, known_types

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("notification-dispatcher")


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Channel:
    id:                   str
    user_id:              str | None
    name:                 str
    type:                 str
    config:               dict
    enabled:              bool
    severity_min:         str
    rule_prefix_filter:   str | None
    source_filter:        list[str] | None
    throttle_seconds:     int

    def passes(self, alert: dict) -> tuple[bool, str | None]:
        """True wenn alert durch alle Filter passt.

        Returns (passed, filter_reason_when_blocked)."""
        if not self.enabled:
            return False, "disabled"

        sev = alert.get("severity", "low")
        if SEVERITY_RANK.get(sev, 0) < SEVERITY_RANK.get(self.severity_min, 3):
            return False, f"severity {sev} < min {self.severity_min}"

        if self.rule_prefix_filter:
            rule = alert.get("rule_id", "")
            if not rule.startswith(self.rule_prefix_filter):
                return False, f"rule {rule!r} not prefix {self.rule_prefix_filter!r}"

        if self.source_filter:
            src = alert.get("source")
            if src not in self.source_filter:
                return False, f"source {src!r} not in {self.source_filter}"

        return True, None


class ChannelCache:
    """In-Memory-Cache. Refresh alle ttl Sekunden."""

    def __init__(self, ttl_s: float) -> None:
        self._ttl_s     = ttl_s
        self._items:    list[Channel] = []
        self._loaded_at: float = 0
        # Throttle-State: pro channel_id der ts der letzten erfolgreichen
        # Delivery — vermeidet Spam bei flood-Alerts.
        self._last_sent: dict[str, float] = {}

    def stale(self) -> bool:
        return (time.monotonic() - self._loaded_at) > self._ttl_s

    async def refresh(self, pool: asyncpg.Pool) -> None:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id::text AS id, user_id::text AS user_id, name, type, config,
                       enabled, severity_min, rule_prefix_filter, source_filter,
                       throttle_seconds
                FROM notification_channels
                WHERE enabled = true
                """
            )
        self._items = [Channel(**dict(r)) for r in rows]
        self._loaded_at = time.monotonic()
        log.info("Channel-Cache refresht: %d aktive Channels", len(self._items))

    def all(self) -> list[Channel]:
        return self._items

    def throttle_ok(self, channel_id: str, throttle_s: int) -> bool:
        """True wenn seit der letzten erfolgreichen Delivery genug Zeit
        vergangen ist."""
        if throttle_s <= 0:
            return True
        last = self._last_sent.get(channel_id, 0)
        return (time.monotonic() - last) >= throttle_s

    def mark_sent(self, channel_id: str) -> None:
        self._last_sent[channel_id] = time.monotonic()


# ────────────────────────────────────────────────────────────────────────

async def log_delivery(
    pool: asyncpg.Pool, channel_id: str, alert: dict, result: DeliveryResult,
) -> None:
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO notification_deliveries
                    (channel_id, alert_id, rule_id, severity, status,
                     status_code, latency_ms, error)
                VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8)
                """,
                channel_id,
                alert.get("alert_id"),
                alert.get("rule_id"),
                alert.get("severity"),
                result.status,
                result.status_code,
                result.latency_ms,
                result.error,
            )
    except Exception as exc:
        log.warning("notification_deliveries INSERT failed: %s", exc)


async def update_last_used(pool: asyncpg.Pool, channel_id: str) -> None:
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE notification_channels SET last_used = now() WHERE id = $1::uuid",
                channel_id,
            )
    except Exception:
        pass


# ────────────────────────────────────────────────────────────────────────

def make_consumer(brokers: str, group_id: str) -> Consumer:
    return Consumer({
        "bootstrap.servers":  brokers,
        "group.id":           group_id,
        "auto.offset.reset":  "latest",   # nur neue Alerts pushen, nicht backfill
        "enable.auto.commit": True,
    })


async def handle_alert(
    alert: dict, cache: ChannelCache, pool: asyncpg.Pool, ctx: DispatcherContext,
) -> None:
    channels = cache.all()
    if not channels:
        return

    # Test-Alert (API test-endpoint setzt diese Flag): nur an den genannten
    # Channel routen, ALLE Filter umgehen (severity, source, throttle).
    test_for = alert.get("test_for_channel")
    if test_for:
        target = next((c for c in channels if c.id == test_for), None)
        if not target:
            # Channel wurde inzwischen deaktiviert oder gelöscht — Cache lädt
            # nur enabled=true. Refresh erzwingen + nochmal probieren.
            await cache.refresh(pool)
            target = next((c for c in cache.all() if c.id == test_for), None)
        if target:
            log.info("Test-Push → channel %s (%s)", target.name, target.type)
            await _send_and_log(target, alert, cache, pool, ctx)
        else:
            log.warning("Test-Push für unbekannten/disabled channel %s", test_for)
        return

    tasks = []
    for ch in channels:
        passed, reason = ch.passes(alert)
        if not passed:
            await log_delivery(pool, ch.id, alert,
                               DeliveryResult(status="filtered", error=reason))
            continue
        if not cache.throttle_ok(ch.id, ch.throttle_seconds):
            await log_delivery(pool, ch.id, alert,
                               DeliveryResult(status="rate_limited",
                                              error=f"throttle {ch.throttle_seconds}s"))
            continue
        tasks.append(_send_and_log(ch, alert, cache, pool, ctx))

    if tasks:
        # Concurrent dispatch — slow Webhook blockt nicht email
        await asyncio.gather(*tasks, return_exceptions=True)


async def _send_and_log(
    ch: Channel, alert: dict, cache: ChannelCache, pool: asyncpg.Pool,
    ctx: DispatcherContext,
) -> None:
    result = await dispatch_to(ch.type, alert, ch.config, ctx)
    await log_delivery(pool, ch.id, alert, result)
    if result.status == "sent":
        cache.mark_sent(ch.id)
        await update_last_used(pool, ch.id)
    elif result.status == "failed":
        log.warning("send to channel %s (%s) failed: %s",
                    ch.name, ch.type, result.error)


# ────────────────────────────────────────────────────────────────────────

async def run(cfg: Config) -> None:
    log.info("Starte notification-dispatcher (input=%s, types=%s)",
             cfg.input_topic, ",".join(known_types()))

    pool = await asyncpg.create_pool(
        cfg.postgres_dsn.replace("postgres://", "postgresql://"),
        min_size=1, max_size=3,
        init=_init_jsonb_codec,
    )
    cache = ChannelCache(ttl_s=cfg.cache_ttl_s)
    await cache.refresh(pool)

    http_client = httpx.AsyncClient(timeout=10.0)
    ctx = DispatcherContext(
        http_client=http_client,
        smtp_host=cfg.smtp_host, smtp_port=cfg.smtp_port,
        smtp_user=cfg.smtp_user, smtp_password=cfg.smtp_password,
        smtp_from=cfg.smtp_from, smtp_use_tls=cfg.smtp_use_tls,
    )

    consumer = make_consumer(cfg.kafka_brokers, cfg.group_id)
    consumer.subscribe([cfg.input_topic])

    stop_event = asyncio.Event()
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_event.set)

    try:
        while not stop_event.is_set():
            if cache.stale():
                await cache.refresh(pool)

            msg = consumer.poll(cfg.poll_timeout_s)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                log.warning("Kafka-Error: %s", msg.error())
                continue
            try:
                alert = orjson.loads(msg.value())
            except Exception:
                log.warning("nicht-parsbarer Alert ignored")
                continue
            await handle_alert(alert, cache, pool, ctx)
    finally:
        log.info("Shutdown — schließe Kafka-Consumer + DB-Pool")
        consumer.close()
        await http_client.aclose()
        await pool.close()


async def _init_jsonb_codec(conn: asyncpg.Connection) -> None:
    import json
    for pg_type in ("json", "jsonb"):
        await conn.set_type_codec(
            pg_type, encoder=json.dumps, decoder=json.loads, schema="pg_catalog",
        )


if __name__ == "__main__":
    asyncio.run(run(Config.from_env()))
