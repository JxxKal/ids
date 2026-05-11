"""api/src/routers/notifications.py — Notification-Channels CRUD + Test.

Endpoints (alle require_admin):
  GET    /api/notifications/channels         — Liste
  POST   /api/notifications/channels         — neuer Channel
  PATCH  /api/notifications/channels/{id}    — update
  DELETE /api/notifications/channels/{id}    — delete
  POST   /api/notifications/channels/{id}/test  — Test-Push mit synthetic alert
  GET    /api/notifications/deliveries        — Audit-Log (für Debug-View)
  GET    /api/notifications/types             — Liste der unterstützten Channel-Types

Channel-Types in V1: webhook / ntfy / email.
Config-Validation pro Type erfolgt soft — der Dispatcher selbst gibt
spezifische Fehler zurück wenn ein Pflichtfeld fehlt.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import asyncpg
import orjson
from confluent_kafka import Producer
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from database import get_pool
from deps import require_admin

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


# Producer wird von main.py via set_producer() gesetzt — gleiches Pattern
# wie in alerts.py (_feedback_producer).
_producer: Producer | None = None


def set_producer(producer: Producer) -> None:
    global _producer
    _producer = producer


# ──── Constants ──────────────────────────────────────────────────────────
# Bewusst nicht aus dispatcher-Code importiert — API darf nicht von
# notification-dispatcher abhängig sein (separater Service). Wenn Phase 2
# einen neuen Type hinzufügt, hier ergänzen.
SUPPORTED_TYPES = {"webhook", "ntfy", "email"}
SEVERITY_LEVELS = {"low", "medium", "high", "critical"}


# ──── Models ─────────────────────────────────────────────────────────────

class ChannelBase(BaseModel):
    name:               str = Field(min_length=1, max_length=80)
    type:               str = Field(pattern=r"^[a-z][a-z0-9_-]{2,32}$")
    config:             dict[str, Any] = Field(default_factory=dict)
    enabled:            bool = True
    severity_min:       str = Field(default="high")
    rule_prefix_filter: str | None = Field(default=None, max_length=128)
    source_filter:      list[str] | None = None
    throttle_seconds:   int = Field(default=30, ge=0, le=3600)


class ChannelCreate(ChannelBase):
    pass


class ChannelUpdate(BaseModel):
    name:               str | None = None
    config:             dict[str, Any] | None = None
    enabled:            bool | None = None
    severity_min:       str | None = None
    rule_prefix_filter: str | None = None
    source_filter:      list[str] | None = None
    throttle_seconds:   int | None = Field(default=None, ge=0, le=3600)


class ChannelOut(ChannelBase):
    id:         UUID
    user_id:    UUID | None = None
    created_at: datetime
    updated_at: datetime
    last_used:  datetime | None = None


class DeliveryOut(BaseModel):
    id:          int
    ts:          datetime
    channel_id:  UUID
    alert_id:    UUID | None
    rule_id:     str | None
    severity:    str | None
    status:      str
    status_code: int | None
    latency_ms:  int | None
    error:       str | None


# ──── Validation ─────────────────────────────────────────────────────────

def _validate_type(t: str) -> None:
    if t not in SUPPORTED_TYPES:
        raise HTTPException(400,
            f"Unknown channel type {t!r}. Supported: {sorted(SUPPORTED_TYPES)}")


def _validate_severity(s: str) -> None:
    if s not in SEVERITY_LEVELS:
        raise HTTPException(400,
            f"Invalid severity_min {s!r}. Allowed: {sorted(SEVERITY_LEVELS)}")


def _validate_config_for_type(type_: str, config: dict) -> None:
    """Light validation — Dispatcher hat die echte Validation, hier nur
    UX-helper damit der Save-Click direkt aussagekräftige Fehler bringt."""
    if type_ == "webhook":
        if not config.get("url"):
            raise HTTPException(400, "Webhook config requires 'url'")
    elif type_ == "ntfy":
        if not config.get("topic"):
            raise HTTPException(400, "ntfy config requires 'topic'")
    elif type_ == "email":
        if not config.get("to"):
            raise HTTPException(400, "Email config requires 'to'")


# ──── Endpoints ──────────────────────────────────────────────────────────

@router.get("/types", dependencies=[Depends(require_admin)])
async def list_supported_types() -> dict[str, list[str]]:
    """Aktuelle Channel-Types die das Backend kennt. Frontend rendert je
    nach Typ ein anderes Form-Layout."""
    return {
        "types":            sorted(SUPPORTED_TYPES),
        "severity_levels":  ["low", "medium", "high", "critical"],
        "source_options":   ["signature", "ml", "suricata", "external"],
    }


@router.get("/channels",
            response_model=list[ChannelOut],
            dependencies=[Depends(require_admin)])
async def list_channels(pool: asyncpg.Pool = Depends(get_pool)) -> list[ChannelOut]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, user_id, name, type, config, enabled, severity_min,
                   rule_prefix_filter, source_filter, throttle_seconds,
                   created_at, updated_at, last_used
            FROM notification_channels
            ORDER BY name
            """
        )
    return [ChannelOut(**dict(r)) for r in rows]


@router.post("/channels",
             response_model=ChannelOut,
             dependencies=[Depends(require_admin)])
async def create_channel(
    body: ChannelCreate,
    pool: asyncpg.Pool = Depends(get_pool),
) -> ChannelOut:
    _validate_type(body.type)
    _validate_severity(body.severity_min)
    _validate_config_for_type(body.type, body.config)

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO notification_channels
                (name, type, config, enabled, severity_min, rule_prefix_filter,
                 source_filter, throttle_seconds)
            VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8)
            RETURNING id, user_id, name, type, config, enabled, severity_min,
                      rule_prefix_filter, source_filter, throttle_seconds,
                      created_at, updated_at, last_used
            """,
            body.name, body.type, body.config, body.enabled, body.severity_min,
            body.rule_prefix_filter, body.source_filter, body.throttle_seconds,
        )
    return ChannelOut(**dict(row))


@router.patch("/channels/{channel_id}",
              response_model=ChannelOut,
              dependencies=[Depends(require_admin)])
async def update_channel(
    channel_id: UUID,
    body:       ChannelUpdate,
    pool:       asyncpg.Pool = Depends(get_pool),
) -> ChannelOut:
    fields = body.model_dump(exclude_none=True)
    if body.severity_min is not None:
        _validate_severity(body.severity_min)
    if not fields:
        raise HTTPException(400, "No fields to update")

    # Build SET-Clause dynamisch
    set_parts: list[str] = []
    args: list[Any] = []
    for i, (key, val) in enumerate(fields.items(), start=2):
        if key == "config":
            set_parts.append(f"{key} = ${i}::jsonb")
        else:
            set_parts.append(f"{key} = ${i}")
        args.append(val)
    set_clause = ", ".join(set_parts)

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"""
            UPDATE notification_channels SET {set_clause}
            WHERE id = $1
            RETURNING id, user_id, name, type, config, enabled, severity_min,
                      rule_prefix_filter, source_filter, throttle_seconds,
                      created_at, updated_at, last_used
            """,
            channel_id, *args,
        )
    if not row:
        raise HTTPException(404, "Channel not found")
    return ChannelOut(**dict(row))


@router.delete("/channels/{channel_id}",
               status_code=204,
               dependencies=[Depends(require_admin)])
async def delete_channel(
    channel_id: UUID,
    pool:       asyncpg.Pool = Depends(get_pool),
) -> None:
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM notification_channels WHERE id = $1",
            channel_id,
        )
    if result.endswith("0"):
        raise HTTPException(404, "Channel not found")


@router.post("/channels/{channel_id}/test", dependencies=[Depends(require_admin)])
async def test_channel(
    channel_id: UUID,
    pool:       asyncpg.Pool = Depends(get_pool),
) -> dict:
    """Sendet einen synthetischen Test-Alert über Kafka 'alerts-enriched-push'
    mit einer speziellen `test_for_channel`-Markierung. Der notification-
    dispatcher erkennt diese Flag und routed NUR an den genannten Channel
    (ignoriert sonst alle Filter)."""
    async with pool.acquire() as conn:
        ch = await conn.fetchrow(
            "SELECT id, name, type FROM notification_channels WHERE id = $1",
            channel_id,
        )
    if not ch:
        raise HTTPException(404, "Channel not found")

    test_alert = {
        "alert_id":     str(uuid.uuid4()),
        "ts":           datetime.now(timezone.utc).isoformat(),
        "rule_id":      "CYJAN_TEST_NOTIFICATION",
        "severity":     "critical",   # ignoriert Filter aber wir setzen critical fürs Demo
        "source":       "test",
        "src_ip":       "203.0.113.42",
        "dst_ip":       "203.0.113.99",
        "src_port":     54321,
        "dst_port":     443,
        "proto":        "TCP",
        "description":  f"Test-Notification für Channel '{ch['name']}' "
                        f"({ch['type']}) — wenn du das auf deinem Gerät siehst, "
                        f"funktioniert die Zustellung.",
        "tags":         ["test", "cyjan-notification"],
        "test_for_channel": str(channel_id),   # Marker für dispatcher
    }

    # Publish auf Kafka — dispatcher konsumiert + erkennt test_for_channel
    if _producer is None:
        raise HTTPException(500, "Kafka producer not initialized — check api startup")
    try:
        _producer.produce("alerts-enriched-push", value=orjson.dumps(test_alert))
        _producer.poll(0)
    except Exception as exc:
        raise HTTPException(500, f"Kafka publish failed: {exc!s}")

    return {
        "ok":          True,
        "channel_id":  str(channel_id),
        "channel":     ch["name"],
        "test_alert":  test_alert,
        "note":        "Test-Alert wurde nach Kafka geschickt. Der notification-"
                       "dispatcher routed das in ~1s an deinen Channel. Prüfe das "
                       "Delivery-Log unter /api/notifications/deliveries für das "
                       "Ergebnis.",
    }


@router.get("/deliveries",
            response_model=list[DeliveryOut],
            dependencies=[Depends(require_admin)])
async def list_deliveries(
    channel_id: UUID | None = None,
    limit:      int = 100,
    pool:       asyncpg.Pool = Depends(get_pool),
) -> list[DeliveryOut]:
    limit = max(1, min(500, limit))
    where_clauses: list[str] = []
    args: list[Any] = []
    if channel_id is not None:
        where_clauses.append(f"channel_id = ${len(args)+1}")
        args.append(channel_id)
    where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    args.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT id, ts, channel_id, alert_id, rule_id, severity, status,
                   status_code, latency_ms, error
            FROM notification_deliveries
            {where}
            ORDER BY ts DESC
            LIMIT ${len(args)}
            """,
            *args,
        )
    return [DeliveryOut(**dict(r)) for r in rows]
