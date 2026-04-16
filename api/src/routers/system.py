"""Stats, System-Config und Threat-Level."""
from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends, HTTPException

from database import get_pool
from models import ConfigResponse, ConfigUpdate, ThreatLevelResponse

router = APIRouter(prefix="/api", tags=["system"])

_THREAT_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}
_THREAT_WINDOW_MIN = 15


@router.get("/stats/threat-level", response_model=ThreatLevelResponse)
async def get_threat_level(pool: asyncpg.Pool = Depends(get_pool)) -> ThreatLevelResponse:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT severity, COUNT(*) AS cnt
            FROM alerts
            WHERE ts > now() - INTERVAL '15 minutes'
              AND is_test = false
            GROUP BY severity
            """
        )

    counts = {r["severity"]: int(r["cnt"]) for r in rows}
    raw_score = sum(_THREAT_WEIGHTS.get(sev, 0) * cnt for sev, cnt in counts.items())

    # Normierung: 0–100 (cap bei 200 Rohpunkten → 100%)
    level = min(100, int(raw_score * 100 / 200))

    if level >= 75:
        label = "red"
    elif level >= 50:
        label = "orange"
    elif level >= 25:
        label = "yellow"
    else:
        label = "green"

    return ThreatLevelResponse(
        level=level,
        label=label,
        alert_counts=counts,
        window_min=_THREAT_WINDOW_MIN,
    )


@router.get("/config", response_model=list[ConfigResponse])
async def list_config(pool: asyncpg.Pool = Depends(get_pool)) -> list[ConfigResponse]:
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT key, value FROM system_config ORDER BY key")
    return [ConfigResponse(key=r["key"], value=dict(r["value"])) for r in rows]


@router.get("/config/{key}", response_model=ConfigResponse)
async def get_config(key: str, pool: asyncpg.Pool = Depends(get_pool)) -> ConfigResponse:
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT key, value FROM system_config WHERE key = $1", key)
    if not row:
        raise HTTPException(status_code=404, detail="Config key not found")
    return ConfigResponse(key=row["key"], value=dict(row["value"]))


@router.patch("/config/{key}", response_model=ConfigResponse)
async def update_config(
    key:  str,
    body: ConfigUpdate,
    pool: asyncpg.Pool = Depends(get_pool),
) -> ConfigResponse:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO system_config (key, value) VALUES ($1, $2)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            RETURNING key, value
            """,
            key, dict(body.value),
        )
    return ConfigResponse(key=row["key"], value=dict(row["value"]))
