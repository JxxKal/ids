"""Config-Store (system_config JSONB, ids-Muster) mit Secret-Masking."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from database import get_pool
from deps import require_admin
from secrets_mask import mask_secrets, merge_secrets

router = APIRouter(prefix="/api/config", tags=["config"])

KNOWN_KEYS = {"fmg", "itop", "dns", "sites", "tracker"}


class ConfigResponse(BaseModel):
    key: str
    value: dict


class ConfigUpdate(BaseModel):
    value: dict


@router.get("/{key}", response_model=ConfigResponse)
async def get_config(key: str, _admin: dict = Depends(require_admin)) -> ConfigResponse:
    if key not in KNOWN_KEYS:
        raise HTTPException(404, "Unbekannter Config-Key")
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT value FROM system_config WHERE key = $1", key)
    value = dict(row["value"]) if row else {}
    return ConfigResponse(key=key, value=mask_secrets(key, value))


@router.patch("/{key}", response_model=ConfigResponse)
async def update_config(
    key: str, body: ConfigUpdate, _admin: dict = Depends(require_admin)
) -> ConfigResponse:
    if key not in KNOWN_KEYS:
        raise HTTPException(404, "Unbekannter Config-Key")
    pool = get_pool()
    async with pool.acquire() as conn:
        stored = await conn.fetchrow("SELECT value FROM system_config WHERE key = $1", key)
        merged = merge_secrets(key, body.value, dict(stored["value"]) if stored else None)
        row = await conn.fetchrow(
            """
            INSERT INTO system_config (key, value) VALUES ($1, $2)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            RETURNING value
            """,
            key, merged,
        )
    return ConfigResponse(key=key, value=mask_secrets(key, dict(row["value"])))


async def read_config(key: str) -> dict:
    """Interner Helper für Services (unmaskiert)."""
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT value FROM system_config WHERE key = $1", key)
    return dict(row["value"]) if row else {}
