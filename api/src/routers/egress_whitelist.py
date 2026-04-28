"""
Egress-Whitelist – CRUD für audit-fähige Whitelist-Einträge legitimer
Egress-Flows.

Mindestens src_ip muss gesetzt sein. dst kann konkret (dst_ip), per CIDR
(dst_net) oder offen (alle) gewählt werden – exklusiv. Soft-Delete via
active=false; nichts wird gelöscht.

Match-Logik (vom AlertFeed-JOIN in routers/alerts.py wiederverwendet):
  active=true UND
  (expires_at IS NULL OR > now()) UND
  src_ip = alert.src_ip UND
  ((dst_ip IS NULL AND dst_net IS NULL) OR
   (dst_ip = alert.dst_ip) OR
   (alert.dst_ip <<= dst_net)) UND
  (dst_port IS NULL OR dst_port = alert.dst_port) UND
  (proto    IS NULL OR proto    = alert.proto)
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from database import get_pool
from deps import require_admin, get_current_user

router = APIRouter(prefix="/api/egress-whitelist", tags=["egress-whitelist"])


# ── Schemas ────────────────────────────────────────────────────────────────


class EgressWhitelistEntry(BaseModel):
    id:             UUID
    src_ip:         str
    dst_ip:         str | None = None
    dst_net:        str | None = None
    dst_port:       int | None = None
    proto:          str | None = None
    reason:         str
    created_by:     str | None = None
    created_at:     datetime
    expires_at:     datetime | None = None
    active:         bool
    deactivated_at: datetime | None = None


class EgressWhitelistCreate(BaseModel):
    src_ip:     str = Field(..., description="Quell-IP, Pflicht.")
    dst_ip:     str | None = None
    dst_net:    str | None = None
    dst_port:   int | None = Field(None, ge=0, le=65535)
    proto:      Literal["TCP", "UDP", "ICMP", "tcp", "udp", "icmp"] | None = None
    reason:     str = Field(..., min_length=3, description="Pflichtbegründung.")
    expires_at: datetime | None = None


# ── Endpoints ──────────────────────────────────────────────────────────────


@router.get(
    "",
    response_model=list[EgressWhitelistEntry],
    dependencies=[Depends(require_admin)],
    summary="Liste aller Whitelist-Einträge inkl. deaktivierter (für Audit).",
)
async def list_entries(
    include_inactive: bool = False,
    pool: asyncpg.Pool = Depends(get_pool),
) -> list[EgressWhitelistEntry]:
    where = "" if include_inactive else "WHERE active = true"
    async with pool.acquire() as conn:
        rows = await conn.fetch(f"""
            SELECT id, src_ip, dst_ip, dst_net, dst_port, proto,
                   reason, created_by, created_at, expires_at, active,
                   deactivated_at
            FROM egress_whitelist
            {where}
            ORDER BY active DESC, created_at DESC
        """)
    return [_row_to_entry(r) for r in rows]


@router.post(
    "",
    response_model=EgressWhitelistEntry,
    dependencies=[Depends(require_admin)],
    status_code=201,
    summary="Whitelist-Eintrag anlegen. dst_ip + dst_net sind exklusiv.",
)
async def create_entry(
    body: EgressWhitelistCreate,
    user: dict = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> EgressWhitelistEntry:
    if body.dst_ip and body.dst_net:
        raise HTTPException(400, "dst_ip und dst_net sind exklusiv – nur eines setzen.")

    proto = body.proto.upper() if body.proto else None
    async with pool.acquire() as conn:
        try:
            row = await conn.fetchrow("""
                INSERT INTO egress_whitelist
                  (src_ip, dst_ip, dst_net, dst_port, proto,
                   reason, created_by, expires_at, active)
                VALUES
                  ($1::inet, $2::inet, $3::cidr, $4, $5,
                   $6, $7, $8, true)
                RETURNING id, src_ip, dst_ip, dst_net, dst_port, proto,
                          reason, created_by, created_at, expires_at, active,
                          deactivated_at
            """,
                body.src_ip,
                body.dst_ip,
                body.dst_net,
                body.dst_port,
                proto,
                body.reason,
                user.get("username"),
                body.expires_at,
            )
        except (asyncpg.exceptions.InvalidTextRepresentationError,
                asyncpg.exceptions.CheckViolationError) as exc:
            raise HTTPException(400, f"Ungültige Eingabe: {exc}") from exc
    if row is None:
        raise HTTPException(500, "Insert lieferte keine Zeile zurück.")
    return _row_to_entry(row)


@router.patch(
    "/{entry_id}/deactivate",
    response_model=EgressWhitelistEntry,
    dependencies=[Depends(require_admin)],
    summary="Soft-Delete: Eintrag deaktivieren (history bleibt erhalten).",
)
async def deactivate_entry(
    entry_id: UUID,
    pool:     asyncpg.Pool = Depends(get_pool),
) -> EgressWhitelistEntry:
    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            UPDATE egress_whitelist
            SET active = false, deactivated_at = now()
            WHERE id = $1 AND active = true
            RETURNING id, src_ip, dst_ip, dst_net, dst_port, proto,
                      reason, created_by, created_at, expires_at, active,
                      deactivated_at
        """, entry_id)
    if row is None:
        raise HTTPException(404, "Whitelist-Eintrag nicht gefunden oder bereits inaktiv.")
    return _row_to_entry(row)


# ── Helpers ────────────────────────────────────────────────────────────────


def _row_to_entry(row: asyncpg.Record) -> EgressWhitelistEntry:
    return EgressWhitelistEntry(
        id=row["id"],
        src_ip=str(row["src_ip"]),
        dst_ip=str(row["dst_ip"]) if row["dst_ip"] else None,
        dst_net=str(row["dst_net"]) if row["dst_net"] else None,
        dst_port=row["dst_port"],
        proto=row["proto"],
        reason=row["reason"],
        created_by=row["created_by"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        active=row["active"],
        deactivated_at=row["deactivated_at"],
    )
