"""Trace-API: Pfad-Trace ausführen + Verlauf."""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from database import get_pool
from deps import get_current_user
from engine.path import TraceError, run_trace
from engine.verdict import Endpoint, TraceResult, aggregate_verdict
from fmg.client import FmgError
from fmg.factory import build_fmg_client
from resolver.chain import is_ipv6
from routers.config import read_config
from suggest.builder import build_suggestion

router = APIRouter(prefix="/api", tags=["trace"])


class TraceRequest(BaseModel):
    src: str = Field(min_length=1, max_length=255)
    dst: str = Field(min_length=1, max_length=255)
    protocol: str = Field(pattern="^(?i)(tcp|udp|icmp)$")
    dst_port: int | None = Field(default=None, ge=1, le=65535)
    src_port: int | None = Field(default=None, ge=1, le=65535)
    icmp_type: int | None = Field(default=None, ge=0, le=255)
    icmp_code: int | None = Field(default=None, ge=0, le=255)


@router.post("/trace", response_model=TraceResult)
async def trace(body: TraceRequest, request: Request,
                user: dict = Depends(get_current_user)) -> TraceResult:
    state = request.app.state
    started = time.monotonic()

    for value in (body.src, body.dst):
        if is_ipv6(value):
            raise HTTPException(400, "IPv6 wird in V1 nicht unterstützt.")
    proto = body.protocol.lower()
    if proto in ("tcp", "udp") and body.dst_port is None:
        raise HTTPException(400, f"Für {proto.upper()} ist ein Ziel-Port erforderlich.")

    itop_cfg = await read_config("itop")
    dns_cfg = await read_config("dns")
    tracker_cfg = await read_config("tracker")
    fmg_cfg = await read_config("fmg")

    inv = state.inventory
    prefixes = state.prefixes
    if not inv.devices:
        raise HTTPException(409, "Kein FMG-Inventar vorhanden — zuerst Sync ausführen.")

    try:
        src_ep = await state.resolver.resolve_endpoint(body.src, inv, itop_cfg, dns_cfg)
        dst_ep = await state.resolver.resolve_endpoint(body.dst, inv, itop_cfg, dns_cfg)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    client = build_fmg_client(fmg_cfg, state.cfg)
    try:
        hops = await run_trace(
            src_ip=src_ep["ip"], dst_ip=dst_ep["ip"], protocol=proto,
            dst_port=body.dst_port, src_port=body.src_port,
            icmp_type=body.icmp_type, icmp_code=body.icmp_code,
            inv=inv, prefixes=prefixes, client=client,
            overlay_pattern=tracker_cfg.get("overlay_pattern", "(?i)(vpn|ovl|sdwan|tun|ipsec)"),
            max_hops=int(tracker_cfg.get("max_hops", 8)),
        )
    except TraceError as exc:
        raise HTTPException(422, str(exc)) from exc
    except FmgError as exc:
        raise HTTPException(502, f"FMG-Fehler: {exc}") from exc
    finally:
        await client.close()

    warnings: list[str] = []
    # VIP/NAT-Erkennung: Ziel ist externe VIP-Adresse → Re-Trace-Hinweis
    vip = None
    for adom in inv.adoms:
        vip_obj = inv.vip_for(adom, dst_ep["ip"])
        if vip_obj:
            mapped = vip_obj.get("mappedip")
            mapped = mapped[0] if isinstance(mapped, list) and mapped else mapped
            vip = {"name": vip_obj.get("name"), "extip": vip_obj.get("extip"),
                   "mappedip": str(mapped) if mapped else None}
            warnings.append(
                f"Ziel {dst_ep['ip']} ist eine VIP ('{vip['name']}'). FortiOS macht "
                "den VIP-Lookup vor dem Policy-Lookup — Trace mit der mapped IP "
                f"({vip['mappedip']}) wiederholen für den Pfad hinter dem NAT."
            )
            break

    # Regel-Vorschläge für Deny-Hops
    for hop in hops:
        if hop.verdict == "DENY" and not hop.after_deny:
            hop.suggestion = build_suggestion(
                inv, hop, src_ip=src_ep["ip"], dst_ip=dst_ep["ip"],
                protocol=proto, dst_port=body.dst_port,
                src_names=src_ep["names"], dst_names=dst_ep["names"],
            )

    result = TraceResult(
        verdict=aggregate_verdict(hops),
        src=Endpoint(**src_ep), dst=Endpoint(**dst_ep),
        protocol=proto, dst_port=body.dst_port, src_port=body.src_port,
        icmp_type=body.icmp_type, icmp_code=body.icmp_code,
        hops=hops, warnings=warnings, vip=vip,
        duration_ms=int((time.monotonic() - started) * 1000),
        inventory_synced_at=inv.synced_at,
    )

    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO traces (username, request, result, verdict, duration_ms)
            VALUES ($1, $2, $3, $4, $5)
            """,
            user.get("username", "?"), body.model_dump(), result.model_dump(),
            result.verdict, result.duration_ms,
        )
    return result


@router.get("/traces")
async def list_traces(request: Request, limit: int = 50,
                      _user: dict = Depends(get_current_user)) -> list[dict]:
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, created_at, username, request, verdict, duration_ms
            FROM traces ORDER BY created_at DESC LIMIT $1
            """,
            min(limit, 200),
        )
    return [dict(r) for r in rows]


@router.get("/traces/{trace_id}")
async def get_trace(trace_id: int, request: Request,
                    _user: dict = Depends(get_current_user)) -> dict:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM traces WHERE id = $1", trace_id)
    if not row:
        raise HTTPException(404, "Trace nicht gefunden")
    return dict(row)
