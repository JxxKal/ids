from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

import asyncpg
from fastapi import APIRouter, Depends, Query

from database import get_pool
from models import ConnectionGraphResponse, ConnectionSummary, FlowListResponse, FlowResponse

router = APIRouter(prefix="/api/flows", tags=["flows"])


def _row_to_flow(row: asyncpg.Record) -> FlowResponse:
    return FlowResponse(
        flow_id=row["flow_id"],
        start_ts=row["start_ts"],
        end_ts=row["end_ts"],
        src_ip=str(row["src_ip"]),
        dst_ip=str(row["dst_ip"]),
        src_port=row["src_port"],
        dst_port=row["dst_port"],
        proto=row["proto"],
        pkt_count=row["pkt_count"],
        byte_count=row["byte_count"],
        stats=dict(row["stats"]) if row["stats"] else None,
    )


@router.get("", response_model=FlowListResponse)
async def list_flows(
    src_ip:   str | None = None,
    dst_ip:   str | None = None,
    proto:    str | None = None,
    dst_port: int | None = None,
    limit:    Annotated[int, Query(ge=1, le=500)] = 100,
    offset:   Annotated[int, Query(ge=0)]         = 0,
    pool:     asyncpg.Pool = Depends(get_pool),
) -> FlowListResponse:
    filters: list[str] = []
    params:  list      = []
    idx = 1

    if src_ip:
        filters.append(f"src_ip = ${idx}::inet"); params.append(src_ip); idx += 1
    if dst_ip:
        filters.append(f"dst_ip = ${idx}::inet"); params.append(dst_ip); idx += 1
    if proto:
        filters.append(f"proto = ${idx}");        params.append(proto);  idx += 1
    if dst_port is not None:
        filters.append(f"dst_port = ${idx}");     params.append(dst_port); idx += 1

    where = ("WHERE " + " AND ".join(filters)) if filters else ""

    async with pool.acquire() as conn:
        total = await conn.fetchval(f"SELECT COUNT(*) FROM flows {where}", *params)
        rows  = await conn.fetch(
            f"""
            SELECT flow_id, start_ts, end_ts, src_ip, dst_ip,
                   src_port, dst_port, proto, pkt_count, byte_count, stats
            FROM flows
            {where}
            ORDER BY start_ts DESC
            LIMIT ${idx} OFFSET ${idx+1}
            """,
            *params, limit, offset,
        )

    return FlowListResponse(
        flows=[_row_to_flow(r) for r in rows],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/graph", response_model=ConnectionGraphResponse)
async def connection_graph(
    src_ip:     str,
    dst_ip:     str,
    center_ts:  float,
    window_min: Annotated[int, Query(ge=1, le=60)] = 5,
    pool:       asyncpg.Pool = Depends(get_pool),
) -> ConnectionGraphResponse:
    """Alle Flows zwischen zwei IPs im Zeitfenster [center_ts ± window_min], gruppiert."""
    center  = datetime.fromtimestamp(center_ts, tz=timezone.utc)
    ts_from = center - timedelta(minutes=window_min)
    ts_to   = center + timedelta(minutes=window_min)

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                src_ip::text,
                dst_ip::text,
                dst_port,
                proto,
                COUNT(*)        AS flow_count,
                SUM(pkt_count)  AS pkt_count,
                SUM(byte_count) AS byte_count,
                MIN(start_ts)   AS first_seen,
                MAX(start_ts)   AS last_seen
            FROM flows
            WHERE start_ts BETWEEN $1 AND $2
              AND (
                    (src_ip = $3::inet AND dst_ip = $4::inet)
                 OR (src_ip = $4::inet AND dst_ip = $3::inet)
              )
            GROUP BY src_ip, dst_ip, dst_port, proto
            ORDER BY flow_count DESC
            LIMIT 100
            """,
            ts_from, ts_to, src_ip, dst_ip,
        )

    connections = [
        ConnectionSummary(
            src_ip=r["src_ip"],
            dst_ip=r["dst_ip"],
            dst_port=r["dst_port"],
            proto=r["proto"],
            flow_count=int(r["flow_count"]),
            pkt_count=int(r["pkt_count"]),
            byte_count=int(r["byte_count"]),
            first_seen=r["first_seen"],
            last_seen=r["last_seen"],
        )
        for r in rows
    ]
    return ConnectionGraphResponse(
        src_ip=src_ip,
        dst_ip=dst_ip,
        window_min=window_min,
        total_flows=sum(c.flow_count for c in connections),
        connections=connections,
    )
