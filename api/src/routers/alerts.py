from __future__ import annotations

import io
import time
from datetime import datetime, timezone
from typing import Annotated

import asyncpg
import orjson
from confluent_kafka import Producer
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from minio import Minio

from database import get_pool
from models import AlertListResponse, AlertResponse, FeedbackRequest

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

# Wird von main.py nach dem Start gesetzt
_feedback_producer: Producer | None = None


def set_feedback_producer(producer: Producer) -> None:
    global _feedback_producer
    _feedback_producer = producer


def _row_to_alert(row: asyncpg.Record) -> AlertResponse:
    return AlertResponse(
        alert_id=row["alert_id"],
        ts=row["ts"],
        flow_id=row["flow_id"],
        source=row["source"],
        rule_id=row["rule_id"],
        severity=row["severity"],
        score=float(row["score"]),
        src_ip=str(row["src_ip"]) if row["src_ip"] else None,
        dst_ip=str(row["dst_ip"]) if row["dst_ip"] else None,
        src_port=row["src_port"],
        dst_port=row["dst_port"],
        proto=row["proto"],
        description=row["description"],
        tags=list(row["tags"] or []),
        enrichment=dict(row["enrichment"]) if row["enrichment"] else None,
        pcap_available=row["pcap_available"],
        pcap_key=row["pcap_key"],
        feedback=row["feedback"],
        feedback_ts=row["feedback_ts"],
        feedback_note=row["feedback_note"],
        is_test=row["is_test"],
    )


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    severity: str | None   = None,
    source:   str | None   = None,
    rule_id:  str | None   = None,
    src_ip:   str | None   = None,
    ts_from:  float | None = None,
    ts_to:    float | None = None,
    is_test:  bool | None = None,
    limit:    Annotated[int, Query(ge=1, le=500)] = 50,
    offset:   Annotated[int, Query(ge=0)]         = 0,
    pool:     asyncpg.Pool = Depends(get_pool),
) -> AlertListResponse:
    filters: list[str] = []
    params:  list = []
    idx = 1

    if is_test is not None:
        filters.append(f"is_test = ${idx}")
        params.append(is_test); idx += 1

    if severity:
        filters.append(f"severity = ${idx}")
        params.append(severity); idx += 1
    if source:
        filters.append(f"source = ${idx}")
        params.append(source); idx += 1
    if rule_id:
        filters.append(f"rule_id = ${idx}")
        params.append(rule_id); idx += 1
    if src_ip:
        filters.append(f"src_ip = ${idx}::inet")
        params.append(src_ip); idx += 1
    if ts_from is not None:
        filters.append(f"ts >= ${idx}")
        params.append(datetime.fromtimestamp(ts_from, tz=timezone.utc)); idx += 1
    if ts_to is not None:
        filters.append(f"ts <= ${idx}")
        params.append(datetime.fromtimestamp(ts_to, tz=timezone.utc)); idx += 1

    where = ("WHERE " + " AND ".join(filters)) if filters else ""

    async with pool.acquire() as conn:
        total = await conn.fetchval(f"SELECT COUNT(*) FROM alerts {where}", *params)
        rows  = await conn.fetch(
            f"""
            SELECT * FROM alerts
            {where}
            ORDER BY ts DESC
            LIMIT ${idx} OFFSET ${idx+1}
            """,
            *params, limit, offset,
        )

    return AlertListResponse(
        alerts=[_row_to_alert(r) for r in rows],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    pool: asyncpg.Pool = Depends(get_pool),
) -> AlertResponse:
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM alerts WHERE alert_id = $1::uuid", alert_id)
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _row_to_alert(row)


@router.patch("/{alert_id}/feedback", response_model=AlertResponse)
async def set_feedback(
    alert_id: str,
    body:     FeedbackRequest,
    pool:     asyncpg.Pool = Depends(get_pool),
) -> AlertResponse:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE alerts
            SET feedback = $2, feedback_ts = now(), feedback_note = $3
            WHERE alert_id = $1::uuid
            RETURNING *
            """,
            alert_id, body.feedback, body.note,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = _row_to_alert(row)

    # Feedback-Event auf Kafka publizieren (für training-loop)
    if _feedback_producer is not None:
        try:
            event = {
                "alert_id":  alert_id,
                "feedback":  body.feedback,
                "note":      body.note,
                "rule_id":   alert.rule_id,
                "source":    alert.source,
                "score":     alert.score,
                "ts":        time.time(),
            }
            _feedback_producer.produce("feedback", value=orjson.dumps(event))
            _feedback_producer.poll(0)
        except Exception:
            pass  # Kafka-Fehler darf UI nicht blockieren

    return alert


def _pcap_proxy(minio: Minio, bucket: str, key: str) -> StreamingResponse:
    """Streamt PCAP-Datei aus MinIO direkt an den Client."""
    try:
        response = minio.get_object(bucket, key)
        return StreamingResponse(
            response,
            media_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": f'attachment; filename="{key.split("/")[-1]}"'},
        )
    except Exception as exc:
        raise HTTPException(status_code=404, detail=f"PCAP not available: {exc}") from exc


def make_pcap_endpoint(minio: Minio, bucket: str):
    @router.get("/{alert_id}/pcap")
    async def download_pcap(
        alert_id: str,
        pool:     asyncpg.Pool = Depends(get_pool),
    ):
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT pcap_available, pcap_key FROM alerts WHERE alert_id = $1::uuid",
                alert_id,
            )
        if not row or not row["pcap_available"]:
            raise HTTPException(status_code=404, detail="PCAP not available")
        return _pcap_proxy(minio, bucket, row["pcap_key"])

    return download_pcap
