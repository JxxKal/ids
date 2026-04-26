from __future__ import annotations

import csv
import io
import socket
import struct
import time
from datetime import datetime, timezone
from typing import Annotated

import asyncpg
import orjson
from confluent_kafka import Producer
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
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
        enrichment=(
            row["enrichment"] if isinstance(row["enrichment"], dict)
            else orjson.loads(row["enrichment"])
        ) if row["enrichment"] else None,
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


@router.get("/export.csv")
async def export_alerts_csv(
    severity: str | None   = None,
    source:   str | None   = None,
    rule_id:  str | None   = None,
    src_ip:   str | None   = None,
    ts_from:  float | None = None,
    ts_to:    float | None = None,
    is_test:  bool | None  = None,
    feedback: str | None   = None,
    limit:    Annotated[int, Query(ge=1, le=10000)] = 5000,
    pool:     asyncpg.Pool = Depends(get_pool),
) -> Response:
    """Exportiert gefilterte Alerts als CSV-Datei."""
    filters: list[str] = []
    params:  list = []
    idx = 1

    if is_test is not None:
        filters.append(f"is_test = ${idx}"); params.append(is_test); idx += 1
    if severity:
        filters.append(f"severity = ${idx}"); params.append(severity); idx += 1
    if source:
        filters.append(f"source = ${idx}"); params.append(source); idx += 1
    if rule_id:
        filters.append(f"rule_id = ${idx}"); params.append(rule_id); idx += 1
    if src_ip:
        filters.append(f"src_ip = ${idx}::inet"); params.append(src_ip); idx += 1
    if ts_from is not None:
        filters.append(f"ts >= ${idx}"); params.append(datetime.fromtimestamp(ts_from, tz=timezone.utc)); idx += 1
    if ts_to is not None:
        filters.append(f"ts <= ${idx}"); params.append(datetime.fromtimestamp(ts_to, tz=timezone.utc)); idx += 1
    if feedback:
        if feedback == "none":
            filters.append("feedback IS NULL")
        else:
            filters.append(f"feedback = ${idx}"); params.append(feedback); idx += 1

    where = ("WHERE " + " AND ".join(filters)) if filters else ""

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT * FROM alerts {where} ORDER BY ts DESC LIMIT ${idx}",
            *params, limit,
        )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "alert_id", "ts", "source", "rule_id", "severity", "score",
        "src_ip", "dst_ip", "proto", "dst_port",
        "description", "tags", "feedback", "feedback_ts", "feedback_note",
        "pcap_available", "is_test",
    ])
    for r in rows:
        writer.writerow([
            r["alert_id"],
            r["ts"].isoformat() if r["ts"] else "",
            r["source"],
            r["rule_id"] or "",
            r["severity"],
            r["score"],
            str(r["src_ip"]) if r["src_ip"] else "",
            str(r["dst_ip"]) if r["dst_ip"] else "",
            r["proto"] or "",
            r["dst_port"] or "",
            r["description"] or "",
            ";".join(r["tags"] or []),
            r["feedback"] or "",
            r["feedback_ts"].isoformat() if r["feedback_ts"] else "",
            r["feedback_note"] or "",
            r["pcap_available"],
            r["is_test"],
        ])

    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="alerts_export.csv"'},
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
            SET feedback     = $2,
                feedback_ts  = now(),
                feedback_note = $3,
                severity     = CASE WHEN $2 = 'fp' THEN 'low' ELSE severity END
            WHERE alert_id = $1::uuid
            RETURNING *
            """,
            alert_id, body.feedback, body.note,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = _row_to_alert(row)

    if _feedback_producer is not None:
        try:
            # Training-Event für training-loop
            _feedback_producer.produce("feedback", value=orjson.dumps({
                "alert_id": alert_id,
                "feedback": body.feedback,
                "note":     body.note,
                "rule_id":  alert.rule_id,
                "source":   alert.source,
                "score":    alert.score,
                "ts":       time.time(),
            }))
            # WS-Push-Event damit alle Clients den Status live sehen —
            # inkl. severity (wird bei FP auf 'low' gesetzt) und tags
            # damit der Client-State vollständig konsistent bleibt.
            _feedback_producer.produce("alerts-enriched-push", value=orjson.dumps({
                "type": "feedback_updated",
                "data": {
                    "alert_id":     alert_id,
                    "feedback":     body.feedback,
                    "feedback_ts":  alert.feedback_ts.isoformat() if alert.feedback_ts else None,
                    "feedback_note": body.note,
                    "severity":     alert.severity,
                    "tags":         list(alert.tags or []),
                },
            }))
            _feedback_producer.poll(0)
        except Exception:
            pass  # Kafka-Fehler darf UI nicht blockieren

    return alert


# ── PCAP-Filter (pure Python, ohne scapy/dpkt-Dependency) ────────────────────
# pcap-store schreibt das volle ±60s-Fenster ungefiltert nach MinIO – nützlich
# für nachträgliche Forensik. Beim Download wollen wir aber per Default nur
# die Pakete sehen, die zum konkreten Alert-Flow gehören (sonst muss der
# Operator im PCAP von Hand wireshark-filtern). Die Filterung passiert
# on-the-fly im API-Container, der Storage bleibt unverändert.

_PCAP_GLOBAL_HDR_LEN = 24
_PCAP_REC_HDR_LEN    = 16
_ETH_HDR_LEN         = 14
_VLAN_TAG_LEN        = 4
_ETHERTYPE_IPV4      = 0x0800
_ETHERTYPE_IPV6      = 0x86DD
_ETHERTYPE_VLAN      = 0x8100


def _pkt_endpoints(frame: bytes) -> tuple[str | None, str | None, int | None, int | None]:
    """Parst Ethernet+IPv4/IPv6 und liefert (src_ip, dst_ip, src_port, dst_port).
    None wenn das Paket nichts Verwertbares enthält (ARP, LLDP …). Tolerant
    gegenüber 802.1Q-VLAN-Tags."""
    if len(frame) < _ETH_HDR_LEN:
        return None, None, None, None
    eth_type = struct.unpack_from("!H", frame, 12)[0]
    offset = _ETH_HDR_LEN
    # Bis zu zwei Q-in-Q-Tags überspringen
    for _ in range(2):
        if eth_type == _ETHERTYPE_VLAN and len(frame) >= offset + _VLAN_TAG_LEN:
            eth_type = struct.unpack_from("!H", frame, offset + 2)[0]
            offset += _VLAN_TAG_LEN
        else:
            break

    if eth_type == _ETHERTYPE_IPV4 and len(frame) >= offset + 20:
        ihl_byte = frame[offset]
        ihl_words = ihl_byte & 0x0F
        ip_hdr_len = ihl_words * 4
        if ip_hdr_len < 20 or len(frame) < offset + ip_hdr_len:
            return None, None, None, None
        proto = frame[offset + 9]
        src   = socket.inet_ntop(socket.AF_INET, frame[offset + 12:offset + 16])
        dst   = socket.inet_ntop(socket.AF_INET, frame[offset + 16:offset + 20])
        sp = dp = None
        if proto in (6, 17) and len(frame) >= offset + ip_hdr_len + 4:  # TCP/UDP
            sp, dp = struct.unpack_from("!HH", frame, offset + ip_hdr_len)
        return src, dst, sp, dp

    if eth_type == _ETHERTYPE_IPV6 and len(frame) >= offset + 40:
        proto = frame[offset + 6]
        src   = socket.inet_ntop(socket.AF_INET6, frame[offset + 8:offset + 24])
        dst   = socket.inet_ntop(socket.AF_INET6, frame[offset + 24:offset + 40])
        sp = dp = None
        if proto in (6, 17) and len(frame) >= offset + 40 + 4:
            sp, dp = struct.unpack_from("!HH", frame, offset + 40)
        return src, dst, sp, dp

    return None, None, None, None


def _filter_pcap(
    pcap_bytes: bytes,
    src_ip:    str | None,
    dst_ip:    str | None,
    src_port:  int | None = None,
    dst_port:  int | None = None,
) -> bytes:
    """Liest ein PCAP-Byte-Blob und gibt einen neuen Blob zurück, der nur
    Pakete enthält die zum (src_ip ↔ dst_ip)-Flow gehören. Ports werden
    falls vorhanden zusätzlich geprüft (bidirektional). Bei nicht-IP-Paketen
    wird der ursprüngliche PCAP-Header übernommen, nicht-passende Records
    fallen weg."""
    if not src_ip and not dst_ip:
        return pcap_bytes

    if len(pcap_bytes) < _PCAP_GLOBAL_HDR_LEN:
        return pcap_bytes
    out = bytearray(pcap_bytes[:_PCAP_GLOBAL_HDR_LEN])

    # Endianness aus dem Magic Number bestimmen.
    magic = struct.unpack_from("<I", pcap_bytes, 0)[0]
    if magic == 0xa1b2c3d4 or magic == 0xa1b23c4d:        # native LE
        rec_hdr_fmt = "<IIII"
    elif magic == 0xd4c3b2a1 or magic == 0x4d3cb2a1:      # swapped BE
        rec_hdr_fmt = ">IIII"
    else:
        # unbekanntes Format → unverändert zurück, lieber vollständig als
        # nichts. Operator kann dann immer noch raw=true wählen.
        return pcap_bytes

    pos = _PCAP_GLOBAL_HDR_LEN
    matched = 0
    while pos + _PCAP_REC_HDR_LEN <= len(pcap_bytes):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(rec_hdr_fmt, pcap_bytes, pos)
        rec_end = pos + _PCAP_REC_HDR_LEN + incl_len
        if rec_end > len(pcap_bytes) or incl_len > 65535:
            break
        frame = pcap_bytes[pos + _PCAP_REC_HDR_LEN:rec_end]

        ip_a, ip_b, sp, dp = _pkt_endpoints(frame)
        keep = False
        if ip_a and ip_b:
            ip_match = (
                (src_ip and dst_ip and {ip_a, ip_b} == {src_ip, dst_ip})
                or (src_ip and not dst_ip and src_ip in (ip_a, ip_b))
                or (dst_ip and not src_ip and dst_ip in (ip_a, ip_b))
            )
            if ip_match:
                if src_port or dst_port:
                    ports_present = {sp, dp} - {None}
                    wanted = {src_port, dst_port} - {None}
                    keep = bool(ports_present & wanted) if wanted else True
                else:
                    keep = True

        if keep:
            out += pcap_bytes[pos:rec_end]
            matched += 1
        pos = rec_end

    return bytes(out) if matched else pcap_bytes  # leer? lieber komplett zurück


def _pcap_proxy(
    minio:    Minio,
    bucket:   str,
    key:      str,
    *,
    filter_:  bool = True,
    src_ip:   str | None = None,
    dst_ip:   str | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
) -> StreamingResponse:
    """Streamt PCAP aus MinIO. Wenn filter_=True (Default), wird das PCAP
    on-the-fly durch _filter_pcap() geleitet, sodass der Operator nur die
    zum Alert gehörigen Pakete bekommt."""
    try:
        response = minio.get_object(bucket, key)
        raw = response.read()
        try:
            response.close()
            response.release_conn()
        except Exception:
            pass
    except Exception as exc:
        raise HTTPException(status_code=404, detail=f"PCAP not available: {exc}") from exc

    payload = raw
    if filter_ and (src_ip or dst_ip):
        payload = _filter_pcap(raw, src_ip, dst_ip, src_port, dst_port)

    fname = key.split("/")[-1]
    if filter_ and (src_ip or dst_ip):
        fname = fname.replace(".pcap", "-filtered.pcap") if fname.endswith(".pcap") else f"{fname}-filtered"

    return StreamingResponse(
        iter([payload]),
        media_type="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": f'attachment; filename="{fname}"',
            "Content-Length":      str(len(payload)),
        },
    )


def make_pcap_endpoint(minio: Minio, bucket: str):
    @router.get("/{alert_id}/pcap")
    async def download_pcap(
        alert_id: str,
        raw:      bool          = Query(False, description="True = ungefiltertes ±60s-Fenster (Debug-Modus)"),
        pool:     asyncpg.Pool  = Depends(get_pool),
    ):
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT pcap_available, pcap_key,
                       src_ip::text AS src_ip, dst_ip::text AS dst_ip,
                       src_port, dst_port
                FROM alerts WHERE alert_id = $1::uuid
                """,
                alert_id,
            )
        if not row or not row["pcap_available"]:
            raise HTTPException(status_code=404, detail="PCAP not available")
        return _pcap_proxy(
            minio, bucket, row["pcap_key"],
            filter_=not raw,
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
        )

    return download_pcap
