"""
Wochenbericht — aggregierte Detection-/Operations-Sicht für eine ISO-Woche.

Phase 1 (on-demand):
  GET /api/reports/weekly                 — aktuelle Woche, JSON
  GET /api/reports/weekly?week=2026-W18   — bestimmte Woche
  GET /api/reports/weekly?fmt=csv         — ZIP-Bundle mit CSVs

Phase 2 (Archivierung):
  - Hintergrund-Cron archiviert beim ersten Zugriff nach Wochenende den
    JSON-Snapshot ins MinIO-Bucket `ids-reports` (Key: weekly/YYYY-Wnn.json).
  - GET /api/reports/weekly?week=… liefert für vergangene Wochen den
    archivierten Snapshot wenn vorhanden, sonst frischen DB-Aggregat. Das
    schützt vor Drift, wenn die alerts-Hypertable retention-pruned wird.
  - GET /api/reports/history?limit=12 listet die letzten archivierten
    Wochen mit Headline und Total.

Read-only (kein admin nötig). Pure SQL-Aggregate über die Hypertable
`alerts` und ein paar Hilfstabellen — keine neuen DB-Strukturen.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import re
import zipfile
from datetime import date, datetime, timedelta, timezone

import asyncpg
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from minio import Minio
from minio.error import S3Error

from database import get_pool

log = logging.getLogger("api.reports")

router = APIRouter(prefix="/api/reports", tags=["reports"])

# ── MinIO-Hooks (optional gesetzt von main.py beim Startup) ──────────────────
#
# Modulscoped, weil der Endpoint sie über zwei Pfade braucht:
#  - weekly_report() liest archivierten Snapshot wenn vorhanden
#  - _archive_loop() schreibt regelmäßig
# main.py setzt das Paar via configure_archive() vor dem include_router-Call.

_minio_client: Minio | None = None
_archive_bucket: str | None = None


def configure_archive(client: Minio, bucket: str) -> None:
    """Wird vom api/main.py beim Startup aufgerufen, sobald MinIO-Client +
    bucket-name verfügbar sind. Idempotent: kann mehrfach aufgerufen werden."""
    global _minio_client, _archive_bucket
    _minio_client = client
    _archive_bucket = bucket


def _archive_key(year: int, week: int) -> str:
    return f"weekly/{year}-W{week:02d}.json"


def _read_archive(year: int, week: int) -> dict | None:
    """Liest einen archivierten Wochenbericht aus MinIO. None wenn nicht
    vorhanden (auch bei MinIO-Fehlern — der Live-Aggregat-Pfad ist immer
    ein gültiger Fallback, daher kein Hochreichen)."""
    if not _minio_client or not _archive_bucket:
        return None
    try:
        key = _archive_key(year, week)
        resp = _minio_client.get_object(_archive_bucket, key)
        try:
            return json.loads(resp.read().decode("utf-8"))
        finally:
            resp.close()
            resp.release_conn()
    except S3Error as exc:
        if exc.code in ("NoSuchKey", "NoSuchBucket"):
            return None
        log.warning("MinIO read %s/%s fehlgeschlagen: %s", _archive_bucket, _archive_key(year, week), exc)
        return None
    except Exception as exc:                                # noqa: BLE001
        log.warning("Archive read fehlgeschlagen für %s-W%s: %s", year, week, exc)
        return None


def _write_archive(year: int, week: int, payload: dict) -> bool:
    """Schreibt einen Snapshot ins Archiv. Gibt True wenn erfolgreich,
    False wenn MinIO nicht erreichbar oder Bucket fehlt — der Cron-Loop
    versucht's beim nächsten Tick erneut."""
    if not _minio_client or not _archive_bucket:
        return False
    try:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        _minio_client.put_object(
            _archive_bucket,
            _archive_key(year, week),
            data=io.BytesIO(body),
            length=len(body),
            content_type="application/json",
        )
        return True
    except Exception as exc:                                # noqa: BLE001
        log.warning("Archive write fehlgeschlagen für %s-W%s: %s", year, week, exc)
        return False


def _list_archive_keys(limit: int = 24) -> list[tuple[int, int]]:
    """Liefert die letzten archivierten Wochen als (year, week)-Tupel,
    absteigend sortiert. Nutzt MinIO-list-Listing — keine DB."""
    if not _minio_client or not _archive_bucket:
        return []
    try:
        objs = _minio_client.list_objects(_archive_bucket, prefix="weekly/", recursive=True)
        out: list[tuple[int, int]] = []
        for o in objs:
            # Key-Form: weekly/YYYY-Wnn.json
            m = re.match(r"^weekly/(\d{4})-W(\d{1,2})\.json$", o.object_name or "")
            if m:
                out.append((int(m.group(1)), int(m.group(2))))
        out.sort(reverse=True)
        return out[:limit]
    except Exception as exc:                                # noqa: BLE001
        log.warning("MinIO list weekly/ fehlgeschlagen: %s", exc)
        return []

# ── Helpers ──────────────────────────────────────────────────────────────────

_WEEK_RE = re.compile(r"^(\d{4})-W(\d{1,2})$")


def _parse_week(s: str | None) -> tuple[int, int]:
    """ISO-Woche '2026-W18' → (2026, 18). Default: aktuelle Woche."""
    if not s:
        iso = date.today().isocalendar()
        return iso.year, iso.week
    m = _WEEK_RE.match(s.strip())
    if not m:
        raise HTTPException(400, "week muss Format YYYY-Wnn haben (z.B. 2026-W18)")
    year = int(m.group(1))
    week = int(m.group(2))
    if not (1 <= week <= 53):
        raise HTTPException(400, "Wochennummer 1–53 erwartet")
    return year, week


def _week_bounds(year: int, week: int) -> tuple[datetime, datetime]:
    """ISO-Woche → [Mo 00:00 UTC, Mo+7d 00:00 UTC). Python date.fromisocalendar
    benutzt Mo als Wochenbeginn, was ISO-konform ist."""
    try:
        monday = date.fromisocalendar(year, week, 1)
    except ValueError as exc:
        raise HTTPException(400, f"Ungültige Woche {year}-W{week}: {exc}")
    start = datetime(monday.year, monday.month, monday.day, tzinfo=timezone.utc)
    end   = start + timedelta(days=7)
    return start, end


def _safe_str(v) -> str:
    return "" if v is None else str(v)


# ── SQL-Aggregate ────────────────────────────────────────────────────────────


async def _alerts_total(conn: asyncpg.Connection, t0: datetime, t1: datetime) -> dict:
    """Gesamt + per Severity, plus Vorwoche zum Vergleich."""
    prev0 = t0 - timedelta(days=7)
    prev1 = t1 - timedelta(days=7)

    cur = await conn.fetch(
        """
        SELECT severity, COUNT(*) AS c
          FROM alerts
         WHERE ts >= $1 AND ts < $2 AND NOT is_test
         GROUP BY severity
        """,
        t0, t1,
    )
    prev = await conn.fetch(
        """
        SELECT severity, COUNT(*) AS c
          FROM alerts
         WHERE ts >= $1 AND ts < $2 AND NOT is_test
         GROUP BY severity
        """,
        prev0, prev1,
    )

    def _to_dict(rows) -> dict[str, int]:
        d = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in rows:
            sev = (r["severity"] or "").lower()
            if sev in d:
                d[sev] = int(r["c"])
        return d

    cur_d  = _to_dict(cur)
    prev_d = _to_dict(prev)
    return {
        "by_severity":      cur_d,
        "by_severity_prev": prev_d,
        "total":      sum(cur_d.values()),
        "total_prev": sum(prev_d.values()),
    }


async def _alerts_daily(conn: asyncpg.Connection, t0: datetime, t1: datetime) -> list[dict]:
    """Alerts pro Tag × Severity, 7 Slots."""
    rows = await conn.fetch(
        """
        SELECT date_trunc('day', ts AT TIME ZONE 'UTC')::date AS day,
               severity,
               COUNT(*) AS c
          FROM alerts
         WHERE ts >= $1 AND ts < $2 AND NOT is_test
         GROUP BY day, severity
         ORDER BY day
        """,
        t0, t1,
    )
    # Pre-fill all 7 days with zeros so the chart has continuous slots.
    bucket: dict[str, dict[str, int]] = {}
    for i in range(7):
        d = (t0 + timedelta(days=i)).date().isoformat()
        bucket[d] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in rows:
        d = r["day"].isoformat()
        sev = (r["severity"] or "").lower()
        if d in bucket and sev in bucket[d]:
            bucket[d][sev] = int(r["c"])
    return [{"date": d, **counts} for d, counts in bucket.items()]


async def _top_rules(conn: asyncpg.Connection, t0: datetime, t1: datetime, limit: int = 10) -> list[dict]:
    rows = await conn.fetch(
        """
        WITH ranked AS (
          SELECT rule_id, source, severity, description,
                 COUNT(*) OVER (PARTITION BY rule_id) AS c,
                 ROW_NUMBER() OVER (PARTITION BY rule_id ORDER BY ts DESC) AS rn
            FROM alerts
           WHERE ts >= $1 AND ts < $2 AND NOT is_test AND rule_id IS NOT NULL
        )
        SELECT rule_id, source, severity, description, c
          FROM ranked
         WHERE rn = 1
         ORDER BY c DESC
         LIMIT $3
        """,
        t0, t1, limit,
    )
    return [
        {
            "rule_id":     r["rule_id"],
            "source":      r["source"],
            "severity":    r["severity"],
            "description": r["description"],
            "count":       int(r["c"]),
        }
        for r in rows
    ]


async def _top_sources(conn: asyncpg.Connection, t0: datetime, t1: datetime, limit: int = 10) -> list[dict]:
    """Top-N Source-IPs nach Alert-Anzahl. Hostname/Display-Name-Lookup
    aus host_info-Tabelle (LEFT JOIN, IP-Match)."""
    rows = await conn.fetch(
        """
        SELECT a.src_ip,
               COUNT(*) AS c,
               MAX(a.severity) AS max_sev,
               h.display_name,
               h.hostname
          FROM alerts a
          LEFT JOIN host_info h ON h.ip = a.src_ip
         WHERE a.ts >= $1 AND a.ts < $2 AND NOT a.is_test AND a.src_ip IS NOT NULL
         GROUP BY a.src_ip, h.display_name, h.hostname
         ORDER BY c DESC
         LIMIT $3
        """,
        t0, t1, limit,
    )
    # MAX(severity) ist Lex-Sort, das stimmt nicht mit der Severity-Order ('critical' > 'high' lexikografisch ist falsch).
    # Wir korrigieren clientseitig auf den höchsten echten Wert.
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    out = []
    for r in rows:
        out.append({
            "src_ip":       str(r["src_ip"]),
            "display_name": r["display_name"],
            "hostname":     r["hostname"],
            "max_severity": r["max_sev"],
            "count":        int(r["c"]),
            "_rank":        sev_rank.get((r["max_sev"] or "").lower(), 0),
        })
    return out


async def _top_external_dests(conn: asyncpg.Connection, t0: datetime, t1: datetime, limit: int = 10) -> list[dict]:
    """Top-N Public-IP-Ziele mit Geo+ASN aus dem Enrichment-JSONB."""
    rows = await conn.fetch(
        """
        SELECT a.dst_ip,
               COUNT(*) AS c,
               MAX(a.enrichment->'dst_geo'->>'country')      AS country,
               MAX(a.enrichment->'dst_geo'->>'country_code') AS country_code,
               MAX(a.enrichment->'dst_asn'->>'org')          AS asn_org
          FROM alerts a
         WHERE a.ts >= $1 AND a.ts < $2
           AND NOT a.is_test
           AND a.enrichment IS NOT NULL
           AND a.enrichment->'dst_geo'->>'country_code' IS NOT NULL
           AND a.dst_ip IS NOT NULL
         GROUP BY a.dst_ip
         ORDER BY c DESC
         LIMIT $3
        """,
        t0, t1, limit,
    )
    return [
        {
            "dst_ip":       str(r["dst_ip"]),
            "country":      r["country"],
            "country_code": r["country_code"],
            "asn":          r["asn_org"],
            "count":        int(r["c"]),
        }
        for r in rows
    ]


async def _tap_summary(conn: asyncpg.Connection, t0: datetime, t1: datetime) -> list[dict]:
    """Pro Tap: Name, last_seen, Alerts in der Woche."""
    rows = await conn.fetch(
        """
        SELECT t.id, t.name, t.site, t.status, t.last_seen,
               (SELECT COUNT(*) FROM alerts a
                 WHERE a.tap_id = t.id AND a.ts >= $1 AND a.ts < $2 AND NOT a.is_test) AS alerts_week
          FROM taps t
         ORDER BY t.name
        """,
        t0, t1,
    )
    return [
        {
            "id":          str(r["id"]),
            "name":        r["name"],
            "site":        r["site"],
            "status":      r["status"],
            "last_seen":   r["last_seen"].isoformat() if r["last_seen"] else None,
            "alerts_week": int(r["alerts_week"]),
        }
        for r in rows
    ]


async def _ml_activity(conn: asyncpg.Connection, t0: datetime, t1: datetime) -> dict:
    """FP/TP-Markierungen in der Woche + Tuner-Aktivität."""
    fb = await conn.fetchrow(
        """
        SELECT
          COUNT(*) FILTER (WHERE feedback = 'fp') AS fp,
          COUNT(*) FILTER (WHERE feedback = 'tp') AS tp
          FROM alerts
         WHERE feedback_ts IS NOT NULL
           AND feedback_ts >= $1 AND feedback_ts < $2
        """,
        t0, t1,
    )
    # Tuner-Cycles: rule_baselines.updated_at innerhalb des Fensters → Cycle-Heuristik.
    # Alle Baselines persistieren gemeinsam, daher zählen wir distinct updated_at-buckets (60s-runden).
    tuner = await conn.fetchrow(
        """
        SELECT COUNT(DISTINCT date_trunc('minute', updated_at)) AS cycles
          FROM rule_baselines
         WHERE updated_at >= $1 AND updated_at < $2
        """,
        t0, t1,
    )
    return {
        "fp_marked":    int(fb["fp"] or 0),
        "tp_marked":    int(fb["tp"] or 0),
        "tuner_cycles": int(tuner["cycles"] or 0),
    }


# ── Egress-Boundary-Breaches (OT/IT-Boundary) ───────────────────────────────────
#
# Eine Boundary-Breach ist ein Alert mit `boundary_priority IS NOT NULL`,
# also einer der Klassen P0–P3 aus Migration 010 (siehe SQL-Kommentar dort).
# `boundary_whitelisted` wird zur Query-Zeit gegen die `egress_whitelist`
# berechnet — wir wenden hier dieselbe NOT-EXISTS-Korrelation wie im
# Alert-Feed-Endpoint (alerts.py) an, damit der Wochenbericht den gleichen
# „aktiven Stand" zeigt wie die Live-Ansicht.

_BOUNDARY_NOT_WHITELISTED = """\
NOT EXISTS (
    SELECT 1 FROM egress_whitelist w
    WHERE w.active = true
      AND (w.expires_at IS NULL OR w.expires_at > now())
      AND w.src_ip = a.src_ip
      AND (
        (w.dst_ip  IS NULL AND w.dst_net IS NULL) OR
        (w.dst_ip  IS NOT NULL AND w.dst_ip  = a.dst_ip) OR
        (w.dst_net IS NOT NULL AND a.dst_ip <<= w.dst_net)
      )
      AND (w.dst_port IS NULL OR w.dst_port = a.dst_port)
      AND (w.proto    IS NULL OR w.proto    = a.proto)
)"""


async def _boundary_summary(conn: asyncpg.Connection, t0: datetime, t1: datetime) -> dict:
    """Zähle Breaches pro Priority + wie viele die Whitelist suppressed.
    Zwei Queries — eine für aktive Breaches gruppiert, eine für den
    Whitelist-Total. Beide sharen den Index `alerts_boundary_priority_ts_idx`."""
    by_prio = await conn.fetch(
        f"""
        SELECT boundary_priority AS p, COUNT(*) AS c
          FROM alerts a
         WHERE a.ts >= $1 AND a.ts < $2 AND NOT a.is_test
           AND a.boundary_priority IS NOT NULL
           AND {_BOUNDARY_NOT_WHITELISTED}
         GROUP BY boundary_priority
        """,
        t0, t1,
    )
    wl_row = await conn.fetchrow(
        f"""
        SELECT COUNT(*) AS c
          FROM alerts a
         WHERE a.ts >= $1 AND a.ts < $2 AND NOT a.is_test
           AND a.boundary_priority IS NOT NULL
           AND NOT ({_BOUNDARY_NOT_WHITELISTED})
        """,
        t0, t1,
    )
    counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    for r in by_prio:
        if r["p"] in counts:
            counts[r["p"]] = int(r["c"])
    return {
        "total":       sum(counts.values()),
        "by_priority": counts,
        "whitelisted": int(wl_row["c"] or 0),
    }


async def _boundary_top_talkers(
    conn: asyncpg.Connection, t0: datetime, t1: datetime, limit: int = 10,
) -> list[dict]:
    """Top-N Source-IPs die Richtung unbekannter Netze (boundary_net_known
    ≠ true) gefeuert haben — also die heißesten internen Sender Richtung
    Außen. Hostname/Display-Name-Lookup aus host_info. MIN(priority) ist
    bewusst lex-sort: 'P0' < 'P1' < 'P2' < 'P3', also liefert MIN die
    schärfste Klassifikation des Talkers."""
    rows = await conn.fetch(
        f"""
        SELECT a.src_ip,
               COUNT(*) AS c,
               MIN(a.boundary_priority) AS top_priority,
               h.display_name,
               h.hostname
          FROM alerts a
          LEFT JOIN host_info h ON h.ip = a.src_ip
         WHERE a.ts >= $1 AND a.ts < $2 AND NOT a.is_test
           AND a.boundary_priority IS NOT NULL
           AND a.boundary_net_known IS DISTINCT FROM TRUE
           AND a.src_ip IS NOT NULL
           AND {_BOUNDARY_NOT_WHITELISTED}
         GROUP BY a.src_ip, h.display_name, h.hostname
         ORDER BY c DESC
         LIMIT $3
        """,
        t0, t1, limit,
    )
    return [
        {
            "src_ip":       str(r["src_ip"]),
            "display_name": r["display_name"],
            "hostname":     r["hostname"],
            "count":        int(r["c"]),
            "top_priority": r["top_priority"],
        }
        for r in rows
    ]


async def _boundary_zone_breakdown(conn: asyncpg.Connection, t0: datetime, t1: datetime) -> dict:
    """Aktive Breaches gruppiert nach (src_zone, dst_zone). Nur Alerts mit
    befüllten Zonen-Spalten (Migration 017+) — ältere Bestandsalerts haben
    NULL und landen im 'unzoned'-Bucket. Damit sieht der User auf einen
    Blick die V2-Coverage."""
    rows = await conn.fetch(
        f"""
        SELECT a.boundary_src_zone AS src,
               a.boundary_dst_zone AS dst,
               COUNT(*) AS c
          FROM alerts a
         WHERE a.ts >= $1 AND a.ts < $2 AND NOT a.is_test
           AND a.boundary_priority IS NOT NULL
           AND {_BOUNDARY_NOT_WHITELISTED}
         GROUP BY a.boundary_src_zone, a.boundary_dst_zone
        """,
        t0, t1,
    )
    by_pair: dict[str, int] = {}
    unzoned = 0
    for r in rows:
        src, dst = r["src"], r["dst"]
        if src and dst:
            by_pair[f"{src}/{dst}"] = int(r["c"])
        else:
            unzoned += int(r["c"])
    return {"by_pair": by_pair, "unzoned": unzoned}


async def _boundary_top_pairs(
    conn: asyncpg.Connection, t0: datetime, t1: datetime, limit: int = 10,
) -> list[dict]:
    """Top-N (src, dst)-Pärchen Richtung unbekannter Netze. Jeder Pair-
    Eintrag bekommt zusätzlich Country/ASN des Ziels aus dem Enrichment-
    JSONB — typisch Internet-Ziele, gelegentlich Multicast/RFC1918 ohne
    Geo-Daten (dann sind die Felder NULL)."""
    rows = await conn.fetch(
        f"""
        SELECT a.src_ip,
               a.dst_ip,
               COUNT(*) AS c,
               MIN(a.boundary_priority) AS top_priority,
               MAX(a.enrichment->'dst_geo'->>'country')      AS dst_country,
               MAX(a.enrichment->'dst_geo'->>'country_code') AS dst_country_code,
               MAX(a.enrichment->'dst_asn'->>'org')          AS dst_asn
          FROM alerts a
         WHERE a.ts >= $1 AND a.ts < $2 AND NOT a.is_test
           AND a.boundary_priority IS NOT NULL
           AND a.boundary_net_known IS DISTINCT FROM TRUE
           AND a.src_ip IS NOT NULL
           AND a.dst_ip IS NOT NULL
           AND {_BOUNDARY_NOT_WHITELISTED}
         GROUP BY a.src_ip, a.dst_ip
         ORDER BY c DESC
         LIMIT $3
        """,
        t0, t1, limit,
    )
    return [
        {
            "src_ip":           str(r["src_ip"]),
            "dst_ip":           str(r["dst_ip"]),
            "count":            int(r["c"]),
            "top_priority":     r["top_priority"],
            "dst_country":      r["dst_country"],
            "dst_country_code": r["dst_country_code"],
            "dst_asn":          r["dst_asn"],
        }
        for r in rows
    ]


async def _suricata_top(conn: asyncpg.Connection, t0: datetime, t1: datetime, limit: int = 5) -> list[dict]:
    rows = await conn.fetch(
        """
        SELECT rule_id, COUNT(*) AS c
          FROM alerts
         WHERE ts >= $1 AND ts < $2
           AND NOT is_test
           AND source = 'suricata'
         GROUP BY rule_id
         ORDER BY c DESC
         LIMIT $3
        """,
        t0, t1, limit,
    )
    return [{"sid": r["rule_id"], "count": int(r["c"])} for r in rows]


async def _audit_summary(conn: asyncpg.Connection, t0: datetime, t1: datetime) -> dict:
    """Logins + Whitelist-Adds in der Woche.
    Logins: users.last_login ist nur der letzte — wir berichten daher
    nur 'aktive User in der Woche' (last_login im Fenster)."""
    active_users = await conn.fetch(
        """
        SELECT username, last_login
          FROM users
         WHERE last_login IS NOT NULL
           AND last_login >= $1 AND last_login < $2
         ORDER BY last_login DESC
        """,
        t0, t1,
    )
    wl = await conn.fetchrow(
        """
        SELECT COUNT(*) AS c
          FROM egress_whitelist
         WHERE created_at >= $1 AND created_at < $2
        """,
        t0, t1,
    )
    return {
        "active_users":    [
            {"username": r["username"], "last_login": r["last_login"].isoformat()}
            for r in active_users
        ],
        "whitelist_adds":  int(wl["c"] or 0),
    }


def _build_headline(detection: dict, top_rules: list[dict]) -> str:
    """Ein-Satz-Befund für die Executive Summary."""
    total = detection["total"]
    if total == 0:
        return "Keine Alerts diese Woche."
    crit = detection["by_severity"]["critical"]
    if crit > 0 and top_rules:
        top = top_rules[0]
        return (
            f"{crit} kritische Alerts diese Woche; Spitzenreiter: "
            f"{top['rule_id']} mit {top['count']} Treffern."
        )
    if top_rules:
        top = top_rules[0]
        return (
            f"{total} Alerts diese Woche, keine kritischen. "
            f"Häufigste Regel: {top['rule_id']} ({top['count']})."
        )
    return f"{total} Alerts diese Woche."


def _trend(cur: int, prev: int) -> dict:
    """Trend-Helper: relative Änderung + Richtung."""
    if prev == 0:
        return {"prev": 0, "delta_pct": None, "direction": "flat" if cur == 0 else "up"}
    pct = round((cur - prev) / prev * 100, 1)
    direction = "up" if pct > 0 else ("down" if pct < 0 else "flat")
    return {"prev": prev, "delta_pct": pct, "direction": direction}


# ── JSON-Endpunkt ────────────────────────────────────────────────────────────


async def _build_weekly_payload(year: int, wk: int) -> dict:
    """Baut den vollständigen Wochenbericht-Payload aus DB-Aggregaten.
    Wird von weekly_report() (live-Pfad) und vom Archiv-Cron benutzt."""
    t0, t1 = _week_bounds(year, wk)

    pool = get_pool()
    async with pool.acquire() as conn:
        detection_total       = await _alerts_total(conn, t0, t1)
        daily                 = await _alerts_daily(conn, t0, t1)
        top_rules             = await _top_rules(conn, t0, t1)
        top_sources_raw       = await _top_sources(conn, t0, t1)
        top_external_dests    = await _top_external_dests(conn, t0, t1)
        taps                  = await _tap_summary(conn, t0, t1)
        ml                    = await _ml_activity(conn, t0, t1)
        suricata              = await _suricata_top(conn, t0, t1)
        audit                 = await _audit_summary(conn, t0, t1)
        boundary_sum          = await _boundary_summary(conn, t0, t1)
        boundary_talkers      = await _boundary_top_talkers(conn, t0, t1)
        boundary_pairs        = await _boundary_top_pairs(conn, t0, t1)
        boundary_zones        = await _boundary_zone_breakdown(conn, t0, t1)

    # _rank-Hilfsspalte aus top_sources entfernen (war nur internes Sort)
    top_sources = [{k: v for k, v in r.items() if not k.startswith("_")} for r in top_sources_raw]

    return {
        "week": {
            "year":      year,
            "week":      wk,
            "from":      t0.isoformat(),
            "to":        t1.isoformat(),
            "generated": datetime.now(timezone.utc).isoformat(),
            "archived":  False,         # vom Archiv-Reader auf True gesetzt
        },
        "summary": {
            "alerts_total":       detection_total["total"],
            "alerts_total_trend": _trend(detection_total["total"], detection_total["total_prev"]),
            "by_severity":        detection_total["by_severity"],
            "by_severity_prev":   detection_total["by_severity_prev"],
            "headline":           _build_headline(detection_total, top_rules),
        },
        "detection": {
            "daily":                daily,
            "top_rules":            top_rules,
            "top_sources":          top_sources,
            "top_external_dests":   top_external_dests,
        },
        "ops": {
            "taps":                 taps,
            "ml":                   ml,
            "suricata_top_sids":    suricata,
        },
        "boundary": {
            "total":       boundary_sum["total"],
            "by_priority": boundary_sum["by_priority"],
            "whitelisted": boundary_sum["whitelisted"],
            "top_talkers": boundary_talkers,
            "top_pairs":   boundary_pairs,
            "by_zone":     boundary_zones["by_pair"],
            "unzoned":     boundary_zones["unzoned"],
        },
        "audit": audit,
    }


def _is_past_week(year: int, wk: int) -> bool:
    """True wenn die Woche jünger als heute UND komplett abgeschlossen ist
    (also der Montag der Woche liegt vor dem Montag der aktuellen Woche)."""
    cur = date.today().isocalendar()
    if year < cur.year:
        return True
    if year > cur.year:
        return False
    return wk < cur.week


@router.get("/weekly", summary="Wochenbericht (JSON oder CSV-ZIP)")
async def weekly_report(
    week: str | None = Query(default=None, description="ISO-Woche YYYY-Wnn (Default: aktuell)"),
    fmt:  str        = Query(default="json", regex="^(json|csv)$"),
):
    """Aggregierter Detection-/Operations-Bericht für eine ISO-Woche.

    Vergangene Wochen werden — wenn ein Archiv-Snapshot in MinIO vorhanden
    ist — daraus zurückgeliefert (immutable, robust gegen retention-Pruning).
    Aktuelle Woche und nicht-archivierte Wochen werden live aus der DB
    aggregiert.

    Wenn `fmt=csv`, kommt ein ZIP zurück mit einer CSV pro Tabelle —
    direkt in Excel/PowerBI lesbar.
    """
    year, wk = _parse_week(week)

    payload: dict | None = None
    if _is_past_week(year, wk):
        archived = await asyncio.to_thread(_read_archive, year, wk)
        if archived is not None:
            archived.setdefault("week", {})["archived"] = True
            payload = archived

    if payload is None:
        payload = await _build_weekly_payload(year, wk)

    if fmt == "csv":
        return _to_csv_zip(payload, year, wk)
    return payload


@router.get("/history", summary="Liste der archivierten Wochen")
async def history(
    limit: int = Query(default=12, ge=1, le=104, description="Max. Anzahl Einträge (Default: 12)"),
) -> dict:
    """Lightweight-Index der archivierten Wochen — sortiert absteigend
    (jüngste zuerst). Pro Eintrag wird der Snapshot kurz gelesen und nur
    die Kennzahlen für die History-Liste rausgereicht; Frontend kann dann
    pro Klick den vollen Bericht über `/weekly?week=YYYY-Wnn` nachladen.

    Wenn MinIO nicht erreichbar ist, kommt eine leere Liste zurück (keine
    503 — der UI-Pfad fällt dann sauber auf nur die aktuelle Woche zurück).
    """
    keys = _list_archive_keys(limit)
    out: list[dict] = []
    for year, wk in keys:
        snap = await asyncio.to_thread(_read_archive, year, wk)
        if snap is None:
            continue
        out.append({
            "week_str":      f"{year}-W{wk:02d}",
            "year":          year,
            "week":          wk,
            "from":          snap.get("week", {}).get("from"),
            "to":            snap.get("week", {}).get("to"),
            "generated":     snap.get("week", {}).get("generated"),
            "alerts_total":  snap.get("summary", {}).get("alerts_total", 0),
            "headline":      snap.get("summary", {}).get("headline", ""),
        })
    return {"items": out, "count": len(out)}


# ── Archive-Cron ─────────────────────────────────────────────────────────────


async def archive_loop() -> None:
    """Hintergrund-Task: prüft stündlich, ob die letzte abgeschlossene Woche
    archiviert ist. Wenn nicht → Snapshot bauen + ins MinIO schreiben.

    Idempotent — re-archiviert nicht. Beim ersten Tick nach Mo 00:00 UTC
    landet die abgelaufene Woche im Archiv. Existierende Archive bleiben
    unangetastet, weil Datapoints sich rückwirkend ändern könnten (FP-Marks,
    feedback) und der Snapshot bewusst frozen ist.

    Aufgehängt im api/main.py-Startup. Stoppt sauber bei CancelledError.
    """
    log.info("Reports-Archive-Loop gestartet")
    # Beim Container-Start einmal sofort prüfen (kein Hour-Wait nach
    # Reboot wenn das Archiv für die letzte Woche fehlt).
    while True:
        try:
            cur = date.today().isocalendar()
            # Letzte abgeschlossene Woche bestimmen (heute - 7 Tage Trick).
            ref = date.today() - timedelta(days=7)
            ref_iso = ref.isocalendar()
            year, wk = ref_iso.year, ref_iso.week
            # Skip, wenn diese Woche zufällig die aktuelle ist (sollte nicht
            # passieren, schützt aber gegen Edge-Cases an Jahreswechseln).
            if (year, wk) != (cur.year, cur.week):
                if await asyncio.to_thread(_read_archive, year, wk) is None:
                    log.info("Archive für %s-W%s fehlt — generiere Snapshot", year, wk)
                    payload = await _build_weekly_payload(year, wk)
                    if await asyncio.to_thread(_write_archive, year, wk, payload):
                        log.info("Archive geschrieben: %s-W%s (alerts=%d)",
                                 year, wk, payload["summary"]["alerts_total"])
        except Exception as exc:                            # noqa: BLE001
            log.warning("Archive-Loop tick failed: %s", exc)
        # 1 h warten — feiner muss es nicht; die Lücke ist max. 60 min nach
        # Mo 00:00 UTC bevor der Snapshot landet.
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            log.info("Reports-Archive-Loop gestoppt")
            return


# ── CSV-Bundle ──────────────────────────────────────────────────────────────


def _csv_response(rows: list[dict], cols: list[str]) -> bytes:
    """Renders rows/cols zu CSV-Bytes (UTF-8). Cols-Reihenfolge ist die
    Spaltenreihenfolge im Output."""
    buf = io.StringIO()
    w   = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow({c: _safe_str(r.get(c)) for c in cols})
    return buf.getvalue().encode("utf-8")


def _to_csv_zip(payload: dict, year: int, week: int) -> StreamingResponse:
    """ZIP mit einer CSV pro Tabelle. Filenames sprechend, damit Excel/
    PowerBI den Inhalt direkt erkennt."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Header-Summary als kleine CSV (Key/Value).
        summary_rows = [
            {"key": "year",            "value": payload["week"]["year"]},
            {"key": "week",            "value": payload["week"]["week"]},
            {"key": "from",            "value": payload["week"]["from"]},
            {"key": "to",              "value": payload["week"]["to"]},
            {"key": "alerts_total",    "value": payload["summary"]["alerts_total"]},
            {"key": "critical",        "value": payload["summary"]["by_severity"]["critical"]},
            {"key": "high",            "value": payload["summary"]["by_severity"]["high"]},
            {"key": "medium",          "value": payload["summary"]["by_severity"]["medium"]},
            {"key": "low",             "value": payload["summary"]["by_severity"]["low"]},
            {"key": "headline",        "value": payload["summary"]["headline"]},
        ]
        zf.writestr("summary.csv", _csv_response(summary_rows, ["key", "value"]))
        zf.writestr("daily.csv", _csv_response(
            payload["detection"]["daily"],
            ["date", "critical", "high", "medium", "low"],
        ))
        zf.writestr("top_rules.csv", _csv_response(
            payload["detection"]["top_rules"],
            ["rule_id", "source", "severity", "count", "description"],
        ))
        zf.writestr("top_sources.csv", _csv_response(
            payload["detection"]["top_sources"],
            ["src_ip", "display_name", "hostname", "max_severity", "count"],
        ))
        zf.writestr("top_external_dests.csv", _csv_response(
            payload["detection"]["top_external_dests"],
            ["dst_ip", "country", "country_code", "asn", "count"],
        ))
        zf.writestr("taps.csv", _csv_response(
            payload["ops"]["taps"],
            ["name", "site", "status", "last_seen", "alerts_week"],
        ))
        zf.writestr("suricata_top.csv", _csv_response(
            payload["ops"]["suricata_top_sids"],
            ["sid", "count"],
        ))
        zf.writestr("ml.csv", _csv_response(
            [payload["ops"]["ml"]],
            ["fp_marked", "tp_marked", "tuner_cycles"],
        ))
        # Boundary-Bereich: Summary als Key/Value, Top-Talker + Top-Pairs als Tabellen.
        b = payload.get("boundary") or {}
        bp = b.get("by_priority") or {}
        zf.writestr("boundary_summary.csv", _csv_response(
            [
                {"key": "total",       "value": b.get("total", 0)},
                {"key": "whitelisted", "value": b.get("whitelisted", 0)},
                {"key": "P0",          "value": bp.get("P0", 0)},
                {"key": "P1",          "value": bp.get("P1", 0)},
                {"key": "P2",          "value": bp.get("P2", 0)},
                {"key": "P3",          "value": bp.get("P3", 0)},
            ],
            ["key", "value"],
        ))
        zf.writestr("boundary_top_talkers.csv", _csv_response(
            b.get("top_talkers") or [],
            ["src_ip", "display_name", "hostname", "count", "top_priority"],
        ))
        zf.writestr("boundary_top_pairs.csv", _csv_response(
            b.get("top_pairs") or [],
            ["src_ip", "dst_ip", "dst_country", "dst_country_code", "dst_asn", "count", "top_priority"],
        ))
        # Zone-Aufschlüsselung als Long-Form CSV (eine Zeile pro Zell-Treffer).
        bz_rows = [
            {"src_zone": k.split("/", 1)[0], "dst_zone": k.split("/", 1)[1], "count": v}
            for k, v in (b.get("by_zone") or {}).items()
        ]
        if b.get("unzoned"):
            bz_rows.append({"src_zone": "—", "dst_zone": "—", "count": b["unzoned"]})
        zf.writestr("boundary_by_zone.csv", _csv_response(
            bz_rows,
            ["src_zone", "dst_zone", "count"],
        ))
        zf.writestr("audit_active_users.csv", _csv_response(
            payload["audit"]["active_users"],
            ["username", "last_login"],
        ))

    buf.seek(0)
    fname = f"cyjan-weekly-{year}-W{week:02d}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
