"""
Wochenbericht — aggregierte Detection-/Operations-Sicht für eine ISO-Woche.

Phase 1 (on-demand, kein Archiv):
  GET /api/reports/weekly                 — aktuelle Woche, JSON
  GET /api/reports/weekly?week=2026-W18   — bestimmte Woche
  GET /api/reports/weekly?fmt=csv         — ZIP-Bundle mit CSVs

Read-only (kein admin nötig). Pure SQL-Aggregate über die Hypertable
`alerts` und ein paar Hilfstabellen — keine neuen DB-Strukturen, kein
Cron, kein Archiv. Phase 2 (Archivierung in MinIO + History-Liste +
Mail-Versand) kommt später.
"""
from __future__ import annotations

import csv
import io
import re
import zipfile
from datetime import date, datetime, timedelta, timezone

import asyncpg
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from database import get_pool

router = APIRouter(prefix="/api/reports", tags=["reports"])

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


@router.get("/weekly", summary="Wochenbericht (JSON oder CSV-ZIP)")
async def weekly_report(
    week: str | None = Query(default=None, description="ISO-Woche YYYY-Wnn (Default: aktuell)"),
    fmt:  str        = Query(default="json", regex="^(json|csv)$"),
):
    """Aggregierter Detection-/Operations-Bericht für eine ISO-Woche.

    Wenn `fmt=csv`, kommt ein ZIP zurück mit einer CSV pro Tabelle —
    direkt in Excel/PowerBI lesbar.
    """
    year, wk = _parse_week(week)
    t0, t1   = _week_bounds(year, wk)

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

    # _rank-Hilfsspalte aus top_sources entfernen (war nur internes Sort)
    top_sources = [{k: v for k, v in r.items() if not k.startswith("_")} for r in top_sources_raw]

    payload = {
        "week": {
            "year":      year,
            "week":      wk,
            "from":      t0.isoformat(),
            "to":        t1.isoformat(),
            "generated": datetime.now(timezone.utc).isoformat(),
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
        "audit": audit,
    }

    if fmt == "csv":
        return _to_csv_zip(payload, year, wk)
    return payload


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
