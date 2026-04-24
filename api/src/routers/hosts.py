"""
Host-Management API.

Endpunkte:
  GET    /api/hosts              – alle bekannten Hosts (Filter: trusted, search)
  GET    /api/hosts/{ip}         – einzelner Host
  POST   /api/hosts              – Host manuell anlegen / aktualisieren
  PUT    /api/hosts/{ip}         – display_name oder trusted-Flag ändern
  DELETE /api/hosts/{ip}         – Host aus host_info entfernen
  POST   /api/hosts/import/csv   – CSV-Import (Hostname;IP-Adresse, Semikolon-getrennt)

CSV-Format:
  Hostname;IP-Adresse
  router.local;192.168.1.1
  # Kommentarzeilen und Leerzeilen werden ignoriert
  printer;10.0.0.5
"""
from __future__ import annotations

import csv
import io
import logging
from typing import Annotated

import asyncpg
import redis as redis_lib
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File

from config import Config
from database import get_pool
from models import HostCreate, HostResponse, HostUpdate

log = logging.getLogger(__name__)
_cfg = Config.from_env()


def _invalidate_enrichment_cache(ip: str) -> None:
    """Löscht den Enrichment-Cache-Eintrag für eine IP damit der nächste Alert
    frische Trust/display_name-Daten aus der DB liest."""
    try:
        r = redis_lib.from_url(_cfg.redis_url, socket_timeout=2)
        r.delete(f"enrichment:{ip}")
    except Exception as exc:
        log.debug("Cache invalidation failed for %s: %s", ip, exc)

router = APIRouter(prefix="/api/hosts", tags=["hosts"])


def _row_to_host(row: asyncpg.Record) -> HostResponse:
    return HostResponse(
        ip=str(row["ip"]),
        hostname=row["hostname"],
        display_name=row["display_name"],
        trusted=row["trusted"],
        trust_source=row["trust_source"],
        asn=dict(row["asn"]) if row["asn"] else None,
        geo=dict(row["geo"]) if row["geo"] else None,
        ping_ms=row["ping_ms"],
        last_seen=row["last_seen"],
        updated_at=row["updated_at"],
    )


@router.get("/unknown", summary="IPs aus Alerts ohne bekannten Host-Eintrag")
async def list_unknown_hosts(
    days:  int            = 30,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    pool:  asyncpg.Pool   = Depends(get_pool),
) -> list[dict]:
    """IPs die in Alerts aufgetaucht sind, aber keinen host_info-Eintrag
    mit Hostname oder Display-Name haben."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            WITH alert_ips AS (
                SELECT DISTINCT ip FROM (
                    SELECT src_ip AS ip FROM alerts
                    WHERE src_ip IS NOT NULL AND is_test = false
                      AND ts > NOW() - ($1 || ' days')::interval
                    UNION
                    SELECT dst_ip AS ip FROM alerts
                    WHERE dst_ip IS NOT NULL AND is_test = false
                      AND ts > NOW() - ($1 || ' days')::interval
                ) t
            ),
            unknown AS (
                SELECT ai.ip FROM alert_ips ai
                WHERE NOT EXISTS (
                    SELECT 1 FROM host_info h
                    WHERE h.ip = ai.ip
                      AND (h.hostname IS NOT NULL OR h.display_name IS NOT NULL)
                )
            )
            SELECT
                u.ip::text                       AS ip,
                COUNT(DISTINCT a.alert_id)::int  AS alert_count,
                MAX(a.ts)                        AS last_seen,
                MIN(a.ts)                        AS first_seen,
                MODE() WITHIN GROUP (ORDER BY a.severity) AS top_severity
            FROM unknown u
            JOIN alerts a ON (a.src_ip = u.ip OR a.dst_ip = u.ip)
              AND a.is_test = false
              AND a.ts > NOW() - ($1 || ' days')::interval
            GROUP BY u.ip
            ORDER BY alert_count DESC, last_seen DESC
            LIMIT $2
            """,
            days, limit,
        )
    return [
        {
            "ip":          r["ip"],
            "alert_count": r["alert_count"],
            "last_seen":   r["last_seen"].isoformat() if r["last_seen"] else None,
            "first_seen":  r["first_seen"].isoformat() if r["first_seen"] else None,
            "top_severity": r["top_severity"],
        }
        for r in rows
    ]


@router.get("", response_model=list[HostResponse])
async def list_hosts(
    trusted: bool | None = None,
    search:  str | None  = None,
    limit:   Annotated[int, Query(ge=1, le=1000)] = 200,
    pool:    asyncpg.Pool = Depends(get_pool),
) -> list[HostResponse]:
    filters: list[str] = []
    params:  list      = []
    idx = 1

    if trusted is not None:
        filters.append(f"trusted = ${idx}"); params.append(trusted); idx += 1
    if search:
        filters.append(
            f"(ip::text ILIKE ${idx} OR hostname ILIKE ${idx} OR display_name ILIKE ${idx})"
        )
        params.append(f"%{search}%"); idx += 1

    where = ("WHERE " + " AND ".join(filters)) if filters else ""

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT ip, hostname, display_name, trusted, trust_source,
                   asn, geo, ping_ms, last_seen, updated_at
            FROM host_info
            {where}
            ORDER BY trusted DESC, last_seen DESC NULLS LAST
            LIMIT ${idx}
            """,
            *params, limit,
        )
    return [_row_to_host(r) for r in rows]


@router.get("/{ip}", response_model=HostResponse)
async def get_host(ip: str, pool: asyncpg.Pool = Depends(get_pool)) -> HostResponse:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM host_info WHERE ip = $1::inet", ip
        )
    if not row:
        raise HTTPException(status_code=404, detail="Host not found")
    return _row_to_host(row)


@router.post("", response_model=HostResponse, status_code=201)
async def create_host(
    body: HostCreate,
    pool: asyncpg.Pool = Depends(get_pool),
) -> HostResponse:
    """
    Legt einen Host an oder aktualisiert ihn.
    Bei trust_source='manual': trusted wird immer auf true gesetzt.
    Überschreibt nur display_name und Trust-Felder, nicht DNS/Geo-Daten
    die der Enrichment-Service setzt.
    """
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO host_info (ip, display_name, trusted, trust_source, updated_at)
                VALUES ($1::inet, $2, $3, $4, now())
                ON CONFLICT (ip) DO UPDATE SET
                  display_name  = COALESCE(EXCLUDED.display_name, host_info.display_name),
                  trusted       = GREATEST(host_info.trusted::int, EXCLUDED.trusted::int)::boolean,
                  trust_source  = CASE
                    WHEN host_info.trusted AND host_info.trust_source = 'manual' THEN 'manual'
                    ELSE EXCLUDED.trust_source
                  END,
                  updated_at    = now()
                RETURNING *
                """,
                body.ip, body.display_name, body.trusted, body.trust_source,
            )
    except asyncpg.InvalidTextRepresentationError:
        raise HTTPException(status_code=422, detail="Invalid IP address format")
    _invalidate_enrichment_cache(body.ip)
    return _row_to_host(row)


@router.put("/{ip}", response_model=HostResponse)
async def update_host(
    ip:   str,
    body: HostUpdate,
    pool: asyncpg.Pool = Depends(get_pool),
) -> HostResponse:
    """Aktualisiert display_name und/oder trusted-Flag."""
    sets:   list[str] = ["updated_at = now()"]
    params: list      = []
    idx = 1

    if body.display_name is not None:
        sets.append(f"display_name = ${idx}"); params.append(body.display_name); idx += 1
    if body.trusted is not None:
        sets.append(f"trusted = ${idx}");      params.append(body.trusted);      idx += 1
        sets.append(f"trust_source = ${idx}"); params.append("manual");          idx += 1

    if len(sets) == 1:
        raise HTTPException(status_code=422, detail="No fields to update")

    params.append(ip)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"UPDATE host_info SET {', '.join(sets)} WHERE ip = ${idx}::inet RETURNING *",
            *params,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Host not found")
    _invalidate_enrichment_cache(ip)
    return _row_to_host(row)


@router.delete("/{ip}", status_code=204, response_model=None)
async def delete_host(ip: str, pool: asyncpg.Pool = Depends(get_pool)) -> None:
    async with pool.acquire() as conn:
        result = await conn.execute("DELETE FROM host_info WHERE ip = $1::inet", ip)
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Host not found")


@router.get("/example.csv")
async def hosts_example_csv():
    """Beispiel-CSV zum Download – zeigt das erwartete Format."""
    content = (
        "# Bekannte Hosts – Cyjan IDS\n"
        "# Spalten: hostname;ip  (oder ip;hostname – Reihenfolge wird automatisch erkannt)\n"
        "# Trennzeichen: Semikolon oder Komma\n"
        "# Zeilen die mit # beginnen sowie Leerzeilen werden ignoriert.\n"
        "hostname;ip\n"
        "router.local;192.168.1.1\n"
        "fileserver;192.168.1.10\n"
        "printer-flur;192.168.1.20\n"
        "dc01.corp.example.com;10.0.0.5\n"
        "# IPv6 wird ebenfalls unterstützt\n"
        "ipv6-host;2001:db8::1\n"
    )
    from fastapi.responses import Response
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="hosts_example.csv"'},
    )


@router.post("/import/csv", response_model=dict)
async def import_csv(
    file: UploadFile = File(...),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    """
    CSV-Import: Hostname;IP-Adresse (Semikolon-getrennt).
    Unterstützt auch Komma als Trennzeichen.
    Leerzeilen und Zeilen die mit # beginnen werden ignoriert.
    Header-Zeile wird automatisch erkannt und übersprungen.

    Gibt { imported, skipped, errors } zurück.
    """
    content = await file.read()
    try:
        text = content.decode("utf-8-sig")  # BOM tolerant
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    # Trennzeichen ermitteln
    sample = text[:2048]
    delimiter = ";" if sample.count(";") >= sample.count(",") else ","

    reader = csv.reader(io.StringIO(text), delimiter=delimiter)

    imported = 0
    skipped  = 0
    errors:  list[str] = []

    async with pool.acquire() as conn:
        for lineno, row in enumerate(reader, start=1):
            # Leerzeilen und Kommentare
            if not row or (row[0].strip().startswith("#")):
                continue

            # Header-Zeile überspringen (keine gültige IP in Spalte 1 oder 2)
            cleaned = [c.strip() for c in row]
            if len(cleaned) < 2:
                skipped += 1
                continue

            # Spalten-Reihenfolge erkennen: Hostname;IP oder IP;Hostname
            col_a, col_b = cleaned[0], cleaned[1]
            hostname, ip_str = _detect_order(col_a, col_b)
            if not ip_str:
                # Header oder unbekanntes Format
                skipped += 1
                continue

            try:
                await conn.execute(
                    """
                    INSERT INTO host_info (ip, hostname, display_name, trusted, trust_source, updated_at)
                    VALUES ($1::inet, $2, $2, true, 'csv', now())
                    ON CONFLICT (ip) DO UPDATE SET
                      hostname      = EXCLUDED.hostname,
                      display_name  = COALESCE(host_info.display_name, EXCLUDED.display_name),
                      trusted       = true,
                      trust_source  = CASE
                        WHEN host_info.trust_source = 'manual' THEN 'manual'
                        ELSE 'csv'
                      END,
                      updated_at    = now()
                    """,
                    ip_str, hostname,
                )
                _invalidate_enrichment_cache(ip_str)
                imported += 1
            except Exception as exc:
                errors.append(f"Zeile {lineno}: {exc}")

    return {"imported": imported, "skipped": skipped, "errors": errors[:20]}


def _detect_order(a: str, b: str) -> tuple[str, str | None]:
    """
    Versucht IP- und Hostname-Spalte zu identifizieren.
    Gibt (hostname, ip_str) zurück; ip_str=None wenn keine IP erkannt.
    """
    import ipaddress

    def is_ip(s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    if is_ip(b):
        return a, b   # Format: Hostname;IP
    if is_ip(a):
        return b, a   # Format: IP;Hostname
    return a, None    # Kein IP in beiden Spalten (z.B. Header)
