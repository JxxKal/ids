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
import re
import time
from datetime import datetime, timezone
from typing import Annotated

import asyncpg
import redis as redis_lib
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File

from config import Config
from database import get_pool
from deps import require_admin
from models import (
    HostCreate, HostResponse, HostRoleUpdate, HostUpdate,
    CustomRolePort, CustomRoleUpsert, CustomRoleResponse,
)
from role_catalog import load_catalog

log = logging.getLogger(__name__)
_cfg = Config.from_env()


# Ein wiederverwendeter Redis-Client (mit interner Connection-Pool) statt pro
# Cache-Invalidation eine neue Verbindung aufzumachen — unter Last sonst
# FD-/Socket-Verschleiß.
_redis_client: redis_lib.Redis | None = None


def _redis() -> redis_lib.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis_lib.from_url(
            _cfg.redis_url, socket_timeout=2, socket_connect_timeout=2,
        )
    return _redis_client


def _invalidate_enrichment_cache(ip: str) -> None:
    """Löscht den Enrichment-Cache-Eintrag für eine IP damit der nächste Alert
    frische Trust/display_name-Daten aus der DB liest."""
    global _redis_client
    try:
        _redis().delete(f"enrichment:{ip}")
    except Exception as exc:
        log.debug("Cache invalidation failed for %s: %s", ip, exc)
        _redis_client = None  # kaputte Verbindung verwerfen → nächster Call baut neu

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
        # detected_roles ist JSONB; asyncpg liefert es bereits als dict
        # (jsonb-Codec). NULL ⇒ Host nie evaluiert.
        detected_roles=dict(row["detected_roles"]) if row["detected_roles"] else None,
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
                      AND ts > NOW() - (make_interval(days := $1))
                    UNION
                    SELECT dst_ip AS ip FROM alerts
                    WHERE dst_ip IS NOT NULL AND is_test = false
                      AND ts > NOW() - (make_interval(days := $1))
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
              AND a.ts > NOW() - (make_interval(days := $1))
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


_CUSTOM_ID_RE = re.compile(r"^custom_[a-z0-9_]{1,40}$")


def _ports_to_specs(ports: list[CustomRolePort]) -> list[dict]:
    """CustomRolePort[] → match-Port-Specs (Einzelport oder {from,to}-Range)."""
    specs: list[dict] = []
    for p in ports:
        if p.port_from is not None and p.port_to is not None:
            a, b = p.port_from, p.port_to
            specs.append({"from": min(a, b), "to": max(a, b), "proto": p.proto})
        elif p.port is not None:
            specs.append({"port": p.port, "proto": p.proto})
    return specs


def _build_match(body: CustomRoleUpsert) -> dict:
    specs = _ports_to_specs(body.ports)
    if not specs:
        raise HTTPException(422, "Mindestens ein gültiger Port oder Range nötig")
    if body.mode == "all":
        return {"required_ports": specs, "any_ports": {"min_any": 0, "ports": []}}
    return {"required_ports": [], "any_ports": {"min_any": body.min_any, "ports": specs}}


def _match_to_view(match: dict):
    """match-Block → (mode, min_any, ports[]) für den Editor."""
    req = match.get("required_ports") or []
    anyb = match.get("any_ports") or {}
    anyp = anyb.get("ports") or []
    if anyp and not req:
        mode, specs, min_any = "any", anyp, int(anyb.get("min_any", 1) or 1)
    else:
        mode, specs, min_any = "all", req, 1
    ports: list[CustomRolePort] = []
    for s in specs:
        if s.get("from") is not None and s.get("to") is not None:
            ports.append(CustomRolePort(port_from=s["from"], port_to=s["to"],
                                        proto=s.get("proto", "TCP")))
        elif s.get("port") is not None:
            ports.append(CustomRolePort(port=s["port"], proto=s.get("proto", "TCP")))
    return mode, min_any, ports


@router.get("/role-catalog", summary="Verfügbare Host-Rollen (id/label/category)")
async def get_role_catalog(pool: asyncpg.Pool = Depends(get_pool)) -> list[dict]:
    """Liefert den Rollen-Katalog für die GUI (Rollen-Filter + manuelle
    Zuweisung). Quelle: Built-in-Katalog-YAMLs (role_catalog.py) + aktivierte
    Custom-Rollen aus host_role_custom."""
    cat = load_catalog()
    try:
        rows = await pool.fetch(
            "SELECT id, label, category FROM host_role_custom WHERE enabled = true ORDER BY label"
        )
        builtin_ids = {c["id"] for c in cat}
        for r in rows:
            if r["id"] not in builtin_ids:
                cat.append({"id": r["id"], "label": r["label"], "category": r["category"]})
    except asyncpg.UndefinedTableError:
        pass   # Migration 029 noch nicht eingespielt.
    except Exception as exc:
        log.warning("Custom-Rollen für Katalog laden fehlgeschlagen: %s", exc)
    return cat


@router.get("/role-catalog/custom", response_model=list[CustomRoleResponse],
            summary="Custom-Rollen (volle Definition, Admin)")
async def list_custom_roles(
    user: dict = Depends(require_admin), pool: asyncpg.Pool = Depends(get_pool),
) -> list[CustomRoleResponse]:
    rows = await pool.fetch(
        """SELECT id, label, category, match, min_flows_per_port, base_confidence, enabled
             FROM host_role_custom ORDER BY label"""
    )
    out: list[CustomRoleResponse] = []
    for r in rows:
        m = r["match"] if isinstance(r["match"], dict) else {}
        mode, min_any, ports = _match_to_view(m)
        out.append(CustomRoleResponse(
            id=r["id"], label=r["label"], category=r["category"], ports=ports,
            mode=mode, min_any=min_any, base_confidence=float(r["base_confidence"]),
            min_flows_per_port=int(r["min_flows_per_port"]), enabled=r["enabled"],
        ))
    return out


@router.put("/role-catalog/custom/{role_id}", response_model=CustomRoleResponse,
            summary="Custom-Rolle anlegen/ändern (Admin)")
async def upsert_custom_role(
    role_id: str, body: CustomRoleUpsert,
    user: dict = Depends(require_admin), pool: asyncpg.Pool = Depends(get_pool),
) -> CustomRoleResponse:
    if not _CUSTOM_ID_RE.match(role_id):
        raise HTTPException(422, "id muss dem Muster custom_[a-z0-9_] entsprechen")
    match = _build_match(body)
    # match als dict direkt — die api-Pool hat einen jsonb-Codec registriert.
    await pool.execute(
        """
        INSERT INTO host_role_custom
            (id, label, category, match, min_flows_per_port, base_confidence,
             enabled, created_by, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
        ON CONFLICT (id) DO UPDATE
          SET label=EXCLUDED.label, category=EXCLUDED.category, match=EXCLUDED.match,
              min_flows_per_port=EXCLUDED.min_flows_per_port,
              base_confidence=EXCLUDED.base_confidence, enabled=EXCLUDED.enabled,
              updated_at=now()
        """,
        role_id, body.label, body.category, match, body.min_flows_per_port,
        body.base_confidence, body.enabled,
        user.get("username") or user.get("sub") or "admin",
    )
    return CustomRoleResponse(
        id=role_id, label=body.label, category=body.category, ports=body.ports,
        mode=body.mode, min_any=body.min_any, base_confidence=body.base_confidence,
        min_flows_per_port=body.min_flows_per_port, enabled=body.enabled,
    )


@router.delete("/role-catalog/custom/{role_id}", status_code=204, response_model=None,
               summary="Custom-Rolle löschen (Admin)")
async def delete_custom_role(
    role_id: str, user: dict = Depends(require_admin), pool: asyncpg.Pool = Depends(get_pool),
) -> None:
    res = await pool.execute("DELETE FROM host_role_custom WHERE id=$1", role_id)
    if res.endswith(" 0"):
        raise HTTPException(404, "Custom-Rolle nicht gefunden")


@router.get("", response_model=list[HostResponse])
async def list_hosts(
    trusted: bool | None = None,
    search:  str | None  = None,
    role:    str | None  = Query(None, description="Filter auf eine erkannte/gesetzte Rolle"),
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
    if role:
        # JSONB-Key-Existenz: detected_roles->'roles' enthält die role_id als Key.
        filters.append(f"(detected_roles->'roles') ? ${idx}")
        params.append(role); idx += 1

    where = ("WHERE " + " AND ".join(filters)) if filters else ""

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT ip, hostname, display_name, trusted, trust_source,
                   asn, geo, ping_ms, last_seen, updated_at, detected_roles
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


async def _known_role_id(pool: asyncpg.Pool, role_id: str) -> bool:
    """True, wenn role_id eine Built-in- oder aktivierte Custom-Rolle ist —
    dieselbe Quelle wie /role-catalog. Verhindert, dass ein Tippfehler beim
    manuellen Setzen eine dauerhaft gelockte Phantom-Rolle anlegt."""
    for c in load_catalog():
        if c.get("id") == role_id:
            return True
    try:
        row = await pool.fetchrow(
            "SELECT 1 FROM host_role_custom WHERE id = $1 AND enabled = true", role_id,
        )
        return row is not None
    except asyncpg.UndefinedTableError:
        return False   # Migration 029 noch nicht eingespielt — nur Built-ins.


@router.put("/{ip}/roles", response_model=HostResponse)
async def update_host_roles(
    ip:   str,
    body: HostRoleUpdate,
    user: dict           = Depends(require_admin),
    pool: asyncpg.Pool   = Depends(get_pool),
) -> HostResponse:
    """Manuelle Rollen-Korrektur (set/reset/remove) — siehe Contract §4.

    Wir nehmen die host_info-Zeile per ``SELECT ... FOR UPDATE`` in die
    Transaktion, damit ein paralleler Detektor-Cycle (alleiniger sonstiger
    Schreiber von detected_roles) nicht zwischen Read und Write reingrätscht.
    """
    role_id = body.role_id
    now_iso = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    # action=set legt eine manuell gelockte Rolle an — role_id muss im Katalog
    # existieren, sonst entstehen durch Tippfehler dauerhafte Phantom-Rollen.
    # Vor der FOR-UPDATE-Transaktion validieren (load_catalog liest Dateien —
    # nicht unter gehaltener Zeilensperre laufen lassen). reset/remove/suppress
    # dürfen weiterhin beliebige role_ids adressieren (Cleanup entfernter Rollen).
    if body.action == "set" and not await _known_role_id(pool, role_id):
        raise HTTPException(status_code=400, detail=f"Unbekannte Rolle-ID: {role_id}")

    async with pool.acquire() as conn:
        async with conn.transaction():
            try:
                row = await conn.fetchrow(
                    "SELECT detected_roles FROM host_info WHERE ip = $1::inet FOR UPDATE",
                    ip,
                )
            except asyncpg.InvalidTextRepresentationError:
                raise HTTPException(status_code=422, detail="Invalid IP address format")
            if not row:
                raise HTTPException(status_code=404, detail="Host not found")

            # detected_roles=NULL ⇒ Host nie evaluiert; mit leerem Shape starten.
            dr = dict(row["detected_roles"]) if row["detected_roles"] else {}
            roles  = dict(dr.get("roles")  or {})
            manual = dict(dr.get("manual") or {})

            if body.action == "set":
                # Rolle manuell setzen + locken. Vorhandene auto-Evidenz bleibt
                # erhalten, source/confidence werden auf manuell überschrieben.
                existing = dict(roles.get(role_id) or {})
                existing.update({
                    "source":     "manual",
                    "confidence": 1.0,
                })
                roles[role_id] = existing
                manual[role_id] = {
                    "locked":  True,
                    "set_by":  user.get("username") or user.get("sub") or "admin",
                    "set_at":  now_iso,
                }

            elif body.action == "reset":
                # Lock ODER Suppress aufheben → nächster Detektor-Cycle
                # übernimmt die Rolle wieder. Wenn die Rolle aktuell als manual
                # existiert, source zurück auf auto stellen; entfernen darf nur
                # der Detektor. (Bei aufgehobenem Suppress ist role_id nicht in
                # roles → der Detektor fügt sie beim nächsten Match neu hinzu.)
                manual.pop(role_id, None)
                if role_id in roles:
                    entry = dict(roles[role_id])
                    entry["source"] = "auto"
                    roles[role_id] = entry

            elif body.action == "remove":
                # auto-Rolle einmalig entfernen (kein Lock). Den manual-Lock
                # nehmen wir gleich mit raus, falls vorhanden.
                roles.pop(role_id, None)
                manual.pop(role_id, None)

            elif body.action == "suppress":
                # Negativ-Lock: Rolle dauerhaft unterdrücken. Rolle aus dem
                # aktiven Set raus + manual[id].suppressed=true — der Detektor
                # fügt sie nie wieder hinzu (matcher überspringt suppressed).
                roles.pop(role_id, None)
                manual[role_id] = {
                    "suppressed": True,
                    "set_by":     user.get("username") or user.get("sub") or "admin",
                    "set_at":     now_iso,
                }

            dr["roles"]  = roles
            dr["manual"] = manual
            # evaluated_at bleibt Sache des Detektors (Contract §1) — hier nicht
            # fabrizieren; ein nie-evaluierter Host hat schlicht keins.

            # dict direkt — jsonb-Codec, KEIN json.dumps + ::jsonb.
            updated = await conn.fetchrow(
                """
                UPDATE host_info
                   SET detected_roles = $2, updated_at = now()
                 WHERE ip = $1::inet
                RETURNING ip, hostname, display_name, trusted, trust_source,
                          asn, geo, ping_ms, last_seen, updated_at, detected_roles
                """,
                ip, dr,
            )

    return _row_to_host(updated)


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


# ── Connections-View für einen Host ───────────────────────────────────────────
# Aggregiert alle Flows + Alerts wo `src_ip = ip` ODER `dst_ip = ip` über ein
# Zeitfenster, gruppiert nach Peer. Plus 60-Bucket-Histogramm für die Sparkline
# unter dem Time-Slider im Frontend.
#
# Query-Strategie: drei Queries parallel, in Python zusammengefügt – sauberer
# als ein 80-Zeilen-CTE-Monster und erlaubt es uns, Severity-Ranking und
# Top-Ports-Sortierung auf der Python-Seite zu machen, wo das nochmal
# wartbarer ist.

_WINDOW_PRESETS = {
    "15m":  900,
    "1h":   3600,
    "6h":   21600,
    "24h":  86400,
}
_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_SEV_INV  = {v: k for k, v in _SEV_RANK.items()}


@router.get(
    "/{ip}/connections",
    summary="Alle Verbindungen eines Hosts in einem Zeitfenster (für Drawer-Visualisierung)",
)
async def get_host_connections(
    ip:     str,
    window: str            = Query("1h", description=f"Preset: {','.join(_WINDOW_PRESETS)}"),
    until:  int | None     = Query(None, description="Unix-Sekunden, Default = now"),
    pool:   asyncpg.Pool   = Depends(get_pool),
) -> dict:
    if window not in _WINDOW_PRESETS:
        raise HTTPException(400, f"window muss eins von {list(_WINDOW_PRESETS)} sein")

    win_sec = _WINDOW_PRESETS[window]

    async with pool.acquire() as conn:
        # Validation des IP-Strings: Cast nach inet im SQL-Layer hebt
        # ungültige Eingaben sofort als InvalidTextRepresentation.
        try:
            await conn.fetchval("SELECT $1::inet", ip)
        except (asyncpg.exceptions.InvalidTextRepresentationError, ValueError) as exc:
            raise HTTPException(400, f"Ungültige IP: {exc}") from exc

        # Window-Grenzen + Bucket-Größe (60 Buckets über das Fenster) als
        # Server-seitige Werte – damit das Frontend keinen until-Parameter
        # senden muss um konsistente Buckets zu kriegen, sondern einfach
        # `now()` der DB nimmt.
        until_ts_sql = "to_timestamp($2)" if until else "now()"
        params: list = [ip]
        if until:
            params.append(until)

        # ── Peers ──────────────────────────────────────────────────────────
        peer_rows = await conn.fetch(
            f"""
            WITH params AS (
                SELECT
                    $1::inet                                AS host_ip,
                    {until_ts_sql}                          AS w_end,
                    {until_ts_sql} - INTERVAL '{win_sec} seconds' AS w_start
            )
            SELECT
                CASE WHEN f.src_ip = p.host_ip THEN f.dst_ip ELSE f.src_ip END
                                                                    AS peer_ip,
                COUNT(*)                                            AS flow_count,
                SUM(f.byte_count)::bigint                           AS total_bytes,
                SUM(CASE WHEN f.src_ip = p.host_ip
                          THEN f.byte_count ELSE 0 END)::bigint    AS bytes_out,
                SUM(CASE WHEN f.dst_ip = p.host_ip
                          THEN f.byte_count ELSE 0 END)::bigint    AS bytes_in,
                bool_or(f.src_ip = p.host_ip)                      AS has_out,
                bool_or(f.dst_ip = p.host_ip)                      AS has_in
            FROM flows f, params p
            WHERE (f.src_ip = p.host_ip OR f.dst_ip = p.host_ip)
              AND f.start_ts >= p.w_start
              AND f.start_ts <  p.w_end
            GROUP BY peer_ip
            ORDER BY total_bytes DESC NULLS LAST
            LIMIT 100
            """,
            *params,
        )

        # ── Top-Ports pro Peer (separate Query, in Python aggregiert) ────
        port_rows = await conn.fetch(
            f"""
            WITH params AS (
                SELECT
                    $1::inet                                AS host_ip,
                    {until_ts_sql}                          AS w_end,
                    {until_ts_sql} - INTERVAL '{win_sec} seconds' AS w_start
            )
            SELECT
                CASE WHEN f.src_ip = p.host_ip THEN f.dst_ip ELSE f.src_ip END AS peer_ip,
                CASE WHEN f.src_ip = p.host_ip THEN f.dst_port ELSE f.src_port END AS peer_port,
                f.proto                                            AS proto,
                COUNT(*)                                           AS cnt
            FROM flows f, params p
            WHERE (f.src_ip = p.host_ip OR f.dst_ip = p.host_ip)
              AND f.start_ts >= p.w_start
              AND f.start_ts <  p.w_end
              AND ((f.src_ip = p.host_ip AND f.dst_port IS NOT NULL)
                OR (f.dst_ip = p.host_ip AND f.src_port IS NOT NULL))
            GROUP BY peer_ip, peer_port, proto
            ORDER BY peer_ip, cnt DESC
            """,
            *params,
        )

        # ── Alerts pro Peer ───────────────────────────────────────────────
        alert_rows = await conn.fetch(
            f"""
            WITH params AS (
                SELECT
                    $1::inet                                AS host_ip,
                    {until_ts_sql}                          AS w_end,
                    {until_ts_sql} - INTERVAL '{win_sec} seconds' AS w_start
            )
            SELECT
                CASE WHEN a.src_ip = p.host_ip THEN a.dst_ip ELSE a.src_ip END AS peer_ip,
                COUNT(*)                                              AS alert_count,
                MAX(CASE a.severity
                        WHEN 'low' THEN 1 WHEN 'medium' THEN 2
                        WHEN 'high' THEN 3 WHEN 'critical' THEN 4
                        ELSE 0 END)                                   AS sev_rank
            FROM alerts a, params p
            WHERE (a.src_ip = p.host_ip OR a.dst_ip = p.host_ip)
              AND a.is_test = false
              AND a.ts >= p.w_start
              AND a.ts <  p.w_end
              AND (a.src_ip = p.host_ip AND a.dst_ip IS NOT NULL
                OR a.dst_ip = p.host_ip AND a.src_ip IS NOT NULL)
            GROUP BY peer_ip
            """,
            *params,
        )

        # ── Histogramm: 60 Buckets über das Fenster ──────────────────────
        bucket_sec = max(1, win_sec // 60)
        hist_rows = await conn.fetch(
            f"""
            WITH params AS (
                SELECT
                    $1::inet                                AS host_ip,
                    {until_ts_sql}                          AS w_end,
                    {until_ts_sql} - INTERVAL '{win_sec} seconds' AS w_start
            )
            SELECT
                EXTRACT(EPOCH FROM time_bucket(INTERVAL '{bucket_sec} seconds',
                                               f.start_ts))::bigint AS bucket_ts,
                COUNT(*)                                  AS flow_count,
                SUM(f.byte_count)::bigint                 AS bytes
            FROM flows f, params p
            WHERE (f.src_ip = p.host_ip OR f.dst_ip = p.host_ip)
              AND f.start_ts >= p.w_start
              AND f.start_ts <  p.w_end
            GROUP BY bucket_ts
            ORDER BY bucket_ts
            """,
            *params,
        )

    # Window-Grenzen Python-seitig ausrechnen – früher als DB-Query, gestolpert
    # über asyncpg "server expects 0 arguments, 1 was passed" weil das SQL kein
    # $1 referenzierte aber `*params` mitbekam. Hier reicht local time.
    end_epoch   = int(until) if until else int(time.time())
    start_epoch = end_epoch - win_sec

    # ── Top-Ports + Alerts in das Peers-Dict mergen ──────────────────────
    peers_by_ip: dict[str, dict] = {}
    for r in peer_rows:
        peer_ip = str(r["peer_ip"])
        peers_by_ip[peer_ip] = {
            "ip":           peer_ip,
            "direction":    "both" if r["has_in"] and r["has_out"] else
                            "out"  if r["has_out"] else "in",
            "flow_count":   int(r["flow_count"]),
            "total_bytes":  int(r["total_bytes"] or 0),
            "bytes_in":     int(r["bytes_in"]    or 0),
            "bytes_out":    int(r["bytes_out"]   or 0),
            "top_ports":    [],
            "alert_count":  0,
            "max_severity": None,
        }

    # Top-Ports: bis zu 5 pro Peer (sind bereits cnt-DESC sortiert).
    for r in port_rows:
        ip_key = str(r["peer_ip"])
        if ip_key not in peers_by_ip:
            continue
        plist = peers_by_ip[ip_key]["top_ports"]
        if len(plist) >= 5:
            continue
        port = r["peer_port"]
        if port is None:
            continue
        plist.append({"port": int(port), "proto": r["proto"], "count": int(r["cnt"])})

    # Alerts pro Peer
    for r in alert_rows:
        ip_key = str(r["peer_ip"])
        if ip_key not in peers_by_ip:
            continue
        peers_by_ip[ip_key]["alert_count"]  = int(r["alert_count"])
        peers_by_ip[ip_key]["max_severity"] = _SEV_INV.get(int(r["sev_rank"] or 0))

    return {
        "ip":           ip,
        "window":       window,
        "window_sec":   win_sec,
        "window_start": start_epoch,
        "window_end":   end_epoch,
        "bucket_sec":   bucket_sec,
        "peers":        list(peers_by_ip.values()),
        "histogram":    [
            {"ts": int(r["bucket_ts"]), "flows": int(r["flow_count"]),
             "bytes": int(r["bytes"] or 0)}
            for r in hist_rows
        ],
    }
