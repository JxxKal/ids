from __future__ import annotations

import csv
import io

import asyncpg
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import Response

from database import get_pool
from deps import require_admin
from models import NetworkCreate, NetworkResponse, NetworkUpdate
from sig_sync import sync_known_networks_file

router = APIRouter(prefix="/api/networks", tags=["networks"])


_VALID_KINDS = {"ot", "it"}


def _normalize_kind(kind: str | None, default: str = "ot") -> str:
    """Mappt eingehende kind-Werte auf das Set {ot, it}. Unbekannte/leere
    Werte fallen auf den Default zurück (per Default 'ot' — implizite Annahme
    aus pre-016)."""
    if not kind:
        return default
    k = kind.strip().lower()
    return k if k in _VALID_KINDS else default


@router.get("", response_model=list[NetworkResponse])
async def list_networks(pool: asyncpg.Pool = Depends(get_pool)) -> list[NetworkResponse]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, cidr, name, description, color, kind FROM known_networks ORDER BY name"
        )
    return [
        NetworkResponse(
            id=r["id"],
            cidr=str(r["cidr"]),
            name=r["name"],
            description=r["description"],
            color=r["color"],
            kind=r["kind"],
        )
        for r in rows
    ]


@router.post("", response_model=NetworkResponse, status_code=201)
async def create_network(
    body: NetworkCreate,
    pool: asyncpg.Pool = Depends(get_pool),
    _admin: dict = Depends(require_admin),
) -> NetworkResponse:
    kind = _normalize_kind(body.kind)
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO known_networks (cidr, name, description, color, kind)
                VALUES ($1::cidr, $2, $3, $4, $5)
                RETURNING id, cidr, name, description, color, kind
                """,
                body.cidr, body.name, body.description, body.color, kind,
            )
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=409, detail="CIDR already exists")
    except asyncpg.InvalidTextRepresentationError:
        raise HTTPException(status_code=422, detail="Invalid CIDR notation")
    await sync_known_networks_file(pool)
    return NetworkResponse(
        id=row["id"],
        cidr=str(row["cidr"]),
        name=row["name"],
        description=row["description"],
        color=row["color"],
        kind=row["kind"],
    )


@router.get("/example.csv")
async def networks_example_csv() -> Response:
    """Beispiel-CSV für Netzwerk-Import."""
    content = (
        "# Bekannte Netzwerke – Cyjan IDS\n"
        "# Spalten: cidr;name;description;color;kind\n"
        "#   cidr        – CIDR-Notation (Pflichtfeld), z.B. 192.168.1.0/24\n"
        "#   name        – Anzeigename (Pflichtfeld)\n"
        "#   description – Beschreibung (optional)\n"
        "#   color       – Hex-Farbe für die UI (optional), z.B. #3b82f6\n"
        "#   kind        – 'ot' oder 'it' (optional, Default 'ot')\n"
        "#                  ot = operational technology (IDS-Kern-Scope)\n"
        "#                  it = corporate-managed, nicht im OT-Scope\n"
        "# Trennzeichen: Semikolon oder Komma\n"
        "cidr;name;description;color;kind\n"
        "192.168.10.0/24;OT-Zellbereich-1;PLC-Segment;#3b82f6;ot\n"
        "192.168.20.0/24;OT-Zellbereich-2;HMI-Segment;#10b981;ot\n"
        "10.50.0.0/16;Office-Frankfurt;Bürotrakt FRA;#8b5cf6;it\n"
        "10.60.0.0/16;Office-Berlin;Bürotrakt BER;#f59e0b;it\n"
        "# Felder description, color und kind können leer bleiben — kind defaultet auf ot:\n"
        "10.10.0.0/16;Server-VLAN;;;\n"
    )
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="networks_example.csv"'},
    )


@router.post("/import/csv", response_model=dict)
async def import_networks_csv(
    file: UploadFile = File(...),
    pool: asyncpg.Pool = Depends(get_pool),
    _admin: dict = Depends(require_admin),
) -> dict:
    """
    CSV-Import für bekannte Netzwerke.
    Pflichtfelder: cidr, name
    Optional: description, color, kind (ot|it, Default 'ot')
    Trennzeichen: Semikolon oder Komma. Kommentare (#) und Leerzeilen werden ignoriert.
    Vorhandene Einträge mit gleicher CIDR werden aktualisiert (incl. kind, falls in CSV gesetzt).
    """
    content = await file.read()
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    sample    = text[:2048]
    delimiter = ";" if sample.count(";") >= sample.count(",") else ","
    reader    = csv.reader(io.StringIO(text), delimiter=delimiter)

    imported = 0
    skipped  = 0
    skipped_ot_priority = 0   # eigene Klasse: existing ot vs. incoming it → ot bleibt
    errors:  list[str] = []

    # Header-Spaltenpositionen ermitteln (case-insensitive)
    col_map: dict[str, int] = {}
    header_parsed = False

    async with pool.acquire() as conn:
        for lineno, row in enumerate(reader, start=1):
            if not row or row[0].strip().startswith("#"):
                continue
            cleaned = [c.strip() for c in row]

            # Header-Zeile erkennen: enthält "cidr" oder "name" (kein Netzwerk-Eintrag)
            if not header_parsed:
                lower = [c.lower() for c in cleaned]
                if "cidr" in lower or "name" in lower:
                    for i, h in enumerate(lower):
                        col_map[h] = i
                    header_parsed = True
                    continue
                # Keine Header-Zeile: Standard-Reihenfolge annehmen (kind als 5. Spalte)
                col_map = {"cidr": 0, "name": 1, "description": 2, "color": 3, "kind": 4}
                header_parsed = True

            def get_col(name: str, default: str = "") -> str:
                idx = col_map.get(name)
                if idx is None or idx >= len(cleaned):
                    return default
                return cleaned[idx].strip()

            cidr  = get_col("cidr")
            name  = get_col("name")
            desc  = get_col("description") or None
            color = get_col("color") or None
            kind  = _normalize_kind(get_col("kind"))

            if not cidr or not name:
                skipped += 1
                continue

            # Hex-Farbe validieren
            if color and not (color.startswith("#") and len(color) in (4, 7)):
                color = None

            # OT-Vorrang-Regel: existing kind=ot darf nicht durch ein
            # incoming kind=it überschrieben werden. Andere Richtung
            # (it → ot) ist explizit gewünscht (OT-Promotion).
            try:
                existing_kind = await conn.fetchval(
                    "SELECT kind FROM known_networks WHERE cidr = $1::cidr",
                    cidr,
                )
            except Exception as exc:
                errors.append(f"Zeile {lineno} ({cidr}): {exc}")
                continue
            if existing_kind == "ot" and kind == "it":
                skipped_ot_priority += 1
                continue

            try:
                # ON CONFLICT (cidr): kind wird nur überschrieben, wenn die CSV-Zelle
                # explizit gesetzt war. Bei leerer kind-Spalte erbt der Eintrag den
                # bisherigen Wert — verhindert dass Re-Imports versehentlich ein
                # bewusst auf 'it' gesetztes Netz zurück auf 'ot' kippen.
                explicit_kind = bool(get_col("kind"))
                await conn.execute(
                    """
                    INSERT INTO known_networks (cidr, name, description, color, kind)
                    VALUES ($1::cidr, $2, $3, $4, $5)
                    ON CONFLICT (cidr) DO UPDATE SET
                      name        = EXCLUDED.name,
                      description = COALESCE(EXCLUDED.description, known_networks.description),
                      color       = COALESCE(EXCLUDED.color, known_networks.color),
                      kind        = CASE WHEN $6 THEN EXCLUDED.kind ELSE known_networks.kind END
                    """,
                    cidr, name, desc, color, kind, explicit_kind,
                )
                imported += 1
            except Exception as exc:
                errors.append(f"Zeile {lineno} ({cidr}): {exc}")

    if imported:
        await sync_known_networks_file(pool)
    return {
        "imported":            imported,
        "skipped":             skipped,
        "skipped_ot_priority": skipped_ot_priority,
        "errors":              errors[:20],
    }


@router.delete("", status_code=200)
async def bulk_delete_networks(
    kind: str | None = None,
    pool: asyncpg.Pool = Depends(get_pool),
    _admin: dict = Depends(require_admin),
) -> dict:
    """Massenlöschen aller bekannten Netzwerke (admin-only).

    Optional auf eine Zone einschränken via ?kind=ot oder ?kind=it.
    Ohne Filter werden ALLE Netze gelöscht — typischer Recovery-Pfad nach
    einem fehlgeschlagenen Import. Klein zu halten, weil ein Frontend-
    Confirm-Dialog davor sitzt; Backend macht keine zusätzliche
    Sicherheitsabfrage."""
    if kind is not None:
        kind = _normalize_kind(kind)
        async with pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM known_networks WHERE kind = $1",
                kind,
            )
    else:
        async with pool.acquire() as conn:
            result = await conn.execute("DELETE FROM known_networks")

    # asyncpg liefert "DELETE <n>" als Status-String; n extrahieren.
    deleted = 0
    if isinstance(result, str) and result.startswith("DELETE "):
        try:
            deleted = int(result.split()[1])
        except (ValueError, IndexError):
            deleted = 0

    if deleted:
        await sync_known_networks_file(pool)
    return {"deleted": deleted, "kind_filter": kind}


@router.patch("/{network_id}", response_model=NetworkResponse)
async def update_network(
    network_id: str,
    body: NetworkUpdate,
    pool: asyncpg.Pool = Depends(get_pool),
    _admin: dict = Depends(require_admin),
) -> NetworkResponse:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, cidr, name, description, color, kind FROM known_networks WHERE id = $1::uuid",
            network_id,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Network not found")
        new_name  = body.name        if body.name        is not None else row["name"]
        new_desc  = body.description if body.description is not None else row["description"]
        new_color = body.color       if body.color       is not None else row["color"]
        new_kind  = _normalize_kind(body.kind, default=row["kind"]) if body.kind is not None else row["kind"]
        row = await conn.fetchrow(
            """
            UPDATE known_networks
               SET name = $2, description = $3, color = $4, kind = $5
             WHERE id = $1::uuid
            RETURNING id, cidr, name, description, color, kind
            """,
            network_id, new_name, new_desc, new_color, new_kind,
        )
    # Name/Beschreibung/kind-Updates ändern den CIDR-Set nicht, aber wir syncen
    # trotzdem — Inhalt-Identität-Check in sync_known_networks_file verhindert
    # unnötige Rewrites.
    await sync_known_networks_file(pool)
    return NetworkResponse(
        id=row["id"],
        cidr=str(row["cidr"]),
        name=row["name"],
        description=row["description"],
        color=row["color"],
        kind=row["kind"],
    )


@router.delete("/{network_id}", status_code=204, response_model=None)
async def delete_network(
    network_id: str,
    pool: asyncpg.Pool = Depends(get_pool),
    _admin: dict = Depends(require_admin),
) -> None:
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM known_networks WHERE id = $1::uuid", network_id
        )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Network not found")
    await sync_known_networks_file(pool)
