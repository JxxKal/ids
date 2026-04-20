from __future__ import annotations

import csv
import io

import asyncpg
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import Response

from database import get_pool
from models import NetworkCreate, NetworkResponse, NetworkUpdate

router = APIRouter(prefix="/api/networks", tags=["networks"])


@router.get("", response_model=list[NetworkResponse])
async def list_networks(pool: asyncpg.Pool = Depends(get_pool)) -> list[NetworkResponse]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, cidr, name, description, color FROM known_networks ORDER BY name"
        )
    return [
        NetworkResponse(
            id=r["id"],
            cidr=str(r["cidr"]),
            name=r["name"],
            description=r["description"],
            color=r["color"],
        )
        for r in rows
    ]


@router.post("", response_model=NetworkResponse, status_code=201)
async def create_network(
    body: NetworkCreate,
    pool: asyncpg.Pool = Depends(get_pool),
) -> NetworkResponse:
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO known_networks (cidr, name, description, color)
                VALUES ($1::cidr, $2, $3, $4)
                RETURNING id, cidr, name, description, color
                """,
                body.cidr, body.name, body.description, body.color,
            )
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=409, detail="CIDR already exists")
    except asyncpg.InvalidTextRepresentationError:
        raise HTTPException(status_code=422, detail="Invalid CIDR notation")
    return NetworkResponse(
        id=row["id"],
        cidr=str(row["cidr"]),
        name=row["name"],
        description=row["description"],
        color=row["color"],
    )


@router.get("/example.csv")
async def networks_example_csv() -> Response:
    """Beispiel-CSV für Netzwerk-Import."""
    content = (
        "# Bekannte Netzwerke – Cyjan IDS\n"
        "# Spalten: cidr;name;description;color\n"
        "#   cidr        – CIDR-Notation (Pflichtfeld), z.B. 192.168.1.0/24\n"
        "#   name        – Anzeigename (Pflichtfeld)\n"
        "#   description – Beschreibung (optional)\n"
        "#   color       – Hex-Farbe für die UI (optional), z.B. #3b82f6\n"
        "# Trennzeichen: Semikolon oder Komma\n"
        "cidr;name;description;color\n"
        "192.168.1.0/24;LAN Büro;Hauptbüro 1. OG;#3b82f6\n"
        "192.168.2.0/24;LAN Lager;Lagergebäude;#10b981\n"
        "10.0.0.0/8;VPN;VPN-Tunnel Mitarbeiter;#8b5cf6\n"
        "172.16.0.0/12;DMZ;Demilitarisierte Zone;#f59e0b\n"
        "# Felder description und color können leer bleiben:\n"
        "10.10.0.0/16;Server-VLAN;;\n"
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
) -> dict:
    """
    CSV-Import für bekannte Netzwerke.
    Pflichtfelder: cidr, name
    Optional: description, color
    Trennzeichen: Semikolon oder Komma. Kommentare (#) und Leerzeilen werden ignoriert.
    Vorhandene Einträge mit gleicher CIDR werden aktualisiert.
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
                # Keine Header-Zeile: Standard-Reihenfolge annehmen
                col_map = {"cidr": 0, "name": 1, "description": 2, "color": 3}
                header_parsed = True

            def get_col(name: str, default: str = "") -> str:
                idx = col_map.get(name)
                if idx is None or idx >= len(cleaned):
                    return default
                return cleaned[idx].strip()

            cidr = get_col("cidr")
            name = get_col("name")
            desc = get_col("description") or None
            color = get_col("color") or None

            if not cidr or not name:
                skipped += 1
                continue

            # Hex-Farbe validieren
            if color and not (color.startswith("#") and len(color) in (4, 7)):
                color = None

            try:
                await conn.execute(
                    """
                    INSERT INTO known_networks (cidr, name, description, color)
                    VALUES ($1::cidr, $2, $3, $4)
                    ON CONFLICT (cidr) DO UPDATE SET
                      name        = EXCLUDED.name,
                      description = COALESCE(EXCLUDED.description, known_networks.description),
                      color       = COALESCE(EXCLUDED.color, known_networks.color)
                    """,
                    cidr, name, desc, color,
                )
                imported += 1
            except Exception as exc:
                errors.append(f"Zeile {lineno} ({cidr}): {exc}")

    return {"imported": imported, "skipped": skipped, "errors": errors[:20]}


@router.patch("/{network_id}", response_model=NetworkResponse)
async def update_network(
    network_id: str,
    body: NetworkUpdate,
    pool: asyncpg.Pool = Depends(get_pool),
) -> NetworkResponse:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, cidr, name, description, color FROM known_networks WHERE id = $1::uuid",
            network_id,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Network not found")
        new_name  = body.name        if body.name        is not None else row["name"]
        new_desc  = body.description if body.description is not None else row["description"]
        new_color = body.color       if body.color       is not None else row["color"]
        row = await conn.fetchrow(
            """
            UPDATE known_networks
               SET name = $2, description = $3, color = $4
             WHERE id = $1::uuid
            RETURNING id, cidr, name, description, color
            """,
            network_id, new_name, new_desc, new_color,
        )
    return NetworkResponse(
        id=row["id"],
        cidr=str(row["cidr"]),
        name=row["name"],
        description=row["description"],
        color=row["color"],
    )


@router.delete("/{network_id}", status_code=204, response_model=None)
async def delete_network(
    network_id: str,
    pool: asyncpg.Pool = Depends(get_pool),
) -> None:
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM known_networks WHERE id = $1::uuid", network_id
        )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Network not found")
