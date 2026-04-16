from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends, HTTPException

from database import get_pool
from models import NetworkCreate, NetworkResponse

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
