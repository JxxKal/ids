"""User-Verwaltung (admin-only, getrimmte ids-Version)."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from database import get_pool
from deps import require_admin
from routers.auth import hash_password

router = APIRouter(prefix="/api/users", tags=["users"])


class UserCreate(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=8)
    role: str = Field(pattern="^(admin|viewer)$")


class UserUpdate(BaseModel):
    password: str | None = Field(default=None, min_length=8)
    role: str | None = Field(default=None, pattern="^(admin|viewer)$")


@router.get("")
async def list_users(_admin: dict = Depends(require_admin)) -> list[dict]:
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, username, role, created_at FROM users ORDER BY username"
        )
    return [dict(r) for r in rows]


@router.post("", status_code=201)
async def create_user(body: UserCreate, _admin: dict = Depends(require_admin)) -> dict:
    pool = get_pool()
    pw_hash = await asyncio.to_thread(hash_password, body.password)
    async with pool.acquire() as conn:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES ($1, $2, $3) RETURNING id, username, role
                """,
                body.username.strip(), pw_hash, body.role,
            )
        except Exception:
            raise HTTPException(409, "Benutzername existiert bereits")
    return dict(row)


@router.patch("/{user_id}")
async def update_user(
    user_id: int, body: UserUpdate, admin: dict = Depends(require_admin)
) -> dict:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id, role FROM users WHERE id = $1", user_id)
        if not row:
            raise HTTPException(404, "User nicht gefunden")
        if body.role and body.role != "admin" and row["role"] == "admin":
            admins = await conn.fetchval("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            if admins <= 1:
                raise HTTPException(400, "Der letzte Admin kann nicht herabgestuft werden")
        if body.password:
            pw_hash = await asyncio.to_thread(hash_password, body.password)
            await conn.execute(
                "UPDATE users SET password_hash = $1 WHERE id = $2", pw_hash, user_id
            )
        if body.role:
            await conn.execute("UPDATE users SET role = $1 WHERE id = $2", body.role, user_id)
        out = await conn.fetchrow("SELECT id, username, role FROM users WHERE id = $1", user_id)
    return dict(out)


@router.delete("/{user_id}", status_code=204)
async def delete_user(user_id: int, admin: dict = Depends(require_admin)) -> None:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT role FROM users WHERE id = $1", user_id)
        if not row:
            raise HTTPException(404, "User nicht gefunden")
        if row["role"] == "admin":
            admins = await conn.fetchval("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            if admins <= 1:
                raise HTTPException(400, "Der letzte Admin kann nicht gelöscht werden")
        await conn.execute("DELETE FROM users WHERE id = $1", user_id)
