"""User-Management: lokale User + SAML-synchronisierte User."""
from __future__ import annotations

from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from passlib.context import CryptContext

from database import get_pool
from models import UserCreate, UserResponse, UserUpdate

router = APIRouter(prefix="/api/users", tags=["users"])

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _row_to_user(row: asyncpg.Record) -> UserResponse:
    return UserResponse(
        id=row["id"],
        username=row["username"],
        email=row["email"],
        display_name=row["display_name"],
        role=row["role"],
        source=row["source"],
        active=row["active"],
        created_at=row["created_at"],
        last_login=row["last_login"],
    )


@router.get("", response_model=list[UserResponse])
async def list_users(pool: asyncpg.Pool = Depends(get_pool)) -> list[UserResponse]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM users ORDER BY source, username"
        )
    return [_row_to_user(r) for r in rows]


@router.post("", response_model=UserResponse, status_code=201)
async def create_user(
    body: UserCreate,
    pool: asyncpg.Pool = Depends(get_pool),
) -> UserResponse:
    pw_hash = _pwd.hash(body.password)
    async with pool.acquire() as conn:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO users (username, email, display_name, role, source, password_hash)
                VALUES ($1, $2, $3, $4, 'local', $5)
                RETURNING *
                """,
                body.username, body.email, body.display_name, body.role, pw_hash,
            )
        except asyncpg.UniqueViolationError:
            raise HTTPException(status_code=409, detail="Benutzername bereits vergeben")
    return _row_to_user(row)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    body:    UserUpdate,
    pool:    asyncpg.Pool = Depends(get_pool),
) -> UserResponse:
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
        if not row:
            raise HTTPException(status_code=404, detail="Benutzer nicht gefunden")

        # SAML-User: Passwort und Username nicht änderbar
        updates: list[str] = []
        params: list = []
        idx = 1

        if body.email is not None:
            updates.append(f"email = ${idx}"); params.append(body.email); idx += 1
        if body.display_name is not None:
            updates.append(f"display_name = ${idx}"); params.append(body.display_name); idx += 1
        if body.role is not None:
            updates.append(f"role = ${idx}"); params.append(body.role); idx += 1
        if body.active is not None:
            updates.append(f"active = ${idx}"); params.append(body.active); idx += 1
        if body.password is not None:
            if row["source"] != "local":
                raise HTTPException(status_code=400, detail="SAML-Benutzer haben kein lokales Passwort")
            updates.append(f"password_hash = ${idx}"); params.append(_pwd.hash(body.password)); idx += 1

        if not updates:
            return _row_to_user(row)

        params.append(user_id)
        updated = await conn.fetchrow(
            f"UPDATE users SET {', '.join(updates)} WHERE id = ${idx} RETURNING *",
            *params,
        )
    return _row_to_user(updated)


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: UUID,
    pool:    asyncpg.Pool = Depends(get_pool),
) -> None:
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT role FROM users WHERE id = $1", user_id)
        if not row:
            raise HTTPException(status_code=404, detail="Benutzer nicht gefunden")

        # Letzten Admin nicht löschen
        if row["role"] == "admin":
            admin_count = await conn.fetchval(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = true"
            )
            if admin_count <= 1:
                raise HTTPException(status_code=400, detail="Letzten Admin-Benutzer kann nicht gelöscht werden")

        await conn.execute("DELETE FROM users WHERE id = $1", user_id)
