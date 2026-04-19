"""Authentifizierung: Login, Logout, aktueller Benutzer."""
from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from passlib.context import CryptContext
from pydantic import BaseModel

from config import Config
from database import get_pool
from deps import get_current_user
from jwt_utils import create_token
from models import UserResponse

router = APIRouter(prefix="/api/auth", tags=["auth"])

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    user:         UserResponse


def _cfg() -> Config:
    from main import cfg
    return cfg


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    pool: asyncpg.Pool = Depends(get_pool),
    cfg:  Config       = Depends(_cfg),
) -> TokenResponse:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM users WHERE username = $1 AND source = 'local' AND active = true",
            body.username,
        )

    if not row or not row["password_hash"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ungültige Anmeldedaten")

    if not _pwd.verify(body.password, row["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ungültige Anmeldedaten")

    # last_login aktualisieren
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET last_login = now() WHERE id = $1",
            row["id"],
        )

    token = create_token(
        cfg.secret_key,
        user_id=str(row["id"]),
        username=row["username"],
        role=row["role"],
    )

    user = UserResponse(
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

    return TokenResponse(access_token=token, user=user)


@router.get("/me", response_model=UserResponse)
async def me(
    current_user: dict           = Depends(get_current_user),
    pool:         asyncpg.Pool   = Depends(get_pool),
) -> UserResponse:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM users WHERE id = $1",
            current_user["sub"],
        )
    if not row:
        raise HTTPException(status_code=404, detail="Benutzer nicht gefunden")
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
