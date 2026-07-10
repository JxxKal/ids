"""Login mit lokalen Usern (bcrypt + JWT HS256)."""
from __future__ import annotations

import asyncio

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from database import get_pool
from deps import get_current_user
from jwt_utils import create_token

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    username: str
    role: str


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request) -> LoginResponse:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, username, password_hash, role FROM users WHERE username = $1",
            body.username.strip(),
        )
    # bcrypt ist CPU-lastig → nicht den Event-Loop blockieren.
    ok = row is not None and await asyncio.to_thread(
        verify_password, body.password, row["password_hash"]
    )
    if not ok:
        raise HTTPException(401, "Benutzername oder Passwort falsch")
    token = create_token(
        request.app.state.cfg.secret_key, str(row["id"]), row["username"], row["role"]
    )
    return LoginResponse(token=token, username=row["username"], role=row["role"])


@router.get("/me")
async def me(user: dict = Depends(get_current_user)) -> dict:
    return {"username": user.get("username"), "role": user.get("role")}
