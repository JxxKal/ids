"""Authentifizierung: Login, Logout, aktueller Benutzer."""
from __future__ import annotations

import time

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request, status
from passlib.context import CryptContext
from pydantic import BaseModel

from config import Config
from database import get_pool
from deps import get_current_user
from jwt_utils import create_token
from models import UserResponse

router = APIRouter(prefix="/api/auth", tags=["auth"])

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── Login-Rate-Limit (in-memory, pro Client-IP) ──────────────────────────────
# Einfacher Sliding-Window-Zähler gegen Brute-Force — kein externer Store nötig,
# der api läuft als ein Container. Bei Überschreitung 429 mit Retry-After.
_RL_MAX     = 5     # erlaubte Versuche
_RL_WINDOW  = 60    # pro Sekunden-Fenster
_rl_hits: dict[str, list[float]] = {}


def _client_ip(request: Request) -> str:
    # Hinter nginx: echte IP aus X-Real-IP / X-Forwarded-For (erste Adresse).
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")


def _rate_limit_check(ip: str) -> None:
    """429, wenn die IP zu viele FEHLGESCHLAGENE Versuche im Fenster hatte."""
    now = time.monotonic()
    hits = [t for t in _rl_hits.get(ip, []) if now - t < _RL_WINDOW]
    _rl_hits[ip] = hits
    if len(hits) >= _RL_MAX:
        retry = int(_RL_WINDOW - (now - hits[0])) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Zu viele fehlgeschlagene Login-Versuche — bitte kurz warten.",
            headers={"Retry-After": str(max(1, retry))},
        )


def _rate_limit_record_failure(ip: str) -> None:
    """Einen Fehlversuch vermerken. Erfolgreiche Logins zählen NICHT mit, damit
    legitime Nutzer nie ausgesperrt werden — nur Passwort-Raten wird gedrosselt."""
    now = time.monotonic()
    _rl_hits.setdefault(ip, []).append(now)
    if len(_rl_hits) > 2048:  # Speicher bändigen
        for k in [k for k, v in _rl_hits.items() if not any(now - t < _RL_WINDOW for t in v)]:
            _rl_hits.pop(k, None)


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
    body:    LoginRequest,
    request: Request,
    pool: asyncpg.Pool = Depends(get_pool),
    cfg:  Config       = Depends(_cfg),
) -> TokenResponse:
    ip = _client_ip(request)
    _rate_limit_check(ip)

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM users WHERE username = $1 AND source = 'local' AND active = true",
            body.username,
        )

    if not row or not row["password_hash"]:
        _rate_limit_record_failure(ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ungültige Anmeldedaten")

    if not _pwd.verify(body.password, row["password_hash"]):
        _rate_limit_record_failure(ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Ungültige Anmeldedaten")

    # Erfolg → IP-Zähler zurücksetzen (legitime Nutzer nie aussperren)
    _rl_hits.pop(ip, None)

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
