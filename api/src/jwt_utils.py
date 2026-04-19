"""JWT-Hilfsfunktionen."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt

ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS     = 8
API_TOKEN_EXPIRE_DAYS  = 365


def create_token(secret: str, user_id: str, username: str, role: str) -> str:
    """Erstellt ein JWT – API-User erhalten ein Token mit 365 Tagen Laufzeit."""
    if role == "api":
        expire = datetime.now(timezone.utc) + timedelta(days=API_TOKEN_EXPIRE_DAYS)
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode(
        {"sub": user_id, "username": username, "role": role, "exp": expire},
        secret,
        algorithm=ALGORITHM,
    )


def decode_token(secret: str, token: str) -> dict:
    """Wirft JWTError bei ungültigem oder abgelaufenem Token."""
    return jwt.decode(token, secret, algorithms=[ALGORITHM])
