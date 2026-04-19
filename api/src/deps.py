"""FastAPI-Abhängigkeiten – aktuellen Benutzer aus JWT ermitteln."""
from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from config import Config
from jwt_utils import decode_token

_bearer = HTTPBearer(auto_error=False)


def _cfg() -> Config:
    from main import cfg  # Lazy-Import um Zirkel zu vermeiden
    return cfg


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    cfg: Config = Depends(_cfg),
) -> dict:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nicht angemeldet",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(cfg.secret_key, credentials.credentials)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token ungültig oder abgelaufen",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin-Rechte erforderlich")
    return user
