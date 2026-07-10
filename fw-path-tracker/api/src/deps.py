"""FastAPI-Abhängigkeiten – aktuellen Benutzer aus JWT ermitteln (ids-Muster)."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from jwt_utils import decode_token

_bearer = HTTPBearer(auto_error=False)


def get_app_state(request: Request):
    """Zugriff auf app.state (Config, Inventory, FMG-Client, Resolver)."""
    return request.app.state


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nicht angemeldet",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(request.app.state.cfg.secret_key, credentials.credentials)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token ungültig oder abgelaufen",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin-Rechte erforderlich"
        )
    return user
