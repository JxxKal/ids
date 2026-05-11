"""Alert-Match-Polling: nach einer Tool-Invocation am Cyjan-API
nach Alerts mit erwarteter rule_id suchen, im definierten Zeitfenster."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx
from jose import jwt as jose_jwt

from config import settings

log = logging.getLogger(__name__)

ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 365 * 24 * 3600
_cached_token: str | None = None


def _service_token() -> str | None:
    """Liefert entweder den statischen CYJAN_API_TOKEN oder mintet ein
    Service-JWT aus API_SECRET_KEY (gleiches Pattern wie rule-tuner).
    None wenn beide nicht gesetzt sind — Aufrufer kennt dann die Konsequenz
    (alert-poll wird 401 zurückbekommen)."""
    global _cached_token
    if settings.api_token:
        return settings.api_token
    if not settings.api_secret_key:
        return None
    if _cached_token is None:
        payload = {
            "sub":      "redteam-orchestrator",
            "username": "redteam-orchestrator-service",
            "role":     "admin",
            "exp":      int(time.time()) + TOKEN_TTL_SECONDS,
        }
        _cached_token = jose_jwt.encode(payload, settings.api_secret_key, algorithm=ALGORITHM)
        log.info("Service-Token aus API_SECRET_KEY gemintet (TTL 1 Jahr)")
    return _cached_token


async def poll_alerts_for_rule(
    rule_id_prefix: str,
    window_sec:     int = 10,
    src_ip:         str | None = None,
) -> list[dict[str, Any]]:
    """Pollt /api/alerts?rule_id=<prefix>&since=<ts> alle 1s für bis zu
    `window_sec` Sekunden. Returns alle gefundenen Alerts mit
    rule_id-Prefix-Match und optionalem src_ip-Filter.

    `rule_id_prefix` kann z.B. "SCAN_001" oder "SURICATA:1:2018927" sein —
    der Cyjan-API-Endpoint matched LIKE 'prefix%'.
    """
    headers = {}
    tok = _service_token()
    if tok:
        headers["Authorization"] = f"Bearer {tok}"

    poll_interval = 1.0
    iterations    = max(1, int(window_sec / poll_interval))

    async with httpx.AsyncClient(timeout=5.0, headers=headers) as cli:
        for i in range(iterations):
            try:
                r = await cli.get(
                    f"{settings.api_base}/api/alerts",
                    params={"rule_id_prefix": rule_id_prefix, "limit": 50},
                )
                if r.status_code == 200:
                    alerts = (r.json() or {}).get("alerts", [])
                    if src_ip:
                        alerts = [a for a in alerts if a.get("src_ip") == src_ip]
                    if alerts:
                        log.info("alert-match: rule_prefix=%s gefunden: %d alerts",
                                 rule_id_prefix, len(alerts))
                        return alerts
                else:
                    log.debug("alert-match poll %d: status=%d", i, r.status_code)
            except Exception as exc:
                log.debug("alert-match poll %d: %s", i, exc)
            await asyncio.sleep(poll_interval)

    log.info("alert-match: rule_prefix=%s keine alerts im %ds-Fenster",
             rule_id_prefix, window_sec)
    return []
