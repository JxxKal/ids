"""Alert-Match-Polling: nach einer Tool-Invocation am Cyjan-API
nach Alerts mit erwarteter rule_id suchen, im definierten Zeitfenster."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from config import settings

log = logging.getLogger(__name__)


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
    if settings.api_token:
        headers["Authorization"] = f"Bearer {settings.api_token}"

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
