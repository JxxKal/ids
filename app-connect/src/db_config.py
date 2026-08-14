"""Config-Overlay aus der Master-DB (`system_config['app_connect']`).

Muster 1:1 aus `mqtt-bridge/src/main.py` (`_read_db_overlay` +
`config_watch_loop`), hier nur in eine Klasse gefasst, weil app-connect den
Store an zwei Stellen braucht: im Supervisor (Reconnect-Entscheidung) und
im internen HTTP-Server (`GET /status` meldet `config_source`).

Fehlertoleranz ist Absicht: ist die DB weg, liefert `effective()` die
ENV-Konfiguration statt zu werfen. app-connect ist der Dienst, der auch
dann noch antworten können muss, wenn rundherum etwas kaputt ist — und
eine Cloud-Verbindung wegen eines DB-Hakelns abzureißen wäre die falsche
Reaktion.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import asyncpg
import orjson

from config import (
    CONFIG_RELOAD_INTERVAL_S,
    DB_CONFIG_KEY,
    Config,
    merge_db_overlay,
)

log = logging.getLogger(__name__)


class ConfigStore:
    """Hält den asyncpg-Pool und baut daraus die effektive Config."""

    def __init__(
        self,
        dsn: str,
        env: dict[str, Any],
        key: str = DB_CONFIG_KEY,
        poll_interval_s: float = CONFIG_RELOAD_INTERVAL_S,
    ) -> None:
        self._dsn = (dsn or "").strip()
        self._env = dict(env)
        self._key = key
        self._poll_interval_s = poll_interval_s
        self._pool: Optional[asyncpg.Pool] = None
        self._warned_no_dsn = False
        self._warned_conn = False

    # ── Pool ─────────────────────────────────────────────────────────────

    async def _ensure_pool(self) -> Optional[asyncpg.Pool]:
        if self._pool is not None:
            return self._pool
        if not self._dsn:
            if not self._warned_no_dsn:
                log.warning("POSTGRES_DSN ist leer — die GUI-Konfiguration aus "
                            "system_config['%s'] kann nicht gelesen werden, es "
                            "gilt ausschließlich die ENV-Konfiguration.", self._key)
                self._warned_no_dsn = True
            return None
        try:
            self._pool = await asyncpg.create_pool(
                self._dsn, min_size=1, max_size=2, command_timeout=10,
            )
            log.info("DB-Verbindung für Config-Overlay steht (system_config['%s'])",
                     self._key)
            self._warned_conn = False
        except Exception as exc:
            if not self._warned_conn:
                log.warning("DB für Config-Overlay nicht erreichbar (%s) — "
                            "ENV-Konfiguration bleibt aktiv, nächster Versuch "
                            "in %.0fs", exc, self._poll_interval_s)
                self._warned_conn = True
            self._pool = None
        return self._pool

    async def close(self) -> None:
        if self._pool is not None:
            try:
                await self._pool.close()
            except Exception:
                pass
            self._pool = None

    # ── Lesen ────────────────────────────────────────────────────────────

    async def read_overlay(self) -> Optional[dict]:
        """`system_config[key].value` als dict. None, wenn der Schlüssel
        fehlt oder die DB gerade nicht mag."""
        pool = await self._ensure_pool()
        if pool is None:
            return None
        try:
            row = await pool.fetchrow(
                "SELECT value FROM system_config WHERE key = $1", self._key
            )
        except Exception as exc:
            log.debug("DB-Overlay-Read fehlgeschlagen: %s", exc)
            # Pool verwerfen — nach einem Verbindungsabriss ist er tot.
            await self.close()
            return None
        if row is None or row["value"] is None:
            return None
        value = row["value"]
        # asyncpg liefert JSONB normalerweise als geparstes dict; manche
        # Setups (kein Codec registriert) geben str/bytes zurück.
        if isinstance(value, (bytes, str)):
            try:
                value = orjson.loads(value)
            except Exception as exc:
                log.warning("system_config['%s'] ist kein gültiges JSON: %s",
                            self._key, exc)
                return None
        return value if isinstance(value, dict) else None

    async def effective(self) -> Config:
        overlay = await self.read_overlay()
        return Config.from_dict(merge_db_overlay(self._env, overlay))

    async def wait_for_change(self, current: Config) -> Config:
        """Blockiert, bis sich die effektive Konfiguration von `current`
        unterscheidet. Für die Ruhezustände (dormant/abgeschaltet)."""
        while True:
            await asyncio.sleep(self._poll_interval_s)
            try:
                fresh = await self.effective()
            except Exception as exc:  # pragma: no cover — Sicherheitsnetz
                log.warning("Config-Poll fehlgeschlagen: %s", exc)
                continue
            if fresh != current:
                return fresh
