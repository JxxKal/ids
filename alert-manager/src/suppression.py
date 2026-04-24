"""
Suppression-Cache: unterdrückt bekannte FP-Kombinationen (rule_id + src_ip).

Lädt alle (rule_id, src_ip)-Paare mit feedback='fp' aus der DB und
markiert eingehende Alerts als 'low', wenn sie matchen.
"""
from __future__ import annotations

import logging
import time

import psycopg2

log = logging.getLogger(__name__)

REFRESH_INTERVAL_S = 60.0


class SuppressionCache:
    def __init__(self, postgres_dsn: str) -> None:
        self._dsn = postgres_dsn
        self._conn: psycopg2.extensions.connection | None = None
        self._rules: set[tuple[str, str]] = set()
        self._last_refresh = 0.0

    def _connect(self) -> None:
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(self._dsn)
            self._conn.autocommit = True

    def refresh(self) -> None:
        try:
            self._connect()
            cur = self._conn.cursor()  # type: ignore[union-attr]
            cur.execute("""
                SELECT DISTINCT rule_id, src_ip::text, dst_ip::text
                FROM alerts
                WHERE feedback = 'fp'
                  AND rule_id IS NOT NULL
                  AND src_ip  IS NOT NULL
                  AND dst_ip  IS NOT NULL
            """)
            self._rules = {(row[0], row[1], row[2]) for row in cur.fetchall()}
            self._last_refresh = time.monotonic()
            log.info("Suppression cache: %d FP-Regeln geladen", len(self._rules))
        except Exception as exc:
            log.warning("Suppression-Cache-Refresh fehlgeschlagen: %s", exc)
            self._conn = None

    def maybe_refresh(self) -> None:
        if time.monotonic() - self._last_refresh > REFRESH_INTERVAL_S:
            self.refresh()

    def should_suppress(self, rule_id: str | None, src_ip: str | None, dst_ip: str | None) -> bool:
        if not rule_id or not src_ip or not dst_ip:
            return False
        return (rule_id, src_ip, dst_ip) in self._rules

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
