"""
Suppression-Cache: unterdrückt bekannte FP-Kombinationen (rule_id + src_ip + dst_ip).

Zwei Layer:
  1. MANUAL (auto-suppressed):  User hat einen Alert mit feedback='fp' markiert
                                → alle exakt gleichen Tupel werden herabgestuft.
  2. ML-LEARNED (ml-suppressed): Tupel tritt ≥ MIN_COUNT-mal über ≥ MIN_DAYS
                                 verteilt in den letzten LEARN_WINDOW_D Tagen auf,
                                 ohne je als TP markiert worden zu sein, und die
                                 Severity ist nicht critical/high. → als gelerntes
                                 Normalmuster herabgestuft.

Ein TP-Feedback auf einem passenden Tupel entfernt es automatisch aus der
ML-Learned-Menge beim nächsten Refresh (Override durch User).
"""
from __future__ import annotations

import logging
import os
import time

import psycopg2

log = logging.getLogger(__name__)

REFRESH_INTERVAL_S = 60.0

# ── ML-Learning Thresholds (per ENV konfigurierbar) ──────────────────────────
LEARN_WINDOW_D = int(os.environ.get("SUPPRESSION_LEARN_WINDOW_D", "7"))
MIN_COUNT      = int(os.environ.get("SUPPRESSION_MIN_COUNT",      "20"))
MIN_DAYS       = int(os.environ.get("SUPPRESSION_MIN_DAYS",       "3"))


class SuppressionCache:
    def __init__(self, postgres_dsn: str) -> None:
        self._dsn = postgres_dsn
        self._conn: psycopg2.extensions.connection | None = None
        self._manual:  set[tuple[str, str, str]] = set()
        self._learned: set[tuple[str, str, str]] = set()
        self._last_refresh = 0.0

    def _connect(self) -> None:
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(self._dsn)
            self._conn.autocommit = True

    def refresh(self) -> None:
        try:
            self._connect()
            cur = self._conn.cursor()  # type: ignore[union-attr]

            # Layer 1: Manuell markierte FPs
            cur.execute("""
                SELECT DISTINCT rule_id, src_ip::text, dst_ip::text
                FROM alerts
                WHERE feedback = 'fp'
                  AND rule_id IS NOT NULL
                  AND src_ip  IS NOT NULL
                  AND dst_ip  IS NOT NULL
            """)
            manual = {(r[0], r[1], r[2]) for r in cur.fetchall()}

            # Layer 2: ML-gelernte Muster
            #   - ≥ MIN_COUNT Treffer in LEARN_WINDOW_D Tagen
            #   - auf ≥ MIN_DAYS verschiedenen Tagen gesehen
            #   - KEIN einziger TP-Feedback in dem Fenster (Sicherheit)
            #   - severity nie critical/high (Sicherheit)
            cur.execute("""
                SELECT rule_id, src_ip::text, dst_ip::text
                FROM alerts
                WHERE ts > NOW() - (%s || ' days')::interval
                  AND is_test = false
                  AND rule_id IS NOT NULL
                  AND src_ip  IS NOT NULL
                  AND dst_ip  IS NOT NULL
                GROUP BY rule_id, src_ip, dst_ip
                HAVING COUNT(*)                                       >= %s
                   AND COUNT(DISTINCT DATE(ts))                       >= %s
                   AND COUNT(*) FILTER (WHERE feedback = 'tp')         = 0
                   AND COUNT(*) FILTER (WHERE severity IN ('critical','high')) = 0
            """, (LEARN_WINDOW_D, MIN_COUNT, MIN_DAYS))
            learned = {(r[0], r[1], r[2]) for r in cur.fetchall()}

            # Manuelle Regeln haben Vorrang vor gelernten (gleiche Semantik)
            learned -= manual

            self._manual  = manual
            self._learned = learned
            self._last_refresh = time.monotonic()
            log.info(
                "Suppression cache: %d manuell (fp) + %d ML-gelernt (window=%dd count>=%d days>=%d)",
                len(self._manual), len(self._learned),
                LEARN_WINDOW_D, MIN_COUNT, MIN_DAYS,
            )
        except Exception as exc:
            log.warning("Suppression-Cache-Refresh fehlgeschlagen: %s", exc)
            self._conn = None

    def maybe_refresh(self) -> None:
        if time.monotonic() - self._last_refresh > REFRESH_INTERVAL_S:
            self.refresh()

    def classify(self, rule_id: str | None, src_ip: str | None, dst_ip: str | None) -> str | None:
        """Gibt 'manual', 'learned' oder None zurück."""
        if not rule_id or not src_ip or not dst_ip:
            return None
        key = (rule_id, src_ip, dst_ip)
        if key in self._manual:
            return "manual"
        if key in self._learned:
            return "learned"
        return None

    # Backwards-compatibility (bestehender main.py Code)
    def should_suppress(self, rule_id: str | None, src_ip: str | None, dst_ip: str | None) -> bool:
        return self.classify(rule_id, src_ip, dst_ip) is not None

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
