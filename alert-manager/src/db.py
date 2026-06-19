"""
TimescaleDB-Writer für Alerts.

Schreibt angereicherte Alerts in die 'alerts'-Hypertable.
Verwendet Batching (BATCH_SIZE Zeilen) mit execute_values für Effizienz.
"""
from __future__ import annotations

import logging
import time
import uuid

import psycopg2
import psycopg2.extras

log = logging.getLogger(__name__)

# Alerts sind das Kernprodukt — bei DB-Ausfall wird NICHT verworfen, sondern
# gepuffert und beim nächsten flush() (spätestens periodisch alle 60s, siehe
# main.py) erneut versucht, bis die DB zurück ist.
MAX_PENDING     = 10000  # Obergrenze gegen OOM bei langem Ausfall — dann älteste verwerfen
RETRY_BACKOFF_S = 10.0   # nach einem DB-Fehler erst nach X s erneut versuchen,
                         # statt den Consumer bei JEDEM Alert ~7s zu blockieren


class AlertWriter:
    def __init__(self, postgres_dsn: str) -> None:
        self._dsn = postgres_dsn
        self._conn: psycopg2.extensions.connection | None = None
        self._pending: list[dict] = []   # noch nicht geschriebene Alerts (DB-Ausfall)
        self._next_retry = 0.0           # monotone Zeit, ab der wieder versucht wird

    def _connect(self) -> None:
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(self._dsn)
            self._conn.autocommit = False
            log.info("Connected to TimescaleDB")

    def write(self, alert: dict) -> None:
        """Puffert einen Alert und versucht zu schreiben (sofort sichtbar)."""
        self._pending.append(alert)
        if len(self._pending) > MAX_PENDING:
            drop = len(self._pending) - MAX_PENDING
            del self._pending[:drop]
            log.error("Alert-Puffer voll (>%d) — %d älteste Alerts verworfen (DB-Ausfall?)",
                      MAX_PENDING, drop)
        self.flush()

    def flush(self) -> None:
        """Schreibt alle gepufferten Alerts. Bei Fehler bleibt der Puffer erhalten
        und wird nach RETRY_BACKOFF_S erneut versucht — kein stiller Verlust."""
        if not self._pending:
            return
        if time.monotonic() < self._next_retry:
            return  # im Backoff-Fenster: nur puffern, DB nicht hämmern/blockieren
        batch = self._pending[:]
        try:
            self._connect()
            self._insert(batch)
            self._conn.commit()  # type: ignore[union-attr]
            self._pending.clear()
        except Exception as exc:
            log.error("DB-Write fehlgeschlagen — %d Alerts gepuffert, Retry in %.0fs: %s",
                      len(self._pending), RETRY_BACKOFF_S, exc)
            if self._conn:
                try:
                    self._conn.rollback()
                except Exception:
                    pass
                self._conn = None
            self._next_retry = time.monotonic() + RETRY_BACKOFF_S

    def _insert(self, batch: list[dict]) -> None:
        import json as _json
        rows = []
        for a in batch:
            mv = a.get("metric_values")
            # Phase 4.5: nur valide dicts persistieren — psycopg2 schreibt
            # Python-dict via JSON-Adapter, hier sicherheitshalber explizit
            # serialisieren damit kein NULL/Object-Mix die Spalte zerschießt.
            mv_json = _json.dumps(mv) if isinstance(mv, dict) and mv else None
            # Phase 7: feedback + feedback_note werden bei Auto-FP-Suppression
            # bereits beim Initial-Insert gesetzt (siehe alert-manager main.py).
            # User-Manuelles Feedback überschreibt das später via PATCH /api/
            # alerts/{id}/feedback (Spaltenwert wird ersetzt, feedback_ts neu).
            fb = a.get("feedback")
            fb_note = a.get("feedback_note") if fb else None
            fb_ts = (a.get("ts") or time.time()) if fb else None
            rows.append((
                str(a.get("alert_id") or uuid.uuid4()),
                a.get("ts") or time.time(),
                a.get("flow_id"),
                a.get("source", "signature"),
                a.get("rule_id"),
                a.get("severity", "low"),
                float(a.get("score") or 0.0),
                a.get("src_ip"),
                a.get("src_port"),
                a.get("dst_ip"),
                a.get("proto"),
                a.get("dst_port"),
                a.get("description", ""),
                a.get("is_test", False),
                list(a.get("tags") or []),
                a.get("tap_id"),
                mv_json,
                fb,
                fb_ts,
                fb_note,
            ))

        psycopg2.extras.execute_values(
            self._conn.cursor(),  # type: ignore[union-attr]
            """
            INSERT INTO alerts (
                alert_id, ts, flow_id, source, rule_id,
                severity, score,
                src_ip, src_port, dst_ip, proto, dst_port,
                description, is_test, tags, tap_id, metric_values,
                feedback, feedback_ts, feedback_note
            ) VALUES %s
            """,
            rows,
            template="""(
                %s, %s::timestamptz, %s, %s, %s,
                %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s::jsonb,
                %s, %s::timestamptz, %s
            )""",
        )

    def close(self) -> None:
        self.flush()
        if self._conn and not self._conn.closed:
            self._conn.close()
