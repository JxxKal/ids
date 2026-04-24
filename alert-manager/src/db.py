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

BATCH_SIZE = 1   # sofortiger Flush: Alerts sofort in DB, sichtbar nach Reload


class AlertWriter:
    def __init__(self, postgres_dsn: str) -> None:
        self._dsn = postgres_dsn
        self._conn: psycopg2.extensions.connection | None = None
        self._batch: list[dict] = []

    def _connect(self) -> None:
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(self._dsn)
            self._conn.autocommit = False
            log.info("Connected to TimescaleDB")

    def write(self, alert: dict) -> None:
        """Puffert einen Alert; schreibt bei BATCH_SIZE automatisch."""
        self._batch.append(alert)
        if len(self._batch) >= BATCH_SIZE:
            self.flush()

    def flush(self) -> None:
        """Schreibt alle gepufferten Alerts in die DB."""
        if not self._batch:
            return
        batch = self._batch[:]
        self._batch.clear()

        for attempt in range(3):
            try:
                self._connect()
                self._insert(batch)
                self._conn.commit()  # type: ignore[union-attr]
                return
            except Exception as exc:
                log.error("DB write attempt %d failed: %s", attempt + 1, exc)
                if self._conn:
                    try:
                        self._conn.rollback()
                    except Exception:
                        pass
                    self._conn = None
                if attempt < 2:
                    time.sleep(2 ** attempt)

        log.error("Dropping batch of %d alerts after 3 failed attempts", len(batch))

    def _insert(self, batch: list[dict]) -> None:
        rows = []
        for a in batch:
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
            ))

        psycopg2.extras.execute_values(
            self._conn.cursor(),  # type: ignore[union-attr]
            """
            INSERT INTO alerts (
                alert_id, ts, flow_id, source, rule_id,
                severity, score,
                src_ip, src_port, dst_ip, proto, dst_port,
                description, is_test, tags
            ) VALUES %s
            """,
            rows,
            template="""(
                %s, %s::timestamptz, %s, %s, %s,
                %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s
            )""",
        )

    def close(self) -> None:
        self.flush()
        if self._conn and not self._conn.closed:
            self._conn.close()
