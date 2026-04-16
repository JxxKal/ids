"""
DB-Zugriffe für den Training-Loop.

  save_sample()       – Gelabelten Flow in training_samples speichern
  load_samples()      – Samples für Training laden
  load_unlabeled_flows() – Normale Flows für Bootstrap/Semi-Supervised
"""
from __future__ import annotations

import json
import logging
import time

import psycopg2
import psycopg2.extras

log = logging.getLogger(__name__)


class TrainingDB:
    def __init__(self, dsn: str) -> None:
        self._dsn  = dsn
        self._conn: psycopg2.extensions.connection | None = None

    def _connect(self) -> None:
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(self._dsn)
            self._conn.autocommit = False

    def save_sample(self, alert_id: str, label: str, features: dict, source: str = "feedback") -> None:
        """Speichert einen gelabelten Flow in training_samples."""
        for attempt in range(3):
            try:
                self._connect()
                with self._conn.cursor() as cur:   # type: ignore[union-attr]
                    cur.execute(
                        """
                        INSERT INTO training_samples (alert_id, label, features, source)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT DO NOTHING
                        """,
                        (alert_id, label, json.dumps(features), source),
                    )
                self._conn.commit()                # type: ignore[union-attr]
                return
            except Exception as exc:
                log.error("save_sample attempt %d: %s", attempt + 1, exc)
                if self._conn:
                    try: self._conn.rollback()
                    except Exception: pass
                    self._conn = None
                if attempt < 2:
                    time.sleep(1)

    def load_samples(self, limit: int = 100_000) -> list[dict]:
        """Lädt gelabelte Samples (neueste zuerst) für das Training."""
        try:
            self._connect()
            with self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:  # type: ignore[union-attr]
                cur.execute(
                    """
                    SELECT features, label
                    FROM training_samples
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cur.fetchall()
            return [{"features": r["features"], "label": r["label"]} for r in rows]
        except Exception as exc:
            log.error("load_samples: %s", exc)
            self._conn = None
            return []

    def count_new_samples(self, since_ts: float) -> int:
        """Zählt neue Samples seit einem Timestamp."""
        try:
            self._connect()
            with self._conn.cursor() as cur:       # type: ignore[union-attr]
                cur.execute(
                    "SELECT COUNT(*) FROM training_samples WHERE created_at > to_timestamp(%s)",
                    (since_ts,),
                )
                return int(cur.fetchone()[0])      # type: ignore[index]
        except Exception as exc:
            log.debug("count_new_samples: %s", exc)
            self._conn = None
            return 0

    def load_flows_for_bootstrap(self, limit: int = 50_000) -> list[dict]:
        """
        Lädt normale Flows aus der flows-Tabelle für semi-supervised Bootstrap.
        Gibt Flow-Feature-Dicts zurück (kompatibel mit features.extract).
        """
        try:
            self._connect()
            with self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:  # type: ignore[union-attr]
                cur.execute(
                    """
                    SELECT
                        EXTRACT(EPOCH FROM (end_ts - start_ts)) AS duration_s,
                        pkt_count, byte_count,
                        (stats->>'pps')::float         AS pps,
                        (stats->>'bps')::float         AS bps,
                        (stats->'pkt_size'->>'mean')::float AS pkt_size_mean,
                        (stats->'pkt_size'->>'std')::float  AS pkt_size_std,
                        (stats->'iat'->>'mean')::float      AS iat_mean,
                        (stats->'iat'->>'std')::float       AS iat_std,
                        (stats->>'entropy_iat')::float      AS entropy_iat,
                        (stats->'tcp_flags'->>'SYN')::float AS syn_ratio,
                        (stats->'tcp_flags'->>'RST')::float AS rst_ratio,
                        (stats->'tcp_flags'->>'FIN')::float AS fin_ratio,
                        dst_port
                    FROM flows
                    ORDER BY start_ts DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cur.fetchall()
            return [dict(r) for r in rows]
        except Exception as exc:
            log.error("load_flows_for_bootstrap: %s", exc)
            self._conn = None
            return []

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
