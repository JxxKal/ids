"""
Kafka-Producer + TimescaleDB-Writer für fertige FlowRecords.

Design:
- Kafka: confluent-kafka Producer (async delivery callbacks)
- DB: psycopg2 mit Batch-Insert (execute_values), kein ORM
- Fehler in DB beeinflussen Kafka-Publishing nicht (und umgekehrt)
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import orjson
import psycopg2
from psycopg2.extras import Json, execute_values
from confluent_kafka import Producer

if TYPE_CHECKING:
    from models import FlowRecord

logger = logging.getLogger(__name__)

TOPIC_FLOWS = "flows"


class FlowPublisher:
    def __init__(self, kafka_brokers: str, postgres_dsn: str, batch_size: int = 100) -> None:
        self._producer = Producer({
            "bootstrap.servers":            kafka_brokers,
            "queue.buffering.max.messages": "50000",
            "queue.buffering.max.ms":       "10",
            "batch.num.messages":           "500",
            "compression.codec":            "lz4",
            "socket.keepalive.enable":      "true",
            "retries":                      "3",
            "retry.backoff.ms":             "100",
        })

        self._conn = psycopg2.connect(postgres_dsn)
        self._conn.autocommit = False

        self._batch_size  = batch_size
        self._pending_db: list[FlowRecord] = []

        # Metriken
        self.kafka_ok:  int = 0
        self.kafka_err: int = 0
        self.db_ok:     int = 0
        self.db_err:    int = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def publish(self, records: list[FlowRecord]) -> None:
        """Sendet Records an Kafka und puffert sie für DB-Batch-Insert."""
        if not records:
            return

        for record in records:
            self._send_kafka(record)
            self._pending_db.append(record)

        # Batch-Insert wenn Schwelle erreicht
        if len(self._pending_db) >= self._batch_size:
            self._flush_db()

        # Delivery-Callbacks verarbeiten (non-blocking)
        self._producer.poll(0)

    def flush(self) -> None:
        """Abschließender Flush vor Shutdown."""
        self._flush_db()
        self._producer.flush(timeout=10)

    def close(self) -> None:
        self.flush()
        try:
            self._conn.close()
        except Exception:
            pass

    @property
    def stats(self) -> dict:
        return {
            "kafka_ok":  self.kafka_ok,
            "kafka_err": self.kafka_err,
            "db_ok":     self.db_ok,
            "db_err":    self.db_err,
        }

    # ── Kafka ─────────────────────────────────────────────────────────────────

    def _send_kafka(self, record: FlowRecord) -> None:
        key     = record.src_ip.encode()
        payload = orjson.dumps(record.to_kafka_dict())

        try:
            self._producer.produce(
                TOPIC_FLOWS,
                key=key,
                value=payload,
                on_delivery=self._on_delivery,
            )
        except BufferError:
            # Queue voll → kurz warten und nochmal
            logger.warning("Kafka-Puffer voll, warte...")
            self._producer.poll(0.5)
            try:
                self._producer.produce(
                    TOPIC_FLOWS,
                    key=key,
                    value=payload,
                    on_delivery=self._on_delivery,
                )
            except BufferError:
                logger.error("Kafka-Puffer dauerhaft voll, verwerfe Flow %s", record.flow_id)
                self.kafka_err += 1

    def _on_delivery(self, err, msg) -> None:
        if err:
            logger.warning("Kafka Delivery-Fehler: %s", err)
            self.kafka_err += 1
        else:
            self.kafka_ok += 1

    # ── TimescaleDB ───────────────────────────────────────────────────────────

    def _flush_db(self) -> None:
        if not self._pending_db:
            return

        rows = [
            (
                r.flow_id,
                datetime.fromtimestamp(r.start_ts, tz=timezone.utc),
                datetime.fromtimestamp(r.end_ts,   tz=timezone.utc),
                r.src_ip,
                r.dst_ip,
                r.src_port,
                r.dst_port,
                r.proto,
                r.ip_version,
                r.pkt_count,
                r.byte_count,
                Json(r.stats),
            )
            for r in self._pending_db
        ]

        try:
            with self._conn.cursor() as cur:
                execute_values(
                    cur,
                    """
                    INSERT INTO flows
                        (flow_id, start_ts, end_ts,
                         src_ip, dst_ip, src_port, dst_port,
                         proto, ip_version, pkt_count, byte_count, stats)
                    VALUES %s
                    ON CONFLICT (flow_id, start_ts) DO NOTHING
                    """,
                    rows,
                )
            self._conn.commit()
            self.db_ok += len(self._pending_db)
            logger.debug("DB-Batch committed: %d flows", len(self._pending_db))

        except psycopg2.OperationalError as e:
            # Verbindungsfehler → reconnect versuchen
            logger.error("DB-Verbindungsfehler: %s – versuche Reconnect", e)
            self.db_err += 1
            try:
                self._conn.close()
            except Exception:
                pass
            # Reconnect mit denselben DSN-Daten (gespeichert im Connection-Objekt)
            self._conn = psycopg2.connect(self._conn.dsn)
            self._conn.autocommit = False

        except Exception as e:
            logger.error("DB-Insert-Fehler: %s", e)
            self.db_err += 1
            try:
                self._conn.rollback()
            except Exception:
                pass

        finally:
            self._pending_db.clear()
