"""
Alert Manager – Einstiegspunkt.

Liest rohe Alerts vom Topic 'alerts-raw' (erzeugt von signature-engine und
ml-engine), führt Deduplication und Score-Normierung durch, und schreibt das
Ergebnis auf 'alerts-enriched' und in TimescaleDB.

Verarbeitungsschritte pro Alert:
  1. Deduplication: gleicher (rule_id, src_ip, dst_ip, dst_port) innerhalb
     DEDUP_WINDOW_S → verwerfen
  2. Score-Anreicherung: severity → numerischer Score
  3. alert_id vergeben (UUID v4)
  4. Publizieren auf 'alerts-enriched'
  5. In TimescaleDB schreiben (gebatcht)

Hinweis: Enrichment (DNS, GeoIP, Ping) übernimmt der enrichment-service,
der ebenfalls 'alerts-enriched' konsumiert und angereicherte Versionen
zurückschreibt.
"""
from __future__ import annotations

import logging
import signal
import sys
import time
import uuid
from datetime import datetime, timezone

import orjson
from confluent_kafka import Consumer, KafkaError, KafkaException, Producer

from config import Config
from db import AlertWriter
from dedup import DedupCache
from scorer import enrich_score
from self_filter import SelfFilter
from suppression import SuppressionCache

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("alert-manager")

INPUT_TOPIC    = "alerts-raw"
FEEDBACK_TOPIC = "feedback"
OUTPUT_TOPIC   = "alerts-enriched"
POLL_TIMEOUT   = 1.0
GROUP_ID       = "alert-manager"


def _make_consumer(brokers: str) -> Consumer:
    return Consumer({
        "bootstrap.servers":  brokers,
        "group.id":           GROUP_ID,
        "auto.offset.reset":  "earliest",
        "enable.auto.commit": True,
    })


def _make_producer(brokers: str) -> Producer:
    return Producer({
        "bootstrap.servers": brokers,
        "acks":              "all",
        "linger.ms":         5,
        "compression.type":  "lz4",
    })


def _delivery_cb(err, msg):
    if err:
        log.error("Alert delivery failed: %s", err)


def run(cfg: Config) -> None:
    dedup        = DedupCache(window_s=cfg.dedup_window_s)
    writer       = AlertWriter(cfg.postgres_dsn)
    suppression  = SuppressionCache(cfg.postgres_dsn)
    self_filter  = SelfFilter()
    suppression.refresh()  # initiales Laden

    consumer = _make_consumer(cfg.kafka_brokers)
    producer  = _make_producer(cfg.kafka_brokers)
    # Subscribe auch auf das Feedback-Topic, damit der SuppressionCache
    # bei FP-Markierung sofort refreshed wird (statt bis zu 60 s zu warten).
    consumer.subscribe([INPUT_TOPIC, FEEDBACK_TOPIC])

    log.info(
        "Alert manager ready | dedup_window=%ds",
        int(cfg.dedup_window_s),
    )

    running = True
    total_in       = 0
    total_self     = 0
    total_deduped  = 0
    total_out      = 0
    last_flush_log = time.monotonic()

    def _stop(sig, _frame):
        nonlocal running
        log.info("Shutdown signal received")
        running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT,  _stop)

    try:
        while running:
            msg = consumer.poll(timeout=POLL_TIMEOUT)

            # Periodisches Stats-Log + DB-Flush
            now_mono = time.monotonic()
            if now_mono - last_flush_log > 60:
                writer.flush()
                log.info(
                    "Stats | in=%d self=%d deduped=%d out=%d",
                    total_in, total_self, total_deduped, total_out,
                )
                last_flush_log = now_mono

            if msg is None:
                if cfg.test_mode:
                    log.info("Test mode: no more messages, exiting")
                    break
                continue

            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    if cfg.test_mode:
                        break
                    continue
                raise KafkaException(msg.error())

            # Feedback-Topic: sofortiger Cache-Refresh, damit neue Alerts
            # unmittelbar nach der FP-Markierung unterdrückt werden (vorher
            # Wartezeit bis zum nächsten 60-s-Intervall).
            if msg.topic() == FEEDBACK_TOPIC:
                try:
                    payload = orjson.loads(msg.value())
                    log.info(
                        "Feedback-Event empfangen (alert=%s, fb=%s) → force refresh",
                        payload.get("alert_id", "?")[:8], payload.get("feedback"),
                    )
                except Exception:
                    log.info("Feedback-Event empfangen → force refresh")
                suppression.refresh()
                continue

            try:
                alert = orjson.loads(msg.value())
            except Exception as exc:
                log.warning("Could not decode alert: %s", exc)
                continue

            total_in += 1

            # 0. Self-Filter: Alerts wo die Appliance selbst src oder dst ist
            #    → verwerfen (kein Security-Event, nur Noise von Updates/DNS/Ping).
            #    Test-Alerts werden davon NICHT gefiltert.
            if not alert.get("is_test") and self_filter.should_drop(
                alert.get("src_ip"), alert.get("dst_ip"),
            ):
                total_self += 1
                continue

            # 1. Deduplication (Test-Alerts immer durchlassen)
            if not alert.get("is_test") and dedup.is_duplicate(alert):
                total_deduped += 1
                continue

            # 2. Score-Normierung
            enrich_score(alert)

            # 2b. Suppression: manuelle FP + ML-gelernte Muster → low
            suppression.maybe_refresh()
            kind = suppression.classify(
                alert.get("rule_id"), alert.get("src_ip"), alert.get("dst_ip"),
            )
            if kind is not None:
                tag = "auto-suppressed" if kind == "manual" else "ml-suppressed"
                if alert.get("severity") != "low":
                    log.info(
                        "Suppression (%s): %s %s → %s → low",
                        kind, alert.get("rule_id"), alert.get("src_ip"), alert.get("dst_ip"),
                    )
                    alert["severity"] = "low"
                    tags = list(alert.get("tags") or [])
                    if tag not in tags:
                        tags.append(tag)
                    alert["tags"] = tags

            # ts auf ISO-String normieren (Signature-Engine liefert Unix-Float)
            ts_raw = alert.get("ts") or time.time()
            if isinstance(ts_raw, (int, float)):
                alert["ts"] = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc).isoformat()

            # 3. Alert-ID vergeben
            alert.setdefault("alert_id", str(uuid.uuid4()))
            alert.setdefault("source", "signature")
            alert.setdefault("feedback", None)
            alert.setdefault("is_test", False)

            # 4. Publizieren
            producer.produce(
                OUTPUT_TOPIC,
                key=(alert.get("src_ip") or "").encode(),
                value=orjson.dumps(alert),
                callback=_delivery_cb,
            )
            producer.poll(0)
            total_out += 1

            # 5. DB-Write
            writer.write(alert)

            log.info(
                "[%s] %s | %s → %s:%s | severity=%s score=%.2f",
                alert["alert_id"][:8],
                alert.get("rule_id", "-"),
                alert.get("src_ip", "-"),
                alert.get("dst_ip", "-"),
                alert.get("dst_port", "-"),
                alert.get("severity", "-"),
                alert.get("score", 0.0),
            )

    finally:
        log.info(
            "Shutting down | in=%d self=%d deduped=%d out=%d",
            total_in, total_self, total_deduped, total_out,
        )
        writer.close()
        suppression.close()
        producer.flush(timeout=10)
        consumer.close()


def main() -> None:
    cfg = Config.from_env()
    log.info(
        "Starting alert-manager | brokers=%s dedup_window=%ds test_mode=%s",
        cfg.kafka_brokers,
        int(cfg.dedup_window_s),
        cfg.test_mode,
    )
    try:
        run(cfg)
    except Exception:
        log.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()
