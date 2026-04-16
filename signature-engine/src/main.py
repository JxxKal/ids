"""
Signature Engine – Einstiegspunkt.

Liest Flow-Events vom Kafka-Topic 'flows', bewertet sie gegen alle aktiven
Signaturen, und schreibt Alerts auf das Topic 'alerts'.

Topics:
  Input:  flows   – Flow-Dicts (JSON), erzeugt vom flow-aggregator
  Output: alerts  – Alert-Dicts (JSON)

Umgebungsvariablen (siehe config.py):
  KAFKA_BROKERS   – Standard: localhost:9092
  RULES_DIR       – Standard: /rules
  TEST_MODE       – Standard: false
    Im Test-Modus werden alle Nachrichten konsumiert und dann beendet.
"""
from __future__ import annotations

import logging
import signal
import sys
import time

import orjson
from confluent_kafka import Consumer, KafkaError, KafkaException, Producer

from config import Config
from engine import SignatureEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("signature-engine")

FLOWS_TOPIC  = "flows"
ALERTS_TOPIC = "alerts"
POLL_TIMEOUT = 1.0   # Sekunden
GROUP_ID     = "signature-engine"


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
        "acks":              "1",
        "linger.ms":         10,
        "compression.type":  "lz4",
    })


def _delivery_cb(err, msg):
    if err:
        log.error("Alert delivery failed: %s", err)


def run(cfg: Config) -> None:
    engine = SignatureEngine(cfg.rules_dir)
    engine.setup()
    log.info("Signature engine ready – %d rules loaded", engine.rule_count)

    consumer = _make_consumer(cfg.kafka_brokers)
    producer  = _make_producer(cfg.kafka_brokers)

    consumer.subscribe([FLOWS_TOPIC])
    log.info("Subscribed to topic '%s'", FLOWS_TOPIC)

    last_reload = time.monotonic()
    running = True

    def _stop(sig, _frame):
        nonlocal running
        log.info("Shutdown signal received")
        running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT,  _stop)

    total_flows  = 0
    total_alerts = 0

    try:
        while running:
            msg = consumer.poll(timeout=POLL_TIMEOUT)

            # Periodischer Hot-Reload
            now = time.monotonic()
            if now - last_reload >= cfg.reload_interval_s:
                if engine.maybe_reload():
                    log.info("Rules reloaded – %d rules active", engine.rule_count)
                last_reload = now

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

            # Flow deserialisieren
            try:
                flow = orjson.loads(msg.value())
            except Exception as exc:
                log.warning("Could not decode flow message: %s", exc)
                continue

            total_flows += 1

            # Regeln auswerten
            alerts = engine.evaluate(flow)

            for alert in alerts:
                total_alerts += 1
                log.info(
                    "ALERT [%s] %s | %s → %s:%s | severity=%s",
                    alert["rule_id"],
                    alert["rule_name"],
                    alert.get("src_ip", "-"),
                    alert.get("dst_ip", "-"),
                    alert.get("dst_port", "-"),
                    alert["severity"],
                )
                producer.produce(
                    ALERTS_TOPIC,
                    value=orjson.dumps(alert),
                    callback=_delivery_cb,
                )

            # Flush periodisch (bei jedem Flow mit Alerts sofort)
            if alerts:
                producer.poll(0)

    finally:
        log.info(
            "Shutting down – flows processed: %d, alerts generated: %d",
            total_flows,
            total_alerts,
        )
        producer.flush(timeout=10)
        consumer.close()


def main() -> None:
    cfg = Config.from_env()
    log.info(
        "Starting signature-engine | brokers=%s rules_dir=%s test_mode=%s",
        cfg.kafka_brokers,
        cfg.rules_dir,
        cfg.test_mode,
    )
    try:
        run(cfg)
    except Exception:
        log.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()
