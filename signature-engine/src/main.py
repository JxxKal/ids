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
import random
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
ALERTS_TOPIC = "alerts-raw"
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


def _metrics_delivery_cb(err, _msg):
    # Metrik-Verluste sind unkritisch (Shadow-Pipeline, kein Alert-Pfad) –
    # debug statt error, damit eine Producer-Backpressure-Phase die Logs
    # nicht flutet.
    if err:
        log.debug("Rule-metric delivery failed: %s", err)


def run(cfg: Config) -> None:
    engine = SignatureEngine(cfg.rules_dir, own_ips=cfg.own_ips, own_nets=cfg.own_nets)
    engine.setup()
    log.info("Signature engine ready – %d rules loaded", engine.rule_count)

    consumer = _make_consumer(cfg.kafka_brokers)
    producer  = _make_producer(cfg.kafka_brokers)

    consumer.subscribe([FLOWS_TOPIC])
    log.info("Subscribed to topic '%s'", FLOWS_TOPIC)

    if cfg.metrics_enabled and cfg.metrics_sampling_rate > 0.0:
        log.info(
            "Shadow-Metrik aktiv: topic=%s sampling=%.4f (≈ 1 von %d Flows)",
            cfg.metrics_topic,
            cfg.metrics_sampling_rate,
            int(round(1.0 / cfg.metrics_sampling_rate)) if cfg.metrics_sampling_rate else 0,
        )
    else:
        log.info("Shadow-Metrik aus (METRICS_ENABLED=false oder rate=0)")

    last_reload = time.monotonic()
    running = True

    def _stop(sig, _frame):
        nonlocal running
        log.info("Shutdown signal received")
        running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT,  _stop)

    total_flows   = 0
    total_alerts  = 0
    total_metrics = 0

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

            # Phase-2 Shadow-Metrik: Bernoulli-Sampling pro Flow. Wenn drin,
            # alle metric-deklarierten Params dieses Flows als Bündel emittieren.
            # Per-Flow-Sample (statt per-Param) hält die Werte für einen Flow
            # zeitlich konsistent — der Tuner kann beim Korrelieren mit Alerts
            # auf einen Snapshot zugreifen.
            metrics_emitted = 0
            if (
                cfg.metrics_enabled
                and cfg.metrics_sampling_rate > 0.0
                and (cfg.metrics_sampling_rate >= 1.0
                     or random.random() < cfg.metrics_sampling_rate)
            ):
                try:
                    metrics = engine.compute_metrics(flow)
                except Exception as exc:
                    log.debug("compute_metrics failed: %s", exc)
                    metrics = []
                for m in metrics:
                    producer.produce(
                        cfg.metrics_topic,
                        # Key: rule_id|param_name → gleiche Partition für gleiche
                        # Metrik, damit der Tuner-Consumer ordering pro Stream hat.
                        key=f"{m['rule_id']}|{m['param_name']}".encode(),
                        value=orjson.dumps(m),
                        callback=_metrics_delivery_cb,
                    )
                    metrics_emitted += 1
                total_metrics += metrics_emitted

            # Flush periodisch (bei jedem Flow mit Alerts oder Metriken sofort)
            if alerts or metrics_emitted:
                producer.poll(0)

    finally:
        log.info(
            "Shutting down – flows processed: %d, alerts generated: %d, metrics emitted: %d",
            total_flows,
            total_alerts,
            total_metrics,
        )
        producer.flush(timeout=10)
        consumer.close()


def main() -> None:
    cfg = Config.from_env()
    log.info(
        "Starting signature-engine | brokers=%s rules_dir=%s test_mode=%s metrics=%s rate=%s",
        cfg.kafka_brokers,
        cfg.rules_dir,
        cfg.test_mode,
        cfg.metrics_enabled,
        cfg.metrics_sampling_rate,
    )
    try:
        run(cfg)
    except Exception:
        log.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()
