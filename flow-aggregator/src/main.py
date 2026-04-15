"""
IDS Flow Aggregator

Liest PacketEvents aus dem Kafka-Topic "raw-packets",
aggregiert sie zu Flows und schreibt fertige FlowRecords in:
  - Kafka-Topic "flows"  (für Signature-Engine + ML-Engine)
  - TimescaleDB          (für API + Dashboard)
"""
import logging
import signal
import time

import orjson
from confluent_kafka import Consumer, KafkaError, KafkaException

from config import Config
from flow import FlowAggregator
from models import PacketEvent
from publisher import FlowPublisher

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("flow-aggregator")


def main() -> None:
    config = Config.from_env()

    logger.info(
        "Flow Aggregator startet | brokers=%s | timeout=%ds | max=%ds | test=%s",
        config.kafka_brokers,
        config.flow_timeout_s,
        config.flow_max_duration_s,
        config.test_mode,
    )

    # ── Graceful Shutdown ─────────────────────────────────────────────────────
    running = True

    def handle_signal(sig, _frame):
        nonlocal running
        logger.info("Signal %s empfangen, starte Shutdown...", sig)
        running = False

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT,  handle_signal)

    # ── Kafka Consumer ────────────────────────────────────────────────────────
    consumer = Consumer({
        "bootstrap.servers":    config.kafka_brokers,
        "group.id":             "ids-flow-aggregator",
        # latest: Wir verarbeiten Echtzeit-Traffic, kein Replay alter Pakete
        "auto.offset.reset":    "latest",
        "enable.auto.commit":   "false",
        # Heartbeat-Intervall: muss < max.poll.interval.ms sein
        "heartbeat.interval.ms": "3000",
        "session.timeout.ms":    "10000",
        "max.poll.interval.ms":  "300000",
    })
    consumer.subscribe(["raw-packets"])
    logger.info("Kafka Consumer subscribed auf 'raw-packets'")

    # ── Publisher (Kafka + DB) ────────────────────────────────────────────────
    publisher = FlowPublisher(
        kafka_brokers=config.kafka_brokers,
        postgres_dsn=config.postgres_dsn,
        batch_size=config.db_batch_size,
    )

    # ── Flow-Aggregator ───────────────────────────────────────────────────────
    aggregator = FlowAggregator(
        timeout_s=config.flow_timeout_s,
        max_duration_s=config.flow_max_duration_s,
    )

    # ── Hauptschleife ─────────────────────────────────────────────────────────
    last_flush  = time.monotonic()
    last_stats  = time.monotonic()
    msgs_total  = 0
    parse_errs  = 0

    try:
        while running:
            msg = consumer.poll(timeout=0.1)

            if msg is None:
                pass  # Timeout – normal, kein Paket in diesem Intervall

            elif msg.error():
                code = msg.error().code()
                if code == KafkaError._PARTITION_EOF:
                    pass  # Ende der Partition – normal
                elif code == KafkaError._ALL_BROKERS_DOWN:
                    logger.error("Alle Kafka-Broker nicht erreichbar, warte...")
                    time.sleep(5)
                else:
                    logger.error("Kafka Consumer Fehler: %s", msg.error())

            else:
                # Paket verarbeiten
                try:
                    data  = orjson.loads(msg.value())
                    pkt   = PacketEvent.model_validate(data)
                    ready = aggregator.add_packet(pkt)
                    if ready:
                        publisher.publish(ready)
                    msgs_total += 1

                except Exception as e:
                    parse_errs += 1
                    if parse_errs % 100 == 1:
                        # Spam vermeiden: nur jede 100. Fehlermeldung loggen
                        logger.warning("Paket-Fehler (insgesamt %d): %s", parse_errs, e)

            now = time.monotonic()

            # Periodischer Flow-Flush (abgelaufene Timeouts)
            if now - last_flush >= config.flush_interval_s:
                expired = aggregator.flush_expired()
                if expired:
                    publisher.publish(expired)
                    logger.debug("Flushed %d abgelaufene Flows", len(expired))
                consumer.commit(asynchronous=True)
                last_flush = now

            # Stats-Logging alle 30 Sekunden
            if now - last_stats >= 30.0:
                pub = publisher.stats
                logger.info(
                    "active_flows=%-6d  msgs=%d  parse_err=%d  "
                    "kafka_ok=%d  kafka_err=%d  db_ok=%d  db_err=%d",
                    aggregator.active_count,
                    msgs_total,
                    parse_errs,
                    pub["kafka_ok"], pub["kafka_err"],
                    pub["db_ok"],    pub["db_err"],
                )
                last_stats = now

    except KafkaException as e:
        logger.critical("Fataler Kafka-Fehler: %s", e)

    finally:
        logger.info("Shutdown: Flushe alle aktiven Flows (%d)...", aggregator.active_count)
        remaining = aggregator.flush_all()
        if remaining:
            publisher.publish(remaining)
        publisher.close()
        consumer.close()
        logger.info(
            "Flow Aggregator beendet | msgs=%d | parse_err=%d",
            msgs_total, parse_errs,
        )


if __name__ == "__main__":
    main()
