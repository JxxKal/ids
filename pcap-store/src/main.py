"""
PCAP Store – Einstiegspunkt.

Abonniert zwei Kafka-Topics gleichzeitig:

  pcap-headers   – Pakete vom Sniffer (JSON PacketEvent mit raw_header_b64)
  alerts-enriched – Alerts vom Alert-Manager

Paket-Flow:
  PacketEvent → Buffer (sliding window MAX_WINDOW_S * 2)

Alert-Flow:
  Alert → PendingAlert anlegen (ready_at = alert_ts + window_s)
  → wenn Buffer-Zeitstempel > ready_at:
      Pakete extrahieren → PCAP bauen → MinIO upload → DB update

Warum Pending-Alerts?
  Der Sniffer sendet Pakete leicht verzögert gegenüber dem Alert-Timestamp.
  Wir warten window_s Sekunden nach dem Alert, damit auch Folge-Pakete
  im PCAP landen.
"""
from __future__ import annotations

import base64
import logging
import signal
import sys
import time

import orjson
from confluent_kafka import Consumer, KafkaError, KafkaException, Producer

from buffer import PacketBuffer, PendingAlert
from config import Config
from pcap_writer import build_pcap
from storage import PcapStorage

PUSH_TOPIC = "alerts-enriched-push"


def _make_producer(brokers: str) -> Producer:
    return Producer({
        "bootstrap.servers": brokers,
        "acks": "1",
        "linger.ms": 5,
    })

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("pcap-store")

PCAP_TOPIC   = "pcap-headers"
ALERTS_TOPIC = "alerts-enriched"
POLL_TIMEOUT = 0.5
GROUP_ID     = "pcap-store"


def _make_consumer(brokers: str) -> Consumer:
    return Consumer({
        "bootstrap.servers":  brokers,
        "group.id":           GROUP_ID,
        "auto.offset.reset":  "earliest",
        "enable.auto.commit": True,
    })


def _handle_packet(msg_value: bytes, buf: PacketBuffer) -> None:
    """Parst ein PacketEvent und fügt es dem Paketpuffer hinzu."""
    try:
        pkt = orjson.loads(msg_value)
        ts  = float(pkt.get("ts") or 0.0)
        raw_b64 = pkt.get("raw_header_b64")
        if not ts or not raw_b64:
            return
        raw = base64.b64decode(raw_b64)
        buf.add(ts, raw)
    except Exception as exc:
        log.debug("Packet parse error: %s", exc)


def _handle_alert(msg_value: bytes, pending: list[PendingAlert], window_s: float) -> None:
    """Registriert einen neuen Alert als PendingAlert."""
    try:
        alert    = orjson.loads(msg_value)
        alert_id = alert.get("alert_id")
        alert_ts = float(alert.get("ts") or time.time())
        if not alert_id:
            return
        # ready_at: alert_ts + window_s (Echtzeit-Sekunden nach Alert)
        ready_at = time.monotonic() + window_s
        pending.append(PendingAlert(
            alert_id=alert_id,
            alert_ts=alert_ts,
            window_s=window_s,
            ready_at=ready_at,
            alert_data=alert,
        ))
        log.debug("Pending alert %s (ready in %.0fs)", alert_id[:8], window_s)
    except Exception as exc:
        log.debug("Alert parse error: %s", exc)


def _flush_pending(
    pending: list[PendingAlert],
    buf: PacketBuffer,
    storage: PcapStorage,
    producer: Producer,
) -> list[PendingAlert]:
    """
    Verarbeitet alle Pending-Alerts deren Zeitfenster abgelaufen ist.
    Gibt die verbleibenden (noch nicht reifen) Alerts zurück.
    """
    now_mono   = time.monotonic()
    remaining: list[PendingAlert] = []

    for pa in pending:
        if now_mono < pa.ready_at:
            remaining.append(pa)
            continue

        packets = buf.extract(pa.alert_ts, pa.window_s)
        if packets:
            pcap_bytes = build_pcap(packets)
            key = storage.upload_pcap(pa.alert_id, pcap_bytes)
            if key:
                storage.mark_pcap_available(pa.alert_id, key)
                log.info(
                    "PCAP stored: %s | %d pkts | %.1f KB",
                    key,
                    len(packets),
                    len(pcap_bytes) / 1024,
                )
                # WS-Clients benachrichtigen dass PCAP jetzt verfügbar ist
                try:
                    msg = orjson.dumps({
                        "type": "pcap_available",
                        "data": {"alert_id": pa.alert_id},
                    })
                    producer.produce(PUSH_TOPIC, value=msg)
                    producer.poll(0)
                except Exception as exc:
                    log.debug("Kafka push failed: %s", exc)
        else:
            log.warning("No packets in window for alert %s", pa.alert_id[:8])

    return remaining


def run(cfg: Config) -> None:
    buf      = PacketBuffer(max_window_s=cfg.pcap_window_s)
    producer = _make_producer(cfg.kafka_brokers)
    storage  = PcapStorage(
        minio_endpoint=cfg.minio_endpoint,
        minio_access_key=cfg.minio_access_key,
        minio_secret_key=cfg.minio_secret_key,
        bucket=cfg.pcap_bucket,
        postgres_dsn=cfg.postgres_dsn,
    )

    consumer = _make_consumer(cfg.kafka_brokers)
    consumer.subscribe([PCAP_TOPIC, ALERTS_TOPIC])
    log.info("PCAP store ready | window=±%.0fs", cfg.pcap_window_s)

    pending: list[PendingAlert] = []
    running = True
    total_pkts   = 0
    total_pcaps  = 0

    def _stop(sig, _frame):
        nonlocal running
        log.info("Shutdown signal received")
        running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT,  _stop)

    try:
        while running:
            msg = consumer.poll(timeout=POLL_TIMEOUT)

            # Pending-Alerts auswerten (auch ohne neue Kafka-Nachricht)
            if pending:
                before = len(pending)
                pending = _flush_pending(pending, buf, storage, producer)
                total_pcaps += before - len(pending)

            if msg is None:
                if cfg.test_mode and not pending:
                    log.info("Test mode: no more messages, exiting")
                    break
                continue

            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    if cfg.test_mode and not pending:
                        break
                    continue
                raise KafkaException(msg.error())

            topic = msg.topic()

            if topic == PCAP_TOPIC:
                _handle_packet(msg.value(), buf)
                total_pkts += 1

            elif topic == ALERTS_TOPIC:
                _handle_alert(msg.value(), pending, cfg.pcap_window_s)

    finally:
        # Restliche Pending-Alerts sofort flushen (Shutdown)
        if pending:
            log.info("Flushing %d pending alerts on shutdown …", len(pending))
            # Alle als sofort bereit markieren
            for pa in pending:
                pa.ready_at = 0
            _flush_pending(pending, buf, storage)

        log.info(
            "Shutting down – packets buffered: %d, PCAPs written: %d",
            total_pkts,
            total_pcaps,
        )
        producer.flush(timeout=5)
        storage.close()
        consumer.close()


def main() -> None:
    cfg = Config.from_env()
    log.info(
        "Starting pcap-store | brokers=%s minio=%s bucket=%s window=±%.0fs test_mode=%s",
        cfg.kafka_brokers,
        cfg.minio_endpoint,
        cfg.pcap_bucket,
        cfg.pcap_window_s,
        cfg.test_mode,
    )
    try:
        run(cfg)
    except Exception:
        log.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()
