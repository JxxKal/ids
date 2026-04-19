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
from datetime import datetime, timezone

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
    """Parst ein PcapRecord vom Sniffer und fügt es dem Paketpuffer hinzu.

    Sniffer-Schema (PcapRecord):
        ts_sec:   u32  – Sekunden seit Epoch
        ts_usec:  u32  – Mikrosekunden-Anteil
        orig_len: u32  – originale Paketlänge
        data_b64: str  – Base64-kodierte rohe Bytes
    """
    try:
        pkt = orjson.loads(msg_value)
        # Timestamp aus ts_sec + ts_usec zusammensetzen
        ts_sec  = pkt.get("ts_sec")
        ts_usec = pkt.get("ts_usec", 0)
        if ts_sec is None:
            return
        ts = float(ts_sec) + float(ts_usec) / 1_000_000
        raw_b64 = pkt.get("data_b64")
        if not raw_b64:
            return
        raw = base64.b64decode(raw_b64)
        buf.add(ts, raw)
    except Exception as exc:
        log.debug("Packet parse error: %s", exc)


def _handle_alert(msg_value: bytes, pending: list[PendingAlert], window_s: float) -> None:
    """Registriert einen neuen Alert als PendingAlert."""
    try:
        alert    = orjson.loads(msg_value)
        log.info("Alert received: keys=%s", list(alert.keys()))
        alert_id = alert.get("alert_id")
        ts_raw = alert.get("ts")
        if ts_raw:
            try:
                alert_ts = datetime.fromisoformat(str(ts_raw)).timestamp()
            except (ValueError, TypeError):
                try:
                    alert_ts = float(ts_raw)
                except (ValueError, TypeError):
                    alert_ts = time.time()
        else:
            alert_ts = time.time()
        if not alert_id:
            log.warning("Alert dropped: no alert_id field. Full alert: %s", alert)
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
        log.info("Pending alert added: %s (alert_ts=%.3f, ready in %.0fs, window=%.0fs)",
                 alert_id[:8], alert_ts, window_s, window_s)
    except Exception as exc:
        log.warning("Alert parse error: %s | raw=%r", exc, msg_value[:200])


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

        buf_count = len(buf._buf)
        buf_newest = buf.newest_ts()
        log.info(
            "Flushing alert %s: alert_ts=%.3f window=%.0fs | buf_count=%d buf_newest=%.3f",
            pa.alert_id[:8], pa.alert_ts, pa.window_s, buf_count, buf_newest,
        )
        packets = buf.extract(pa.alert_ts, pa.window_s)
        log.info("Packets extracted for %s: %d", pa.alert_id[:8], len(packets))
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
    last_stats_log = time.monotonic()

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
                now_mono = time.monotonic()
                if now_mono - last_stats_log >= 30:
                    log.info(
                        "Buffer stats: pkts_received=%d buf_count=%d buf_newest=%.3f pending=%d",
                        total_pkts, len(buf._buf), buf.newest_ts(), len(pending),
                    )
                    last_stats_log = now_mono

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
