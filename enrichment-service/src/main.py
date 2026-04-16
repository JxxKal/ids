"""
Enrichment Service – Einstiegspunkt.

Liest angereicherte Alerts vom Topic 'alerts-enriched', reichert die
enthaltenen IP-Adressen mit DNS, Ping, GeoIP und Known-Network-Daten an
und schreibt das Ergebnis zurück in die TimescaleDB (alerts.enrichment).

Flow:
  1. Alert aus Kafka lesen
  2. src_ip und dst_ip enrichen (Redis-Cache first)
  3. alerts.enrichment in TimescaleDB aktualisieren
  4. host_info-Tabelle upserten

Wichtig: private IPs (RFC1918) werden nicht ge-pingt und nicht per GeoIP
abgefragt, da beides keinen Sinn ergibt.

Design-Entscheidung: kein Re-Publish auf alerts-enriched (vermeidet Loop).
Die API liest Enrichment-Daten aus der DB. Echtzeit-Updates erreichen die
WebSocket-Clients via PostgreSQL NOTIFY (aus dem API-Service).
"""
from __future__ import annotations

import logging
import signal
import sys
import time

import orjson
from confluent_kafka import Consumer, KafkaError, KafkaException

from cache import EnrichmentCache
from config import Config
from db import EnrichmentDB
from enricher import (
    asn_lookup,
    geo_lookup,
    init_geoip,
    is_private_ip,
    ping_host,
    resolve_hostname,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("enrichment-service")

INPUT_TOPIC  = "alerts-enriched"
POLL_TIMEOUT = 1.0
GROUP_ID     = "enrichment-service"


def _make_consumer(brokers: str) -> Consumer:
    return Consumer({
        "bootstrap.servers":  brokers,
        "group.id":           GROUP_ID,
        "auto.offset.reset":  "earliest",
        "enable.auto.commit": True,
    })


def _enrich_ip(
    ip: str | None,
    cfg: Config,
    cache: EnrichmentCache,
    db: EnrichmentDB,
) -> dict | None:
    """Reichert eine einzelne IP an. Gibt Enrichment-Dict oder None zurück."""
    if not ip:
        return None

    # Cache prüfen
    cached = cache.get(ip)
    if cached is not None:
        return cached

    private = is_private_ip(ip)

    hostname = resolve_hostname(ip, cfg.dns_timeout_s)
    ping_ms  = ping_host(ip, cfg.ping_timeout_ms)
    geo      = None if private else geo_lookup(ip)
    asn      = None if private else asn_lookup(ip)
    network  = db.get_network_for_ip(ip)

    info: dict = {
        "hostname": hostname,
        "ping_ms":  ping_ms,
        "geo":      geo,
        "asn":      asn,
        "network":  network,
    }

    # Im Cache + host_info speichern
    cache.set(ip, info)
    db.upsert_host_info(ip, info)

    return info


def run(cfg: Config) -> None:
    init_geoip(cfg.geoip_city_db, cfg.geoip_asn_db)

    cache = EnrichmentCache(cfg.redis_url, cfg.cache_ttl_s)
    db    = EnrichmentDB(cfg.postgres_dsn)

    consumer = _make_consumer(cfg.kafka_brokers)
    consumer.subscribe([INPUT_TOPIC])

    log.info("Enrichment service ready")

    running = True
    total   = 0

    def _stop(sig, _frame):
        nonlocal running
        log.info("Shutdown signal received")
        running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT,  _stop)

    try:
        while running:
            msg = consumer.poll(timeout=POLL_TIMEOUT)

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

            try:
                alert = orjson.loads(msg.value())
            except Exception as exc:
                log.warning("Could not decode alert: %s", exc)
                continue

            alert_id = alert.get("alert_id")
            if not alert_id:
                continue

            # Bereits angereicherte Alerts überspringen
            if alert.get("enrichment"):
                continue

            src_ip = alert.get("src_ip")
            dst_ip = alert.get("dst_ip")

            t0 = time.monotonic()
            src_info = _enrich_ip(src_ip, cfg, cache, db)
            dst_info = _enrich_ip(dst_ip, cfg, cache, db)
            elapsed_ms = int((time.monotonic() - t0) * 1000)

            enrichment = {
                "src_hostname": src_info.get("hostname") if src_info else None,
                "dst_hostname": dst_info.get("hostname") if dst_info else None,
                "src_network":  src_info.get("network")  if src_info else None,
                "dst_network":  dst_info.get("network")  if dst_info else None,
                "src_ping_ms":  src_info.get("ping_ms")  if src_info else None,
                "dst_ping_ms":  dst_info.get("ping_ms")  if dst_info else None,
                "src_asn":      src_info.get("asn")      if src_info else None,
                "dst_asn":      dst_info.get("asn")      if dst_info else None,
                "src_geo":      src_info.get("geo")      if src_info else None,
                "dst_geo":      dst_info.get("geo")      if dst_info else None,
            }

            db.update_alert_enrichment(alert_id, enrichment)

            total += 1
            log.debug(
                "Enriched %s | %s → %s | %dms",
                alert_id[:8],
                src_ip or "-",
                dst_ip or "-",
                elapsed_ms,
            )

            if total % 100 == 0:
                log.info("Enriched %d alerts", total)

    finally:
        log.info("Shutting down – enriched %d alerts", total)
        db.close()
        consumer.close()


def main() -> None:
    cfg = Config.from_env()
    log.info(
        "Starting enrichment-service | brokers=%s redis=%s test_mode=%s",
        cfg.kafka_brokers,
        cfg.redis_url,
        cfg.test_mode,
    )
    try:
        run(cfg)
    except Exception:
        log.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()
