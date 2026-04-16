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
    """
    Reichert eine einzelne IP an.
    Gibt Enrichment-Dict inkl. trusted/trust_source/display_name zurück.
    """
    if not ip:
        return None

    # Cache prüfen (enthält auch Trust-Felder wenn bereits gecacht)
    cached = cache.get(ip)
    if cached is not None:
        return cached

    private = is_private_ip(ip)

    # Trust-Status VOR der DNS-Auflösung lesen (manuell/csv hat Vorrang)
    trust = db.get_host_trust(ip)

    hostname = resolve_hostname(ip, cfg.dns_timeout_s)
    ping_ms  = ping_host(ip, cfg.ping_timeout_ms)
    geo      = None if private else geo_lookup(ip)
    asn      = None if private else asn_lookup(ip)
    network  = db.get_network_for_ip(ip)

    info: dict = {
        "hostname":     hostname,
        "ping_ms":      ping_ms,
        "geo":          geo,
        "asn":          asn,
        "network":      network,
        # Trust-Felder – entweder aus DB (manual/csv) oder aus DNS-Ergebnis
        "trusted":      trust["trusted"] or bool(hostname),
        "trust_source": trust["trust_source"] or ("dns" if hostname else None),
        "display_name": trust["display_name"],
    }

    # Im Cache + host_info speichern
    cache.set(ip, info)
    db.upsert_host_info(ip, info)

    return info


def _check_unknown_host(
    ip: str | None,
    info: dict | None,
    direction: str,
    db: EnrichmentDB,
) -> None:
    """
    Erzeugt einen UNKNOWN_HOST_001-Alert wenn:
    - IP ist eine private/interne Adresse
    - Host ist nicht als trusted bekannt
    - In den letzten UNKNOWN_HOST_DEDUP_S war noch kein solcher Alert
    """
    if not ip or not info:
        return
    if info.get("trusted"):
        return
    if not is_private_ip(ip):
        return
    if db.should_alert_unknown_host(ip):
        db.insert_unknown_host_alert(ip, direction)


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

            def _f(info: dict | None, key: str):
                return info.get(key) if info else None

            enrichment = {
                "src_hostname":     _f(src_info, "hostname"),
                "dst_hostname":     _f(dst_info, "hostname"),
                "src_network":      _f(src_info, "network"),
                "dst_network":      _f(dst_info, "network"),
                "src_ping_ms":      _f(src_info, "ping_ms"),
                "dst_ping_ms":      _f(dst_info, "ping_ms"),
                "src_asn":          _f(src_info, "asn"),
                "dst_asn":          _f(dst_info, "asn"),
                "src_geo":          _f(src_info, "geo"),
                "dst_geo":          _f(dst_info, "geo"),
                # Trust-Felder
                "src_trusted":      _f(src_info, "trusted"),
                "dst_trusted":      _f(dst_info, "trusted"),
                "src_trust_source": _f(src_info, "trust_source"),
                "dst_trust_source": _f(dst_info, "trust_source"),
                "src_display_name": _f(src_info, "display_name"),
                "dst_display_name": _f(dst_info, "display_name"),
            }

            db.update_alert_enrichment(alert_id, enrichment)

            # Unknown-Host-Alert für unbekannte interne IPs
            _check_unknown_host(src_ip, src_info, "src", db)
            _check_unknown_host(dst_ip, dst_info, "dst", db)

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
