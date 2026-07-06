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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import orjson
from confluent_kafka import Consumer, KafkaError, KafkaException, Producer

from boundary import classify_v2 as classify_boundary_v2
from boundary import parse_priority_map_v2
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

# ── Heartbeat für den Docker-Healthcheck ─────────────────────────────────────
# Die Hauptschleife touch't /tmp/heartbeat (rate-limited auf 5 s); der
# Compose-Healthcheck meldet unhealthy, wenn das File älter als 120 s ist.
# Bewusst an die Schleife gekoppelt statt an den Prozess: ein hängender
# Consumer fällt so auf, ein bloß lebender Interpreter reicht nicht.
_HB_LAST = 0.0


def _beat() -> None:
    global _HB_LAST
    now = time.monotonic()
    if now - _HB_LAST < 5.0:
        return
    _HB_LAST = now
    try:
        Path("/tmp/heartbeat").touch()
    except OSError:
        pass


INPUT_TOPIC   = "alerts-enriched"
PUSH_TOPIC    = "alerts-enriched-push"
POLL_TIMEOUT  = 1.0
GROUP_ID      = "enrichment-service"

# ── Thread-Pool für die blockierenden Netz-Lookups ───────────────────────────
# rDNS (bis dns_timeout_s) und Ping (bis ping_timeout_ms) sind reine Netz-I/O
# und blockierten bisher seriell (src.rDNS → src.Ping → dst.rDNS → dst.Ping),
# im Worst-Case ~6 s/Alert. Bei Scan-Bursts mit vielen nicht-pingbaren IPs
# staut das den Consumer und die Enriched-Pushes hinken hinterher.
# Wir stoßen die vier Calls (rDNS+Ping je für src und dst) gemeinsam an, sodass
# der Worst-Case auf ~langsamster-Einzel-Call (~2 s) sinkt. 4 Worker genügen,
# da wir pro Alert höchstens 4 Lookups parallel offen haben (danach blockiert
# die Schleife bis zum Ergebnis). DB/Cache/GeoIP bleiben bewusst im Hauptthread
# — kein Lock nötig, keine Race beim Cache-Write.
_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="enrich")


def _make_producer(brokers: str) -> Producer:
    return Producer({
        "bootstrap.servers": brokers,
        "acks": "1",
        "linger.ms": 5,
        "compression.type": "lz4",
    })


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
    netfut: tuple | None = None,
) -> dict | None:
    """
    Reichert eine einzelne IP an.
    Gibt Enrichment-Dict inkl. trusted/trust_source/display_name zurück.

    ``netfut`` ist ein optionales (rDNS-Future, Ping-Future)-Tupel, das der
    Aufrufer bereits parallel angestoßen hat (siehe _enrich_pair). Fehlt es,
    laufen rDNS und Ping hier wie gehabt seriell.
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

    # rDNS + Ping: entweder die vom Aufrufer parallel gestarteten Futures
    # einsammeln oder – als Fallback – hier direkt (seriell) auflösen.
    if netfut is not None:
        hostname = netfut[0].result()
        ping_ms  = netfut[1].result()
    else:
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


def _enrich_pair(
    src_ip: str | None,
    dst_ip: str | None,
    cfg: Config,
    cache: EnrichmentCache,
    db: EnrichmentDB,
) -> tuple[dict | None, dict | None]:
    """
    Reichert src und dst gemeinsam an und lässt dabei die blockierenden
    Netz-Lookups (rDNS + Ping) beider IPs parallel laufen.

    Die Futures werden vom Hauptthread angestoßen, DB/Cache/GeoIP bleiben im
    Hauptthread — dadurch keine Race beim Cache-Write und keine Anforderung an
    die Thread-Sicherheit von DB-/Redis-Client. Nur nicht-gecachte IPs lösen
    Lookups aus (gecachte bleiben billig); doppelte IPs (src == dst) werden
    einmalig angestoßen.
    """
    futures: dict[str, tuple] = {}
    for ip in (src_ip, dst_ip):
        if ip and ip not in futures and cache.get(ip) is None:
            futures[ip] = (
                _POOL.submit(resolve_hostname, ip, cfg.dns_timeout_s),
                _POOL.submit(ping_host, ip, cfg.ping_timeout_ms),
            )

    src_info = _enrich_ip(src_ip, cfg, cache, db, futures.get(src_ip or ""))
    dst_info = _enrich_ip(dst_ip, cfg, cache, db, futures.get(dst_ip or ""))
    return src_info, dst_info


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

    cache    = EnrichmentCache(cfg.redis_url, cfg.cache_ttl_s)
    db       = EnrichmentDB(cfg.postgres_dsn)
    producer = _make_producer(cfg.kafka_brokers)

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
            _beat()
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
            # src + dst parallel anreichern (rDNS/Ping nebenläufig statt seriell)
            src_info, dst_info = _enrich_pair(src_ip, dst_ip, cfg, cache, db)
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

            # ── Egress-Boundary-Klassifikation ────────────────────────
            # V2 (Phase B): src_zone × dst_zone-Matrix mit 3 Zonen
            #   ot       — known_networks.kind='ot' (OT-Scope)
            #   it       — known_networks.kind='it' (Corporate IT, nicht im OT-Scope)
            #   internet — alles außerhalb von known_networks
            # Priority aus system_config-Key 'boundary_priority_map_v2', sonst
            # DEFAULT_PRIORITY_MAP_V2.
            #
            # V1-Felder (net_known/src_known/dst_known) werden weiter befüllt
            # für Alert-Detail-View-Backwards-Compat. boundary_priority kommt
            # aus V2-Klassifikator — V1-Map wird für neue Alerts nicht mehr
            # konsultiert.
            #
            # Boundary nur klassifizieren wenn ein vollständiges
            # Verbindungspaar vorliegt. Ohne dst_ip (z.B. IRMA-Asset-Warnings,
            # die nur einen src_ip-Status melden) ist es definitionsgemäß
            # KEIN Egress-Event — Boundary-Felder bleiben NULL und solche
            # Alerts erscheinen nicht in der Boundary-View. Vor dem Fix
            # mappte db.get_zone(None) auf "internet", was OT-Asset-Warnings
            # fälschlich als ot/internet → P0 klassifizierte.
            if not src_ip or not dst_ip:
                src_zone  = None
                dst_zone  = None
                net_known = None
                src_known = None
                dst_known = None
                priority  = None
            else:
                src_zone  = db.get_zone(src_ip)
                dst_zone  = db.get_zone(dst_ip)
                net_known = dst_zone in ("ot", "it")  # = "dst ist in known_networks"
                src_known = bool(_f(src_info, "trusted"))
                dst_known = bool(_f(dst_info, "trusted"))
                pmap_v2_raw = db.get_boundary_priority_map_v2()
                pmap_v2     = parse_priority_map_v2(pmap_v2_raw) if pmap_v2_raw else None
                priority    = classify_boundary_v2(src_zone, dst_zone, pmap_v2)
            db.update_alert_boundary(
                alert_id, net_known, src_known, dst_known, priority,
                src_zone=src_zone, dst_zone=dst_zone,
            )
            enrichment["boundary"] = {
                "net_known": net_known,
                "src_known": src_known,
                "dst_known": dst_known,
                "src_zone":  src_zone,
                "dst_zone":  dst_zone,
                "priority":  priority,
            }

            # Enrichment-Update an API-WebSocket pushen
            try:
                push_msg = orjson.dumps({
                    "type": "alert_enriched",
                    "data": {"alert_id": alert_id, "enrichment": enrichment},
                })
                producer.produce(PUSH_TOPIC, value=push_msg)
                producer.poll(0)
            except Exception as push_exc:
                log.debug("Push to %s failed: %s", PUSH_TOPIC, push_exc)

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
        _POOL.shutdown(wait=False)
        db.close()
        producer.flush(timeout=5)
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
