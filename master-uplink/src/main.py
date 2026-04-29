"""
master-uplink — mTLS-WebSocket-Endpunkt für Remote-Tap-Alerts.

Hört auf TCP/8443 mit Master-CA als Trust-Root und CERT_REQUIRED. Jeder
sich verbindende Tap muss ein vom Master signiertes Cert mit CN
'tap:<uuid>' präsentieren. Wir matchen den Cert-Fingerprint gegen die
taps-Tabelle und akzeptieren nur Verbindungen für status='active'.

Pro Verbindung läuft eine Coroutine die Alert-Frames als JSON empfängt
und in den Kafka-Topic 'alerts-raw' weiterreicht – mit zusätzlichem Feld
tap_id, damit downstream alert-manager + frontend wissen woher er kommt.
Heartbeat alle 30 s (server → client), bei Timeout schließt der Server.

Die Kommunikation in Gegenrichtung (Master → Tap) für Rule-Sync läuft
NICHT über den WebSocket-Frame-Strom, sondern als HTTP GET /config auf
demselben Port (mTLS-stack identisch). Implementiert als
process_request-Hook in einer WebSocketServerProtocol-Subclass, weil die
Legacy-Signatur (path, request_headers) sonst keinen Zugang zum
SSL-Object und damit zum Cert-Fingerprint hat.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import ssl
import time
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path

import asyncpg
import orjson
import websockets
from confluent_kafka import Producer
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from websockets.legacy.server import WebSocketServerProtocol

LISTEN_HOST = os.environ.get("UPLINK_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("UPLINK_PORT", "8443"))
KAFKA_BROKERS = os.environ.get("KAFKA_BROKERS", "kafka:9092")
ALERTS_TOPIC = os.environ.get("ALERTS_TOPIC", "alerts-raw")
# Phase-2 Shadow-Metrik: Tap-uplink schickt `metric`-Frames neben den
# Alerts. Wir produzieren sie 1:1 in das Master-rule-metrics-Topic, damit
# der spätere Rule-Tuner (Phase 4) Master- und Tap-Metriken im selben
# Reservoir aggregieren kann.
METRICS_TOPIC = os.environ.get("METRICS_TOPIC", "rule-metrics")
POSTGRES_DSN = os.environ.get(
    "POSTGRES_DSN",
    "postgresql://ids:ids-change-me@timescaledb:5432/ids",
)
MASTER_CA_DIR = os.environ.get("MASTER_CA_DIR", "/var/lib/cyjan/master-ca")
HEARTBEAT_INTERVAL_S = float(os.environ.get("HEARTBEAT_INTERVAL_S", "30"))
HEARTBEAT_TIMEOUT_S = float(os.environ.get("HEARTBEAT_TIMEOUT_S", "75"))

# Reverse-Channel: Tap pollt /config alle 5 min und überträgt die ausgelieferten
# Dateien atomar in seinen lokalen signature-rules-Volume. Quelle für die
# YAMLs ist das gleiche Layout wie auf dem Master:
#   $RULES_DIR/builtin/*.yml      – buildin-Regeln (read-only via host-bind)
#   $RULES_DIR/custom/*.yml       – evtl. eigene custom-Regeln (writable)
#   $RULES_DIR/custom/_overrides.json
#   $RULES_DIR/custom/_suricata_overrides.json
RULES_DIR = Path(os.environ.get("RULES_DIR", "/rules"))

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [master-uplink] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def _wait_for_ca() -> tuple[Path, Path]:
    """api initialisiert die Master-CA beim Startup. master-uplink kann
    schneller hochkommen als die api – statt zu crashen warten wir bis zu
    5 min und retryn alle 2s."""
    import time
    ca_cert = Path(MASTER_CA_DIR) / "master-ca.pem"
    ca_key  = Path(MASTER_CA_DIR) / "master-ca.key"
    deadline = time.time() + 300
    while time.time() < deadline:
        if ca_cert.exists() and ca_key.exists():
            return ca_cert, ca_key
        log.info("Warte auf Master-CA unter %s ...", MASTER_CA_DIR)
        time.sleep(2)
    raise FileNotFoundError(
        f"Master-CA fehlt nach 5 min unter {MASTER_CA_DIR}. "
        "Läuft der api-Container? master_ca.init() im Startup-Hook erwartet."
    )


def _build_ssl_context() -> ssl.SSLContext:
    ca_cert, ca_key = _wait_for_ca()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Master-Cert: wir benutzen das CA-Cert als Server-Cert. Funktional ist
    # das ungewöhnlich (CA als Server-Cert), in unserem Inter-Service-mTLS-
    # Szenario aber praktisch: der Tap kennt nur die Master-CA und vertraut
    # ihr. Das spart einen separaten Server-Cert-Lifecycle.
    ctx.load_cert_chain(certfile=str(ca_cert), keyfile=str(ca_key))
    ctx.load_verify_locations(cafile=str(ca_cert))
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _peer_fingerprint(ssl_object: ssl.SSLObject) -> str | None:
    """Liefert SHA-256-Fingerprint des präsentierten Client-Certs."""
    der = ssl_object.getpeercert(binary_form=True)
    if not der:
        return None
    cert = x509.load_der_x509_certificate(der)
    return cert.fingerprint(hashes.SHA256()).hex()


def _peer_cn(ssl_object: ssl.SSLObject) -> str | None:
    der = ssl_object.getpeercert(binary_form=True)
    if not der:
        return None
    cert = x509.load_der_x509_certificate(der)
    for attr in cert.subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            return str(attr.value)
    return None


class TapAuth:
    """Fingerprint → tap_id Lookup gegen taps-Tabelle."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None

    async def init(self) -> None:
        self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=4)

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()

    async def lookup(self, fingerprint: str) -> dict | None:
        assert self._pool
        row = await self._pool.fetchrow(
            "SELECT id, name, status FROM taps WHERE cert_fingerprint=$1",
            fingerprint,
        )
        if not row:
            return None
        return {"id": str(row["id"]), "name": row["name"], "status": row["status"]}

    async def heartbeat(self, tap_id: str, alerts_delta: int, peer: str) -> None:
        assert self._pool
        await self._pool.execute(
            """
            UPDATE taps
               SET last_seen=now(),
                   alerts_received=alerts_received + $2,
                   ip_last=$3
             WHERE id=$1
            """,
            tap_id, alerts_delta, peer,
        )

    async def get_dns_resolvers(self) -> list[str]:
        """Liest die system_config-Allowlist 'dns_resolvers'. JSONB-Spalte;
        asyncpg gibt sie als String zurück (kein automatisches JSON-Decode),
        deshalb hier orjson-loads."""
        assert self._pool
        try:
            row = await self._pool.fetchrow(
                "SELECT value::text AS v FROM system_config WHERE key='dns_resolvers'"
            )
        except Exception as exc:
            log.warning("dns_resolvers-Query fehlgeschlagen: %s", exc)
            return []
        if not row or not row["v"]:
            return []
        try:
            decoded = orjson.loads(row["v"])
            if isinstance(decoded, list):
                return [str(x) for x in decoded]
        except Exception:
            pass
        return []


def _delivery_cb(err, _msg) -> None:
    if err is not None:
        log.error("Kafka delivery failure: %s", err)


# ── Reverse-Channel: Config-Bundle für Tap-Pull ──────────────────────────────

# In-process cache. Sämtliche Taps pollen nominell alle 5 min, bei N Taps
# heißt das im Schnitt N/300s Hits. Der Cache flacht Bursts ab und schützt
# auch vor missbräuchlichen Polls, weil das Bundle aus mehreren Disk-Reads
# + einem DB-Query gebaut wird.
_BUNDLE_CACHE_TTL_S = 30.0
_bundle_cache: dict = {"body": None, "etag": None, "expires_at": 0.0}


def _build_bundle_sync() -> tuple[dict, bool]:
    """Liest Builtin-YAMLs + Custom-Overrides synchron in ein dict. Liefert
    (bundle_dict_partial, complete). complete=False signalisiert dass ein
    Read fehlgeschlagen ist – der Tap löscht in dem Fall keine als 'fehlend'
    interpretierten Builtin-Files."""
    bundle: dict = {
        "version": "1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "complete": True,
        "rules": {},
        "rules_overrides": None,
        "suricata_overrides": None,
        "known_networks": None,
        "dns_resolvers": [],
    }

    builtin_dir = RULES_DIR / "builtin"
    custom_dir  = RULES_DIR / "custom"

    if builtin_dir.is_dir():
        for f in sorted(builtin_dir.glob("*.yml")):
            try:
                bundle["rules"][f.name] = f.read_text(encoding="utf-8")
            except Exception as exc:
                log.warning("YAML %s nicht lesbar: %s – Bundle als incomplete markiert", f, exc)
                bundle["complete"] = False

    overrides_path = custom_dir / "_overrides.json"
    if overrides_path.is_file():
        try:
            bundle["rules_overrides"] = orjson.loads(overrides_path.read_bytes())
        except Exception as exc:
            log.warning("_overrides.json nicht parsebar: %s", exc)
            bundle["complete"] = False

    suricata_path = custom_dir / "_suricata_overrides.json"
    if suricata_path.is_file():
        try:
            bundle["suricata_overrides"] = orjson.loads(suricata_path.read_bytes())
        except Exception as exc:
            log.warning("_suricata_overrides.json nicht parsebar: %s", exc)
            bundle["complete"] = False

    # known_networks.json (CIDR-Liste der bekannten/internen Netze) — wird
    # vom signature-engine-Loader für den value_internal/value-Split gelesen.
    # Quelle: API schreibt die Datei beim Network-CRUD direkt ins Volume.
    known_path = custom_dir / "_known_networks.json"
    if known_path.is_file():
        try:
            bundle["known_networks"] = orjson.loads(known_path.read_bytes())
        except Exception as exc:
            log.warning("_known_networks.json nicht parsebar: %s", exc)
            bundle["complete"] = False

    return bundle, bundle["complete"]


async def build_config_bundle(auth: TapAuth) -> tuple[bytes, str]:
    """JSON-Bundle aller syncbaren Master-Konfig-Dateien für die Tap-Pull-Schleife.
    Liefert (body_bytes, etag).

    Layout der Antwort:
      {
        "version": "1",
        "generated_at": ISO-Timestamp,
        "complete": bool,                        # false → Tap überspringt Cleanup
        "rules":              {filename: yaml_content},
        "rules_overrides":    {...} oder null,
        "suricata_overrides": {...} oder null,
        "dns_resolvers":      [...]
      }

    Suppression-Patterns (manual + ML) syncen wir bewusst NICHT in V1.
    Tap forwardet alle Alerts an den Master, dort greift Suppression im
    alert-manager. Bandbreite kostet das nicht spürbar.

    Caching: Bundle wird _BUNDLE_CACHE_TTL_S (30s) im Speicher gehalten und
    mit ETag (sha256-prefix) versehen. Tap kann via If-None-Match einen
    304 zurückbekommen.
    """
    now = time.time()
    if _bundle_cache["body"] is not None and now < _bundle_cache["expires_at"]:
        return _bundle_cache["body"], _bundle_cache["etag"]

    # File-IO synchron – aber im Thread-Executor, damit der Event-Loop die
    # parallele Tap-Alert-Verarbeitung nicht ins Stocken kommt.
    bundle, _complete = await asyncio.to_thread(_build_bundle_sync)
    bundle["dns_resolvers"] = await auth.get_dns_resolvers()

    body = orjson.dumps(bundle)
    etag = '"' + hashlib.sha256(body).hexdigest()[:32] + '"'

    _bundle_cache["body"]       = body
    _bundle_cache["etag"]       = etag
    _bundle_cache["expires_at"] = now + _BUNDLE_CACHE_TTL_S

    return body, etag


def _make_protocol_class(auth: TapAuth):
    """Liefert eine WebSocketServerProtocol-Subclass die /config-HTTP-GETs
    in process_request abfängt und das Config-Bundle direkt zurückgibt
    (HTTP 200 oder 304). Andere Pfade → None, dann läuft der WS-Upgrade
    normal weiter.

    Subclass weil die Legacy-API process_request mit Signatur
    (path, request_headers) → Optional[(status, headers, body)] aufruft;
    nur als Methode haben wir Zugang zu self.transport für den Cert-Lookup.
    """

    class TapProto(WebSocketServerProtocol):
        async def process_request(self, path, request_headers):
            if path.split("?", 1)[0] != "/config":
                return None

            ssl_obj = self.transport.get_extra_info("ssl_object")
            if ssl_obj is None:
                return (
                    HTTPStatus.UPGRADE_REQUIRED,
                    [("Content-Type", "text/plain")],
                    b"TLS required",
                )
            fingerprint = _peer_fingerprint(ssl_obj)
            if not fingerprint:
                return (
                    HTTPStatus.UNAUTHORIZED,
                    [("Content-Type", "text/plain")],
                    b"client cert required",
                )
            info = await auth.lookup(fingerprint)
            if not info or info["status"] != "active":
                log.warning("/config-Request mit unbekanntem/revokeden Cert (fp=%s)",
                            fingerprint[:16])
                return (
                    HTTPStatus.FORBIDDEN,
                    [("Content-Type", "text/plain")],
                    b"unknown or revoked tap",
                )

            try:
                body, etag = await build_config_bundle(auth)
            except Exception as exc:
                log.error("Config-Bundle-Build gescheitert: %s", exc)
                return (
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    [("Content-Type", "text/plain")],
                    f"bundle error: {exc}".encode(),
                )

            inm = request_headers.get("If-None-Match")
            if inm and inm == etag:
                return (
                    HTTPStatus.NOT_MODIFIED,
                    [("ETag", etag), ("Cache-Control", "no-cache")],
                    b"",
                )

            log.info("Config-Bundle ausgeliefert an %s (%d Bytes, etag=%s)",
                     info["name"], len(body), etag)
            return (
                HTTPStatus.OK,
                [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(body))),
                    ("Cache-Control", "no-cache"),
                    ("ETag", etag),
                ],
                body,
            )

    return TapProto


async def handle_tap(ws, auth: TapAuth, producer: Producer) -> None:
    ssl_obj = ws.transport.get_extra_info("ssl_object")
    if ssl_obj is None:
        log.warning("Verbindung ohne TLS – sollte nicht passieren, schließe")
        await ws.close(code=4400, reason="TLS required")
        return

    fingerprint = _peer_fingerprint(ssl_obj)
    cn = _peer_cn(ssl_obj)
    peer = ws.remote_address[0] if ws.remote_address else "?"
    if not fingerprint:
        await ws.close(code=4401, reason="no client cert")
        return

    info = await auth.lookup(fingerprint)
    if not info:
        log.warning("Unbekannter Tap-Cert (cn=%s, fp=%s, peer=%s)",
                    cn, fingerprint[:16], peer)
        await ws.close(code=4403, reason="unknown tap")
        return
    if info["status"] != "active":
        log.warning("Revoked Tap versucht zu connecten: name=%s peer=%s",
                    info["name"], peer)
        await ws.close(code=4403, reason="revoked")
        return

    tap_id = info["id"]
    tap_name = info["name"]
    log.info("Tap verbunden: name=%s id=%s peer=%s", tap_name, tap_id, peer)
    alerts_received = 0
    metrics_received = 0

    async def heartbeat_loop() -> None:
        try:
            while True:
                await asyncio.sleep(HEARTBEAT_INTERVAL_S)
                try:
                    await ws.send(orjson.dumps({"type": "ping"}).decode())
                except websockets.ConnectionClosed:
                    return
        except asyncio.CancelledError:
            return

    async def stats_loop() -> None:
        nonlocal alerts_received
        try:
            while True:
                await asyncio.sleep(15)
                if alerts_received:
                    delta = alerts_received
                    alerts_received = 0
                    await auth.heartbeat(tap_id, delta, peer)
                else:
                    # auch ohne neue Alerts: last_seen aktualisieren
                    await auth.heartbeat(tap_id, 0, peer)
        except asyncio.CancelledError:
            return

    hb = asyncio.create_task(heartbeat_loop())
    st = asyncio.create_task(stats_loop())

    try:
        # Read-Timeout: wenn länger als HEARTBEAT_TIMEOUT_S kein Frame ankommt
        # (auch kein pong), gehen wir davon aus dass die Verbindung tot ist und
        # schließen. Sonst kann ein hängender Tap mit halb-offenem TCP ewig
        # einen Slot belegen ohne dass Daten fließen.
        while True:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=HEARTBEAT_TIMEOUT_S)
            except asyncio.TimeoutError:
                log.warning("Tap %s timeout – kein Frame seit %.0fs, schließe",
                            tap_name, HEARTBEAT_TIMEOUT_S)
                await ws.close(code=4408, reason="receive timeout")
                break
            try:
                msg = orjson.loads(raw)
            except Exception as exc:
                log.warning("Ungültiges JSON von %s: %s", tap_name, exc)
                continue

            mtype = msg.get("type", "alert")
            if mtype == "pong":
                continue
            if mtype == "alert":
                alert = msg.get("payload") or {}
                if not isinstance(alert, dict):
                    continue
                alert["tap_id"] = tap_id
                alert["source"] = alert.get("source", "signature")  # Default falls fehlt

                try:
                    producer.produce(
                        ALERTS_TOPIC,
                        key=(alert.get("src_ip") or tap_id).encode(),
                        value=orjson.dumps(alert),
                        callback=_delivery_cb,
                    )
                    producer.poll(0)
                    alerts_received += 1
                except Exception as exc:
                    log.error("Kafka produce (alert) fehlgeschlagen: %s", exc)
                    # Bei Kafka-Down keinen Disconnect erzwingen: der Tap-Buffer
                    # würde sonst unnötig anwachsen. Wir signalisieren backpressure
                    # über den nicht gesendeten Ack (Tap-seitig optional).
                continue

            if mtype == "metric":
                # Phase-2 Shadow-Metrik vom Tap. Schema:
                #   {rule_id, param_name, metric_value, src_ip, scope, ts}
                # Wir taggen mit tap_id, damit der Tuner später Master- und
                # Tap-Beiträge auseinanderhalten kann (z.B. um pro Tap einen
                # eigenen Reservoir-Stream zu fahren).
                metric = msg.get("payload") or {}
                if not isinstance(metric, dict) or "rule_id" not in metric:
                    continue
                metric["tap_id"] = tap_id
                try:
                    producer.produce(
                        METRICS_TOPIC,
                        key=f"{metric.get('rule_id', '')}|{metric.get('param_name', '')}".encode(),
                        value=orjson.dumps(metric),
                        callback=_delivery_cb,
                    )
                    producer.poll(0)
                    metrics_received += 1
                except Exception as exc:
                    log.error("Kafka produce (metric) fehlgeschlagen: %s", exc)
                continue

            log.warning("Unbekannter Frame-Type von %s: %s", tap_name, mtype)

    except websockets.ConnectionClosed as exc:
        log.info("Tap %s disconnected: %s (alerts=%d metrics=%d)",
                 tap_name, exc.code, alerts_received, metrics_received)
    finally:
        hb.cancel()
        st.cancel()
        # Final-Stats persistieren. Metriken zählen aktuell nicht in die
        # taps.alerts_received-Spalte rein – das wäre irreführend für die UI.
        # Falls später ein metrics_received-Counter in der DB erwünscht ist,
        # kann auth.heartbeat() um ein zweites Argument erweitert werden.
        if alerts_received:
            await auth.heartbeat(tap_id, alerts_received, peer)


async def amain() -> None:
    auth = TapAuth(POSTGRES_DSN)
    await auth.init()

    producer = Producer({
        "bootstrap.servers": KAFKA_BROKERS,
        "linger.ms": 20,
        "acks": "1",
    })

    ssl_ctx = _build_ssl_context()
    log.info("master-uplink lauscht auf wss://%s:%d  (mTLS, Topics %s + %s)",
             LISTEN_HOST, LISTEN_PORT, ALERTS_TOPIC, METRICS_TOPIC)

    proto_cls = _make_protocol_class(auth)
    async with websockets.serve(
        lambda ws: handle_tap(ws, auth, producer),
        host=LISTEN_HOST,
        port=LISTEN_PORT,
        ssl=ssl_ctx,
        ping_interval=None,           # eigener Heartbeat
        max_size=1 * 1024 * 1024,     # 1 MB pro Frame ist großzügig für ein Alert-JSON
        create_protocol=proto_cls,
    ):
        try:
            await asyncio.Future()    # forever
        finally:
            await auth.close()
            producer.flush(timeout=5)


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
