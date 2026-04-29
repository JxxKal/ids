"""
tap-uplink — schickt am Remote-Tap erzeugte Alerts via mTLS-WSS an den Master.

Architektur:

   alerts-raw (lokales Kafka)        SQLite-Queue           wss://master:8443
        │                                ▲                          ▲
        │ Consumer-Thread                │ push                     │ send
        ▼                                │                          │
    ┌───────────────────────────────────────┐         ┌───────────────────────────┐
    │   Producer-Loop (Async)               │ ──────► │  WSS-Sender (Async)       │
    │   • orjson-decode                     │  Queue  │  • mTLS-Handshake         │
    │   • Filter is_test (optional)         │         │  • Reconnect-Backoff      │
    │   • Push in DiskQueue                 │         │  • Heartbeat              │
    └───────────────────────────────────────┘         └───────────────────────────┘

Damit überlebt der Tap beliebige Master-Outages bis 24h (Queue-Cap = 1 GB)
und schickt bei Reconnect die ältesten Alerts zuerst nach. Echtzeit-Pfad
(Master online): jeder Alert wird sofort durchgereicht ohne dass die
Queue spürbar wächst.

Ohne Pairing (= /etc/cyjan/tap.pem fehlt) läuft tap-uplink in einer Idle-
Schleife und beschwert sich nur, statt zu crashen – damit das tap-api
trotzdem hochkommen und das Pairing anbieten kann.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import httpx
import orjson
import websockets
from confluent_kafka import Consumer, KafkaError, KafkaException
from cryptography import x509

from disk_queue import DiskQueue
from state      import StateWriter

# ── Konfiguration ─────────────────────────────────────────────────────────────

KAFKA_BROKERS = os.environ.get("KAFKA_BROKERS", "kafka:9092")
ALERTS_TOPIC  = os.environ.get("ALERTS_TOPIC", "alerts-raw")
# Phase-2 Shadow-Metrik: lokales rule-metrics-Topic; tap-uplink wrapped jeden
# Record als {"type":"metric"}-Frame und schickt ihn über die gleiche WSS-
# Verbindung an den Master. Topic muss am Tap existieren (init-topics-tap.sh)
# — fehlt es, ignoriert confluent-kafka die Subscription mit warning, der
# alerts-Pfad bleibt davon unbeeinflusst.
METRICS_TOPIC = os.environ.get("METRICS_TOPIC", "rule-metrics")
GROUP_ID      = os.environ.get("KAFKA_GROUP_ID", "tap-uplink")

MASTER_URL    = os.environ.get("MASTER_URL", "wss://master.example.com:8443/uplink")
TAP_CERT      = os.environ.get("TAP_CERT", "/etc/cyjan/tap.pem")
TAP_KEY       = os.environ.get("TAP_KEY",  "/etc/cyjan/tap.key")
MASTER_CA     = os.environ.get("MASTER_CA", "/etc/cyjan/master-ca.pem")

QUEUE_PATH    = os.environ.get("QUEUE_PATH", "/var/lib/cyjan/uplink-queue.db")
QUEUE_MAX_GB  = float(os.environ.get("QUEUE_MAX_GB", "1.0"))
STATE_PATH    = os.environ.get("STATE_PATH", "/run/cyjan/tap-uplink.state.json")

SEND_BATCH_SIZE = int(os.environ.get("SEND_BATCH_SIZE", "50"))
HEARTBEAT_TO    = float(os.environ.get("HEARTBEAT_TIMEOUT_S", "75"))
RECONNECT_MIN_S = 1.0
RECONNECT_MAX_S = 60.0

# Reverse-Channel: Config-Pull alle CONFIG_POLL_INTERVAL_S Sekunden vom Master.
# Schreibt in $RULES_DIR/{builtin,custom}/. signature-engine reagiert mit
# inotify auf die Änderungen.
RULES_DIR             = Path(os.environ.get("RULES_DIR", "/rules"))
CONFIG_POLL_INTERVAL_S = float(os.environ.get("CONFIG_POLL_INTERVAL_S", "300"))   # 5 min
CONFIG_POLL_TIMEOUT_S  = float(os.environ.get("CONFIG_POLL_TIMEOUT_S",  "30"))
CONFIG_BUNDLE_MAX_BYTES = int(os.environ.get("CONFIG_BUNDLE_MAX_BYTES", str(50 * 1024 * 1024)))
CONFIG_SCHEMA_VERSION   = "1"

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [tap-uplink] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def _has_pairing() -> bool:
    return Path(TAP_CERT).exists() and Path(TAP_KEY).exists() and Path(MASTER_CA).exists()


def _cert_expires_at() -> float | None:
    try:
        cert = x509.load_pem_x509_certificate(Path(TAP_CERT).read_bytes())
        return cert.not_valid_after_utc.timestamp()
    except Exception:
        return None


def _build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(certfile=TAP_CERT, keyfile=TAP_KEY)
    ctx.load_verify_locations(cafile=MASTER_CA)
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Hostname-Check ist hier bewusst aus: das Server-Cert auf dem Master ist
    # in V1 das Master-CA-Cert selbst (CN='Cyjan IDS Master CA'), ohne
    # IP/DNS-SAN. Da die Authentizität des Servers ohnehin über die CA-
    # Verifikation + den fixen Cert-Trust-Anchor des Tap garantiert ist,
    # ist Hostname-Matching redundant. V2: separates Server-Cert mit
    # IP/DNS-SAN signieren.
    ctx.check_hostname = False
    return ctx


# Cache für SSL-Context. Bei jedem Reconnect / Config-Poll vermeidet das
# unnötige Disk-Reads + Context-Aufbau. Invalidierung über mtime der drei
# Cert-Dateien – wenn der Wizard rotiert, holt sich der nächste Aufruf den
# frischen Context.
_ssl_cache: dict = {"ctx": None, "mtime": None}


def _cert_mtimes() -> tuple[float, float, float] | None:
    try:
        return (
            Path(TAP_CERT).stat().st_mtime,
            Path(TAP_KEY).stat().st_mtime,
            Path(MASTER_CA).stat().st_mtime,
        )
    except FileNotFoundError:
        return None


def _get_ssl_context() -> ssl.SSLContext:
    mt = _cert_mtimes()
    if _ssl_cache["ctx"] is not None and _ssl_cache["mtime"] == mt:
        return _ssl_cache["ctx"]
    ctx = _build_ssl_context()
    _ssl_cache["ctx"] = ctx
    _ssl_cache["mtime"] = mt
    return ctx


# ── Kafka-Consumer (in eigenem Thread) ───────────────────────────────────────


def _kafka_consumer_thread(diskq: DiskQueue, stop: threading.Event) -> None:
    """Liest alerts-raw + rule-metrics und pusht jede Message in die DiskQueue.
    Frame-Type wird anhand des Quell-Topics gesetzt (alert vs. metric). Läuft
    in einem dedizierten Thread, weil confluent-kafka synchron ist.

    Outage-Verhalten: Beide Streams nutzen denselben Disk-Buffer + denselben
    1-GB-Cap. Bei langem Master-Outage verdrängen die volumen-stärkeren
    Records (= Metriken bei aktivem Sampling) ggf. ältere Alerts. Das ist
    bewusst so: Alerts sind selten und werden auch ohne Tuning vom alert-
    manager normal geschluckt sobald reconnected; Metrik-Backlog wird
    schwerer kompensierbar je länger der Outage ist."""
    topics = [ALERTS_TOPIC, METRICS_TOPIC]
    consumer = Consumer({
        "bootstrap.servers": KAFKA_BROKERS,
        "group.id": GROUP_ID,
        "auto.offset.reset": "latest",
        "enable.auto.commit": True,
    })
    consumer.subscribe(topics)
    log.info("Kafka-Consumer subscribed: %s @ %s", topics, KAFKA_BROKERS)

    try:
        while not stop.is_set():
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                log.warning("Kafka error: %s", msg.error())
                continue
            payload = msg.value()
            if not payload:
                continue
            # Frame-Format: {"type":"alert"|"metric","payload":<original-dict>}
            # Type ergibt sich aus dem Quell-Topic. Klein-Wrapping erlaubt es,
            # zukünftige Telemetrie-Streams (Heartbeats, Health-Snapshots)
            # über denselben WSS-Frame-Strom zu schicken ohne neues Schema.
            topic = msg.topic()
            if topic == ALERTS_TOPIC:
                ftype = "alert"
            elif topic == METRICS_TOPIC:
                ftype = "metric"
            else:
                # Unwahrscheinlich (subscribe nur auf zwei Topics), aber
                # Topic-Auto-Routing in confluent-kafka kann Wildcards öffnen –
                # lieber explizit drop statt mit unbekanntem Type rauspushen.
                log.debug("Unbekanntes Topic %s übersprungen", topic)
                continue
            try:
                payload_obj = orjson.loads(payload)
                frame = orjson.dumps({"type": ftype, "payload": payload_obj})
                diskq.push(frame)
            except Exception as exc:
                log.error("Push in Queue fehlgeschlagen (%s): %s", ftype, exc)
    finally:
        consumer.close()
        log.info("Kafka-Consumer beendet")


# ── WSS-Sender (Async) ───────────────────────────────────────────────────────


class Uplink:
    def __init__(self, diskq: DiskQueue, state: StateWriter) -> None:
        self._diskq = diskq
        self._state = state
        self._sent_total = 0
        self._last_send_at: float | None = None
        self._last_connect_at: float | None = None
        self._last_disconnect_at: float | None = None
        self._last_error: str | None = None

    def _write_state(self, connection: str) -> None:
        st = self._diskq.stats()
        self._state.write(
            connection=connection,
            master_url=MASTER_URL,
            last_connect_at=self._last_connect_at,
            last_disconnect_at=self._last_disconnect_at,
            last_send_at=self._last_send_at,
            sent_total=self._sent_total,
            queue_count=st["count"],
            queue_bytes=st["bytes"],
            cert_expires_at=_cert_expires_at(),
            last_error=self._last_error,
        )

    async def run(self) -> None:
        backoff = RECONNECT_MIN_S
        while True:
            if not _has_pairing():
                self._last_error = f"keine Pairing-Dateien unter {TAP_CERT} – pair zuerst"
                self._write_state("starting")
                await asyncio.sleep(5)
                continue

            self._write_state("reconnecting")
            try:
                ssl_ctx = _get_ssl_context()
                async with websockets.connect(
                    MASTER_URL,
                    ssl=ssl_ctx,
                    ping_interval=None,            # eigener Heartbeat im Frame
                    open_timeout=10,
                    close_timeout=5,
                    max_size=1 * 1024 * 1024,
                ) as ws:
                    self._last_connect_at = time.time()
                    self._last_error = None
                    backoff = RECONNECT_MIN_S
                    log.info("WSS verbunden mit %s", MASTER_URL)
                    self._write_state("connected")

                    await asyncio.gather(
                        self._send_loop(ws),
                        self._receive_loop(ws),
                    )
            except Exception as exc:
                self._last_error = f"{type(exc).__name__}: {exc}"
                self._last_disconnect_at = time.time()
                log.warning("WSS-Verbindung weg: %s – Reconnect in %.1fs",
                            self._last_error, backoff)
                self._write_state("down")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, RECONNECT_MAX_S)

    async def _send_loop(self, ws) -> None:
        """Pumpt Disk-Queue → WSS, ältester zuerst. Wenn Queue leer ist:
        kurz warten, nicht busy-loopen."""
        idle = 0
        while True:
            batch = self._diskq.pop_batch(SEND_BATCH_SIZE)
            if not batch:
                idle += 1
                # alle 5s State refresh, damit die UI nicht "festhängt"
                if idle % 50 == 0:
                    self._write_state("connected")
                await asyncio.sleep(0.1)
                continue
            idle = 0
            ids_sent: list[int] = []
            try:
                for row_id, payload in batch:
                    await ws.send(payload)
                    ids_sent.append(row_id)
                self._diskq.ack(ids_sent)
                self._sent_total += len(ids_sent)
                self._last_send_at = time.time()
                if self._sent_total % 100 == 0:
                    self._write_state("connected")
            except Exception:
                # Was bereits raus war: ack. Was nicht: bleibt in der Queue
                # für den nächsten Verbindungsaufbau.
                self._diskq.ack(ids_sent)
                raise

    async def _receive_loop(self, ws) -> None:
        """Empfängt ping/pong vom Master. Aktuell nur Heartbeat – der
        Reverse-Channel (Rule-Sync) läuft über REST-Pull, nicht hier."""
        while True:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=HEARTBEAT_TO)
            except asyncio.TimeoutError:
                raise RuntimeError(
                    f"Master >{HEARTBEAT_TO:.0f}s ohne Heartbeat – Reconnect"
                )
            try:
                msg = orjson.loads(raw)
            except Exception:
                continue
            if msg.get("type") == "ping":
                await ws.send(orjson.dumps({"type": "pong"}).decode())


# ── Reverse-Channel-Polling (Master → Tap Rule-Sync) ────────────────────────


def _config_url() -> str:
    """Wandelt MASTER_URL (wss://host:port/uplink) in HTTPS-Variante mit
    /config-Pfad um. ws:// → http:// (Test-Setup ohne TLS)."""
    p = urlparse(MASTER_URL)
    scheme = {"wss": "https", "ws": "http"}.get(p.scheme, p.scheme or "https")
    return urlunparse((scheme, p.netloc, "/config", "", "", ""))


def _atomic_write(path: Path, content: bytes) -> None:
    """tmp + rename → kein partieller Read durch signature-engine-inotify."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(content)
    os.replace(tmp, path)


def _apply_config_bundle(bundle: dict) -> tuple[int, int]:
    """Schreibt das Bundle in den lokalen RULES_DIR. Liefert (rules_count,
    side_files_count) für Logging.

    `complete=False` im Bundle (Master konnte mind. eine YAML nicht lesen)
    → wir schreiben zwar die ausgelieferten Files, löschen aber KEINE
    builtin-YAMLs, die nicht im Bundle stehen. Sonst würde ein transienter
    Read-Fehler am Master eine Rule am Tap dauerhaft entfernen, bis der
    nächste Poll sie wieder herstellt.
    """
    builtin_dir = RULES_DIR / "builtin"
    custom_dir  = RULES_DIR / "custom"
    complete = bool(bundle.get("complete", True))

    # Vorhandene Builtin-YAMLs aufräumen die nicht mehr im Bundle sind.
    # Custom-Files werden NICHT angefasst – das ist sonst-User-territory.
    rules = bundle.get("rules", {}) or {}
    if isinstance(rules, dict):
        # Aktuelle YAMLs schreiben.
        for fname, body in rules.items():
            # Schutz vor Path-Traversal: nur einfache Dateinamen erlauben
            if Path(fname).name != fname or fname.startswith(".") or not fname.endswith(".yml"):
                log.warning("Skip rule mit auffälligem Dateinamen: %s", fname)
                continue
            _atomic_write(builtin_dir / fname, body.encode("utf-8"))
        # Veraltete YAMLs in builtin/ entfernen, die nicht mehr im Bundle sind.
        # Nur wenn der Master das Bundle als vollständig markiert hat.
        if complete and builtin_dir.is_dir():
            keep = set(rules.keys())
            for f in builtin_dir.glob("*.yml"):
                if f.name not in keep:
                    try:
                        f.unlink(missing_ok=True)
                        log.info("Veraltete Rule entfernt: %s", f.name)
                    except Exception as exc:
                        log.warning("Konnte %s nicht löschen: %s", f, exc)
        elif not complete:
            log.info("Bundle als incomplete markiert – Cleanup veralteter "
                     "builtin-YAMLs übersprungen")

    side_files = 0
    ovr = bundle.get("rules_overrides")
    if ovr is not None:
        _atomic_write(custom_dir / "_overrides.json", orjson.dumps(ovr))
        side_files += 1
    sov = bundle.get("suricata_overrides")
    if sov is not None:
        _atomic_write(custom_dir / "_suricata_overrides.json", orjson.dumps(sov))
        side_files += 1
    kn = bundle.get("known_networks")
    if kn is not None:
        # Wird vom signature-engine-Loader für den internal/external
        # Param-Split (Phase-1-ML-Tuner-Vorbereitung) konsumiert.
        _atomic_write(custom_dir / "_known_networks.json", orjson.dumps(kn))
        side_files += 1
    dns = bundle.get("dns_resolvers")
    if dns is not None:
        # Eigene Datei – am Tap aktuell nicht aktiv konsumiert (alert-manager
        # läuft ausschließlich am Master), aber für V2 schon mit-synct.
        _atomic_write(custom_dir / "_dns_resolvers.json", orjson.dumps(dns))
        side_files += 1

    return len(rules), side_files


async def _fetch_bundle(client: httpx.AsyncClient, url: str,
                        last_etag: str | None) -> tuple[int, bytes, str | None]:
    """HTTP GET mit If-None-Match. Streamt die Antwort und bricht bei
    CONFIG_BUNDLE_MAX_BYTES ab, damit ein gross/böswilliger Master den Tap
    nicht via OOM kippt. Liefert (status, body_bytes, etag)."""
    headers = {"If-None-Match": last_etag} if last_etag else {}
    async with client.stream("GET", url, headers=headers) as resp:
        etag = resp.headers.get("ETag")
        if resp.status_code == 304:
            return 304, b"", etag
        if resp.status_code != 200:
            # Body trotzdem ein Stück lesen, damit das Logging informativ bleibt.
            await resp.aread()
            return resp.status_code, resp.content[:512], etag

        cl = resp.headers.get("content-length")
        if cl is not None and int(cl) > CONFIG_BUNDLE_MAX_BYTES:
            raise RuntimeError(
                f"Config-Bundle zu groß ({cl} > {CONFIG_BUNDLE_MAX_BYTES})"
            )

        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes():
            total += len(chunk)
            if total > CONFIG_BUNDLE_MAX_BYTES:
                raise RuntimeError(
                    f"Config-Bundle überschritt {CONFIG_BUNDLE_MAX_BYTES} bytes mid-stream"
                )
            chunks.append(chunk)
        return 200, b"".join(chunks), etag


async def config_poll_loop() -> None:
    """Pollt MASTER /config alle CONFIG_POLL_INTERVAL_S Sekunden mit mTLS-Cert.
    Liefert atomar in den signature-rules-Volume; signature-engine zieht via
    inotify nach. Skip-If-Unchanged via ETag (server-seitig) und sha256-Hash
    (client-seitig als Backup, falls der Server keinen ETag setzt)."""
    url = _config_url()
    log.info("Config-Poll-Loop aktiv: alle %.0fs gegen %s",
             CONFIG_POLL_INTERVAL_S, url)
    # Beim Boot kurz warten, damit der WSS-Reconnect zuerst läuft (sonst
    # konkurrieren die Verbindungen um den ersten Cert-Read).
    await asyncio.sleep(5)

    last_etag: str | None = None
    last_hash: str | None = None

    while True:
        if not _has_pairing():
            await asyncio.sleep(min(30, CONFIG_POLL_INTERVAL_S))
            continue

        try:
            # SSL-Context enthält bereits den Client-Cert via load_cert_chain;
            # cert=(...) zusätzlich zu setzen wäre redundant und in manchen
            # httpx-Versionen mehrdeutig.
            ssl_ctx = _get_ssl_context()
            async with httpx.AsyncClient(
                timeout=CONFIG_POLL_TIMEOUT_S,
                verify=ssl_ctx,
            ) as client:
                status, body, etag = await _fetch_bundle(client, url, last_etag)

            if status == 304:
                last_etag = etag or last_etag
                log.debug("Config-Poll: 304 Not Modified")
            elif status != 200:
                log.warning("Config-Poll HTTP %d: %s", status, body[:200])
            else:
                # Schema-Version checken; defensiv gegen V2-Master + V1-Tap.
                try:
                    bundle = orjson.loads(body)
                except Exception as exc:
                    log.warning("Config-Bundle nicht parsebar: %s", exc)
                    await asyncio.sleep(CONFIG_POLL_INTERVAL_S)
                    continue
                ver = str(bundle.get("version", ""))
                if ver != CONFIG_SCHEMA_VERSION:
                    log.warning("Bundle-Schema %r unbekannt (erwartet %r) – Skip",
                                ver, CONFIG_SCHEMA_VERSION)
                    await asyncio.sleep(CONFIG_POLL_INTERVAL_S)
                    continue

                # Backup-Skip falls Server kein ETag setzt: Hash über Body.
                bhash = hashlib.sha256(body).hexdigest()
                if bhash == last_hash:
                    log.debug("Config-Poll: Bundle inhaltlich unverändert – Skip Apply")
                else:
                    rc, sc = _apply_config_bundle(bundle)
                    log.info("Config-Poll erfolgreich: %d Rules + %d Side-Files "
                             "(complete=%s, gen=%s)",
                             rc, sc, bundle.get("complete", True),
                             bundle.get("generated_at"))
                    last_hash = bhash

                last_etag = etag or last_etag
        except Exception as exc:
            log.warning("Config-Poll fehlgeschlagen: %s", exc)

        await asyncio.sleep(CONFIG_POLL_INTERVAL_S)


async def amain() -> None:
    diskq = DiskQueue(QUEUE_PATH, max_bytes=int(QUEUE_MAX_GB * 1024 * 1024 * 1024))
    state = StateWriter(STATE_PATH)
    state.write(
        connection="starting", master_url=MASTER_URL,
        last_connect_at=None, last_disconnect_at=None, last_send_at=None,
        sent_total=0, queue_count=diskq.stats()["count"],
        queue_bytes=diskq.stats()["bytes"], cert_expires_at=_cert_expires_at(),
        last_error=None,
    )

    stop = threading.Event()
    t = threading.Thread(target=_kafka_consumer_thread, args=(diskq, stop), daemon=True)
    t.start()

    # Reverse-Channel-Polling parallel zur WSS-Uplink-Schleife. Beide laufen
    # nebenher; Ausfall des einen beendet nicht den anderen.
    poll_task = asyncio.create_task(config_poll_loop())

    uplink = Uplink(diskq, state)
    try:
        await uplink.run()
    finally:
        poll_task.cancel()
        stop.set()
        t.join(timeout=5)


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
