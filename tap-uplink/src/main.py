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
import logging
import os
import ssl
import threading
import time
from pathlib import Path

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


# ── Kafka-Consumer (in eigenem Thread) ───────────────────────────────────────


def _kafka_consumer_thread(diskq: DiskQueue, stop: threading.Event) -> None:
    """Liest alerts-raw und pusht jeden Alert in die DiskQueue. Läuft in
    einem dedizierten Thread, weil confluent-kafka synchron ist."""
    consumer = Consumer({
        "bootstrap.servers": KAFKA_BROKERS,
        "group.id": GROUP_ID,
        "auto.offset.reset": "latest",
        "enable.auto.commit": True,
    })
    consumer.subscribe([ALERTS_TOPIC])
    log.info("Kafka-Consumer subscribed: %s @ %s", ALERTS_TOPIC, KAFKA_BROKERS)

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
            try:
                # Frame-Format: {"type":"alert","payload":<original-alert-dict>}
                # Die Klein-Wrapping-Schicht kostet ein paar Bytes, vereinfacht
                # aber den Master-Endpoint, weil Kontroll-Frames (ping/pong/
                # später cmd/ack) das gleiche Schema benutzen können.
                alert = orjson.loads(payload)
                frame = orjson.dumps({"type": "alert", "payload": alert})
                diskq.push(frame)
            except Exception as exc:
                log.error("Push in Queue fehlgeschlagen: %s", exc)
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
                ssl_ctx = _build_ssl_context()
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
    /config-Pfad um. Für ws:// → http:// (Test-Setup ohne TLS, eher selten)."""
    u = MASTER_URL
    if u.startswith("wss://"):
        u = "https://" + u[len("wss://"):]
    elif u.startswith("ws://"):
        u = "http://" + u[len("ws://"):]
    # Pfad ersetzen: /uplink → /config (oder direkt anhängen wenn keiner da)
    head, _, _path = u.partition("?")
    base = head.rsplit("/", 1)[0] if "/" in head[len("https://"):] else head
    return base + "/config"


def _atomic_write(path: Path, content: bytes) -> None:
    """tmp + rename → kein partieller Read durch signature-engine-inotify."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(content)
    os.replace(tmp, path)


def _apply_config_bundle(bundle: dict) -> tuple[int, int]:
    """Schreibt das Bundle in den lokalen RULES_DIR. Liefert (rules_count,
    side_files_count) für Logging."""
    builtin_dir = RULES_DIR / "builtin"
    custom_dir  = RULES_DIR / "custom"

    # Vorhandene Builtin-YAMLs aufräumen die nicht mehr im Bundle sind.
    # Custom-Files werden NICHT angefasst – das ist sonst-User-territory.
    rules = bundle.get("rules", {}) or {}
    if isinstance(rules, dict):
        # Aktuelle YAMLs schreiben.
        for fname, body in rules.items():
            # Schutz vor Path-Traversal: nur einfache Dateinamen erlauben
            if "/" in fname or fname.startswith(".") or not fname.endswith(".yml"):
                log.warning("Skip rule mit auffälligem Dateinamen: %s", fname)
                continue
            _atomic_write(builtin_dir / fname, body.encode("utf-8"))
        # Veraltete YAMLs in builtin/ entfernen, die nicht mehr im Bundle sind.
        if builtin_dir.is_dir():
            keep = set(rules.keys())
            for f in builtin_dir.glob("*.yml"):
                if f.name not in keep:
                    try:
                        f.unlink()
                        log.info("Veraltete Rule entfernt: %s", f.name)
                    except Exception as exc:
                        log.warning("Konnte %s nicht löschen: %s", f, exc)

    side_files = 0
    ovr = bundle.get("rules_overrides")
    if ovr is not None:
        _atomic_write(custom_dir / "_overrides.json", orjson.dumps(ovr))
        side_files += 1
    sov = bundle.get("suricata_overrides")
    if sov is not None:
        _atomic_write(custom_dir / "_suricata_overrides.json", orjson.dumps(sov))
        side_files += 1
    dns = bundle.get("dns_resolvers")
    if dns is not None:
        # Eigene Datei – am Tap aktuell nicht aktiv konsumiert (alert-manager
        # läuft ausschließlich am Master), aber für V2 schon mit-synct.
        _atomic_write(custom_dir / "_dns_resolvers.json", orjson.dumps(dns))
        side_files += 1

    return len(rules), side_files


async def config_poll_loop() -> None:
    """Pollt MASTER /config alle 5 min mit mTLS-Cert. Liefert atomar in
    den signature-rules-Volume; signature-engine zieht via inotify nach."""
    url = _config_url()
    log.info("Config-Poll-Loop aktiv: alle %.0fs gegen %s",
             CONFIG_POLL_INTERVAL_S, url)
    # Beim Boot kurz warten, damit der WSS-Reconnect zuerst läuft (sonst
    # konkurrieren die Verbindungen um den ersten Cert-Read).
    await asyncio.sleep(5)

    while True:
        if not _has_pairing():
            await asyncio.sleep(min(30, CONFIG_POLL_INTERVAL_S))
            continue

        try:
            ssl_ctx = _build_ssl_context()
            async with httpx.AsyncClient(
                timeout=CONFIG_POLL_TIMEOUT_S,
                verify=ssl_ctx,
                cert=(TAP_CERT, TAP_KEY),
            ) as client:
                resp = await client.get(url)
            if resp.status_code != 200:
                log.warning("Config-Poll HTTP %d: %s", resp.status_code, resp.text[:200])
            else:
                bundle = resp.json()
                rc, sc = _apply_config_bundle(bundle)
                log.info("Config-Poll erfolgreich: %d Rules + %d Side-Files (gen=%s)",
                         rc, sc, bundle.get("generated_at"))
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
