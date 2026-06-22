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
import dataclasses
import hashlib
import io
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
# pcap-headers-Topic: Sniffer schreibt jedes Paket-Header-Sample rein.
# tap-uplink hält daraus einen ±PCAP_WINDOW_S-Ringbuffer in-memory und
# baut bei lokal-detektierten Alarmen das passende PCAP für master-uplink.
PCAP_TOPIC      = os.environ.get("PCAP_TOPIC",       "pcap-headers")
PCAP_WINDOW_S   = float(os.environ.get("PCAP_WINDOW_S", "60"))
PCAP_GROUP_ID   = os.environ.get("PCAP_GROUP_ID",    "tap-uplink-pcap")
# In-memory Ringbuffer-Cap (sliding-window). 16 MB Frame-Limit am Master
# definiert die obere Grenze einer einzelnen PCAP-Übertragung; bei
# typischer 60s × 18kpps × 128 Byte snaplen wären das ~140 MB roh —
# zu viel für ein Frame. Wir limitieren die buf-Länge daher pragmatisch
# (Drop-Oldest), damit ein Spike-Mirror keinen RAM-Run-Away erzeugt.
PCAP_MAX_PACKETS_IN_BUF = int(os.environ.get("PCAP_MAX_PACKETS_IN_BUF", "200000"))
# Maximale Bytes pro hochgeladenem PCAP. Bei Überschreitung droppen wir
# den ältesten Paketanteil bis das PCAP-Bytes-Limit unterschritten ist.
PCAP_MAX_UPLOAD_BYTES   = int(os.environ.get("PCAP_MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))

MASTER_URL    = os.environ.get("MASTER_URL", "wss://master.example.com:8443/uplink")
# Plain ws:// gegen den master-uplink (mTLS-only Endpoint) führt zu einem
# ValueError der websockets-Lib ("connect() received a ssl argument for a
# ws:// URI"). Statt User mit kryptischem Stack zu nerven: automatisch zu
# wss:// upgraden + im Log warnen. Echtes plain-WS-Setup ist im Cyjan-
# Master-Stack nicht vorgesehen — der Endpoint hat per Compose immer TLS.
if MASTER_URL.startswith("ws://"):
    _orig = MASTER_URL
    MASTER_URL = "wss://" + MASTER_URL[len("ws://"):]
    # `log` ist hier noch nicht initialisiert (wird unten konfiguriert).
    # Statt Import-Order zu verbiegen, nutzen wir print() — landet im
    # Container-Stdout und damit im docker-compose-Log.
    print(
        f"[WARN] tap-uplink: MASTER_URL={_orig} → upgrade auf {MASTER_URL} "
        f"(master-uplink ist mTLS-only auf 8443, plain ws:// funktioniert nicht).",
        flush=True,
    )
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

# Tap-Version: kommt aus /opt/ids/VERSION via Bind-Mount auf
# /etc/cyjan/version (siehe docker-compose.tap.yml). Wird beim Connect
# einmal als hello-Frame an master-uplink geschickt, damit die UI im
# Master-Frontend pro Tap die laufende Version anzeigen kann.
TAP_VERSION_FILE = os.environ.get("TAP_VERSION_FILE", "/etc/cyjan/version")
def _read_tap_version() -> str:
    try:
        return Path(TAP_VERSION_FILE).read_text().strip()
    except Exception:
        return "unknown"

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [tap-uplink] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

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


# ── PCAP-Builder (Mini-pcap-store, host-internal) ──────────────────────────
# tap-uplink-V1: konsumiert pcap-headers lokal, hält ±PCAP_WINDOW_S-Ringbuffer,
# erzeugt bei lokal-detektierten Alerts das libpcap-File und schickt es als
# pcap_upload-Frame an master-uplink. Damit haben Tap-Alerts auch dann ein
# PCAP, wenn der pcap-store nur am Master läuft.

import base64 as _b64
import struct as _struct
from collections import deque as _deque

_PCAP_GLOBAL_HEADER = _struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,   # magic
    2, 4,         # version major.minor
    0, 0,         # thiszone, sigfigs
    65535,        # snaplen
    1,            # LINKTYPE_ETHERNET
)
_PKT_HEADER_FMT = "<IIII"


class _PacketBuffer:
    """Thread-safer Ringbuffer für (timestamp, raw_bytes). Cleanup beim
    add() — ältere als max_window_s werden verworfen. cap auf
    PCAP_MAX_PACKETS_IN_BUF schützt gegen Spike-Mirror der Memory wegfrisst."""
    def __init__(self, max_window_s: float, max_packets: int) -> None:
        self._max_s = max_window_s * 2 + 10
        self._max_n = max_packets
        self._buf: _deque[tuple[float, bytes]] = _deque()
        self._lock = threading.Lock()

    def add(self, ts: float, raw: bytes) -> None:
        with self._lock:
            self._buf.append((ts, raw))
            cutoff = time.time() - self._max_s
            while self._buf and self._buf[0][0] < cutoff:
                self._buf.popleft()
            while len(self._buf) > self._max_n:
                self._buf.popleft()

    def extract(self, center_ts: float, window_s: float) -> list[tuple[float, bytes]]:
        lo = center_ts - window_s
        hi = center_ts + window_s
        with self._lock:
            return [(ts, raw) for ts, raw in self._buf if lo <= ts <= hi]

    def newest_ts(self) -> float:
        with self._lock:
            return self._buf[-1][0] if self._buf else 0.0


def _build_pcap(packets: list[tuple[float, bytes]], max_bytes: int) -> bytes:
    """Baut libpcap-File. Wenn das Total-Bytes-Limit überschritten würde,
    werden die ältesten Pakete weggelassen (latest-wins-Strategie — der
    User will eher den Trigger-Moment + danach sehen, weniger den
    Vorlauf)."""
    sorted_pkts = sorted(packets, key=lambda x: x[0])
    # Größe vorberechnen, dann von vorn droppen bis es passt
    total = len(_PCAP_GLOBAL_HEADER)
    sizes: list[int] = []
    for _, raw in sorted_pkts:
        s = 16 + len(raw)
        sizes.append(s)
        total += s
    drop_from_start = 0
    while total > max_bytes and drop_from_start < len(sorted_pkts):
        total -= sizes[drop_from_start]
        drop_from_start += 1
    sorted_pkts = sorted_pkts[drop_from_start:]

    buf = io.BytesIO()
    buf.write(_PCAP_GLOBAL_HEADER)
    for ts, raw in sorted_pkts:
        ts_sec  = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        pkt_len = len(raw)
        buf.write(_struct.pack(_PKT_HEADER_FMT, ts_sec, ts_usec, pkt_len, pkt_len))
        buf.write(raw)
    return buf.getvalue()


@dataclasses.dataclass
class _PendingAlert:
    alert_id: str
    alert_ts: float
    ready_at: float


# Globale Shared-State zwischen den drei Threads (alerts-Consumer,
# pcap-Consumer, Flush-Loop). Lock zwischen alerts-Consumer und Flush.
_pcap_buffer  = _PacketBuffer(PCAP_WINDOW_S, PCAP_MAX_PACKETS_IN_BUF)
_pending_lock = threading.Lock()
_pending_alerts: list[_PendingAlert] = []


def _kafka_pcap_consumer_thread(stop: threading.Event) -> None:
    """Konsumiert pcap-headers vom lokalen Tap-Kafka, packt Pakete in den
    in-memory Ringbuffer. Eigener Thread weil die Volumina (18 kpps) den
    alerts-Consumer-Loop sonst blocken würden. auto.offset.reset=latest:
    bei Crash/Restart fangen wir frisch an, kein Backlog-Replay (alte
    Pakete sind eh wertlos für PCAPs zu zukünftigen Alerts)."""
    consumer = Consumer({
        "bootstrap.servers": KAFKA_BROKERS,
        "group.id":          PCAP_GROUP_ID,
        "auto.offset.reset": "latest",
        "enable.auto.commit": True,
        # Höhere fetch-Größe weil Volume — defaults sind oft konservativ:
        "fetch.message.max.bytes": 10 * 1024 * 1024,
    })
    try:
        consumer.subscribe([PCAP_TOPIC])
    except Exception as exc:
        log.warning("pcap-Consumer subscribe-Fehler: %s — Topic vmtl. nicht initialisiert", exc)
        consumer.close()
        return

    log.info("Kafka-pcap-Consumer subscribed: %s @ %s", PCAP_TOPIC, KAFKA_BROKERS)
    pkt_count = 0
    try:
        while not stop.is_set():
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                # Topic noch nicht angelegt → resilient warten, evtl. kommt
                # er beim nächsten init-topics-Run.
                log.debug("pcap-Consumer Kafka-error: %s", msg.error())
                continue
            try:
                pkt = orjson.loads(msg.value())
                ts_sec  = pkt.get("ts_sec")
                if ts_sec is None:
                    continue
                ts_usec = pkt.get("ts_usec", 0)
                ts = float(ts_sec) + float(ts_usec) / 1_000_000
                raw_b64 = pkt.get("data_b64")
                if not raw_b64:
                    continue
                _pcap_buffer.add(ts, _b64.b64decode(raw_b64))
                pkt_count += 1
                if pkt_count % 50000 == 0:
                    log.debug("pcap-buf: %d Pakete eingebucht", pkt_count)
            except Exception as exc:
                log.debug("pcap-Paket-parse Fehler: %s", exc)
    finally:
        consumer.close()
        log.info("Kafka-pcap-Consumer beendet")


def _flush_pending_pcaps_thread(diskq: DiskQueue, stop: threading.Event) -> None:
    """Polls die pending-Liste alle 1s. Reife Alarme (ts + window_s
    erreicht) werden zu PCAP-Files konvertiert und als pcap_upload-Frame
    in die DiskQueue gepusht — von dort aus geht die Übertragung über
    den existierenden _send_loop an den Master."""
    log.info("PCAP-Flush-Thread aktiv (window=%.0fs)", PCAP_WINDOW_S)
    while not stop.is_set():
        time.sleep(1.0)
        now_mono = time.monotonic()
        ripe: list[_PendingAlert] = []
        with _pending_lock:
            still_pending: list[_PendingAlert] = []
            for pa in _pending_alerts:
                if now_mono >= pa.ready_at:
                    ripe.append(pa)
                else:
                    still_pending.append(pa)
            _pending_alerts.clear()
            _pending_alerts.extend(still_pending)

        for pa in ripe:
            packets = _pcap_buffer.extract(pa.alert_ts, PCAP_WINDOW_S)
            if not packets:
                log.warning("Keine Pakete im Fenster für Alert %s", pa.alert_id[:8])
                continue
            try:
                pcap_bytes = _build_pcap(packets, PCAP_MAX_UPLOAD_BYTES)
                pcap_b64   = _b64.b64encode(pcap_bytes).decode()
                frame = orjson.dumps({
                    "type": "pcap_upload",
                    "payload": {
                        "alert_id": pa.alert_id,
                        "pcap_b64": pcap_b64,
                    },
                })
                diskq.push(frame)
                log.info("pcap_upload für Alert %s queued (%d Pakete, %d Bytes)",
                         pa.alert_id[:8], len(packets), len(pcap_bytes))
            except Exception as exc:
                log.warning("pcap_upload-Build fail %s: %s", pa.alert_id[:8], exc)
    log.info("PCAP-Flush-Thread beendet")


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
            _beat()
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
                # PCAP-Pfad: bei jedem Alert einen PendingAlert anlegen,
                # damit der Flush-Thread nach Window-Ablauf das passende
                # PCAP aus dem in-memory Ringbuffer baut.
                if ftype == "alert":
                    alert_id = payload_obj.get("alert_id")
                    ts_raw   = payload_obj.get("ts")
                    if alert_id:
                        try:
                            from datetime import datetime
                            alert_ts = datetime.fromisoformat(str(ts_raw)).timestamp() \
                                       if ts_raw else time.time()
                        except (ValueError, TypeError):
                            try:
                                alert_ts = float(ts_raw) if ts_raw else time.time()
                            except (ValueError, TypeError):
                                alert_ts = time.time()
                        with _pending_lock:
                            _pending_alerts.append(_PendingAlert(
                                alert_id=alert_id,
                                alert_ts=alert_ts,
                                ready_at=time.monotonic() + PCAP_WINDOW_S,
                            ))
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

                    # Hello-Frame: Tap stellt sich beim Master vor, schickt
                    # die laufende Version + Schema-Version mit. master-
                    # uplink persistiert das in taps.version. Failsoft —
                    # bei Send-Fehler einfach weiter (älterer Master ohne
                    # hello-Handler ignoriert das Frame).
                    try:
                        await ws.send(orjson.dumps({
                            "type":    "hello",
                            "version": _read_tap_version(),
                            "schema":  CONFIG_SCHEMA_VERSION,
                        }).decode())
                    except Exception as exc:
                        log.debug("hello-frame send fail (uncritical): %s", exc)

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
            elif msg.get("type") == "update_now":
                # Master triggert Update. Wir schreiben einen Trigger-File
                # ins host-bind-mountete /run/cyjan-update/, ein systemd-
                # path-watcher auf dem Host läuft daraufhin
                # `cyjan-tap update --from-master -y`. Wir können hier
                # nicht selbst docker-Befehle absetzen — kein docker socket
                # im tap-uplink-Container, und auch wenn er da wäre, würde
                # ein Self-Restart das compose --force-recreate auf einen
                # wegfallenden Trigger-Prozess setzen. Host-side ist der
                # saubere Weg.
                trigger_path = Path("/host/cyjan-update/trigger")
                try:
                    trigger_path.parent.mkdir(parents=True, exist_ok=True)
                    trigger_path.write_text(
                        f"{time.strftime('%Y-%m-%dT%H:%M:%S')} master={MASTER_URL}\n"
                    )
                    log.info("update_now-Frame empfangen — Trigger geschrieben (%s)", trigger_path)
                except Exception as exc:
                    log.warning("Konnte update-Trigger nicht schreiben: %s", exc)


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
    hrc = bundle.get("host_role_catalog")
    if hrc is not None:
        # Gebündelte Host-Rollen-Katalog-YAMLs vom Master. Am Tap aktuell noch
        # nicht aktiv konsumiert (Detektor läuft master-only), aber für
        # V1-forward schon mit-synct, damit ein künftiger Tap-Detektor denselben
        # Katalog sieht.
        _atomic_write(custom_dir / "_host_role_catalog.json", orjson.dumps(hrc))
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

    # PCAP-Side: separater Consumer für pcap-headers + periodischer Flush.
    # Beide daemon-Threads, sterben mit dem Hauptprozess. Wenn Topic
    # pcap-headers nicht existiert (alte Tap-Init-Topics-Variante), failt
    # der Subscribe failsoft und der Thread beendet sich — der Stack läuft
    # ohne PCAP-Feature weiter.
    t_pcap  = threading.Thread(target=_kafka_pcap_consumer_thread, args=(stop,), daemon=True)
    t_flush = threading.Thread(target=_flush_pending_pcaps_thread, args=(diskq, stop), daemon=True)
    t_pcap.start()
    t_flush.start()

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
        t_pcap.join(timeout=5)
        t_flush.join(timeout=5)


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
