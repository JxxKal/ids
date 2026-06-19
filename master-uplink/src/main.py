"""
master-uplink — mTLS-Endpunkt für Remote-Tap-Alerts.

Hört auf TCP/8443 (TLS, CERT_REQUIRED) mit Master-CA als Trust-Root.
Jeder sich verbindende Tap muss ein vom Master signiertes Cert mit CN
'tap:<uuid>' präsentieren. Wir matchen den Cert-Fingerprint gegen die
taps-Tabelle und akzeptieren nur Verbindungen für status='active'.

aiohttp-Server mit drei Endpoints:
  • GET /uplink   — WebSocket-Upgrade, Tap pumpt Alerts/Metrics/PCAPs rein.
  • GET /config   — Reverse-Channel-Pull: Builtin-Rules + Overrides als JSON.
  • GET /tap-update/<file>   — Update-Bundle (images-tap.tar.zst, compose,
                  scripts, manifest). web.FileResponse → sendfile-Streaming,
                  damit auch 300+ MB-Bundles ohne RAM-Crash übertragen werden.

Heartbeat alle 30 s (server → client) als WebSocket-Frame, bei Timeout
schließt der Server. Update-Push via Kafka-unabhängigem Loop (taps-Tabelle
poll alle 5s + send_str("update_now")).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

import asyncpg
import orjson
import base64
import io

from aiohttp import web, WSMsgType
from confluent_kafka import Producer
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from minio import Minio
from minio.error import S3Error

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

# MinIO-Zugang für PCAP-Upload aus tap-uplink-Frames. tap-uplink-V1 schickt
# fertige PCAP-Bytes über mTLS-WSS, master-uplink legt sie unter
# alerts/<alert_id>.pcap im ids-pcaps-Bucket ab und setzt
# alerts.pcap_available=true in Postgres.
MINIO_ENDPOINT   = os.environ.get("MINIO_ENDPOINT",   "minio:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "ids-access")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "ids-secret-change-me")
PCAP_BUCKET      = os.environ.get("PCAP_BUCKET",      "ids-pcaps")
PUSH_TOPIC       = os.environ.get("PUSH_TOPIC",       "alerts-enriched-push")

# Tap-Update-Pfad. /opt/ids/tap-update/ am Host wird per Bind-Mount nach
# /tap-update gemappt. Inhalt entsteht durch die System-Update-Pipeline
# (api/src/routers/update.py): das Update-ZIP enthält ein tap-update/-
# Subdir mit images-tap.tar.zst + manifest.json + docker-compose.tap.yml +
# scripts/. Solange dort kein manifest.json liegt, antworten wir 404.
TAP_UPDATE_DIR = Path(os.environ.get("TAP_UPDATE_DIR", "/tap-update"))

# Whitelist der via /tap-update/<...> auslieferbaren Pfade. Alles andere
# (insb. Path-Traversal mit '..') gibt 404 — das ist die einzige Auth-
# Schicht hier neben dem mTLS-Cert-Check, also bewusst eng halten.
_TAP_UPDATE_FILES: dict[str, str] = {
    "manifest":               "manifest.json",
    "compose":                "docker-compose.tap.yml",
    "bundle":                 "images-tap.tar.zst",
    "scripts/post-update.sh":         "scripts/post-update.sh",
    "scripts/daemon.json":            "scripts/daemon.json",
    "scripts/cyjan-maintenance":      "scripts/cyjan-maintenance",
    "scripts/cyjan-maintenance.service": "scripts/cyjan-maintenance.service",
    "scripts/cyjan-maintenance.timer":   "scripts/cyjan-maintenance.timer",
    "scripts/cyjan-mirror-tune":         "scripts/cyjan-mirror-tune",
    "scripts/cyjan-mirror-tune.service": "scripts/cyjan-mirror-tune.service",
    "scripts/cyjan-tap-update.path":     "scripts/cyjan-tap-update.path",
    "scripts/cyjan-tap-update.service":  "scripts/cyjan-tap-update.service",
    "scripts/cyjan-update.tmpfiles":     "scripts/cyjan-update.tmpfiles",
    "scripts/cyjan-tap":                 "scripts/cyjan-tap",
}

_TAP_UPDATE_CONTENT_TYPES: dict[str, str] = {
    ".json": "application/json",
    ".yml":  "application/yaml",
    ".yaml": "application/yaml",
    ".zst":  "application/octet-stream",
    ".sh":   "text/x-shellscript",
}

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [master-uplink] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


# ── PCAP-Upload aus tap-uplink-Frames ─────────────────────────────────────
# minio-Client wird lazy initialisiert beim ersten pcap_upload — kein
# Master-Stack-Crash wenn MinIO mal kurz nicht erreichbar ist.
_minio_client: Minio | None = None
_pcap_pool: asyncpg.Pool | None = None


def _get_minio() -> Minio:
    global _minio_client
    if _minio_client is None:
        _minio_client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=False,
        )
    return _minio_client


def _upload_pcap(alert_id: str, pcap_bytes: bytes) -> str | None:
    """Lädt PCAP-Bytes nach ids-pcaps/alerts/<alert_id>.pcap. Synchron —
    wird aus dem ws-handler über asyncio.to_thread gerufen, damit die
    Event-Loop nicht blockiert."""
    key = f"alerts/{alert_id}.pcap"
    try:
        client = _get_minio()
        client.put_object(
            PCAP_BUCKET,
            key,
            data=io.BytesIO(pcap_bytes),
            length=len(pcap_bytes),
            content_type="application/vnd.tcpdump.pcap",
        )
        return key
    except S3Error as exc:
        log.warning("MinIO put_object %s: %s", key, exc)
    except Exception as exc:
        log.warning("PCAP-Upload Fehler für %s: %s", alert_id[:8], exc)
    return None


async def _mark_pcap_available(alert_id: str, pcap_key: str) -> None:
    """alerts.pcap_available = TRUE + pcap_key setzen. Lazy-Pool, weil
    der WSS-Server ohne Master-DB läuft (nur TapAuth nutzt asyncpg)."""
    global _pcap_pool
    if _pcap_pool is None:
        _pcap_pool = await asyncpg.create_pool(POSTGRES_DSN, min_size=1, max_size=2)
    await _pcap_pool.execute(
        """
        UPDATE alerts
           SET pcap_available = TRUE, pcap_key = $2
         WHERE alert_id = $1
        """,
        alert_id, pcap_key,
    )


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

    async def report_version(self, tap_id: str, version: str) -> None:
        """Persistiert die vom Tap im hello-Frame gemeldete Version. Wird
        nur bei Wertänderung (oder fehlendem version_reported_at) up-
        gedated, damit der ts nicht bei jedem Reconnect rauscht."""
        assert self._pool
        await self._pool.execute(
            """
            UPDATE taps
               SET version             = $2,
                   version_reported_at = now()
             WHERE id = $1
               AND (version IS DISTINCT FROM $2 OR version_reported_at IS NULL)
            """,
            tap_id, version,
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


async def _authenticate_request(request: web.Request, auth: TapAuth):
    """mTLS-Cert-Check als gemeinsame Vorab-Prüfung für alle HTTP-Endpoints
    und WebSocket-Upgrade. Holt Peer-Cert aus SSL-Transport, schlägt
    fingerprint in der taps-Tabelle nach. Returnt Tap-Info-Dict oder
    HTTP-Error-Response.
    """
    transport = request.transport
    ssl_obj = transport.get_extra_info("ssl_object") if transport else None
    if ssl_obj is None:
        return None, web.Response(status=426, text="TLS required")
    fingerprint = _peer_fingerprint(ssl_obj)
    if not fingerprint:
        return None, web.Response(status=401, text="client cert required")
    info = await auth.lookup(fingerprint)
    if not info or info["status"] != "active":
        log.warning("HTTP %s mit unbekanntem/revokten Cert (fp=%s)",
                    request.path, fingerprint[:16])
        return None, web.Response(status=403, text="unknown or revoked tap")
    return info, None


async def _http_config(request: web.Request) -> web.StreamResponse:
    """Reverse-Channel — Tap pullt aktuelles Config-Bundle (Builtin-YAMLs +
    Overrides + known_networks) als JSON. Klein genug (<1 MB) um
    in-memory zu builden. ETag-Cache."""
    auth: TapAuth = request.app["auth"]
    info, err = await _authenticate_request(request, auth)
    if err is not None:
        return err
    try:
        body, etag = await build_config_bundle(auth)
    except Exception as exc:
        log.error("Config-Bundle-Build gescheitert: %s", exc)
        return web.Response(status=500, text=f"bundle error: {exc}")

    if request.headers.get("If-None-Match") == etag:
        return web.Response(status=304, headers={"ETag": etag, "Cache-Control": "no-cache"})

    log.info("Config-Bundle ausgeliefert an %s (%d Bytes, etag=%s)",
             info["name"], len(body), etag)
    return web.Response(
        body=body,
        content_type="application/json",
        headers={"ETag": etag, "Cache-Control": "no-cache"},
    )


async def _http_tap_update(request: web.Request) -> web.StreamResponse:
    """Liefert Dateien aus /tap-update/ aus. Whitelist-basiert (kein
    Path-Traversal). Manuelles Chunk-Streaming via web.StreamResponse —
    aiohttp's web.FileResponse fiel bei langen TLS-Streams (>30 MB
    bei 337 MB Bundles) reproduzierbar mid-stream aus, vermutlich durch
    eine unglückliche Interaktion zwischen sendfile-Fallback und SSL
    transport. Die manuelle Variante kontrolliert Chunk-Größe, schreibt
    via response.write() direkt in den TLS-Stream und ist über große
    Files vorhersagbar stabil.

    Heap-sicher: ein einzelner 256-KB-Chunk im Speicher, kein read_bytes()."""
    auth: TapAuth = request.app["auth"]
    info, err = await _authenticate_request(request, auth)
    if err is not None:
        return err

    sub = request.match_info["filename"]
    rel = _TAP_UPDATE_FILES.get(sub)
    if rel is None:
        return web.Response(status=404, text="unknown tap-update path")
    target = TAP_UPDATE_DIR / rel
    if not target.exists() or not target.is_file():
        return web.Response(status=404, text=f"{rel} not staged")

    suffix = target.suffix.lower()
    ctype  = _TAP_UPDATE_CONTENT_TYPES.get(suffix, "application/octet-stream")
    size = target.stat().st_size
    log.info("tap-update %s wird gestreamt an %s (%d Bytes, chunked)",
             sub, info["name"], size)

    response = web.StreamResponse(
        status=200,
        headers={
            "Content-Type":   ctype,
            "Content-Length": str(size),
        },
    )
    await response.prepare(request)

    chunk_size = 256 * 1024  # 256 KB — Balance aus Syscall-Overhead und Latency
    bytes_written = 0
    try:
        with target.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                await response.write(chunk)
                bytes_written += len(chunk)
        await response.write_eof()
    except (asyncio.CancelledError, ConnectionResetError) as exc:
        log.warning("tap-update %s an %s nach %d/%d Bytes abgebrochen: %s",
                    sub, info["name"], bytes_written, size, exc)
        raise

    return response


async def handle_tap(request: web.Request) -> web.WebSocketResponse:
    """aiohttp-Handler für /uplink-WebSocket. Vor dem upgrade machen wir den
    mTLS-Cert-Check (gleich wie für die HTTP-Endpoints), nach Upgrade läuft
    die Frame-Loop weiter. tap-uplink-Client nutzt websockets.connect, das
    ist API-kompatibel mit aiohttp-Server."""
    auth: TapAuth = request.app["auth"]
    producer: Producer = request.app["producer"]

    transport = request.transport
    ssl_obj = transport.get_extra_info("ssl_object") if transport else None
    if ssl_obj is None:
        return web.Response(status=426, text="TLS required")

    fingerprint = _peer_fingerprint(ssl_obj)
    cn = _peer_cn(ssl_obj)
    peer = request.remote or "?"
    if not fingerprint:
        return web.Response(status=401, text="no client cert")

    info = await auth.lookup(fingerprint)
    if not info:
        log.warning("Unbekannter Tap-Cert (cn=%s, fp=%s, peer=%s)",
                    cn, fingerprint[:16], peer)
        return web.Response(status=403, text="unknown tap")
    if info["status"] != "active":
        log.warning("Revoked Tap versucht zu connecten: name=%s peer=%s",
                    info["name"], peer)
        return web.Response(status=403, text="revoked")

    # Frame-Limit auf 16 MB — Alert-JSON ist <10 KB, pcap_upload-Frames
    # sind base64-encoded und bei großen PCAPs ~1–5 MB, im Extremfall
    # mehr. Großzügig bemessen.
    ws = web.WebSocketResponse(max_msg_size=16 * 1024 * 1024, heartbeat=None)
    await ws.prepare(request)

    tap_id = info["id"]
    tap_name = info["name"]
    log.info("Tap verbunden: name=%s id=%s peer=%s", tap_name, tap_id, peer)
    alerts_received = 0
    metrics_received = 0

    # In active_taps registrieren, damit der trigger_loop den Tap pingen
    # kann. Eintrag wird im finally weiter unten wieder entfernt.
    _active_taps[tap_id] = ws

    async def heartbeat_loop() -> None:
        try:
            while True:
                await asyncio.sleep(HEARTBEAT_INTERVAL_S)
                if ws.closed:
                    return
                try:
                    await ws.send_str(orjson.dumps({"type": "ping"}).decode())
                except (ConnectionResetError, RuntimeError):
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
                ws_msg = await asyncio.wait_for(ws.receive(), timeout=HEARTBEAT_TIMEOUT_S)
            except asyncio.TimeoutError:
                log.warning("Tap %s timeout – kein Frame seit %.0fs, schließe",
                            tap_name, HEARTBEAT_TIMEOUT_S)
                await ws.close(code=4408, message=b"receive timeout")
                break
            if ws_msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED):
                break
            if ws_msg.type == WSMsgType.ERROR:
                log.info("Tap %s WebSocket-Error: %s", tap_name, ws.exception())
                break
            if ws_msg.type not in (WSMsgType.TEXT, WSMsgType.BINARY):
                continue
            raw = ws_msg.data
            try:
                msg = orjson.loads(raw)
            except Exception as exc:
                log.warning("Ungültiges JSON von %s: %s", tap_name, exc)
                continue

            mtype = msg.get("type", "alert")
            if mtype == "pong":
                continue
            if mtype == "hello":
                version = str(msg.get("version") or "").strip()[:64]
                if version:
                    try:
                        await auth.report_version(tap_id, version)
                        log.info("Tap %s meldet Version %s", tap_name, version)
                    except Exception as exc:
                        log.warning("report_version fail %s: %s", tap_name, exc)
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

            if mtype == "pcap_upload":
                # tap-uplink-V1 hat lokal die ±60s-Pakete korreliert, ein
                # libpcap-Format-File gebaut und sendet es uns base64-
                # encoded mit der zugehörigen alert_id. Wir laden es in
                # MinIO unter der gleichen Key-Convention wie pcap-store
                # (alerts/<alert_id>.pcap) und setzen pcap_available in
                # der DB.
                payload = msg.get("payload") or {}
                if not isinstance(payload, dict):
                    continue
                alert_id = payload.get("alert_id")
                pcap_b64 = payload.get("pcap_b64")
                if not alert_id or not pcap_b64:
                    log.warning("pcap_upload-Frame unvollständig von %s", tap_name)
                    continue
                try:
                    pcap_bytes = base64.b64decode(pcap_b64)
                except Exception as exc:
                    log.warning("pcap_upload b64-decode fail %s: %s", alert_id[:8], exc)
                    continue
                if len(pcap_bytes) < 24:   # libpcap-global-header ist 24 Bytes
                    log.warning("pcap_upload zu klein (%d Bytes) von %s", len(pcap_bytes), tap_name)
                    continue
                key = await asyncio.to_thread(_upload_pcap, alert_id, pcap_bytes)
                if key:
                    await _mark_pcap_available(alert_id, key)
                    # Frontend live benachrichtigen — alerts-enriched-push ist
                    # der Topic den die api-WebSocket-Streamer konsumiert.
                    try:
                        producer.produce(
                            PUSH_TOPIC,
                            value=orjson.dumps({"type": "pcap_available",
                                                "data": {"alert_id": alert_id}}),
                            callback=_delivery_cb,
                        )
                        producer.poll(0)
                    except Exception as exc:
                        log.debug("WS-broadcast pcap_available fail: %s", exc)
                    log.info("PCAP von %s übernommen: %s (%d Bytes)",
                             tap_name, key, len(pcap_bytes))
                continue

            log.warning("Unbekannter Frame-Type von %s: %s", tap_name, mtype)

    except (ConnectionResetError, asyncio.CancelledError) as exc:
        log.info("Tap %s disconnected: %s (alerts=%d metrics=%d)",
                 tap_name, exc, alerts_received, metrics_received)
    finally:
        hb.cancel()
        st.cancel()
        _active_taps.pop(tap_id, None)
        # Final-Stats persistieren. Metriken zählen aktuell nicht in die
        # taps.alerts_received-Spalte rein – das wäre irreführend für die UI.
        # Falls später ein metrics_received-Counter in der DB erwünscht ist,
        # kann auth.heartbeat() um ein zweites Argument erweitert werden.
        if alerts_received:
            await auth.heartbeat(tap_id, alerts_received, peer)
        if not ws.closed:
            await ws.close()
    return ws


# Aktive Tap-WebSockets (in-memory). update_trigger_loop nutzt das, um
# bei einem `update_requested_at > update_acked_at`-Eintrag in der taps-
# Tabelle einen "update_now"-Frame an den passenden Tap zu schicken.
_active_taps: dict[str, web.WebSocketResponse] = {}


async def update_trigger_loop(auth: "TapAuth") -> None:
    """Pollt alle 5 s die taps-Tabelle nach pending Update-Triggers und
    sendet WebSocket-Frames an die aktiven Tap-Connections. Lockless,
    weil _active_taps und DB-State eindeutige Single-Source-of-Truths
    sind und der Loop in einer einzigen asyncio-Task läuft."""
    assert auth._pool is not None
    while True:
        try:
            rows = await auth._pool.fetch(
                """
                SELECT id::text AS id, name, update_requested_at
                  FROM taps
                 WHERE status = 'active'
                   AND update_requested_at IS NOT NULL
                   AND (update_acked_at IS NULL
                        OR update_requested_at > update_acked_at)
                """
            )
            for row in rows:
                tap_id = row["id"]
                ws = _active_taps.get(tap_id)
                if ws is None or ws.closed:
                    # Tap aktuell nicht connected — wir warten. Sobald er
                    # sich verbindet, greift der nächste Loop-Pass.
                    continue
                try:
                    await ws.send_str(orjson.dumps({
                        "type": "update_now",
                        "ts":   row["update_requested_at"].isoformat() if row["update_requested_at"] else None,
                    }).decode())
                    await auth._pool.execute(
                        "UPDATE taps SET update_acked_at = now() WHERE id = $1::uuid",
                        tap_id,
                    )
                    log.info("update-trigger an %s gesendet", row["name"])
                except Exception as exc:
                    log.warning("update-trigger fail für %s: %s", row["name"], exc)
        except Exception as exc:
            log.warning("update_trigger_loop poll-error: %s", exc)
        await asyncio.sleep(5)


async def amain() -> None:
    auth = TapAuth(POSTGRES_DSN)
    await auth.init()

    producer = Producer({
        "bootstrap.servers": KAFKA_BROKERS,
        "linger.ms": 20,
        "acks": "1",
        "compression.type": "lz4",
    })

    ssl_ctx = _build_ssl_context()
    log.info("master-uplink lauscht auf https://%s:%d  (mTLS, Topics %s + %s)",
             LISTEN_HOST, LISTEN_PORT, ALERTS_TOPIC, METRICS_TOPIC)

    # aiohttp-Application — ein Server für WebSocket (/uplink) + HTTP-
    # Endpoints (/config, /tap-update/<file>). FileResponse für Bundle-
    # Streaming via sendfile-Syscall — keine RAM-Loading-Crashes mehr.
    app = web.Application()
    app["auth"] = auth
    app["producer"] = producer
    app.router.add_get("/uplink", handle_tap)
    # Backwards-Compat: tap-uplink-Client verbindet sich gegen
    # wss://master:8443/uplink (oder gegen die Root-URL wss://master:8443/).
    # Damit beides funktioniert, mounten wir den Handler auch unter / .
    app.router.add_get("/", handle_tap)
    app.router.add_get("/config", _http_config)
    app.router.add_get("/tap-update/{filename:.+}", _http_tap_update)

    # Update-Trigger-Loop: pollt taps.update_requested_at und sendet
    # update_now-Frames an die aktiven Connections. Läuft parallel zum
    # HTTP-Server.
    trigger_task = asyncio.create_task(update_trigger_loop(auth))

    runner = web.AppRunner(app, handle_signals=True)
    await runner.setup()
    site = web.TCPSite(runner, host=LISTEN_HOST, port=LISTEN_PORT, ssl_context=ssl_ctx)
    await site.start()
    try:
        await asyncio.Future()    # forever
    finally:
        trigger_task.cancel()
        await runner.cleanup()
        await auth.close()
        producer.flush(timeout=5)


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
