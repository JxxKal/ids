"""
tap-api — minimales Status-/Konfig-Webinterface für den Remote-Tap.

Drei Pages:
  /          Status: Sniffer + Master-Verbindung + Queue
  /config    Config-View (Master-URL, Tap-Cert-Status, Mirror-Interface)
  /alerts    JSON-Endpoint mit Disk-Queue-Stats

Plus zwei Maschinen-Endpunkte für die `cyjan-tap`-CLI:
  GET  /api/state         – tap-uplink-State (Pass-through der state.json)
  POST /api/test-alert    – produziert einen synthetischen Alert ins lokale Kafka

Bewusst KEIN Auth – tap-api lauscht per Default auf 127.0.0.1 + dem Mgmt-
VLAN, exponiert nichts gegen das WAN. Wer es ins Internet stellt, hat ein
größeres Problem als das Fehlen von Login-Boxen.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import httpx
from confluent_kafka import Producer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [tap-api] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("tap-api")

STATE_PATH    = os.environ.get("STATE_PATH", "/run/cyjan/tap-uplink.state.json")
KAFKA_BROKERS = os.environ.get("KAFKA_BROKERS", "kafka:9092")
ALERTS_TOPIC  = os.environ.get("ALERTS_TOPIC", "alerts-raw")
MASTER_URL    = os.environ.get("MASTER_URL", "")
TAP_CERT      = os.environ.get("TAP_CERT", "/etc/cyjan/tap.pem")
MIRROR_IFACE  = os.environ.get("MIRROR_IFACE", "")

BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI(title="Cyjan IDS Remote Tap", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

# Kafka-Producer für /api/test-alert. Connection-Aufbau lazy bei erstem Use.
_producer: Producer | None = None


def _producer_get() -> Producer:
    global _producer
    if _producer is None:
        _producer = Producer({"bootstrap.servers": KAFKA_BROKERS, "linger.ms": 0})
    return _producer


def _read_state() -> dict:
    try:
        return json.loads(Path(STATE_PATH).read_bytes())
    except FileNotFoundError:
        return {
            "connection": "unknown",
            "master_url": MASTER_URL,
            "sent_total": 0,
            "queue_count": 0,
            "queue_bytes": 0,
            "last_error": "tap-uplink State-Datei fehlt – Service läuft nicht?",
        }
    except Exception as exc:
        return {"connection": "error", "last_error": str(exc)}


def _config_view() -> dict:
    cert_present = Path(TAP_CERT).exists()
    return {
        "master_url":      MASTER_URL,
        "mirror_iface":    MIRROR_IFACE,
        "tap_cert_path":   TAP_CERT,
        "tap_cert_present": cert_present,
        "kafka_brokers":   KAFKA_BROKERS,
        "alerts_topic":    ALERTS_TOPIC,
    }


# ── HTML-Pages ────────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def page_status(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        "status.html",
        {"request": request, "state": _read_state(), "config": _config_view()},
    )


@app.get("/config", response_class=HTMLResponse)
async def page_config(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        "config.html",
        {"request": request, "config": _config_view()},
    )


# ── System-Last (Mirror-Traffic + Sniffer-Drops + Host-Ressourcen) ───────────
#
# Direkt aus api/src/routers/system.py portiert. tap-api wird nur read-only
# aufgerufen (kein Auth, lokal-only), die Implementation ist identisch zur
# Master-API damit beide das gleiche Bild liefern.

_HOST_PROC = Path("/host/proc")
_HOST_SYS_NET = Path("/host/sys/class/net")

_cpu_prev: list[int] = []
_cpu_prev_t: float = 0.0
_net_prev: dict[str, tuple[int, int, int, int, float]] = {}

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def _cpu_pct() -> float | None:
    """Linux-CPU-Auslastung über /proc/stat-Delta. Erster Aufruf gibt None
    zurück (keine Baseline) — der nächste Tick (~1 s später) liefert dann den
    realen Wert."""
    global _cpu_prev, _cpu_prev_t
    try:
        line = (_HOST_PROC / "stat").read_text().splitlines()[0]
        vals = list(map(int, line.split()[1:8]))
        now = time.monotonic()
        result: float | None = None
        if _cpu_prev and now - _cpu_prev_t > 0.1:
            delta = [v2 - v1 for v1, v2 in zip(_cpu_prev, vals)]
            total = sum(delta)
            idle = delta[3] + delta[4]
            result = round((total - idle) / total * 100, 1) if total > 0 else 0.0
        _cpu_prev = vals
        _cpu_prev_t = now
        return result
    except Exception:
        return None


def _mem() -> dict:
    try:
        info: dict[str, int] = {}
        for line in (_HOST_PROC / "meminfo").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                info[parts[0].rstrip(":")] = int(parts[1])
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", 0)
        used = total - avail
        return {
            "total_mb": total // 1024,
            "used_mb":  used // 1024,
            "pct":      round(used / total * 100, 1) if total else None,
        }
    except Exception:
        return {"total_mb": 0, "used_mb": 0, "pct": None}


def _disk() -> dict:
    """Disk-Auslastung des Volumes auf dem `/var/lib/cyjan/uplink-queue.db`
    sitzt — das ist genau der Grund warum Disk hier interessant ist
    (Outage-Buffer kann bei langer Master-Trennung anwachsen). Fallback
    `/`, weil das Tap-OS ein Single-Partition-Layout fährt."""
    try:
        # /var/lib/cyjan ist im tap-uplink-Container, nicht hier — wir nehmen
        # was der Container selbst sieht. Auf dem Tap-OS ist alles auf /, das
        # passt.
        st = os.statvfs("/")
        total = st.f_frsize * st.f_blocks
        free  = st.f_frsize * st.f_bfree
        used  = total - free
        return {
            "total_gb": round(total / 1e9, 1),
            "used_gb":  round(used  / 1e9, 1),
            "pct":      round(used / total * 100, 1) if total else None,
        }
    except Exception:
        return {"total_gb": 0.0, "used_gb": 0.0, "pct": None}


def _net_rates(iface: str) -> dict | None:
    """Mirror-Interface-Raten aus /sys/class/net/<iface>/statistics. Erster
    Aufruf liefert nur die absoluten Drop-Counter, ab dem zweiten Tick
    auch Bps/pps.

    Drop-Counter werden bewusst getrennt geliefert:
      rx_dropped      → Kernel-Stack-Drop. Auf Mirror-Ports oft sehr hoch
                        ohne dass ein echter Verlust passiert: der Kernel
                        zählt jedes Paket als 'dropped' das nicht für die
                        eigene MAC ist und keiner regulären Socket zu-
                        ordenbar ist. Der AF_PACKET-Sniffer sieht diese
                        Pakete trotzdem (PROMISC). Daher als informativ
                        zu werten — NICHT als Ring-Buffer-Indikator.
      hw_drops        → Summe aus rx_fifo_errors + rx_missed_errors +
                        rx_over_errors. Das sind die echten Hardware-/
                        Ring-Buffer-Drops, die eine ethtool-G-Erweiterung
                        rechtfertigen. Wenn diese Zahl steigt, ist der
                        Ring-Buffer das Bottleneck."""
    global _net_prev
    if not iface:
        return None
    stats_dir = _HOST_SYS_NET / iface / "statistics"
    if not stats_dir.is_dir():
        return None
    try:
        def rd(f: str, default: int = 0) -> int:
            try:
                return int((stats_dir / f).read_text())
            except FileNotFoundError:
                return default
        rx_b = rd("rx_bytes"); tx_b = rd("tx_bytes")
        rx_p = rd("rx_packets"); tx_p = rd("tx_packets")
        rx_d = rd("rx_dropped")
        # Echte HW-Drops: viele NICs füllen NICHT alle drei Counter, daher
        # summieren wir sie. Fehlende Files → 0 (ist kein echter Counter,
        # aber ein vorsichtiger Default).
        hw_drops = (
            rd("rx_fifo_errors")
            + rd("rx_missed_errors")
            + rd("rx_over_errors")
        )
        now = time.monotonic()
        prev = _net_prev.get(iface)
        _net_prev[iface] = (rx_b, tx_b, rx_p, tx_p, now)
        base = {
            "rx_bps":     None,
            "tx_bps":     None,
            "rx_pps":     None,
            "tx_pps":     None,
            "rx_dropped": rx_d,
            "hw_drops":   hw_drops,
        }
        if prev is None:
            return base
        p_rx_b, p_tx_b, p_rx_p, p_tx_p, p_t = prev
        dt = now - p_t
        if dt < 0.1:
            return base
        return {
            "rx_bps":     round((rx_b - p_rx_b) / dt),
            "tx_bps":     round((tx_b - p_tx_b) / dt),
            "rx_pps":     round((rx_p - p_rx_p) / dt),
            "tx_pps":     round((tx_p - p_tx_p) / dt),
            "rx_dropped": rx_d,
            "hw_drops":   hw_drops,
        }
    except Exception:
        return None


def _sniffer_stats() -> dict:
    """Letzte 'sniffer stats'-Zeile aus den Container-Logs parsen. Auf dem
    Tap heißt der Container `cyjan-tap-sniffer` (vs. `ids-sniffer` am
    Master). Wenn docker-CLI fehlt (Image ohne Mount), kommt None für die
    Live-Werte zurück — die Total-Counter aus der State-Datei der tap-uplink
    bleiben davon unberührt."""
    if not shutil.which("docker"):
        return {"pps": None, "drop_pct": None, "total_captured": 0,
                "total_dropped": 0, "kafka_errors": 0,
                "note": "docker-CLI im tap-api-Container nicht verfügbar"}
    try:
        r = subprocess.run(
            ["docker", "logs", "--tail", "30", "cyjan-tap-sniffer"],
            capture_output=True, text=True, timeout=3,
        )
        text = _ANSI_RE.sub("", r.stdout + r.stderr)
        for line in reversed(text.splitlines()):
            if "sniffer stats" not in line:
                continue
            def _f(pattern: str, default: float = 0.0) -> float:
                m = re.search(pattern, line)
                return float(m.group(1)) if m else default
            def _i(pattern: str) -> int:
                m = re.search(pattern, line)
                return int(m.group(1)) if m else 0
            return {
                "pps":            _f(r'pps="([^"]+)"'),
                "drop_pct":       _f(r'drop_pct="([^%"]+)%?"'),
                "total_captured": _i(r'total_cap=(\d+)'),
                "total_dropped":  _i(r'total_drop=(\d+)'),
                "kafka_errors":   _i(r'kafka_errors=(\d+)'),
            }
    except Exception as exc:
        return {"pps": None, "drop_pct": None, "total_captured": 0,
                "total_dropped": 0, "kafka_errors": 0, "note": str(exc)}
    return {"pps": None, "drop_pct": None, "total_captured": 0,
            "total_dropped": 0, "kafka_errors": 0,
            "note": "noch keine 'sniffer stats'-Zeile in den letzten 30 Logs"}


# ── Maschinen-Endpunkte (für CLI) ─────────────────────────────────────────────


@app.get("/api/state")
async def api_state() -> JSONResponse:
    return JSONResponse(_read_state())


@app.get("/api/load")
async def api_load() -> JSONResponse:
    """Last-Snapshot: Mirror-Traffic-Raten, Sniffer-Drops, Host-Ressourcen.

    `/api/state` bleibt der Master-Connection-Status; `/api/load` ist die
    Tap-lokale Health-Sicht. Aufgerufen von der CLI-Subkommando
    `cyjan-tap load` und (folgt) der HTML-Status-Page.
    """
    return JSONResponse({
        "iface":   MIRROR_IFACE,
        "cpu_pct": _cpu_pct(),
        "mem":     _mem(),
        "disk":    _disk(),
        "net":     _net_rates(MIRROR_IFACE),
        "sniffer": _sniffer_stats(),
    })


@app.get("/api/config")
async def api_config() -> JSONResponse:
    return JSONResponse(_config_view())


class PairBody(BaseModel):
    master_url:  str = Field(min_length=1)         # https://master:8000 oder http://...
    token:       str = Field(min_length=10)
    verify_ssl:  bool = Field(default=False)        # Default false: Master hat typisch
                                                    # ein Self-Signed-Cert. Erst NACH
                                                    # dem Pairing kennen wir die Master-CA
                                                    # für ordentliche Validierung.


@app.post("/api/pair")
async def api_pair(body: PairBody) -> JSONResponse:
    """Generiert lokal Key + CSR, postet sie mit dem Pairing-Token an den
    Master, schreibt das signierte Cert + die Master-CA nach /etc/cyjan.
    Idempotent NICHT – jeder Token ist one-shot. Wer das Cert verloren
    hat, lässt sich vom Admin einen neuen Token + neuen Tap-Eintrag
    geben.

    `master_url` ist die HTTPS-Basis-URL der Master-API – NICHT die WSS-
    Uplink-URL. Wir hängen `/api/taps/pair` an. Beispiel:
        https://192.168.1.230:8001
    """
    cert_dir = Path("/etc/cyjan")
    if (cert_dir / "tap.pem").exists():
        raise HTTPException(409, "Tap ist bereits gepairt – cert existiert. Reset zuerst.")

    cert_dir.mkdir(parents=True, exist_ok=True)

    # 1) Lokal Key + CSR erzeugen. Subject CN wird vom Master überschrieben
    #    (er setzt CN=tap:<uuid>) – der CSR-CN dient nur als Audit-Trail.
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "cyjan-remote-tap"),
        ]))
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    # 2) An Master posten. verify=False ist hier bewusst der Default: ohne
    #    Master-CA-PEM (die wir GERADE erst beim Pairing bekommen) hat der
    #    Tap kein Trust-Anchor für eine richtige Cert-Validierung. Der Token
    #    selbst ist die Authentifizierung des Calls; eine MITM-Attacke
    #    bekäme zwar das Token, aber der Master bekommt sofort die CSR
    #    und legt einen Tap an – der echte Tap würde beim eigenen Pair-
    #    Versuch ein 'Token bereits verwendet'-409 sehen und Alarm schlagen.
    #
    # Fallback-Logik: Wenn die übergebene URL https:// ist und der Master
    # in Wirklichkeit HTTP serviert (typisches LAN-Setup ohne TLS), kommt
    # ein TLS-Handshake-Error. Wir versuchen dann automatisch http://.
    base = body.master_url.rstrip("/")
    candidates = [base]
    if base.startswith("https://"):
        candidates.append("http://" + base[len("https://"):])

    last_exc: Exception | None = None
    resp = None
    for cand in candidates:
        url = cand + "/api/taps/pair"
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=body.verify_ssl) as client:
                resp = await client.post(url, json={"token": body.token, "csr_pem": csr_pem})
            break
        except httpx.HTTPError as exc:
            last_exc = exc
            log.warning("Master-Pair-Call gegen %s fehlgeschlagen: %s", cand, exc)
            continue
    if resp is None:
        raise HTTPException(502, f"Master nicht erreichbar (alle Schemes): {last_exc}")
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, f"Master abgewiesen: {resp.text[:200]}")
    data = resp.json()

    # 3) Persistieren – Key zuerst (am wichtigsten zu schützen).
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    (cert_dir / "tap.key").write_bytes(key_pem)
    os.chmod(cert_dir / "tap.key", 0o600)
    (cert_dir / "tap.pem").write_text(data["cert_pem"])
    os.chmod(cert_dir / "tap.pem", 0o644)
    (cert_dir / "master-ca.pem").write_text(data["master_ca_pem"])
    os.chmod(cert_dir / "master-ca.pem", 0o644)

    log.warning("Tap gepairt: tap_id=%s", data.get("tap_id"))
    return JSONResponse({
        "paired": True,
        "tap_id": data.get("tap_id"),
        "cert_expires_at": data.get("expires_at"),
        "next_step": "tap-uplink-Container neu starten, damit das neue Cert gelesen wird",
    })


# ── Auto-Pair (token-frei, Admin-bestätigt am Master) ────────────────────────
#
# Workflow:
#   1) /api/auto-pair-start: generiert lokal Key+CSR, postet /api/taps/announce
#      am Master. Persistiert State (Key + master_url + fingerprint + pending_id)
#      in /var/lib/cyjan/auto-pair-state.json. Returnt status='pending'.
#   2) /api/auto-pair-status: pollt Master /api/taps/announce-status. Bei
#      'approved' wird das Cert + CA wie beim normalen Pairing in /etc/cyjan
#      geschrieben, der State-File gelöscht und tap-uplink neu gestartet.
#   3) Bei 'rejected' wird der State-File auch gelöscht (Operator muss neu
#      anstoßen).

_AUTO_PAIR_STATE = Path("/var/lib/cyjan/auto-pair-state.json")


def _hardware_id() -> str:
    """Stabile Tap-Identität. /etc/machine-id ist unter systemd ein 32-Zeichen-
    Hex und überlebt Reboots, ändert sich aber bei OS-Reinstall — was sinnvoll
    ist (frische OS = Admin soll bewusst neu approven)."""
    try:
        return Path("/etc/machine-id").read_text().strip()
    except OSError:
        # Fallback für Container-Lab ohne /etc/machine-id.
        import socket, hashlib
        return hashlib.sha256(socket.gethostname().encode()).hexdigest()[:32]


def _csr_fingerprint(csr_pem: str) -> str:
    """SHA256 des CSR-public-keys — identisch zur Master-Berechnung."""
    csr_obj = x509.load_pem_x509_csr(csr_pem.encode())
    pub = csr_obj.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    import hashlib
    return hashlib.sha256(pub).hexdigest()


class AutoPairStartBody(BaseModel):
    master_url: str = Field(min_length=1)
    name:       str | None = Field(default=None, max_length=80)
    verify_ssl: bool = Field(default=False)


@app.post("/api/auto-pair-start")
async def api_auto_pair_start(body: AutoPairStartBody) -> JSONResponse:
    """Lokal Key+CSR erzeugen, Master /api/taps/announce rufen, State
    persistieren. Idempotent: wenn der State-File schon existiert (Re-Run),
    wird das vorhandene Material wiederverwendet — der Master macht selbst
    UPSERT auf hardware_id+fingerprint."""
    cert_dir = Path("/etc/cyjan")
    if (cert_dir / "tap.pem").exists():
        raise HTTPException(409, "Tap ist bereits gepairt – cert existiert. Reset zuerst.")

    _AUTO_PAIR_STATE.parent.mkdir(parents=True, exist_ok=True)

    # State wiederverwenden wenn vorhanden — sonst neuen Key+CSR generieren.
    if _AUTO_PAIR_STATE.exists():
        try:
            state = json.loads(_AUTO_PAIR_STATE.read_text())
        except Exception:
            state = {}
    else:
        state = {}

    if not state.get("key_pem") or not state.get("csr_pem"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "cyjan-remote-tap"),
            ]))
            .sign(private_key=key, algorithm=hashes.SHA256())
        )
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        state["key_pem"] = key_pem
        state["csr_pem"] = csr_pem

    fingerprint = _csr_fingerprint(state["csr_pem"])
    hardware_id = _hardware_id()
    name = body.name or os.uname().nodename or "cyjan-tap"

    # Announce am Master. Wie beim Token-Pair: erst https, fallback http.
    base = body.master_url.rstrip("/")
    candidates = [base]
    if base.startswith("https://"):
        candidates.append("http://" + base[len("https://"):])

    payload = {
        "name":        name,
        "hardware_id": hardware_id,
        "csr_pem":     state["csr_pem"],
        "hostname":    os.uname().nodename,
        "version":     os.environ.get("CYJAN_VERSION", "unknown"),
    }
    last_exc: Exception | None = None
    resp = None
    for cand in candidates:
        url = cand + "/api/taps/announce"
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=body.verify_ssl) as client:
                resp = await client.post(url, json=payload)
            base = cand  # erfolgreiche URL für Polling cachen
            break
        except httpx.HTTPError as exc:
            last_exc = exc
            log.warning("Master-Announce gegen %s fehlgeschlagen: %s", cand, exc)
            continue
    if resp is None:
        raise HTTPException(502, f"Master nicht erreichbar: {last_exc}")
    if resp.status_code not in (200, 201):
        raise HTTPException(resp.status_code, f"Master abgewiesen: {resp.text[:200]}")
    data = resp.json()

    # State persistieren
    state["master_url"]  = base
    state["hardware_id"] = hardware_id
    state["fingerprint"] = fingerprint
    state["pending_id"]  = data.get("pending_id")
    state["name"]        = name
    state["verify_ssl"]  = body.verify_ssl
    _AUTO_PAIR_STATE.write_text(json.dumps(state))
    os.chmod(_AUTO_PAIR_STATE, 0o600)

    return JSONResponse({
        "status":     data.get("status", "pending"),
        "pending_id": data.get("pending_id"),
        "message":    data.get("message"),
        "next_step":  "GET /api/auto-pair-status alle 5–30 s pollen bis status=approved.",
    })


async def _check_auto_pair_status() -> dict:
    """Single-Shot: pollt Master einmal und installiert Cert bei approval.

    Wird sowohl vom GET-Endpoint /api/auto-pair-status als auch vom
    Background-Poller (Lifecycle-Hook unten) aufgerufen — Logic ist
    identisch, Result wird einmalig zentral berechnet.

    Return-Form (raised exceptions kommen aus dem httpx-Layer):
      {"status": "no-pending"|"pending"|"approved"|"rejected"|"unknown",
       "message": "...", "tap_id": "...", ...}
    """
    if not _AUTO_PAIR_STATE.exists():
        return {"status": "no-pending", "message": "Kein laufendes Auto-Pair."}
    try:
        state = json.loads(_AUTO_PAIR_STATE.read_text())
    except Exception as exc:
        raise HTTPException(500, f"State-File defekt: {exc}")

    base = state["master_url"]
    hwid = state["hardware_id"]
    fp   = state["fingerprint"]
    url  = f"{base}/api/taps/announce-status/{hwid}/{fp}"

    try:
        async with httpx.AsyncClient(timeout=15.0, verify=state.get("verify_ssl", False)) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Master nicht erreichbar: {exc}")
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, f"Master-Status: {resp.text[:200]}")
    data = resp.json()
    status = data.get("status", "unknown")

    if status == "approved":
        cert_dir = Path("/etc/cyjan")
        cert_dir.mkdir(parents=True, exist_ok=True)
        (cert_dir / "tap.key").write_text(state["key_pem"])
        os.chmod(cert_dir / "tap.key", 0o600)
        (cert_dir / "tap.pem").write_text(data["cert_pem"])
        os.chmod(cert_dir / "tap.pem", 0o644)
        (cert_dir / "master-ca.pem").write_text(data["master_ca_pem"])
        os.chmod(cert_dir / "master-ca.pem", 0o644)
        # State-File aufräumen — fertig gepairt.
        _AUTO_PAIR_STATE.unlink(missing_ok=True)
        log.warning("Tap auto-pair APPROVED: tap_id=%s", data.get("tap_id"))
        return {
            "status":          "approved",
            "tap_id":          data.get("tap_id"),
            "cert_expires_at": data.get("expires_at"),
            "next_step":       "tap-uplink picked up cert beim nächsten retry-tick (5s)",
        }

    if status == "rejected":
        _AUTO_PAIR_STATE.unlink(missing_ok=True)
        log.warning("Tap auto-pair REJECTED")
        return {"status": "rejected", "message": data.get("message")}

    return {"status": status, "message": data.get("message")}


@app.get("/api/auto-pair-status")
async def api_auto_pair_status() -> JSONResponse:
    """Pollt Master und installiert das Cert wenn approved.

    Identisch zum Background-Poller — manuelle CLI-Trigger bleibt aber
    zusätzlich verfügbar (cyjan-tap auto-pair pollt diesen Endpoint)."""
    return JSONResponse(await _check_auto_pair_status())


async def _auto_pair_poller_loop() -> None:
    """Background-Task: pollt periodisch /api/auto-pair-status, solange ein
    State-File existiert UND noch kein Cert auf Disk ist.

    Vorher hat der ids-setup-Wizard nur /api/auto-pair-start aufgerufen
    (= Announce am Master) — die Folge-Phase 'pollen bis approved' fehlte
    komplett, weshalb tap-uplink endlos im 'starting'-State hing.

    Stoppt sich selbst nicht — läuft solange tap-api läuft, wacht regelmäßig
    auf, no-ops bei nichts zu tun. Default-Cadence 30s; bei reachability-
    Errors wird einfach beim nächsten Tick erneut probiert."""
    cert_path = Path("/etc/cyjan/tap.pem")
    interval = float(os.environ.get("AUTO_PAIR_POLL_INTERVAL_S", "30"))
    log.info("Auto-Pair-Poller gestartet (interval=%.0fs)", interval)
    while True:
        try:
            if _AUTO_PAIR_STATE.exists() and not cert_path.exists():
                result = await _check_auto_pair_status()
                status = result.get("status")
                if status == "approved":
                    log.info("Auto-Pair-Poller: Cert installiert, tap-uplink picked it up")
                elif status == "rejected":
                    log.warning("Auto-Pair-Poller: Master hat REJECTED — State gelöscht")
                # bei 'pending' oder 'unknown' einfach beim nächsten Tick erneut
        except HTTPException as exc:
            # 502 (Master nicht erreichbar) ist Normalbetrieb für Air-Gap-
            # Phasen — nur debug loggen, kein WARNING-Spam.
            log.debug("Auto-Pair-Poll-Fehler: %s", exc.detail)
        except Exception as exc:                                 # noqa: BLE001
            log.warning("Auto-Pair-Poll-Tick fehlgeschlagen: %s", exc)
        await asyncio.sleep(interval)


@app.on_event("startup")
async def _startup_hooks() -> None:
    """Hängt Background-Tasks auf — läuft genau einmal beim ASGI-Boot."""
    asyncio.create_task(_auto_pair_poller_loop())


@app.post("/api/test-alert")
async def api_test_alert() -> JSONResponse:
    """Erzeugt einen synthetischen Alert und schiebt ihn in das lokale
    Kafka. Der tap-uplink nimmt ihn auf, schickt ihn an den Master, und
    dort sollte er sichtbar werden mit `tap_id=<id>` und tags=['tap-test']."""
    alert = {
        "alert_id":   str(uuid.uuid4()),
        "rule_id":    "TAP_TEST_001",
        "source":     "signature",
        "severity":   "low",
        "description": "Synthetischer Test-Alert vom Remote-Tap",
        "src_ip":     "192.0.2.1",
        "dst_ip":     "192.0.2.2",
        "dst_port":   12345,
        "proto":      "TCP",
        "score":      0.10,
        "ts":         time.time(),
        "tags":       ["tap-test", "synthetic"],
        "is_test":    True,
    }
    p = _producer_get()
    p.produce(ALERTS_TOPIC, value=json.dumps(alert).encode())
    p.poll(0)
    p.flush(timeout=2)
    log.info("Test-Alert erzeugt: %s", alert["alert_id"])
    return JSONResponse({"sent": True, "alert_id": alert["alert_id"]})
