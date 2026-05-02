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

import json
import logging
import os
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


# ── Maschinen-Endpunkte (für CLI) ─────────────────────────────────────────────


@app.get("/api/state")
async def api_state() -> JSONResponse:
    return JSONResponse(_read_state())


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


@app.get("/api/auto-pair-status")
async def api_auto_pair_status() -> JSONResponse:
    """Pollt Master und installiert das Cert wenn approved."""
    if not _AUTO_PAIR_STATE.exists():
        return JSONResponse({"status": "no-pending", "message": "Kein laufendes Auto-Pair."})
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
        return JSONResponse({
            "status":          "approved",
            "tap_id":          data.get("tap_id"),
            "cert_expires_at": data.get("expires_at"),
            "next_step":       "tap-uplink-Container neu starten",
        })

    if status == "rejected":
        _AUTO_PAIR_STATE.unlink(missing_ok=True)
        log.warning("Tap auto-pair REJECTED")
        return JSONResponse({"status": "rejected", "message": data.get("message")})

    return JSONResponse({"status": status, "message": data.get("message")})


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
