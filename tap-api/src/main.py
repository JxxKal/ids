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
    url = body.master_url.rstrip("/") + "/api/taps/pair"
    try:
        async with httpx.AsyncClient(timeout=30.0, verify=body.verify_ssl) as client:
            resp = await client.post(url, json={"token": body.token, "csr_pem": csr_pem})
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Master nicht erreichbar: {exc}")
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
