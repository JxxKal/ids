"""
irma-bridge
===========
Pollt die IRMA IDS REST-API und publiziert neue Alarme normalisiert
nach Kafka → alerts-raw, wo der alert-manager sie weiterverarbeitet.

IRMA-Token läuft nach 2 Minuten ab → proaktive Erneuerung alle 90 s.
Letzter bekannter Alarm-ID wird in LAST_ID_FILE persistiert, damit
bei einem Neustart keine doppelten Alarme entstehen.

Umgebungsvariablen:
  IRMA_BASE_URL        REST-Basis-URL       (Standard: https://10.133.168.115/rest)
  IRMA_USER            Benutzername
  IRMA_PASS            Passwort
  IRMA_POLL_INTERVAL   Sekunden zwischen Abfragen  (Standard: 30)
  IRMA_SSL_VERIFY      true/false – SSL-Zertifikat prüfen (Standard: false)
  KAFKA_BROKERS        Bootstrap-Server     (Standard: kafka:9092)
  LOG_LEVEL            DEBUG/INFO/WARNING   (Standard: INFO)
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from datetime import timezone
from pathlib import Path

import requests
import urllib3
from confluent_kafka import Producer

# ── Konfiguration ─────────────────────────────────────────────────────────────

IRMA_BASE      = os.getenv("IRMA_BASE_URL",      "https://10.133.168.115/rest").rstrip("/")
IRMA_USER      = os.getenv("IRMA_USER",          "")
IRMA_PASS      = os.getenv("IRMA_PASS",          "")
POLL_INTERVAL  = int(os.getenv("IRMA_POLL_INTERVAL", "30"))
SSL_VERIFY     = os.getenv("IRMA_SSL_VERIFY", "false").lower() == "true"
KAFKA_BROKERS  = os.getenv("KAFKA_BROKERS",     "kafka:9092")
OUTPUT_TOPIC   = "alerts-raw"
LAST_ID_FILE   = Path("/data/irma_last_id")
TOKEN_TTL_S    = 90   # IRMA-Token läuft nach 120 s ab → 90 s Sicherheitsabstand

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s %(levelname)-8s [irma-bridge] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("irma-bridge")

if not SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Kafka ─────────────────────────────────────────────────────────────────────

def _delivery_cb(err, msg):
    if err:
        log.error("Kafka delivery error: %s", err)

producer = Producer({
    "bootstrap.servers": KAFKA_BROKERS,
    "acks": "1",
})

# ── IRMA Auth ─────────────────────────────────────────────────────────────────

class IrmaClient:
    def __init__(self) -> None:
        self._session   = requests.Session()
        self._token_ts  = 0.0

    def _login(self) -> None:
        log.info("IRMA: Anmeldung als '%s'", IRMA_USER)
        resp = self._session.post(
            f"{IRMA_BASE}/login",
            json={"user": IRMA_USER, "pass": IRMA_PASS},
            verify=SSL_VERIFY,
            timeout=15,
        )
        resp.raise_for_status()
        token = resp.json()["token"]
        self._session.headers.update({"Authorization": f"Bearer {token}"})
        self._token_ts = time.time()
        log.info("IRMA: Token erhalten")

    def _ensure_token(self) -> None:
        if time.time() - self._token_ts >= TOKEN_TTL_S:
            self._login()

    def get_alarms_after(self, last_id: int) -> list[dict]:
        self._ensure_token()
        resp = self._session.get(
            f"{IRMA_BASE}/alarm",
            params={"after": last_id},
            verify=SSL_VERIFY,
            timeout=20,
        )
        if resp.status_code == 401:
            # Token abgelaufen → neu anmelden
            self._token_ts = 0
            self._ensure_token()
            resp = self._session.get(
                f"{IRMA_BASE}/alarm",
                params={"after": last_id},
                verify=SSL_VERIFY,
                timeout=20,
            )
        resp.raise_for_status()
        return resp.json().get("alarms") or []

# ── ID-Persistenz ─────────────────────────────────────────────────────────────

def load_last_id() -> int:
    try:
        return int(LAST_ID_FILE.read_text().strip())
    except Exception:
        return 0

def save_last_id(last_id: int) -> None:
    LAST_ID_FILE.parent.mkdir(parents=True, exist_ok=True)
    LAST_ID_FILE.write_text(str(last_id))

# ── Alarm-Mapping ─────────────────────────────────────────────────────────────

def _map_severity(alarm: dict) -> str:
    """IRMA liefert keine Severity – grobe Heuristik über das Protokoll."""
    proto = (alarm.get("proto") or "").upper()
    note  = (alarm.get("note")  or "").lower()
    if any(k in note for k in ("exploit", "attack", "malware", "ransomware", "backdoor")):
        return "high"
    if any(k in note for k in ("scan", "brute", "flood", "dos", "inject")):
        return "medium"
    if proto in ("MODBUS", "DNP3", "ENIP", "BACNET", "S7"):
        return "high"   # OT-Protokolle immer high
    return "medium"

def map_alarm(alarm: dict) -> dict:
    proto = alarm.get("proto") or ""
    tags  = ["irma", "external"]
    if proto.upper() in ("MODBUS", "DNP3", "ENIP", "BACNET", "S7"):
        tags.append("ot")
    return {
        "alert_id":    str(uuid.uuid4()),
        "ts":          alarm.get("createTimestamp"),
        "source":      "external",
        "rule_id":     alarm.get("note") or "IRMA-ALARM",
        "severity":    _map_severity(alarm),
        "score":       0.5,
        "src_ip":      alarm.get("srcIp"),
        "dst_ip":      alarm.get("dstIp"),
        "dst_port":    alarm.get("port"),
        "proto":       proto or None,
        "description": alarm.get("msg"),
        "tags":        tags,
        "is_test":     False,
    }

# ── Haupt-Schleife ────────────────────────────────────────────────────────────

def run() -> None:
    import orjson

    if not IRMA_USER or not IRMA_PASS:
        log.error("IRMA_USER / IRMA_PASS nicht gesetzt – Bridge inaktiv")
        while True:
            time.sleep(60)

    client  = IrmaClient()
    last_id = load_last_id()
    log.info("Start – letzte IRMA-ID: %d, Poll-Intervall: %ds", last_id, POLL_INTERVAL)

    while True:
        try:
            alarms = client.get_alarms_after(last_id)
            if alarms:
                log.info("IRMA: %d neue Alarme (after=%d)", len(alarms), last_id)
                new_max = last_id
                for alarm in alarms:
                    alert = map_alarm(alarm)
                    producer.produce(
                        OUTPUT_TOPIC,
                        key=(alert.get("src_ip") or "").encode(),
                        value=orjson.dumps(alert),
                        callback=_delivery_cb,
                    )
                    producer.poll(0)
                    irma_id = alarm.get("id") or 0
                    if irma_id > new_max:
                        new_max = irma_id
                    log.debug(
                        "[%s] %s | %s → %s | severity=%s",
                        str(alarm.get("id")),
                        alert.get("rule_id"),
                        alert.get("src_ip", "-"),
                        alert.get("dst_ip", "-"),
                        alert.get("severity"),
                    )
                producer.flush(timeout=5)
                save_last_id(new_max)
                last_id = new_max
            else:
                log.debug("IRMA: keine neuen Alarme (after=%d)", last_id)

        except requests.exceptions.ConnectionError as exc:
            log.warning("IRMA nicht erreichbar: %s", exc)
        except requests.exceptions.HTTPError as exc:
            log.error("IRMA HTTP-Fehler: %s", exc)
        except Exception as exc:
            log.exception("Unerwarteter Fehler: %s", exc)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
