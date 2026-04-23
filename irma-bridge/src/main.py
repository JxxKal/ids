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

import json
import logging
import os
import time
import uuid
from datetime import timezone
from pathlib import Path

import psycopg2
import requests
import urllib3
from confluent_kafka import Producer

# ── Konfiguration (Env = Fallback, DB überschreibt) ───────────────────────────

ENV_BASE       = os.getenv("IRMA_BASE_URL",      "https://10.133.168.115/rest").rstrip("/")
ENV_USER       = os.getenv("IRMA_USER",          "")
ENV_PASS       = os.getenv("IRMA_PASS",          "")
ENV_POLL       = int(os.getenv("IRMA_POLL_INTERVAL", "30"))
ENV_SSL_VERIFY = os.getenv("IRMA_SSL_VERIFY", "false").lower() == "true"
POSTGRES_DSN   = os.getenv("POSTGRES_DSN", "")
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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Config-Loader (system_config.irma aus DB, Fallback auf env) ───────────────

def load_config() -> dict:
    """
    Lädt die IRMA-Config aus system_config.irma. Wenn nicht gesetzt oder
    die DB nicht erreichbar ist, fällt auf die Env-Variablen zurück.
    Rückgabe: {enabled, base_url, user, password, poll_interval, ssl_verify}
    """
    cfg = {
        "enabled":       bool(ENV_USER and ENV_PASS),
        "base_url":      ENV_BASE,
        "user":          ENV_USER,
        "password":      ENV_PASS,
        "poll_interval": ENV_POLL,
        "ssl_verify":    ENV_SSL_VERIFY,
    }
    if not POSTGRES_DSN:
        return cfg
    try:
        conn = psycopg2.connect(POSTGRES_DSN, connect_timeout=5)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT value FROM system_config WHERE key = 'irma'")
                row = cur.fetchone()
        finally:
            conn.close()
    except Exception as exc:
        log.warning("DB-Config nicht lesbar (%s) – nutze Env-Fallback", exc)
        return cfg
    if not row:
        return cfg
    val = row[0] if isinstance(row[0], dict) else json.loads(row[0])
    if val.get("enabled") is not None:       cfg["enabled"]       = bool(val["enabled"])
    if val.get("base_url"):                  cfg["base_url"]      = val["base_url"].rstrip("/")
    if val.get("user"):                      cfg["user"]          = val["user"]
    if val.get("password"):                  cfg["password"]      = val["password"]
    if val.get("poll_interval"):             cfg["poll_interval"] = int(val["poll_interval"])
    if val.get("ssl_verify") is not None:    cfg["ssl_verify"]    = bool(val["ssl_verify"])
    return cfg

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
    def __init__(self, base_url: str, user: str, password: str, ssl_verify: bool) -> None:
        self._base       = base_url.rstrip("/")
        self._user       = user
        self._password   = password
        self._ssl_verify = ssl_verify
        self._session    = requests.Session()
        self._token_ts   = 0.0

    def _login(self) -> None:
        log.info("IRMA: Anmeldung an %s als '%s'", self._base, self._user)
        resp = self._session.post(
            f"{self._base}/login",
            json={"user": self._user, "pass": self._password},
            verify=self._ssl_verify,
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
            f"{self._base}/alarm",
            params={"after": last_id},
            verify=self._ssl_verify,
            timeout=20,
        )
        if resp.status_code == 401:
            # Token abgelaufen → neu anmelden
            self._token_ts = 0
            self._ensure_token()
            resp = self._session.get(
                f"{self._base}/alarm",
                params={"after": last_id},
                verify=self._ssl_verify,
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

def _config_sig(cfg: dict) -> tuple:
    """Signatur-Tuple, um Config-Änderungen zu erkennen."""
    return (cfg["base_url"], cfg["user"], cfg["password"], cfg["ssl_verify"], cfg["enabled"])


def run() -> None:
    import orjson

    cfg     = load_config()
    client  = None
    last_id = load_last_id()
    log.info("Start – letzte IRMA-ID: %d", last_id)

    while True:
        # Config-Refresh: jede Iteration frisch aus DB laden, bei Änderung
        # Client neu bauen (Token wird verworfen).
        new_cfg = load_config()
        if client is None or _config_sig(new_cfg) != _config_sig(cfg):
            cfg = new_cfg
            if cfg["enabled"] and cfg["user"] and cfg["password"]:
                log.info("IRMA-Config (neu/geändert) aktiv: %s @ %s", cfg["user"], cfg["base_url"])
                client = IrmaClient(cfg["base_url"], cfg["user"], cfg["password"], cfg["ssl_verify"])
            else:
                if client is not None:
                    log.info("IRMA deaktiviert oder Credentials leer – Bridge idle")
                client = None

        if client is None:
            time.sleep(max(10, cfg["poll_interval"]))
            continue

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

        time.sleep(cfg["poll_interval"])


if __name__ == "__main__":
    run()
