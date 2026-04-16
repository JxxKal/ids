"""
suricata-bridge  (läuft im Container ids-snort-bridge)
=======================================================
Liest Suricata EVE JSON (eine Zeile pro Event) aus dem Shared-Volume
und publiziert Alert-Events normalisiert nach Kafka → alerts-raw.

Suricata EVE JSON Alert-Struktur:
  {
    "timestamp": "2024-01-01T12:00:00.000000+0000",
    "event_type": "alert",
    "src_ip": "1.2.3.4",  "src_port": 12345,
    "dest_ip": "5.6.7.8", "dest_port": 80,
    "proto": "TCP",
    "alert": {
      "severity": 1,          # 1=critical … 4=low
      "gid": 1,
      "signature_id": 2001219,
      "rev": 20,
      "signature": "ET SCAN ...",
      "category": "Attempted Information Leak"
    }
  }

Umgebungsvariablen:
  KAFKA_BROKERS      Bootstrap-Server   (Standard: kafka:9092)
  SNORT_ALERT_FILE   Pfad zu eve.json   (Standard: /var/log/suricata/eve.json)
  TEST_MODE          true → is_test=true (Standard: false)
  LOG_LEVEL          DEBUG/INFO/WARNING  (Standard: INFO)
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone

from confluent_kafka import Producer

# ── Konfiguration ─────────────────────────────────────────────────────────────

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "kafka:9092")
ALERTS_TOPIC  = "alerts-raw"
ALERT_FILE    = os.getenv("SNORT_ALERT_FILE", "/var/log/suricata/eve.json")
TEST_MODE     = os.getenv("TEST_MODE", "false").lower() == "true"

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [suricata-bridge] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Suricata Severity (1–4) → IDS Severity + Score ───────────────────────────

_SEVERITY: dict[int, tuple[str, float]] = {
    1: ("critical", 0.95),
    2: ("high",     0.80),
    3: ("medium",   0.55),
    4: ("low",      0.30),
}


def _parse_ts(ts: str) -> float:
    """Suricata ISO-Timestamp → Unix-Float.
    Format: '2024-01-01T12:00:00.000000+0000'
    """
    try:
        # Python 3.11+ versteht +0000; älter braucht manuelles Parsen
        ts_clean = ts.replace("+0000", "+00:00")
        return datetime.fromisoformat(ts_clean).timestamp()
    except Exception:
        return time.time()


def _map_alert(rec: dict) -> dict | None:
    """Suricata EVE JSON → alerts-raw Event. Gibt None zurück für Non-Alert-Events."""
    if rec.get("event_type") not in ("alert", "drop"):
        return None

    alert_obj = rec.get("alert", {})
    severity_num    = int(alert_obj.get("severity", 3))
    severity, score = _SEVERITY.get(severity_num, ("medium", 0.55))

    gid = alert_obj.get("gid", 1)
    sid = alert_obj.get("signature_id", 0)
    rev = alert_obj.get("rev", 0)
    rule_id = f"SURICATA:{gid}:{sid}:{rev}"

    cat  = alert_obj.get("category", "")
    tags = ["suricata"] + ([cat.lower()] if cat else [])

    dst_port_raw = rec.get("dest_port")
    dst_port = int(dst_port_raw) if dst_port_raw else None

    return {
        "alert_id":    str(uuid.uuid4()),
        "rule_id":     rule_id,
        "source":      "suricata",
        "severity":    severity,
        "description": alert_obj.get("signature", ""),
        "src_ip":      rec.get("src_ip"),
        "dst_ip":      rec.get("dest_ip"),
        "dst_port":    dst_port,
        "proto":       (rec.get("proto") or "").upper() or None,
        "score":       score,
        "ts":          _parse_ts(rec.get("timestamp", "")),
        "tags":        tags,
        "is_test":     TEST_MODE,
    }


# ── Tail-Generator ────────────────────────────────────────────────────────────

def _tail(path: str):
    """Liefert neue Zeilen aus einer wachsenden Datei.
    Erkennt Datei-Truncation (Suricata-Neustart / Log-Rotation)."""
    while not os.path.exists(path):
        log.info("Warte auf EVE-Log %s …", path)
        time.sleep(2)

    with open(path, "r") as fh:
        fh.seek(0, 2)   # bestehenden Inhalt überspringen
        log.info("Lese Events aus %s", path)
        while True:
            line = fh.readline()
            if line:
                yield line.strip()
            else:
                try:
                    if fh.tell() > os.path.getsize(path):
                        log.warning("EVE-Log wurde gekürzt – starte von vorne")
                        fh.seek(0)
                except OSError:
                    pass
                time.sleep(0.05)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    producer = Producer({
        "bootstrap.servers": KAFKA_BROKERS,
        "linger.ms": 20,
    })
    log.info("Suricata-Bridge gestartet  →  %s @ %s", ALERTS_TOPIC, KAFKA_BROKERS)

    for line in _tail(ALERT_FILE):
        if not line:
            continue
        try:
            rec   = json.loads(line)
            alert = _map_alert(rec)
            if alert is None:
                continue
            producer.produce(
                ALERTS_TOPIC,
                json.dumps(alert, default=str).encode(),
            )
            producer.poll(0)
            log.info(
                "Alert  %s  %s → %s:%s  [%s]",
                alert["rule_id"],
                alert["src_ip"],
                alert["dst_ip"],
                alert["dst_port"],
                alert["severity"],
            )
        except json.JSONDecodeError:
            log.warning("Ungültiges JSON übersprungen: %.120s", line)
        except Exception as exc:
            log.error("Verarbeitungsfehler: %s", exc)


if __name__ == "__main__":
    main()
