"""
snort-bridge
============
Liest Snort 3 alert_json Ausgabe (eine JSON-Zeile pro Alert) aus der
gemeinsamen Log-Datei und publiziert normalisierte Alerts nach Kafka
ins Topic alerts-raw.

Umgebungsvariablen:
  KAFKA_BROKERS      Kafka Bootstrap-Server   (Standard: kafka:9092)
  SNORT_ALERT_FILE   Pfad zur alert_json.txt  (Standard: /var/log/snort/alert_json.txt)
  TEST_MODE          true → is_test=true       (Standard: false)
  LOG_LEVEL          DEBUG/INFO/WARNING        (Standard: INFO)
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
ALERT_FILE    = os.getenv("SNORT_ALERT_FILE", "/var/log/snort/alert_json.txt")
TEST_MODE     = os.getenv("TEST_MODE", "false").lower() == "true"

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [snort-bridge] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Priorität → Severity + Score ──────────────────────────────────────────────

_PRIORITY: dict[int, tuple[str, float]] = {
    1: ("critical", 0.95),
    2: ("high",     0.80),
    3: ("medium",   0.55),
}


def _parse_ts(ts: str) -> float:
    """Snort-Timestamp 'MM/DD-HH:MM:SS.ffffff' → Unix-Float."""
    try:
        year = datetime.now(timezone.utc).year
        dt = datetime.strptime(f"{year}/{ts}", "%Y/%m/%d-%H:%M:%S.%f")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return time.time()


def _map_alert(rec: dict) -> dict:
    """Snort JSON-Record → alerts-raw Event."""
    priority         = int(rec.get("priority", 3))
    severity, score  = _PRIORITY.get(priority, ("low", 0.30))

    rule_raw = rec.get("rule", "")           # z.B. "1:2001219:20"
    rule_id  = f"SNORT:{rule_raw}" if rule_raw else "SNORT:unknown"

    # Klassifikation als Tag übernehmen (Snort 3 JSON-Key: 'class')
    cls  = rec.get("class") or rec.get("class_") or ""
    tags = ["snort"] + ([cls.strip().lower()] if cls.strip() else [])

    dst_port_raw = rec.get("dst_port")
    dst_port = int(dst_port_raw) if dst_port_raw is not None else None
    if dst_port == 0:
        dst_port = None

    return {
        "alert_id":    str(uuid.uuid4()),
        "rule_id":     rule_id,
        "source":      "snort",
        "severity":    severity,
        "description": rec.get("msg", ""),
        "src_ip":      rec.get("src_addr"),
        "dst_ip":      rec.get("dst_addr"),
        "dst_port":    dst_port,
        "proto":       (rec.get("proto") or "").upper() or None,
        "score":       score,
        "ts":          _parse_ts(rec.get("timestamp", "")),
        "tags":        tags,
        "is_test":     TEST_MODE,
    }


# ── Tail-Generator ────────────────────────────────────────────────────────────

def _tail(path: str):
    """Liefert neue Zeilen aus einer wachsenden Datei (tail -f Semantik).
    Erkennt auch Datei-Truncation (Snort-Neustart)."""
    while not os.path.exists(path):
        log.info("Warte auf Alert-Datei %s …", path)
        time.sleep(2)

    with open(path, "r") as fh:
        fh.seek(0, 2)   # vorhandenen Inhalt überspringen
        log.info("Lese Alerts aus %s", path)
        while True:
            line = fh.readline()
            if line:
                yield line.strip()
            else:
                # Truncation erkennen (Datei kleiner als aktuelle Position)
                try:
                    if fh.tell() > os.path.getsize(path):
                        log.warning("Alert-Datei wurde gekürzt – starte von vorne")
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
    log.info("Snort-Bridge gestartet  →  %s @ %s", ALERTS_TOPIC, KAFKA_BROKERS)
    log.info("is_test=%s", TEST_MODE)

    for line in _tail(ALERT_FILE):
        if not line:
            continue
        try:
            rec   = json.loads(line)
            alert = _map_alert(rec)
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
