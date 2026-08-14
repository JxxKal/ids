"""Alert-Feld-Whitelist (protocol.md §4).

Gegenstück zu `master-uplink._ALERT_ALLOWED_FIELDS`, nur in der anderen
Richtung: dort begrenzt die Whitelist, was ein Tap in den Master schieben
darf; hier begrenzt sie, was das OT-Netz überhaupt verlässt.

Bewusst NICHT durchgereicht:
  metric_values  — Tuner-Interna, für die App wertlos
  flow_id        — interner Join-Key
  enrichment     — kann Geo/rDNS/Kundennamen enthalten
  feedback_note  — Freitext eines Operators

Wer die Details braucht, holt sie per RPC. Dann ist es eine bewusste
Abfrage und kein automatischer Abfluss.
"""
from __future__ import annotations

from config import SEVERITY_RANK

_EVENT_ALERT_FIELDS: frozenset[str] = frozenset({
    "alert_id", "ts", "severity", "source", "rule_id", "rule_name",
    "src_ip", "dst_ip", "src_port", "dst_port", "proto",
    "description", "tags", "score", "is_test", "tap_id",
})


def sanitize_alert(alert: dict) -> dict:
    """Reduziert einen Kafka-Alert auf die Whitelist. Unbekannte Felder
    fallen still raus (kein Logging pro Alert — das wäre bei Alert-Stürmen
    ein Log-Flood); die Whitelist ist statisch, ein neues Feld in der
    Pipeline ist kein Fehlerfall."""
    return {k: alert[k] for k in _EVENT_ALERT_FIELDS if k in alert}


def severity_at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_RANK.get((severity or "low").lower(), 0) >= SEVERITY_RANK.get(
        (minimum or "low").lower(), 0
    )
