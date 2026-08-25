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

import time
from datetime import datetime, timezone

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


def is_stale(ts: object, max_age_s: int) -> bool:
    """True, wenn der Zeitstempel älter als `max_age_s` Sekunden ist.

    Versteht beide Formen, die auf `alerts-enriched` vorkommen: Unix-Sekunden
    (Float/Int, so produziert es die snort-bridge) und ISO 8601 (so
    produzieren es alert-manager und der Retention-Monitor der API). Naive
    ISO-Zeiten gelten als UTC — das ist die Konvention der Pipeline.

    Unlesbares oder fehlendes gilt als FRISCH, nicht als alt: der Wächter
    soll Rückstand aussortieren, nicht bei einem Formatwechsel in der
    Pipeline stillschweigend alle Benachrichtigungen abdrehen. Fail-open ist
    hier die sichere Richtung — das Gegenteil wäre ein stummer Alarmkanal.
    """
    try:
        if isinstance(ts, (int, float)):
            event_s = float(ts)
        elif isinstance(ts, str) and ts:
            parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            event_s = parsed.timestamp()
        else:
            return False
        return (time.time() - event_s) > max_age_s
    except (ValueError, OverflowError, OSError):
        return False


def severity_at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_RANK.get((severity or "low").lower(), 0) >= SEVERITY_RANK.get(
        (minimum or "low").lower(), 0
    )
