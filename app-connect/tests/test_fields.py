"""Feld-Whitelist (protocol.md §4): was das OT-Netz verlässt, ist
abschließend aufgezählt."""
from fields import _EVENT_ALERT_FIELDS, sanitize_alert, severity_at_least

FULL_ALERT = {
    # erlaubt
    "alert_id": "3f1c9a2e-4b6d-4e7a-9c1f-0a2b3c4d5e6f",
    "ts": "2026-08-14T10:00:00Z",
    "severity": "critical",
    "source": "signature",
    "rule_id": "SCAN_001",
    "rule_name": "Port-Scan",
    "src_ip": "10.0.0.5",
    "dst_ip": "10.0.0.9",
    "src_port": 44321,
    "dst_port": 502,
    "proto": "TCP",
    "description": "Viele Zielports in kurzer Zeit",
    "tags": ["scan"],
    "score": 0.87,
    "is_test": False,
    "tap_id": "b1c2d3e4-0000-4000-8000-000000000000",
    # explizit NICHT erlaubt (§4)
    "metric_values": {"port_count": 51},
    "flow_id": "f00d",
    "enrichment": {"hostname": "plc-halle-3.kunde.local", "geo": "DE"},
    "feedback_note": "Kollege sagt, das war der Scanner vom Audit",
    "feedback": "fp",
    "pcap_key": "alerts/3f1c.pcap",
    "boundary_src_zone": "OT",
}

FORBIDDEN = ["metric_values", "flow_id", "enrichment", "feedback_note",
             "feedback", "pcap_key", "boundary_src_zone"]


def test_whitelist_matches_spec():
    assert _EVENT_ALERT_FIELDS == {
        "alert_id", "ts", "severity", "source", "rule_id", "rule_name",
        "src_ip", "dst_ip", "src_port", "dst_port", "proto",
        "description", "tags", "score", "is_test", "tap_id",
    }


def test_allowed_fields_survive():
    out = sanitize_alert(FULL_ALERT)
    for key in _EVENT_ALERT_FIELDS:
        assert out[key] == FULL_ALERT[key]


def test_forbidden_fields_are_stripped():
    out = sanitize_alert(FULL_ALERT)
    for key in FORBIDDEN:
        assert key not in out, f"{key} darf das OT-Netz nicht verlassen"
    assert set(out) <= _EVENT_ALERT_FIELDS


def test_unknown_future_field_is_dropped():
    """Neue Pipeline-Felder fließen NICHT automatisch ab — die Whitelist
    ist positiv, nicht negativ."""
    out = sanitize_alert({**FULL_ALERT, "brandneues_feld": "geheim"})
    assert "brandneues_feld" not in out


def test_missing_fields_are_not_invented():
    out = sanitize_alert({"alert_id": "x", "severity": "low"})
    assert out == {"alert_id": "x", "severity": "low"}


def test_severity_threshold():
    assert severity_at_least("critical", "high")
    assert severity_at_least("high", "high")
    assert not severity_at_least("medium", "high")
    assert not severity_at_least("low", "medium")
    assert severity_at_least("LOW", "low")
    # Unbekannte Severity zählt als niedrigste Stufe, statt zu crashen.
    assert not severity_at_least("kaputt", "medium")
    assert severity_at_least("kaputt", "low")
