"""Topic-Templating für die MQTT-Bridge.

Schema (Option B aus dem Design-Grilling): nur der Prefix ist konfigurierbar,
alles dahinter ist fest. Das hält Subscriber-Wildcards stabil und vermeidet
Broken-Templates beim Plant-Onboarding.

Schema:
  Events:    {prefix}/{host}/alerts/{severity}/{source}
  Threat:    {prefix}/{host}/threat
  Status:    {prefix}/{host}/status
  Tap-State: {prefix}/{host}/taps/{tap_name}/status

Per-Origin-Identity: {host} ist
  - master_host_id (z.B. "master-81") für Master-eigene Alerts
  - tap.name (z.B. "tap-werk-a") für Tap-Alerts (mqtt-bridge schaut tap_id
    im Frame und resolved zum Tap-Namen aus der DB)

Sanitization: MQTT-Topic-Levels dürfen kein '#', '+', '/' enthalten. Wenn
ein Tap-Name ungewohnt geschrieben ist, escapen wir das auf '_' damit
das Topic gültig bleibt — die HMI-Subscriber-Templates kennen den
Tap-Namen aus der gleichen Sanitization, also passt das stabil.
"""
from __future__ import annotations


_INVALID_TOPIC_CHARS = ("/", "#", "+", "\x00")


def sanitize(level: str) -> str:
    """Macht aus einem freien Identifier (Tap-Name, Hostname) einen
    MQTT-Topic-Level-tauglichen String. Whitespace und MQTT-Wildcards
    werden zu '_'."""
    if not level:
        return "_"
    out = level.strip()
    for ch in _INVALID_TOPIC_CHARS:
        out = out.replace(ch, "_")
    out = out.replace(" ", "_")
    return out or "_"


def event_topic(prefix: str, host: str, severity: str, source: str) -> str:
    return f"{prefix}/{sanitize(host)}/alerts/{sanitize(severity)}/{sanitize(source)}"


def threat_topic(prefix: str, host: str) -> str:
    return f"{prefix}/{sanitize(host)}/threat"


def status_topic(prefix: str, host: str) -> str:
    return f"{prefix}/{sanitize(host)}/status"


def tap_status_topic(prefix: str, host: str, tap_name: str) -> str:
    return f"{prefix}/{sanitize(host)}/taps/{sanitize(tap_name)}/status"
