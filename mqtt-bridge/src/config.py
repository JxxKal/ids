"""mqtt-bridge — Konfiguration.

V1.0 (initial bring-up): env-var-only.
V1.1 (jetzt): env-defaults + Hot-Reload aus `system_config['mqtt']`-JSONB.

Settings-UI schreibt nach `system_config[key='mqtt']`. mqtt-bridge pollt
diesen Eintrag alle 30s und baut bei jeder Änderung eine neue effektive
Config (env als Bootstrap, DB-Felder überschreiben pro Feld). Connection-
relevante Felder (broker, tls, identity, prefix) führen zum Reconnect;
filter-only-Änderungen (severity_min, sources, blocklist) wirken sofort
beim nächsten Publish.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

log = logging.getLogger(__name__)


SEVERITY_ORDER = ["low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Welche Felder einen Reconnect des MQTT-Clients triggern, wenn sie sich
# ändern. Alles andere kann live übernommen werden.
CONNECTION_FIELDS = (
    "enabled",
    "broker_host", "broker_port",
    "use_tls", "tls_verify", "server_ca_path",
    "username", "password",
    "client_id",
    "master_host_id",
    "topic_prefix",
)


@dataclass(frozen=True)
class Config:
    enabled: bool

    # Kafka
    kafka_brokers: str
    alerts_topic: str

    # Postgres (für Tap-Status, Threat-Level-Polling, Hot-Reload-Read)
    postgres_dsn: str

    # MQTT-Broker
    broker_host: str
    broker_port: int
    client_id: str
    use_tls: bool
    tls_verify: bool
    server_ca_path: str
    username: str
    password: str

    # Per-Origin-Identity
    master_host_id: str

    # Topic-Prefix
    topic_prefix: str

    # QoS
    qos_events: int
    qos_state: int

    # Rate-Limit + Inflight
    rate_limit_per_sec: int
    inflight_max: int

    # State-Topic-Tick
    threat_publish_interval_s: int
    tap_publish_interval_s: int

    # Filter
    severity_min: str
    sources_allowed: tuple[str, ...]
    rule_id_blocklist: tuple[str, ...]

    @classmethod
    def from_env(cls) -> "Config":
        return cls.from_dict(_env_dict())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Config":
        return cls(**d)

    def severity_passes(self, severity: str) -> bool:
        rank = SEVERITY_RANK.get((severity or "low").lower(), 0)
        return rank >= SEVERITY_RANK[self.severity_min]

    def source_passes(self, source: str) -> bool:
        if not self.sources_allowed:
            return True
        return (source or "signature") in self.sources_allowed

    def rule_id_passes(self, rule_id: str) -> bool:
        if not rule_id or not self.rule_id_blocklist:
            return True
        for pattern in self.rule_id_blocklist:
            if pattern.endswith("*"):
                if rule_id.startswith(pattern[:-1]):
                    return False
            elif rule_id == pattern:
                return False
        return True

    def differs_in_connection(self, other: "Config") -> bool:
        for f in CONNECTION_FIELDS:
            if getattr(self, f) != getattr(other, f):
                return True
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Env- und DB-Layer
# ─────────────────────────────────────────────────────────────────────────────


def _env_dict() -> dict[str, Any]:
    """Liest Konfig aus env-vars und gibt sie als dict zurück (so dass sie
    pro-Feld mit DB-Werten ge-overlayed werden kann)."""
    sev_min = os.environ.get("MQTT_SEVERITY_MIN", "low").strip().lower()
    if sev_min not in SEVERITY_RANK:
        log.warning("MQTT_SEVERITY_MIN=%r ungültig, falle auf 'low' zurück", sev_min)
        sev_min = "low"

    sources_raw = os.environ.get("MQTT_SOURCES", "signature,ml,suricata,external").strip()
    sources = tuple(s.strip() for s in sources_raw.split(",") if s.strip())

    block_raw = os.environ.get("MQTT_RULE_ID_BLOCKLIST", "").strip()
    blocks = tuple(b.strip() for b in block_raw.split(",") if b.strip())

    master_id = os.environ.get("MQTT_MASTER_HOST_ID", "").strip()
    if not master_id:
        master_id = os.environ.get("HOSTNAME", "").strip() or "master"

    return {
        "enabled": os.environ.get("MQTT_ENABLED", "false").lower() == "true",
        "kafka_brokers": os.environ.get("KAFKA_BROKERS", "kafka:9092"),
        "alerts_topic": os.environ.get("MQTT_ALERTS_TOPIC", "alerts-enriched"),
        "postgres_dsn": os.environ.get("POSTGRES_DSN", "postgres://ids:ids@timescaledb:5432/ids"),
        "broker_host": os.environ.get("MQTT_BROKER_HOST", "localhost"),
        "broker_port": int(os.environ.get("MQTT_BROKER_PORT", "8883")),
        "client_id": os.environ.get("MQTT_CLIENT_ID", f"cyjan-{master_id}"),
        "use_tls": os.environ.get("MQTT_USE_TLS", "true").lower() == "true",
        "tls_verify": os.environ.get("MQTT_TLS_VERIFY", "true").lower() == "true",
        "server_ca_path": os.environ.get("MQTT_SERVER_CA_PATH", "").strip(),
        "username": os.environ.get("MQTT_USERNAME", ""),
        "password": os.environ.get("MQTT_PASSWORD", ""),
        "master_host_id": master_id,
        "topic_prefix": os.environ.get("MQTT_TOPIC_PREFIX", "cyjan").strip("/") or "cyjan",
        "qos_events": _int_clamped("MQTT_QOS_EVENTS", 1, 0, 1),
        "qos_state": _int_clamped("MQTT_QOS_STATE", 0, 0, 1),
        "rate_limit_per_sec": max(1, int(os.environ.get("MQTT_RATE_LIMIT_PER_SEC", "200"))),
        "inflight_max": max(1, int(os.environ.get("MQTT_INFLIGHT_MAX", "10"))),
        "threat_publish_interval_s": max(5, int(os.environ.get("MQTT_THREAT_INTERVAL_S", "30"))),
        "tap_publish_interval_s": max(5, int(os.environ.get("MQTT_TAP_INTERVAL_S", "30"))),
        "severity_min": sev_min,
        "sources_allowed": sources,
        "rule_id_blocklist": blocks,
    }


# Felder die aus dem DB-JSON 1:1 ins Config-Dict übernommen werden,
# wenn sie dort gesetzt sind. Reihenfolge irrelevant.
DB_FIELD_MAPPING: dict[str, type] = {
    "enabled": bool,
    "broker_host": str,
    "broker_port": int,
    "use_tls": bool,
    "tls_verify": bool,
    "username": str,
    "password": str,
    "client_id": str,
    "master_host_id": str,
    "topic_prefix": str,
    "qos_events": int,
    "qos_state": int,
    "rate_limit_per_sec": int,
    "inflight_max": int,
    "threat_publish_interval_s": int,
    "tap_publish_interval_s": int,
    "severity_min": str,
    "sources_allowed": tuple,
    "rule_id_blocklist": tuple,
}


def merge_db_overlay(env: dict[str, Any], db_value: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Nimmt das env-Dict und überschreibt pro Feld, sofern es im DB-Patch
    gesetzt ist. Ungültige/leere DB-Werte werden ignoriert (env bleibt)."""
    if not db_value or not isinstance(db_value, dict):
        return env

    merged = dict(env)
    for key, typ in DB_FIELD_MAPPING.items():
        if key not in db_value:
            continue
        raw = db_value[key]
        try:
            if typ is bool:
                merged[key] = bool(raw)
            elif typ is int:
                merged[key] = int(raw)
            elif typ is str:
                # Strings dürfen leer sein — aber leere `client_id`,
                # `master_host_id`, `topic_prefix` fallen auf env-Default
                # zurück, weil sonst die Topic-Pfade leer würden.
                v = (raw or "").strip() if isinstance(raw, str) else str(raw or "")
                if not v and key in ("client_id", "master_host_id", "topic_prefix"):
                    continue
                merged[key] = v
            elif typ is tuple:
                if isinstance(raw, (list, tuple)):
                    merged[key] = tuple(str(x).strip() for x in raw if str(x).strip())
                elif isinstance(raw, str):
                    merged[key] = tuple(s.strip() for s in raw.split(",") if s.strip())
        except (ValueError, TypeError) as exc:
            log.warning("DB-Overlay-Feld %r ignoriert (Wert=%r, Fehler=%s)", key, raw, exc)

    # Schema-Sanitisierung post-merge:
    sev = merged.get("severity_min", "low")
    if sev not in SEVERITY_RANK:
        log.warning("severity_min=%r ungültig (DB), falle auf env-Default zurück", sev)
        merged["severity_min"] = env["severity_min"]

    # Topic-Prefix darf keine Slashes haben
    merged["topic_prefix"] = (merged.get("topic_prefix") or "cyjan").strip("/") or "cyjan"

    # client_id: falls DB master_host_id geändert hat, env-Default-Pattern
    # neu bauen, sonst zeigt der Topic auf den neuen Host aber die client_id
    # noch auf den alten. Nur wenn explizit DB.client_id leer/nicht gesetzt.
    if "client_id" not in db_value or not (db_value.get("client_id") or "").strip():
        merged["client_id"] = f"cyjan-{merged['master_host_id']}"

    return merged


def _int_clamped(env: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(os.environ.get(env, str(default)))
    except ValueError:
        v = default
    return max(lo, min(hi, v))
