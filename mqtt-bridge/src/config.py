"""mqtt-bridge — env-var-basierte Konfiguration für V1.0.

V1.1 ersetzt das durch system_config['mqtt']-JSONB mit Hot-Reload (analog
IRMA, iTop). V1.0 bleibt env-var-only damit der initiale Bring-up
schlank bleibt und unabhängig von DB-Migrations getestet werden kann.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


# Severity-Order für severity_min-Filter. Niedrig bis hoch.
SEVERITY_ORDER = ["low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


@dataclass(frozen=True)
class Config:
    enabled: bool

    # Kafka
    kafka_brokers: str
    alerts_topic: str

    # Postgres (für Tap-Status, Threat-Level-Polling)
    postgres_dsn: str

    # MQTT-Broker
    broker_host: str
    broker_port: int
    client_id: str
    use_tls: bool
    tls_verify: bool
    server_ca_path: str  # leer = kein custom CA
    username: str
    password: str

    # Per-Origin-Identity
    master_host_id: str  # z.B. "master-81"; default = HOSTNAME

    # Topic-Prefix (Option B aus dem Grilling — nur Prefix konfigurierbar,
    # Schema dahinter ist fest: <prefix>/<host>/alerts/<sev>/<src> etc.)
    topic_prefix: str

    # QoS
    qos_events: int  # 0 oder 1
    qos_state: int

    # Rate-Limit + Inflight
    rate_limit_per_sec: int
    inflight_max: int

    # State-Topic-Tick
    threat_publish_interval_s: int  # Default 30s
    tap_publish_interval_s: int     # Default 30s

    # Filter (Cyjan-side soft-cap, Default = alles)
    severity_min: str               # low|medium|high|critical
    sources_allowed: tuple[str, ...]
    rule_id_blocklist: tuple[str, ...]

    @classmethod
    def from_env(cls) -> "Config":
        # Filter-Defaults: alles durch
        sev_min = os.environ.get("MQTT_SEVERITY_MIN", "low").strip().lower()
        if sev_min not in SEVERITY_RANK:
            log.warning("MQTT_SEVERITY_MIN=%r ungültig, falle auf 'low' zurück", sev_min)
            sev_min = "low"

        sources_raw = os.environ.get("MQTT_SOURCES", "signature,ml,suricata,external").strip()
        sources = tuple(s.strip() for s in sources_raw.split(",") if s.strip())

        block_raw = os.environ.get("MQTT_RULE_ID_BLOCKLIST", "").strip()
        blocks = tuple(b.strip() for b in block_raw.split(",") if b.strip())

        # Master-Host-Identity. In V1.0: env-var > Hostname > "master".
        master_id = os.environ.get("MQTT_MASTER_HOST_ID", "").strip()
        if not master_id:
            master_id = os.environ.get("HOSTNAME", "").strip() or "master"

        return cls(
            enabled=os.environ.get("MQTT_ENABLED", "false").lower() == "true",
            kafka_brokers=os.environ.get("KAFKA_BROKERS", "kafka:9092"),
            alerts_topic=os.environ.get("MQTT_ALERTS_TOPIC", "alerts-enriched"),
            postgres_dsn=os.environ.get("POSTGRES_DSN", "postgres://ids:ids@timescaledb:5432/ids"),
            broker_host=os.environ.get("MQTT_BROKER_HOST", "localhost"),
            broker_port=int(os.environ.get("MQTT_BROKER_PORT", "8883")),
            client_id=os.environ.get("MQTT_CLIENT_ID", f"cyjan-{master_id}"),
            use_tls=os.environ.get("MQTT_USE_TLS", "true").lower() == "true",
            tls_verify=os.environ.get("MQTT_TLS_VERIFY", "true").lower() == "true",
            server_ca_path=os.environ.get("MQTT_SERVER_CA_PATH", "").strip(),
            username=os.environ.get("MQTT_USERNAME", ""),
            password=os.environ.get("MQTT_PASSWORD", ""),
            master_host_id=master_id,
            topic_prefix=os.environ.get("MQTT_TOPIC_PREFIX", "cyjan").strip("/") or "cyjan",
            qos_events=_int_clamped("MQTT_QOS_EVENTS", 1, 0, 1),
            qos_state=_int_clamped("MQTT_QOS_STATE", 0, 0, 1),
            rate_limit_per_sec=max(1, int(os.environ.get("MQTT_RATE_LIMIT_PER_SEC", "200"))),
            inflight_max=max(1, int(os.environ.get("MQTT_INFLIGHT_MAX", "10"))),
            threat_publish_interval_s=max(5, int(os.environ.get("MQTT_THREAT_INTERVAL_S", "30"))),
            tap_publish_interval_s=max(5, int(os.environ.get("MQTT_TAP_INTERVAL_S", "30"))),
            severity_min=sev_min,
            sources_allowed=sources,
            rule_id_blocklist=blocks,
        )

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
        # Wildcard-Support: "ASSET::*" matched alle die mit "ASSET::" beginnen.
        for pattern in self.rule_id_blocklist:
            if pattern.endswith("*"):
                if rule_id.startswith(pattern[:-1]):
                    return False
            elif rule_id == pattern:
                return False
        return True


def _int_clamped(env: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(os.environ.get(env, str(default)))
    except ValueError:
        v = default
    return max(lo, min(hi, v))
