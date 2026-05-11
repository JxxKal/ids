"""Config aus env-Vars."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    kafka_brokers:  str
    postgres_dsn:   str
    input_topic:    str
    group_id:       str
    poll_timeout_s: float
    # Throttling: refresh DB-Channel-Cache alle N Sekunden, damit neu angelegte
    # Channels innerhalb dieser Zeit anfangen Push zu kriegen.
    cache_ttl_s:    float
    # Default-SMTP-Config (System-weit) — kann pro Channel überschrieben werden.
    smtp_host:      str
    smtp_port:      int
    smtp_user:      str
    smtp_password:  str
    smtp_from:      str
    smtp_use_tls:   bool

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            kafka_brokers  = os.environ.get("KAFKA_BROKERS", "kafka:9092"),
            postgres_dsn   = os.environ.get("POSTGRES_DSN",
                                             "postgres://ids:ids@timescaledb:5432/ids"),
            input_topic    = os.environ.get("NOTIFY_INPUT_TOPIC", "alerts-enriched-push"),
            group_id       = os.environ.get("NOTIFY_GROUP_ID", "notification-dispatcher"),
            poll_timeout_s = float(os.environ.get("NOTIFY_POLL_TIMEOUT_S", "1.0")),
            cache_ttl_s    = float(os.environ.get("NOTIFY_CACHE_TTL_S", "30")),
            smtp_host      = os.environ.get("SMTP_HOST", ""),
            smtp_port      = int(os.environ.get("SMTP_PORT", "587")),
            smtp_user      = os.environ.get("SMTP_USER", ""),
            smtp_password  = os.environ.get("SMTP_PASSWORD", ""),
            smtp_from      = os.environ.get("SMTP_FROM", "cyjan-ids@localhost"),
            smtp_use_tls   = os.environ.get("SMTP_USE_TLS", "true").lower() in ("1","true","yes"),
        )
