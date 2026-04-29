import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    kafka_brokers:    str
    metrics_topic:    str
    consumer_group:   str
    postgres_dsn:     str
    api_base_url:     str
    api_secret_key:   str
    # Reservoir + Persistierung.
    reservoir_size:   int
    persist_interval_s: float
    state_poll_interval_s: float
    tuning_cycle_s:   float
    min_samples:      int

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            kafka_brokers=os.environ.get("KAFKA_BROKERS", "kafka:9092"),
            metrics_topic=os.environ.get("METRICS_TOPIC", "rule-metrics"),
            consumer_group=os.environ.get("KAFKA_GROUP_ID", "rule-tuner"),
            postgres_dsn=os.environ.get(
                "POSTGRES_DSN",
                "postgresql://ids:ids-change-me@timescaledb:5432/ids",
            ),
            api_base_url=os.environ.get("API_BASE_URL", "http://api:8000"),
            api_secret_key=os.environ.get(
                "API_SECRET_KEY",
                # Fallback wie in api/src/config.py — gleicher Default,
                # damit lokale Dev-Stacks ohne explizites SECRET_KEY laufen.
                "change-me-in-production",
            ),
            reservoir_size=int(os.environ.get("RESERVOIR_SIZE", "10000")),
            persist_interval_s=float(os.environ.get("PERSIST_INTERVAL_S", "60")),
            state_poll_interval_s=float(os.environ.get("STATE_POLL_INTERVAL_S", "30")),
            # Default 6h: spec-konform, aber per env überstellbar damit Tests
            # mit kürzeren Cycles laufen können.
            tuning_cycle_s=float(os.environ.get("TUNING_CYCLE_S", str(6 * 3600))),
            min_samples=int(os.environ.get("MIN_SAMPLES", "100")),
        )
