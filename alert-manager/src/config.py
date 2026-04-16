import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    kafka_brokers: str
    postgres_dsn: str
    # Zeitfenster für Deduplication in Sekunden
    dedup_window_s: float
    test_mode: bool

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            kafka_brokers=os.environ.get("KAFKA_BROKERS", "localhost:9092"),
            postgres_dsn=os.environ.get(
                "POSTGRES_DSN",
                "postgresql://ids:ids-change-me@localhost:5432/ids",
            ),
            dedup_window_s=float(os.environ.get("DEDUP_WINDOW_S", "300")),
            test_mode=os.environ.get("TEST_MODE", "false").lower() == "true",
        )
