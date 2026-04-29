import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    kafka_brokers: str
    postgres_dsn: str | None     # leer = nur Kafka, kein DB-Insert (Tap-Mode)
    flow_timeout_s: int       # Inaktivitäts-Timeout: Flow endet nach X Sekunden ohne Pakete
    flow_max_duration_s: int  # Maximale Flow-Dauer unabhängig von Aktivität
    flush_interval_s: float   # Wie oft abgelaufene Flows geprüft werden
    db_batch_size: int        # Flows pro DB-Batch-Insert
    test_mode: bool

    @classmethod
    def from_env(cls) -> "Config":
        # POSTGRES_DSN ist im Master-Mode pflicht (flows-Hypertable wird
        # geschrieben), im Tap-Mode jedoch leer – dann läuft der Aggregator
        # nur als Kafka-Publisher, ohne DB-Anbindung.
        postgres_dsn = os.environ.get("POSTGRES_DSN") or None

        return cls(
            kafka_brokers=os.environ.get("KAFKA_BROKERS", "localhost:9092"),
            postgres_dsn=postgres_dsn,
            flow_timeout_s=int(os.environ.get("FLOW_TIMEOUT_S", "30")),
            flow_max_duration_s=int(os.environ.get("FLOW_MAX_DURATION_S", "300")),
            flush_interval_s=5.0,
            db_batch_size=100,
            test_mode=os.environ.get("TEST_MODE", "false").lower() == "true",
        )
