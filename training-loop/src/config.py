import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    kafka_brokers: str
    postgres_dsn: str
    models_dir: str
    # Mindestanzahl neuer gelabelter Samples für ein Retrain
    min_new_samples: int
    # Maximale Samples für Training (neueste bevorzugt)
    max_train_samples: int
    # Intervall zwischen Retrain-Checks in Sekunden
    retrain_interval_s: float
    contamination: float
    test_mode: bool

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            kafka_brokers=os.environ.get("KAFKA_BROKERS", "localhost:9092"),
            postgres_dsn=os.environ.get(
                "POSTGRES_DSN",
                "postgresql://ids:ids-change-me@localhost:5432/ids",
            ),
            models_dir=os.environ.get("MODELS_DIR", "/models"),
            min_new_samples=int(os.environ.get("MIN_NEW_SAMPLES", "50")),
            max_train_samples=int(os.environ.get("MAX_TRAIN_SAMPLES", "100000")),
            retrain_interval_s=float(
                os.environ.get("RETRAIN_INTERVAL_S", "86400")
            ),
            contamination=float(os.environ.get("CONTAMINATION", "0.01")),
            test_mode=os.environ.get("TEST_MODE", "false").lower() == "true",
        )
