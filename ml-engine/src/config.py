import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    kafka_brokers: str
    postgres_dsn: str
    models_dir: str
    # Wie viele Bootstrap-Flows gesammelt werden bevor das erste Modell trainiert wird
    bootstrap_min_samples: int
    # Wie viele neue Flows seit letztem Training bis zum nächsten Online-Update
    partial_fit_interval: int
    # Wie oft (Flows) das Modell neu gespeichert wird
    save_interval: int
    # Contamination-Parameter für IsolationForest (geschätzter Outlier-Anteil)
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
            bootstrap_min_samples=int(os.environ.get("BOOTSTRAP_MIN_SAMPLES", "500")),
            partial_fit_interval=int(os.environ.get("PARTIAL_FIT_INTERVAL", "200")),
            save_interval=int(os.environ.get("SAVE_INTERVAL", "1000")),
            contamination=float(os.environ.get("CONTAMINATION", "0.01")),
            test_mode=os.environ.get("TEST_MODE", "false").lower() == "true",
        )
