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
    # Ziel-Alert-Rate für die Auto-Threshold-Kalibrierung (Anteil der Flows,
    # der als Anomalie gemeldet werden soll). Threshold = (1-rate)-Quantil der
    # Score-Verteilung. Default 0.1 % — sichtbar, aber kein Flood.
    target_alert_rate: float
    # Wie viele Flows beim Startup fürs Kalibrieren aus der DB gezogen werden.
    calibration_samples: int
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
            contamination=float(os.environ.get("CONTAMINATION", "0.005")),
            target_alert_rate=float(os.environ.get("ML_TARGET_ALERT_RATE", "0.001")),
            calibration_samples=int(os.environ.get("ML_CALIBRATION_SAMPLES", "20000")),
            test_mode=os.environ.get("TEST_MODE", "false").lower() == "true",
        )
