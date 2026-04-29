import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    kafka_brokers: str
    rules_dir: str
    # Wie oft auf geänderte Regel-Dateien geprüft wird (Hot-Reload)
    reload_interval_s: float
    test_mode: bool
    # Phase-2 Shadow-Metrik-Pipeline:
    # Pro evaluiertem Flow wird mit Wahrscheinlichkeit metrics_sampling_rate
    # (Bernoulli) ein Bündel `rule-metrics`-Records auf metrics_topic
    # geschrieben — einer pro `(rule, param)` mit `metric:`-Deklaration.
    # Sampling spart Volumen: bei 1 % und ~10k Flows/s landen ~100 Sample-
    # Bündel/s im Topic. Komplett deaktivierbar über metrics_enabled=false.
    metrics_enabled: bool
    metrics_topic: str
    metrics_sampling_rate: float

    @classmethod
    def from_env(cls) -> "Config":
        try:
            rate = float(os.environ.get("METRICS_SAMPLING_RATE", "0.01"))
        except ValueError:
            rate = 0.01
        # Clamp auf [0, 1] — Werte außerhalb ergeben keinen Sinn und
        # wurden in der Vergangenheit schon mal als Tippfehler gesetzt.
        rate = max(0.0, min(1.0, rate))
        return cls(
            kafka_brokers=os.environ.get("KAFKA_BROKERS", "localhost:9092"),
            rules_dir=os.environ.get("RULES_DIR", "/rules"),
            reload_interval_s=30.0,
            test_mode=os.environ.get("TEST_MODE", "false").lower() == "true",
            metrics_enabled=os.environ.get("METRICS_ENABLED", "true").lower() == "true",
            metrics_topic=os.environ.get("METRICS_TOPIC", "rule-metrics"),
            metrics_sampling_rate=rate,
        )
