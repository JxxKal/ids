import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    kafka_brokers: str
    rules_dir: str
    # Wie oft auf geänderte Regel-Dateien geprüft wird (Hot-Reload)
    reload_interval_s: float
    test_mode: bool

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            kafka_brokers=os.environ.get("KAFKA_BROKERS", "localhost:9092"),
            rules_dir=os.environ.get("RULES_DIR", "/rules"),
            reload_interval_s=30.0,
            test_mode=os.environ.get("TEST_MODE", "false").lower() == "true",
        )
