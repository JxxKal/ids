import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    kafka_brokers: str
    postgres_dsn: str
    # IP-Adresse des Ziels im Test-Netzwerk (feste IP des traffic-generator-Containers)
    target_ip: str
    # Eigene IP (Quelle der Test-Pakete)
    src_ip: str
    test_mode: bool

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            kafka_brokers=os.environ.get("KAFKA_BROKERS", "localhost:9092"),
            postgres_dsn=os.environ.get(
                "POSTGRES_DSN",
                "postgresql://ids:ids-change-me@localhost:5432/ids",
            ),
            target_ip=os.environ.get("TARGET_IP", "172.28.0.100"),
            src_ip=os.environ.get("SRC_IP", "172.28.0.1"),
            test_mode=os.environ.get("TEST_MODE", "true").lower() == "true",
        )
