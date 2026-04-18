import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    kafka_brokers: str
    postgres_dsn: str
    flows_topic: str
    # Test-Quell-IP für synthetische Flows (sollte nicht im echten Traffic vorkommen)
    src_ip: str
    # Ziel-IP für Flows die eine Zieladresse benötigen
    target_ip: str

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            kafka_brokers=os.environ.get("KAFKA_BROKERS", "localhost:9092"),
            postgres_dsn=os.environ.get(
                "POSTGRES_DSN",
                "postgresql://ids:ids-change-me@localhost:5432/ids",
            ),
            flows_topic=os.environ.get("FLOWS_TOPIC", "flows"),
            src_ip=os.environ.get("SRC_IP", "10.255.255.100"),
            target_ip=os.environ.get("TARGET_IP", "10.255.255.1"),
        )
