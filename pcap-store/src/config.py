import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    kafka_brokers: str
    postgres_dsn: str
    minio_endpoint: str
    minio_access_key: str
    minio_secret_key: str
    pcap_bucket: str
    # ±Sekunden um den Alert-Timestamp für das PCAP-Fenster
    pcap_window_s: float
    test_mode: bool

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            kafka_brokers=os.environ.get("KAFKA_BROKERS", "localhost:9092"),
            postgres_dsn=os.environ.get(
                "POSTGRES_DSN",
                "postgresql://ids:ids-change-me@localhost:5432/ids",
            ),
            minio_endpoint=os.environ.get("MINIO_ENDPOINT", "localhost:9000"),
            minio_access_key=os.environ.get("MINIO_ACCESS_KEY", "ids-access"),
            minio_secret_key=os.environ.get("MINIO_SECRET_KEY", "ids-secret-change-me"),
            pcap_bucket=os.environ.get("PCAP_BUCKET", "ids-pcaps"),
            pcap_window_s=float(os.environ.get("PCAP_WINDOW_S", "60")),
            test_mode=os.environ.get("TEST_MODE", "false").lower() == "true",
        )
