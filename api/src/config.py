import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    postgres_dsn: str
    redis_url: str
    kafka_brokers: str
    minio_endpoint: str
    minio_access_key: str
    minio_secret_key: str
    pcap_bucket: str
    secret_key: str
    test_mode: bool

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            postgres_dsn=os.environ.get(
                "POSTGRES_DSN",
                "postgresql://ids:ids-change-me@localhost:5432/ids",
            ),
            redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379"),
            kafka_brokers=os.environ.get("KAFKA_BROKERS", "localhost:9092"),
            minio_endpoint=os.environ.get("MINIO_ENDPOINT", "localhost:9000"),
            minio_access_key=os.environ.get("MINIO_ACCESS_KEY", "ids-access"),
            minio_secret_key=os.environ.get("MINIO_SECRET_KEY", "ids-secret-change-me"),
            pcap_bucket=os.environ.get("PCAP_BUCKET", "ids-pcaps"),
            secret_key=os.environ.get("SECRET_KEY", "change-me-in-production"),
            test_mode=os.environ.get("TEST_MODE", "false").lower() == "true",
        )
