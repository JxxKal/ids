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
    reports_bucket: str         # MinIO-Bucket für archivierte Wochenberichte (JSON-Snapshots)
    secret_key: str
    test_mode: bool
    master_ca_dir: str          # Verzeichnis für Master-CA (Cert + Key) für mTLS-Auth der Remote-Taps
    # Retention-/Disk-Monitor (verhindert stilles Volllaufen der Disk)
    retention_check_enabled: bool
    retention_check_interval_s: int
    retention_disk_warn_pct: int    # Disk-Auslastung in %, ab der alarmiert wird
    retention_db_size_warn_gb: int  # DB-Größe in GB, ab der alarmiert wird (Catch-all für fehlende Retention)

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
            reports_bucket=os.environ.get("REPORTS_BUCKET", "ids-reports"),
            secret_key=os.environ.get("SECRET_KEY", "change-me-in-production"),
            test_mode=os.environ.get("TEST_MODE", "false").lower() == "true",
            master_ca_dir=os.environ.get("MASTER_CA_DIR", "/var/lib/cyjan/master-ca"),
            retention_check_enabled=os.environ.get("RETENTION_CHECK_ENABLED", "true").lower() == "true",
            retention_check_interval_s=int(os.environ.get("RETENTION_CHECK_INTERVAL_S", "21600")),
            retention_disk_warn_pct=int(os.environ.get("RETENTION_DISK_WARN_PCT", "85")),
            retention_db_size_warn_gb=int(os.environ.get("RETENTION_DB_SIZE_WARN_GB", "25")),
        )
