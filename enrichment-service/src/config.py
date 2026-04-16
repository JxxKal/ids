import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    kafka_brokers: str
    postgres_dsn: str
    redis_url: str
    # Timeout für Ping in Millisekunden
    ping_timeout_ms: int
    # Timeout für DNS-Auflösung in Sekunden
    dns_timeout_s: float
    # Redis/DB Cache TTL in Sekunden
    cache_ttl_s: int
    # Pfade zu MaxMind GeoLite2-Datenbanken (leer = deaktiviert)
    geoip_city_db: str
    geoip_asn_db: str
    test_mode: bool

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            kafka_brokers=os.environ.get("KAFKA_BROKERS", "localhost:9092"),
            postgres_dsn=os.environ.get(
                "POSTGRES_DSN",
                "postgresql://ids:ids-change-me@localhost:5432/ids",
            ),
            redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379"),
            ping_timeout_ms=int(os.environ.get("PING_TIMEOUT_MS", "1000")),
            dns_timeout_s=float(os.environ.get("DNS_TIMEOUT_MS", "2000")) / 1000.0,
            cache_ttl_s=int(os.environ.get("CACHE_TTL_S", "3600")),
            geoip_city_db=os.environ.get("GEOIP_CITY_DB", "/geoip/GeoLite2-City.mmdb"),
            geoip_asn_db=os.environ.get("GEOIP_ASN_DB", "/geoip/GeoLite2-ASN.mmdb"),
            test_mode=os.environ.get("TEST_MODE", "false").lower() == "true",
        )
