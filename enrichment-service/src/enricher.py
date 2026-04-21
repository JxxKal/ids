"""
IP-Enrichment: DNS, Ping, GeoIP, ASN, Known Networks.

Alle Funktionen sind best-effort – bei Fehler wird None zurückgegeben,
kein Exception-Propagation nach oben.

GeoIP/ASN nutzt DB-IP.com Free-Datenbanken (kein Account erforderlich):
  /geoip/GeoLite2-City.mmdb  ← dbip-city-lite-YYYY-MM.mmdb
  /geoip/GeoLite2-ASN.mmdb   ← dbip-asn-lite-YYYY-MM.mmdb
  Download: https://db-ip.com/db/lite.php
Kompatibel auch mit MaxMind GeoLite2 (.mmdb).
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from pathlib import Path
from typing import Any

import icmplib

log = logging.getLogger(__name__)

# GeoIP-Reader werden lazy initialisiert
_city_reader = None
_asn_reader  = None


def init_geoip(city_db: str, asn_db: str) -> None:
    """Lädt mmdb-Datenbanken via maxminddb (MaxMind + DB-IP kompatibel)."""
    global _city_reader, _asn_reader
    try:
        import maxminddb
        if Path(city_db).exists():
            _city_reader = maxminddb.open_database(city_db)
            log.info("GeoIP City DB loaded: %s", city_db)
        else:
            log.warning("GeoIP City DB not found: %s – geo enrichment disabled", city_db)
    except Exception as exc:
        log.warning("GeoIP City init failed: %s", exc)

    try:
        import maxminddb
        if Path(asn_db).exists():
            _asn_reader = maxminddb.open_database(asn_db)
            log.info("GeoIP ASN DB loaded: %s", asn_db)
        else:
            log.warning("GeoIP ASN DB not found: %s – ASN enrichment disabled", asn_db)
    except Exception as exc:
        log.warning("GeoIP ASN init failed: %s", exc)


def resolve_hostname(ip: str, timeout_s: float) -> str | None:
    """Reverse-DNS-Auflösung. Gibt Hostname oder None zurück."""
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout_s)
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname if hostname != ip else None
        finally:
            socket.setdefaulttimeout(old_timeout)
    except Exception:
        return None


def ping_host(ip: str, timeout_ms: int) -> float | None:
    """ICMP Ping. Gibt Latenz in ms oder None bei Nicht-Erreichbarkeit zurück."""
    try:
        result = icmplib.ping(
            ip,
            count=1,
            timeout=timeout_ms / 1000.0,
            privileged=True,
        )
        if result.is_alive:
            return round(result.avg_rtt, 2)
    except Exception as exc:
        log.debug("Ping %s failed: %s", ip, exc)
    return None


def geo_lookup(ip: str) -> dict[str, Any] | None:
    """GeoIP-Lookup via maxminddb (MaxMind + DB-IP). Gibt Dict oder None zurück."""
    if _city_reader is None:
        return None
    try:
        data = _city_reader.get(ip)
        if not data:
            return None
        country  = data.get("country") or {}
        city     = data.get("city") or {}
        location = data.get("location") or {}
        names    = country.get("names") or {}
        cnames   = city.get("names") or {}
        return {
            "country":      names.get("en") or names.get("de"),
            "country_code": country.get("iso_code"),
            "city":         cnames.get("en") or cnames.get("de"),
            "lat":          location.get("latitude"),
            "lon":          location.get("longitude"),
        }
    except Exception:
        return None


def asn_lookup(ip: str) -> dict[str, Any] | None:
    """ASN-Lookup via maxminddb (MaxMind + DB-IP). Gibt Dict oder None zurück."""
    if _asn_reader is None:
        return None
    try:
        data = _asn_reader.get(ip)
        if not data:
            return None
        return {
            "number": data.get("autonomous_system_number"),
            "org":    data.get("autonomous_system_organization"),
        }
    except Exception:
        return None


def is_private_ip(ip: str) -> bool:
    """Gibt True zurück für RFC1918/Loopback/Link-Local Adressen."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
