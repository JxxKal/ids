"""
IP-Enrichment: DNS, Ping, GeoIP, ASN, Known Networks.

Alle Funktionen sind best-effort – bei Fehler wird None zurückgegeben,
kein Exception-Propagation nach oben.

GeoIP/ASN benötigt MaxMind GeoLite2-Datenbanken:
  /geoip/GeoLite2-City.mmdb
  /geoip/GeoLite2-ASN.mmdb
  Download: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
  (kostenloses Konto erforderlich)
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
    """Lädt MaxMind-Datenbanken. Stille Fehler wenn Dateien fehlen."""
    global _city_reader, _asn_reader
    try:
        import geoip2.database
        if Path(city_db).exists():
            _city_reader = geoip2.database.Reader(city_db)
            log.info("GeoIP City DB loaded: %s", city_db)
        else:
            log.warning("GeoIP City DB not found: %s – geo enrichment disabled", city_db)
    except Exception as exc:
        log.warning("GeoIP City init failed: %s", exc)

    try:
        import geoip2.database
        if Path(asn_db).exists():
            _asn_reader = geoip2.database.Reader(asn_db)
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
    """GeoIP-Lookup. Gibt Dict oder None zurück."""
    if _city_reader is None:
        return None
    try:
        resp = _city_reader.city(ip)
        return {
            "country":      resp.country.name,
            "country_code": resp.country.iso_code,
            "city":         resp.city.name,
            "lat":          resp.location.latitude,
            "lon":          resp.location.longitude,
        }
    except Exception:
        return None


def asn_lookup(ip: str) -> dict[str, Any] | None:
    """ASN-Lookup. Gibt Dict oder None zurück."""
    if _asn_reader is None:
        return None
    try:
        resp = _asn_reader.asn(ip)
        return {
            "number": resp.autonomous_system_number,
            "org":    resp.autonomous_system_organization,
        }
    except Exception:
        return None


def is_private_ip(ip: str) -> bool:
    """Gibt True zurück für RFC1918/Loopback/Link-Local Adressen."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
