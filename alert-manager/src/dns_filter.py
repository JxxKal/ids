"""
DNS-Resolver-Allowlist – pragmatischer FP-Filter für DNS-Server-Traffic.

Hintergrund:
  Auf Hosts die als DNS-Resolver fungieren (interner BIND/Unbound, public
  DNS via 8.8.8.8 etc.), sieht der Sniffer pro Konversation ZWEI unidirek-
  tionale Flow-Records: einen Client→Server (dst_port=53) und einen
  Server→Client (src_port=53, dst_port=ephemeral). Da der flow-aggregator
  die Richtung NICHT zusammenfasst, sehen die Scan-Regeln (SCAN_001/002)
  den Resolver wie einen Scanner, der scheinbar viele unique dst_ports
  bedient – jede Antwort an einen Client geht an dessen ephemeral Port.

  Außerdem feuern DNS_AMP_001 und DNS_NONSTANDARD_001 false-positive auf
  legitimen Resolver-Traffic, weil pps + kleine Pakete bei populären
  Recursive-Resolvern Standard sind.

Lösung:
  User pflegt in den Settings eine Liste bekannter DNS-Resolver-IPs/CIDRs.
  Alerts mit medium/low-Severity, an denen einer dieser Resolver beteiligt
  ist (src ODER dst), werden vor dem DB-Write verworfen. High/critical
  kommt weiterhin durch – wenn jemand wirklich DNS-Tunneling oder DGA
  macht, soll der Analyst das sehen.

Persistenz:
  system_config-Key 'dns_resolvers' mit Wert
    {"resolvers": ["192.168.1.1", "8.8.8.8", "10.0.0.0/24"]}
  Periodischer Refresh aus DB (Standard 60s), damit GUI-Edits ohne
  alert-manager-Restart wirken.
"""
from __future__ import annotations

import logging
import time
from ipaddress import ip_address, ip_network

import psycopg2

log = logging.getLogger(__name__)

REFRESH_INTERVAL_S = 60.0
SUPPRESSED_SEVERITIES = {"medium", "low"}


class DnsResolverFilter:
    def __init__(self, postgres_dsn: str) -> None:
        self._dsn = postgres_dsn
        self._conn: psycopg2.extensions.connection | None = None
        self._nets: list = []
        self._last_refresh = 0.0

    def _connect(self) -> None:
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(self._dsn)
            self._conn.autocommit = True

    def refresh(self) -> None:
        try:
            self._connect()
            cur = self._conn.cursor()  # type: ignore[union-attr]
            cur.execute(
                "SELECT value FROM system_config WHERE key = %s",
                ("dns_resolvers",),
            )
            row = cur.fetchone()
            entries: list[str] = []
            if row and isinstance(row[0], dict):
                entries = list(row[0].get("resolvers") or [])

            nets = []
            for raw in entries:
                raw = str(raw).strip()
                if not raw:
                    continue
                try:
                    nets.append(ip_network(raw, strict=False))
                except ValueError as exc:
                    log.warning("DNS-Resolver-Allowlist: ungültige IP/CIDR '%s' (%s)", raw, exc)

            self._nets = nets
            self._last_refresh = time.monotonic()
            log.info(
                "DNS-Resolver-Allowlist: %d Range(s) aktiv – %s",
                len(nets), ", ".join(str(n) for n in nets) or "(leer)",
            )
        except Exception as exc:
            log.warning("DNS-Resolver-Allowlist-Refresh fehlgeschlagen: %s", exc)
            self._conn = None

    def maybe_refresh(self) -> None:
        if time.monotonic() - self._last_refresh > REFRESH_INTERVAL_S:
            self.refresh()

    def _is_resolver(self, ip_str: str | None) -> bool:
        if not ip_str or not self._nets:
            return False
        try:
            ip = ip_address(str(ip_str).split("/")[0])
            return any(ip in net for net in self._nets)
        except ValueError:
            return False

    def should_drop(self, alert: dict) -> bool:
        """True wenn der Alert verworfen werden soll.

        Bedingung: severity ist medium oder low UND mindestens eine Seite
        (src oder dst) ist ein konfigurierter Resolver. High/critical wird
        nie unterdrückt – das wären echte DNS-Angriffe (Tunnel, DGA), die
        der Analyst sehen muss.
        """
        if alert.get("severity") not in SUPPRESSED_SEVERITIES:
            return False
        if not self._nets:
            return False
        return self._is_resolver(alert.get("src_ip")) or self._is_resolver(alert.get("dst_ip"))

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
