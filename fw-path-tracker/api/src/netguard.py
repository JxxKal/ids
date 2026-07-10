"""SSRF-Schutz für admin-konfigurierbare Ziele (portiert aus ids itop.py).

Blockt Requests an Loopback- und Link-Local-Ziele (inkl. Cloud-Metadata
169.254.169.254). Angewendet auf FMG-Host, iTop-URL und DNS-Resolver —
alles server-seitig angefragte, frei konfigurierbare Ziele. Private
LAN-Ranges bleiben erlaubt (On-Prem-FMG/iTop ist der Normalfall).
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from fastapi import HTTPException


def guard_egress_host(host: str, label: str = "Ziel") -> None:
    host = (host or "").strip()
    if not host:
        raise HTTPException(400, f"{label} ohne gültigen Host.")

    candidates: set[str] = set()
    try:
        ipaddress.ip_address(host)
        candidates.add(host)
    except ValueError:
        try:
            for info in socket.getaddrinfo(host, None):
                candidates.add(info[4][0])
        except socket.gaierror as exc:
            raise HTTPException(400, f"{label} '{host}' nicht auflösbar: {exc}") from exc

    for addr in candidates:
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])  # %zone bei link-local v6 strippen
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local:
            raise HTTPException(
                400,
                f"{label} {addr} ist nicht erlaubt (loopback/link-local, SSRF-Schutz).",
            )


def guard_egress_url(url: str, label: str = "Ziel") -> None:
    guard_egress_host(urlparse(url).hostname or "", label)
