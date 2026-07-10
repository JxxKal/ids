"""Resolver-Quelle 3: DNS (A + PTR) mit konfigurierbaren Resolvern/Suchdomains."""
from __future__ import annotations

import asyncio
import logging

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename

from netguard import guard_egress_host

log = logging.getLogger("resolver.dns")

_TIMEOUT_S = 3.0


def _resolver(dns_cfg: dict) -> dns.asyncresolver.Resolver:
    res = dns.asyncresolver.Resolver()
    servers = [s for s in (dns_cfg.get("resolvers") or []) if s]
    if servers:
        for s in servers:
            guard_egress_host(s, "DNS-Resolver")
        res.nameservers = servers
    res.lifetime = _TIMEOUT_S
    return res


async def resolve_name(dns_cfg: dict, name: str) -> dict | None:
    res = _resolver(dns_cfg)
    domains = [""] + [d for d in (dns_cfg.get("search_domains") or []) if d]
    for domain in domains:
        fqdn = f"{name}.{domain}".rstrip(".") if domain else name
        try:
            answer = await res.resolve(fqdn, "A")
            ips = [r.to_text() for r in answer]
            if ips:
                return {"ip": ips[0], "name": fqdn, "provenance": "dns"}
        except (dns.exception.DNSException, asyncio.TimeoutError):
            continue
    return None


async def resolve_ip(dns_cfg: dict, ip: str) -> dict | None:
    res = _resolver(dns_cfg)
    try:
        answer = await res.resolve(dns.reversename.from_address(ip), "PTR")
        names = [r.to_text().rstrip(".") for r in answer]
        if names:
            return {"name": names[0], "provenance": "dns"}
    except (dns.exception.DNSException, asyncio.TimeoutError, ValueError):
        pass
    return None
