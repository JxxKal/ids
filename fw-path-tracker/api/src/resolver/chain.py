"""Resolver-Kette: FMG-Objekte → iTop → DNS, mit Provenance + TTL-Cache."""
from __future__ import annotations

import ipaddress
import logging

from cachetools import TTLCache

from inventory.store import Inventory
from resolver import dns_source, fmg_source
from resolver.itop_source import ItopSource

log = logging.getLogger("resolver.chain")


def is_ip(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value.strip())
        return True
    except ValueError:
        return False


def is_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value.strip())
        return True
    except ValueError:
        return False


class ResolverChain:
    def __init__(self, ttl_s: int = 900):
        self.itop = ItopSource()
        self._cache: TTLCache = TTLCache(maxsize=2048, ttl=ttl_s)

    async def resolve_endpoint(self, value: str, inv: Inventory,
                               itop_cfg: dict, dns_cfg: dict) -> dict:
        """User-Eingabe (IP oder Name) → {ip, names: [{name, provenance}]}.

        Wirft ValueError, wenn kein Name auflösbar ist.
        """
        value = value.strip()
        cached = self._cache.get(("ep", value))
        if cached:
            return cached

        if is_ip(value):
            names = await self._names_for_ip(value, inv, itop_cfg, dns_cfg)
            result = {"ip": value, "names": names, "provenance": "ip"}
        else:
            hit = fmg_source.resolve_name(inv, value)
            if hit is None and itop_cfg.get("base_url"):
                hit = await self.itop.resolve_name(itop_cfg, value)
            if hit is None:
                hit = await dns_source.resolve_name(dns_cfg, value)
            if hit is None:
                raise ValueError(
                    f"'{value}' ist über keine Quelle (FMG-Objekt, iTop, DNS) auflösbar."
                )
            result = {
                "ip": hit["ip"],
                "names": [{"name": hit.get("name", value), "provenance": hit["provenance"]}],
                "provenance": hit["provenance"],
            }
        self._cache[("ep", value)] = result
        return result

    async def _names_for_ip(self, ip: str, inv: Inventory,
                            itop_cfg: dict, dns_cfg: dict) -> list[dict]:
        names: list[dict] = []
        hit = fmg_source.resolve_ip(inv, ip)
        if hit:
            names.append({"name": hit["name"], "provenance": "fmg"})
        if itop_cfg.get("base_url"):
            try:
                hit = await self.itop.resolve_ip(itop_cfg, ip)
                if hit:
                    names.append({"name": hit["name"], "provenance": "itop"})
            except Exception as exc:
                log.warning("iTop-Resolve %s: %s", ip, exc)
        hit = await dns_source.resolve_ip(dns_cfg, ip)
        if hit:
            names.append({"name": hit["name"], "provenance": "dns"})
        return names

    async def search(self, q: str, inv: Inventory, itop_cfg: dict,
                     limit: int = 10) -> list[dict]:
        """Autocomplete: FMG-Objektnamen + iTop-Hosts (DNS nur bei Submit)."""
        out = fmg_source.search(inv, q, limit)
        if itop_cfg.get("base_url") and len(out) < limit:
            try:
                out += await self.itop.search(itop_cfg, q, limit - len(out))
            except Exception as exc:
                log.warning("iTop-Suche '%s': %s", q, exc)
        return out
