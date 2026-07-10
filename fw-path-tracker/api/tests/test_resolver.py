"""Resolver-Kette: FMG-Quelle, Fallback-Reihenfolge, Provenance, IPv6-Gate."""
from __future__ import annotations

import pytest

from resolver import dns_source, fmg_source
from resolver.chain import ResolverChain, is_ip, is_ipv6


def test_is_ip():
    assert is_ip("10.1.1.10")
    assert not is_ip("srv-db")
    assert is_ipv6("2001:db8::1")
    assert not is_ipv6("10.1.1.10")


def test_fmg_resolve_name(inventory):
    hit = fmg_source.resolve_name(inventory, "srv-db")
    assert hit == {"ip": "10.2.1.30", "name": "srv-db", "provenance": "fmg", "adom": "corp"}
    # /20-Objekte sind keine Host-Objekte → nicht auflösbar
    assert fmg_source.resolve_name(inventory, "net-site-a") is None


def test_fmg_resolve_ip(inventory):
    hit = fmg_source.resolve_ip(inventory, "10.2.1.30")
    assert hit["name"] == "srv-db" and hit["provenance"] == "fmg"
    assert fmg_source.resolve_ip(inventory, "10.9.9.9") is None


def test_fmg_search(inventory):
    hits = fmg_source.search(inventory, "srv")
    assert hits and hits[0]["name"] == "srv-db" and hits[0]["provenance"] == "fmg"


async def test_chain_ip_input_collects_names(inventory, monkeypatch):
    chain = ResolverChain()

    async def fake_ptr(cfg, ip):
        return {"name": "db01.corp.example", "provenance": "dns"}
    monkeypatch.setattr(dns_source, "resolve_ip", fake_ptr)

    result = await chain.resolve_endpoint("10.2.1.30", inventory, {}, {})
    assert result["ip"] == "10.2.1.30"
    provs = [n["provenance"] for n in result["names"]]
    assert provs == ["fmg", "dns"]  # iTop nicht konfiguriert → übersprungen


async def test_chain_name_fmg_first(inventory, monkeypatch):
    chain = ResolverChain()

    async def fail_dns(cfg, name):  # DNS darf gar nicht gefragt werden
        raise AssertionError("DNS gefragt obwohl FMG getroffen hat")
    monkeypatch.setattr(dns_source, "resolve_name", fail_dns)

    result = await chain.resolve_endpoint("srv-db", inventory, {}, {})
    assert result["ip"] == "10.2.1.30" and result["provenance"] == "fmg"


async def test_chain_name_dns_fallback(inventory, monkeypatch):
    chain = ResolverChain()

    async def fake_a(cfg, name):
        return {"ip": "10.1.2.20", "name": f"{name}.corp.example", "provenance": "dns"}
    monkeypatch.setattr(dns_source, "resolve_name", fake_a)

    result = await chain.resolve_endpoint("web01", inventory, {}, {})
    assert result["ip"] == "10.1.2.20" and result["provenance"] == "dns"


async def test_chain_unresolvable_raises(inventory, monkeypatch):
    chain = ResolverChain()

    async def no_a(cfg, name):
        return None
    monkeypatch.setattr(dns_source, "resolve_name", no_a)

    with pytest.raises(ValueError, match="keine Quelle"):
        await chain.resolve_endpoint("gibts-nicht", inventory, {}, {})
