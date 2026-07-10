"""Path-Engine gegen die Lab-Matrix (deterministisch via FixtureTransport):
intra-site allow · cross-site allow / implizit-deny / explizit-deny ·
VDOM-Link-Pfad · Ziel=Internet · Gerät offline · Quelle unbekannt · Loop-Guard.
"""
from __future__ import annotations

import pytest

from engine.path import TraceError, find_ingress, run_trace
from engine.verdict import aggregate_verdict
from fmg.client import FmgClient
from fmg.transport import FixtureTransport
from fmg_fixtures import add_policy_lookup, add_route, tcp_params

OVERLAY = "(?i)(vpn|ovl|sdwan|tun|ipsec)"


def make_client() -> tuple[FmgClient, FixtureTransport]:
    t = FixtureTransport()
    return FmgClient(t, auth_mode="token"), t


async def _trace(inventory, prefixes, client, src, dst, port=443):
    return await run_trace(
        src_ip=src, dst_ip=dst, protocol="tcp", dst_port=port,
        inv=inventory, prefixes=prefixes, client=client,
        overlay_pattern=OVERLAY, max_hops=8,
    )


async def test_intra_site_allow(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.1.2.20", "lan2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.1.2.20", 443), 100)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.1.2.20")
    assert len(hops) == 1
    hop = hops[0]
    assert (hop.device, hop.vdom, hop.srcintf, hop.egress) == ("fw-a", "root", "lan1", "lan2")
    assert hop.egress_class == "LOCAL"
    assert hop.verdict == "ALLOW"
    assert hop.matched_policy.policyid == 100 and hop.matched_policy.hit
    assert hop.src_zone == "inside-a"
    assert aggregate_verdict(hops) == "ALLOW"


async def test_cross_site_allow(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.2.1.30", "vpn-to-b")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.2.1.30", 443), 100)
    add_route(t, "fw-b", "root", "10.2.1.30", "lan1")
    add_policy_lookup(t, "fw-b", "root",
                      tcp_params("vpn-to-a", "10.1.1.10", "10.2.1.30", 443), 200)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.2.1.30")
    assert len(hops) == 2
    assert hops[0].egress_class == "OVERLAY"
    assert (hops[1].device, hops[1].srcintf) == ("fw-b", "vpn-to-a")
    assert hops[1].egress_class == "LOCAL"
    assert [h.verdict for h in hops] == ["ALLOW", "ALLOW"]
    assert aggregate_verdict(hops) == "ALLOW"


async def test_cross_site_implicit_deny(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.2.1.30", "vpn-to-b")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.2.1.30", 443), 100)
    add_route(t, "fw-b", "root", "10.2.1.30", "lan1")
    add_policy_lookup(t, "fw-b", "root",
                      tcp_params("vpn-to-a", "10.1.1.10", "10.2.1.30", 443), None)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.2.1.30")
    assert [h.verdict for h in hops] == ["ALLOW", "DENY"]
    assert hops[1].matched_policy is None  # implizites Deny: keine Policy
    assert aggregate_verdict(hops) == "DENY"


async def test_explicit_deny(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.2.1.30", "vpn-to-b")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.2.1.30", 443), 110)
    # Nach dem Deny läuft der Trace best-effort weiter (UI graut spätere Hops aus)
    add_route(t, "fw-b", "root", "10.2.1.30", "lan1")
    add_policy_lookup(t, "fw-b", "root",
                      tcp_params("vpn-to-a", "10.1.1.10", "10.2.1.30", 443), 200)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.2.1.30")
    assert hops[0].verdict == "DENY"
    assert hops[0].matched_policy.policyid == 110
    assert hops[0].matched_policy.action == "deny"
    assert not hops[0].after_deny and hops[1].after_deny
    assert aggregate_verdict(hops) == "DENY"


async def test_vdom_link_path(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.1.8.20", "vlink0")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.1.8.20", 443), 100)
    add_route(t, "fw-a", "dmz", "10.1.8.20", "dmz-lan")
    add_policy_lookup(t, "fw-a", "dmz",
                      tcp_params("vlink1", "10.1.1.10", "10.1.8.20", 443), 100)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.1.8.20")
    assert len(hops) == 2
    assert hops[0].egress_class == "VDOM_LINK"
    assert (hops[1].device, hops[1].vdom, hops[1].srcintf) == ("fw-a", "dmz", "vlink1")
    assert hops[1].egress_class == "LOCAL"
    assert aggregate_verdict(hops) == "ALLOW"


async def test_internet_default_route(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "8.8.8.8", "wan")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "8.8.8.8", 443), 100)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "8.8.8.8")
    assert len(hops) == 1
    assert hops[0].egress_class == "DEFAULT"
    assert hops[0].verdict == "ALLOW"


async def test_device_offline_degraded(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.2.1.30", "vpn-to-b", offline=True)
    # Hop 2 antwortet normal
    add_route(t, "fw-b", "root", "10.2.1.30", "lan1")
    add_policy_lookup(t, "fw-b", "root",
                      tcp_params("vpn-to-a", "10.1.1.10", "10.2.1.30", 443), 200)

    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.2.1.30")
    assert hops[0].degraded
    # Cache-Route (static 10.2.0.0/20 via vpn-to-b) trägt den Pfad weiter
    assert hops[0].route["source"] == "cache-static"
    assert hops[0].egress == "vpn-to-b"
    assert hops[0].verdict == "UNKNOWN"
    assert len(hops) == 2 and hops[1].verdict == "ALLOW"
    assert aggregate_verdict(hops) == "DEGRADED"


async def test_unknown_source_raises(inventory, prefixes):
    client, _ = make_client()
    with pytest.raises(TraceError, match="keinem bekannten Standort-Prefix"):
        await _trace(inventory, prefixes, client, "172.16.99.1", "10.1.1.10")


def test_find_ingress_prefers_connected(inventory, prefixes):
    assert find_ingress(prefixes, inventory, "10.1.1.10") == ("fw-a", "root", "lan1")
    assert find_ingress(prefixes, inventory, "10.2.1.30") == ("fw-b", "root", "lan1")


async def test_candidates_ordered_with_hit(inventory, prefixes):
    client, t = make_client()
    add_route(t, "fw-a", "root", "10.1.2.20", "lan2")
    add_policy_lookup(t, "fw-a", "root",
                      tcp_params("lan1", "10.1.1.10", "10.1.2.20", 443), 100)
    hops = await _trace(inventory, prefixes, client, "10.1.1.10", "10.1.2.20")
    cand = hops[0].candidates
    # Reihenfolge wie im Package; Treffer markiert
    assert [c.policyid for c in cand] == [100, 110]
    assert [c.hit for c in cand] == [True, False]
