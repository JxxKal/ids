"""Suggestion-Builder: Objekt-Wiederverwendung, Neuvorschläge, CLI/JSON-RPC."""
from __future__ import annotations

from engine.verdict import Hop
from suggest.builder import build_suggestion


def _deny_hop(**overrides) -> Hop:
    base = dict(index=1, device="fw-b", vdom="root", adom="corp",
                srcintf="vpn-to-a", src_zone="overlay",
                egress="lan1", egress_zone="lan1", egress_class="LOCAL",
                verdict="DENY")
    base.update(overrides)
    return Hop(**base)


def test_reuses_existing_objects(inventory):
    s = build_suggestion(
        inventory, _deny_hop(),
        src_ip="10.1.1.10", dst_ip="10.2.1.30", protocol="tcp", dst_port=443,
        src_names=[{"name": "ws0042.corp.example", "provenance": "dns"}],
        dst_names=[{"name": "srv-db", "provenance": "fmg"}],
    )
    # Ziel: exaktes /32-Objekt existiert → wiederverwenden
    assert s["dst_obj"] == {"name": "srv-db", "existing": True}
    # Quelle: nur /20-Netz-Objekt matcht → das engste existierende Objekt
    assert s["src_obj"]["name"] == "net-site-a" and s["src_obj"]["existing"]
    # Service 443 existiert
    assert s["service"] == {"name": "HTTPS", "existing": True}
    assert s["src_zone"] == "overlay" and s["dst_zone"] == "lan1"
    assert s["package"] == "pkg-b"
    assert 'set srcintf "overlay"' in s["cli"]
    assert "Installation via FortiManager" in s["note"]


def test_new_objects_when_nothing_matches(inventory):
    s = build_suggestion(
        inventory, _deny_hop(),
        src_ip="192.0.2.77", dst_ip="10.2.9.9", protocol="udp", dst_port=1514,
        src_names=[{"name": "extern-host.example.net", "provenance": "dns"}],
        dst_names=[],
    )
    assert s["src_obj"]["existing"] is False
    assert s["src_obj"]["name"] == "h-extern-host"       # Hostname-Kurzform
    assert s["src_obj"]["subnet"] == "192.0.2.77/32"
    assert s["dst_obj"]["name"] == "h-10.2.9.9"          # kein Name → IP
    assert s["service"]["existing"] is False
    assert s["service"]["name"] == "svc-udp-1514"
    # Neue Objekte tauchen im CLI auf
    assert "config firewall address" in s["cli"]
    assert "set udp-portrange 1514" in s["cli"]
    # JSON-RPC-Bodies: 2 Adressen + 1 Service + 1 Policy
    assert len(s["jsonrpc"]) == 4
    assert '"method": "add"' in s["jsonrpc"][0]


def test_icmp_uses_all_icmp(inventory):
    s = build_suggestion(
        inventory, _deny_hop(),
        src_ip="10.1.1.10", dst_ip="10.2.1.30", protocol="icmp", dst_port=None,
        src_names=[], dst_names=[],
    )
    assert s["service"] == {"name": "ALL_ICMP", "existing": True}


def test_missing_adom_returns_none(inventory):
    hop = _deny_hop(adom=None)
    assert build_suggestion(inventory, hop, src_ip="1.2.3.4", dst_ip="5.6.7.8",
                            protocol="tcp", dst_port=80,
                            src_names=[], dst_names=[]) is None
