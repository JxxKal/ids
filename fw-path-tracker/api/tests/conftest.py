"""Gemeinsame Test-Fixtures: synthetisches Lab mit 2 Sites + VDOM-Link.

Topologie:
  Site A (10.1.0.0/20) — fw-a (VDOMs root + dmz, ADOM corp)
    root: lan1 10.1.1.1/24, lan2 10.1.2.1/24, vpn-to-b (tunnel), wan, vlink0
    dmz:  vlink1, dmz-lan 10.1.8.1/24
  Site B (10.2.0.0/20) — fw-b (VDOM root, ADOM corp)
    root: lan1 10.2.1.1/24, vpn-to-a (tunnel), wan
  Full-Mesh: statische Routen über die vpn-Tunnel; Default-Route via wan.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from inventory.store import Inventory  # noqa: E402

ADOM = "corp"


def _row(kind: str, key: str, data) -> dict:
    return {"adom": ADOM, "kind": kind, "key": key, "data": data}


def lab_snapshot_rows() -> list[dict]:
    return [
        _row("device", "fw-a", {"name": "fw-a", "vdom": [{"name": "root"}, {"name": "dmz"}]}),
        _row("device", "fw-b", {"name": "fw-b", "vdom": [{"name": "root"}]}),

        _row("interface", "fw-a", [
            {"name": "lan1", "ip": ["10.1.1.1", "255.255.255.0"], "vdom": ["root"]},
            {"name": "lan2", "ip": ["10.1.2.1", "255.255.255.0"], "vdom": ["root"]},
            {"name": "vpn-to-b", "type": "tunnel", "vdom": ["root"]},
            {"name": "wan", "ip": ["203.0.113.1", "255.255.255.252"], "vdom": ["root"]},
            {"name": "vlink0", "type": "vdom-link", "vdom": ["root"]},
            {"name": "vlink1", "type": "vdom-link", "vdom": ["dmz"]},
            {"name": "dmz-lan", "ip": ["10.1.8.1", "255.255.255.0"], "vdom": ["dmz"]},
        ]),
        _row("interface", "fw-b", [
            {"name": "lan1", "ip": ["10.2.1.1", "255.255.255.0"], "vdom": ["root"]},
            {"name": "vpn-to-a", "type": "tunnel", "vdom": ["root"]},
            {"name": "wan", "ip": ["198.51.100.1", "255.255.255.252"], "vdom": ["root"]},
        ]),

        _row("zone", "inside-a", {"name": "inside-a", "dynamic_mapping": [
            {"_scope": [{"name": "fw-a", "vdom": "root"}], "local-intf": ["lan1", "lan2"]},
        ]}),
        _row("zone", "overlay", {"name": "overlay", "dynamic_mapping": [
            {"_scope": [{"name": "fw-a", "vdom": "root"}], "local-intf": ["vpn-to-b"]},
            {"_scope": [{"name": "fw-b", "vdom": "root"}], "local-intf": ["vpn-to-a"]},
        ]}),

        _row("package", "pkg-a", {"name": "pkg-a", "scope member": [
            {"name": "fw-a", "vdom": "root"}, {"name": "fw-a", "vdom": "dmz"},
        ]}),
        _row("package", "pkg-b", {"name": "pkg-b", "scope member": [
            {"name": "fw-b", "vdom": "root"},
        ]}),

        _row("policy", "pkg-a", [
            {"policyid": 100, "name": "allow-inside", "action": 1, "status": 1,
             "srcintf": ["inside-a"], "dstintf": ["any"],
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"]},
            {"policyid": 110, "name": "deny-guest", "action": 0, "status": 1,
             "srcintf": ["any"], "dstintf": ["any"],
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"]},
        ]),
        _row("policy", "pkg-b", [
            {"policyid": 200, "name": "allow-from-a", "action": 1, "status": 1,
             "srcintf": ["overlay"], "dstintf": ["any"],
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"]},
            {"policyid": 210, "name": "deny-legacy", "action": 0, "status": 1,
             "srcintf": ["any"], "dstintf": ["any"],
             "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"]},
        ]),

        _row("address", "srv-db", {"name": "srv-db",
                                   "subnet": ["10.2.1.30", "255.255.255.255"]}),
        _row("address", "net-site-a", {"name": "net-site-a",
                                       "subnet": ["10.1.0.0", "255.255.240.0"]}),
        _row("service", "HTTPS", {"name": "HTTPS", "protocol": "TCP/UDP/SCTP",
                                  "tcp-portrange": ["443"]}),
        _row("vip", "vip-web", {"name": "vip-web", "extip": "203.0.113.10",
                                "mappedip": ["10.1.2.20"]}),

        _row("route", "fw-a|root", [
            {"dst": ["10.2.0.0", "255.255.240.0"], "device": ["vpn-to-b"], "gateway": "0.0.0.0"},
            {"dst": ["0.0.0.0", "0.0.0.0"], "device": ["wan"], "gateway": "203.0.113.2"},
        ]),
        _row("route", "fw-b|root", [
            {"dst": ["10.1.0.0", "255.255.240.0"], "device": ["vpn-to-a"], "gateway": "0.0.0.0"},
            {"dst": ["0.0.0.0", "0.0.0.0"], "device": ["wan"], "gateway": "198.51.100.2"},
        ]),
    ]


@pytest.fixture
def inventory() -> Inventory:
    return Inventory.build(lab_snapshot_rows(), synced_at="2026-07-10T00:00:00+00:00")


@pytest.fixture
def prefixes(inventory: Inventory):
    return inventory.build_prefix_table()
