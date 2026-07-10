"""PrefixTable: LPM, Quellen-Priorität, Default-Routen-Ausschluss."""
from __future__ import annotations

from inventory.prefixes import PrefixTable


def test_longest_prefix_wins():
    t = PrefixTable()
    t.add("10.1.0.0/20", "static", "fw-a", "root", "vpn")
    t.add("10.1.1.0/24", "connected", "fw-b", "root", "lan1")
    hit = t.lookup("10.1.1.10")
    assert hit.device == "fw-b" and hit.source == "connected"


def test_source_priority_on_tie():
    t = PrefixTable()
    t.add("10.1.1.0/24", "static", "fw-a", "root", "vpn")
    t.add("10.1.1.0/24", "connected", "fw-b", "root", "lan1")
    t.add("10.1.1.0/24", "override", "fw-c", "root", None, site_name="Site C")
    hits = t.lookup_all("10.1.1.10")
    assert [h.source for h in hits] == ["override", "connected", "static"]
    assert t.lookup("10.1.1.10").device == "fw-c"


def test_default_route_excluded():
    t = PrefixTable()
    t.add("0.0.0.0/0", "static", "fw-a", "root", "wan")
    assert t.lookup("8.8.8.8") is None
    assert t.entries == []


def test_no_match_returns_none():
    t = PrefixTable()
    t.add("10.1.0.0/20", "connected", "fw-a", "root", "lan1")
    assert t.lookup("192.168.99.1") is None


def test_lab_inventory_prefixes(inventory, prefixes):
    # Site A connected schlägt die Site-A-Static-Route von fw-b
    hit = prefixes.lookup("10.1.1.10")
    assert (hit.device, hit.vdom, hit.interface) == ("fw-a", "root", "lan1")
    # Site B aus Sicht der Tabelle: connected auf fw-b gewinnt (LPM /24 > /20)
    hit = prefixes.lookup("10.2.1.30")
    assert (hit.device, hit.source) == ("fw-b", "connected")
    # DMZ-Subnetz liegt auf fw-a/dmz
    hit = prefixes.lookup("10.1.8.20")
    assert (hit.device, hit.vdom) == ("fw-a", "dmz")


def test_site_override_wins(inventory):
    table = inventory.build_prefix_table(
        [{"name": "Sonderfall", "cidr": "10.1.1.0/24", "device": "fw-x", "vdom": "root"}]
    )
    assert table.lookup("10.1.1.10").device == "fw-x"
