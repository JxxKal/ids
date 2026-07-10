"""Path-Engine: Hop-Loop mit Live-Lookups (router/lookup + firewall/policy-lookup).

Pro Hop laufen genau zwei Live-Aufrufe gegen die FortiGate (via FMG-Proxy);
alles andere (Kandidaten, Zonen, Namen) kommt aus dem Inventory-Cache.
Gerät offline ⇒ Degraded Mode: Route aus dem Cache, Verdict UNKNOWN.
"""
from __future__ import annotations

import ipaddress
import logging

from engine.classify import classify_egress
from engine.verdict import Candidate, Hop
from fmg.client import FmgClient, FmgError, FmgTargetOffline
from fmg.proxy import fortios_results, monitor_get
from inventory.prefixes import PrefixTable
from inventory.store import Inventory

log = logging.getLogger("engine.path")

PROTO_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1}


class TraceError(Exception):
    """Harter Fehler, der den Trace verhindert (z.B. Quelle unbekannt)."""


def find_ingress(prefixes: PrefixTable, inv: Inventory, src_ip: str) -> tuple[str, str, str]:
    """Start-(Device, VDOM, srcintf) aus der PrefixTable (connected bevorzugt)."""
    entries = prefixes.lookup_all(src_ip)
    if not entries:
        raise TraceError(
            f"Quelle {src_ip} liegt in keinem bekannten Standort-Prefix. "
            "FMG-Sync aktuell? Site-Override unter Einstellungen → Standorte möglich."
        )
    entry = next((e for e in entries if e.source in ("override", "connected")), entries[0])
    srcintf = entry.interface
    if not srcintf:
        # Override ohne Interface: connected Netz der Quelle auf dem Gerät suchen
        addr = ipaddress.IPv4Address(src_ip)
        for net, intf in inv.connected_networks(entry.device, entry.vdom):
            if addr in net:
                srcintf = intf
                break
    if not srcintf:
        raise TraceError(
            f"Kein Quell-Interface für {src_ip} auf {entry.device}/{entry.vdom} bestimmbar."
        )
    return entry.device, entry.vdom, srcintf


async def _live_route(client: FmgClient, adom: str, device: str, vdom: str,
                      dst_ip: str) -> dict | None:
    """router/lookup → {interface, gateway, ...} oder None (kein Treffer).

    ASSUMPTION (Lab): Feldnamen der Antwort variieren (interface/oif/gateway) —
    Parser ist tolerant, gegen Lab-Mitschnitt verifizieren.
    """
    resp = await monitor_get(client, adom, device, vdom, "router/lookup",
                             {"destination": dst_ip})
    results = fortios_results(resp)
    if isinstance(results, list):
        results = results[0] if results else None
    if not isinstance(results, dict):
        return None
    interface = results.get("interface") or results.get("oif") or results.get("intf")
    if not interface:
        return None
    return {
        "interface": interface,
        "gateway": results.get("gateway") or results.get("gw"),
        "raw": results,
        "source": "live",
    }


def cached_route(inv: Inventory, device: str, vdom: str, dst_ip: str) -> dict | None:
    """Degraded Mode: LPM über connected + statische Routen aus dem Cache."""
    addr = ipaddress.IPv4Address(dst_ip)
    best: tuple[int, dict] | None = None
    for net, intf in inv.connected_networks(device, vdom):
        if addr in net and (best is None or net.prefixlen >= best[0]):
            best = (net.prefixlen, {"interface": intf, "gateway": None,
                                    "source": "cache-connected"})
    for rt in inv.static_routes.get((device, vdom), []):
        if addr in rt["network"] and rt.get("interface"):
            if best is None or rt["network"].prefixlen > best[0]:
                best = (rt["network"].prefixlen,
                        {"interface": rt["interface"], "gateway": rt.get("gateway"),
                         "source": "cache-static"})
    return best[1] if best else None


async def _live_policy_lookup(client: FmgClient, adom: str, device: str, vdom: str,
                              srcintf: str, src_ip: str, dst_ip: str, protocol: str,
                              dst_port: int | None, src_port: int | None,
                              icmp_type: int | None, icmp_code: int | None) -> dict:
    """firewall/policy-lookup → {success, policy_id}.

    ASSUMPTION (Lab): exakte Form des Erfolgs-Payloads verifizieren
    (success/policy_id vs. results-verschachtelt).
    """
    params: dict = {
        "srcintf": srcintf,
        "sourceip": src_ip,
        "dest": dst_ip,
        "protocol": protocol.lower(),
    }
    if protocol.lower() == "icmp":
        if icmp_type is not None:
            params["icmptype"] = icmp_type
        if icmp_code is not None:
            params["icmpcode"] = icmp_code
    else:
        if dst_port is not None:
            params["destport"] = dst_port
        if src_port is not None:
            params["sourceport"] = src_port
    resp = await monitor_get(client, adom, device, vdom, "firewall/policy-lookup", params)
    results = fortios_results(resp)
    if not isinstance(results, dict):
        results = resp if isinstance(resp, dict) else {}
    success = bool(results.get("success"))
    policy_id = results.get("policy_id", results.get("policyid"))
    return {"success": success, "policy_id": policy_id}


async def run_trace(*, src_ip: str, dst_ip: str, protocol: str,
                    dst_port: int | None = None, src_port: int | None = None,
                    icmp_type: int | None = None, icmp_code: int | None = None,
                    inv: Inventory, prefixes: PrefixTable, client: FmgClient,
                    overlay_pattern: str, max_hops: int = 8) -> list[Hop]:
    device, vdom, srcintf = find_ingress(prefixes, inv, src_ip)

    hops: list[Hop] = []
    visited: set[tuple[str, str]] = set()
    deny_seen = False

    while len(hops) < max_hops:
        if (device, vdom) in visited:
            if hops:
                hops[-1].warnings.append(
                    f"Routing-Schleife erkannt: {device}/{vdom} bereits besucht — Abbruch."
                )
            break
        visited.add((device, vdom))
        adom = inv.adom_of(device)
        hop = Hop(index=len(hops), device=device, vdom=vdom, adom=adom,
                  srcintf=srcintf, src_zone=inv.zone_of(device, vdom, srcintf),
                  after_deny=deny_seen)

        # ── a) Route (live, sonst Cache) ─────────────────────────────────────
        route = None
        if adom is None:
            hop.warnings.append(f"Gerät {device} nicht im FMG-Snapshot — Sync nötig.")
        else:
            try:
                route = await _live_route(client, adom, device, vdom, dst_ip)
            except FmgTargetOffline as exc:
                hop.degraded = True
                hop.warnings.append(f"{exc} — nutze gecachte Routen (Degraded Mode).")
            except FmgError as exc:
                hop.degraded = True
                hop.warnings.append(f"Route-Lookup fehlgeschlagen: {exc}")
        if route is None:
            route = cached_route(inv, device, vdom, dst_ip)
            if route is not None and not hop.degraded and adom is not None:
                hop.warnings.append("Live-Route ohne Treffer — Cache-Route verwendet.")
        hop.route = route
        if route is None:
            hop.egress_class = "DEFAULT"
            hop.warnings.append(
                f"Keine Route zu {dst_ip} auf {device}/{vdom} — Ziel unerreichbar?"
            )
            hop.verdict = "UNKNOWN"
            hops.append(hop)
            break
        hop.egress = route["interface"]
        hop.egress_zone = inv.zone_of(device, vdom, hop.egress)

        # ── b) Klassifikation ────────────────────────────────────────────────
        cls = classify_egress(inv, prefixes, overlay_pattern, device, vdom,
                              hop.egress, dst_ip)
        hop.egress_class = cls.egress_class
        hop.warnings.extend(cls.warnings)

        # ── c) Policy-Lookup (live) ──────────────────────────────────────────
        lookup = None
        if not hop.degraded and adom is not None:
            try:
                lookup = await _live_policy_lookup(
                    client, adom, device, vdom, srcintf, src_ip, dst_ip,
                    protocol, dst_port, src_port, icmp_type, icmp_code)
            except FmgTargetOffline as exc:
                hop.degraded = True
                hop.warnings.append(f"{exc} — Verdict UNKNOWN.")
            except FmgError as exc:
                hop.warnings.append(f"Policy-Lookup fehlgeschlagen: {exc}")

        # ── d) Kandidaten + Verdict ──────────────────────────────────────────
        candidates = [Candidate(**p) for p in
                      inv.candidate_policies(device, vdom, srcintf, hop.egress)]
        if lookup is None:
            hop.verdict = "UNKNOWN"
        elif not lookup["success"]:
            hop.verdict = "DENY"  # implizites Deny (keine Policy matcht)
        else:
            pid = lookup["policy_id"]
            match = next((c for c in candidates if c.policyid == pid), None)
            if match is None:
                # Nicht in den Kandidaten (Zonen-Filter oder Cache stale) →
                # in der vollen Policy-Liste suchen
                full = next((Candidate(**p) for p in inv.policies.get((device, vdom), [])
                             if p.get("policyid") == pid), None)
                if full is not None:
                    match = full
                    candidates.insert(0, full)
                    hop.warnings.append(
                        f"Policy {pid} matcht live, war aber nicht in den "
                        "Zonen-Kandidaten — Zonen-Mapping prüfen."
                    )
            if match is not None:
                match.hit = True
                hop.matched_policy = match
                hop.verdict = "ALLOW" if match.action == "accept" else "DENY"
            else:
                hop.verdict = "UNKNOWN"
                hop.warnings.append(
                    f"Policy {pid} matcht live, ist aber nicht im FMG-Cache — "
                    "Sync veraltet? Aktion unbekannt."
                )
        hop.candidates = candidates
        if hop.verdict == "DENY":
            deny_seen = True
        hops.append(hop)

        # ── e) Nächster Hop ──────────────────────────────────────────────────
        if cls.egress_class in ("LOCAL", "DEFAULT"):
            break
        if cls.next_device is None or cls.next_vdom is None:
            break
        device, vdom = cls.next_device, cls.next_vdom
        srcintf = cls.next_srcintf or "any"
    else:
        if hops:
            hops[-1].warnings.append(f"max_hops={max_hops} erreicht — Trace abgebrochen.")

    return hops
