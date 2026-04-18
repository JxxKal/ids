"""
Synthetische Flow-Szenarien für den Traffic Generator.

Jedes Szenario erzeugt eine Liste von Flow-Dicts die direkt in das
Kafka-Topic 'flows' injiziert werden – kein Packet-Capture nötig.

Die Flows haben is_test=True, sodass sie im Alert-Log gesondert markiert
und gefiltert werden können.
"""
from __future__ import annotations

import random
from typing import Callable


def scenario_test_001(src_ip: str, _target_ip: str) -> list[dict]:
    """TEST_001: EICAR-Äquivalent – TCP SYN+FIN+URG+PSH an Port 65535."""
    return [
        {
            "proto":    "TCP",
            "src_ip":   src_ip,
            "dst_ip":   "10.0.0.1",
            "dst_port": 65535,
            "is_test":  True,
            "stats": {
                "tcp_flags_abs": {"SYN": 1, "FIN": 1, "URG": 1, "PSH": 1,
                                  "ACK": 0, "RST": 0},
            },
        }
    ]


def scenario_scan_001(src_ip: str, _target_ip: str) -> list[dict]:
    """
    SCAN_001: TCP SYN Port Scan
    55 SYN-Flows an verschiedene Ports → unique_dst_ports > 50 in 60s.
    """
    ports = random.sample(range(1, 65535), 55)
    return [
        {
            "proto":    "TCP",
            "src_ip":   src_ip,
            "dst_ip":   "10.0.0.1",
            "dst_port": port,
            "is_test":  True,
            "stats": {
                "tcp_flags_abs": {"SYN": 1, "FIN": 0, "ACK": 0,
                                  "RST": 0, "PSH": 0, "URG": 0},
                "connection_state": "SYN_ONLY",
            },
        }
        for port in ports
    ]


def scenario_dos_syn_001(src_ip: str, _target_ip: str) -> list[dict]:
    """
    DOS_SYN_001: SYN Flood
    510 SYN-Flows → syn_count > 500 in 10s.
    """
    return [
        {
            "proto":    "TCP",
            "src_ip":   src_ip,
            "dst_ip":   "10.0.0.1",
            "dst_port": 80,
            "is_test":  True,
            "stats": {
                "tcp_flags_abs": {"SYN": 1, "FIN": 0, "ACK": 0,
                                  "RST": 0, "PSH": 0, "URG": 0},
            },
        }
        for _ in range(510)
    ]


def scenario_recon_003(src_ip: str, _target_ip: str) -> list[dict]:
    """
    RECON_003: Viele RST-Verbindungen
    55 TCP-RST-Flows → flow_rate > 50 in 60s, connection_state == RESET.
    """
    return [
        {
            "proto":    "TCP",
            "src_ip":   src_ip,
            "dst_ip":   "10.0.0.1",
            "dst_port": random.randint(1, 65535),
            "is_test":  True,
            "stats": {
                "connection_state": "RESET",
                "tcp_flags_abs": {"SYN": 0, "FIN": 0, "ACK": 0,
                                  "RST": 1, "PSH": 0, "URG": 0},
            },
        }
        for _ in range(55)
    ]


def scenario_dns_dga_001(src_ip: str, _target_ip: str) -> list[dict]:
    """
    DNS_DGA_001: DNS High-Entropy (DGA-Verdacht)
    Einzelner UDP-Flow an Port 53 mit hoher IAT-Entropie und >10 Paketen.
    """
    return [
        {
            "proto":    "UDP",
            "src_ip":   src_ip,
            "dst_ip":   "8.8.8.8",
            "dst_port": 53,
            "is_test":  True,
            "stats": {
                "entropy_iat": 3.2,
                "pkt_count":   15,
                "byte_count":  1200,
            },
        }
    ]


# Scenario-Registry: scenario_id → (expected_rule_id, fn)
SCENARIOS: dict[str, tuple[str, Callable]] = {
    "TEST_001":    ("TEST_001",    scenario_test_001),
    "SCAN_001":    ("SCAN_001",    scenario_scan_001),
    "DOS_SYN_001": ("DOS_SYN_001", scenario_dos_syn_001),
    "RECON_003":   ("RECON_003",   scenario_recon_003),
    "DNS_DGA_001": ("DNS_DGA_001", scenario_dns_dga_001),
}
