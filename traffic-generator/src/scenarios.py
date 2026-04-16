"""
Test-Szenarien: Synthetischer Netzwerkverkehr mit Scapy.

Jedes Szenario ist eine Funktion die:
  - Pakete generiert die die entsprechende IDS-Regel auslösen
  - Scapy send() / sendp() mit inter=... für Rate-Control verwendet
  - Kein Payload – nur Header (konform mit IDS-Scope)

Alle Szenarien senden an target_ip von src_ip aus.
"""
from __future__ import annotations

import random
import time

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.sendrecv import send

# Scapy-Warnungen unterdrücken
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def scenario_test_001(src_ip: str, target_ip: str) -> None:
    """
    TEST_001: EICAR-Äquivalent
    TCP-Paket mit SYN+FIN+URG+PSH an Port 65535.
    """
    pkt = (
        IP(src=src_ip, dst=target_ip)
        / TCP(dport=65535, flags="SFUP")
    )
    send(pkt, verbose=False)


def scenario_scan_001(src_ip: str, target_ip: str) -> None:
    """
    SCAN_001: TCP SYN Port Scan
    100 SYN-Pakete an verschiedene Ports in ~3 Sekunden.
    """
    ports = random.sample(range(1, 65535), 100)
    for port in ports:
        pkt = IP(src=src_ip, dst=target_ip) / TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.03)


def scenario_dos_syn_001(src_ip: str, target_ip: str) -> None:
    """
    DOS_SYN_001: SYN Flood
    600 SYN-Pakete an Port 80 in ~6 Sekunden (>500 in 10s Fenster).
    """
    pkt = IP(src=src_ip, dst=target_ip) / TCP(dport=80, flags="S")
    for _ in range(600):
        send(pkt, verbose=False)
        time.sleep(0.01)


def scenario_recon_003(src_ip: str, target_ip: str) -> None:
    """
    RECON_003: ICMP Host Sweep (Ping Sweep)
    ICMP Echo an 25 verschiedene IPs (simuliert /24-Sweep).
    """
    base = target_ip.rsplit(".", 1)[0]
    for i in range(1, 26):
        dst = f"{base}.{i}"
        pkt = IP(src=src_ip, dst=dst) / ICMP()
        send(pkt, verbose=False)
        time.sleep(0.05)


def scenario_dns_dga_001(src_ip: str, _target_ip: str) -> None:
    """
    DNS_DGA_001: DNS High-Entropy (DGA-Verdacht)
    15 DNS-Anfragen für zufällige Hochentropie-Domains an Port 53.
    """
    import string

    def _random_domain(length: int = 16) -> str:
        chars = string.ascii_lowercase + string.digits
        return "".join(random.choices(chars, k=length)) + ".com"

    dns_server = "8.8.8.8"
    for _ in range(15):
        domain = _random_domain()
        pkt = (
            IP(src=src_ip, dst=dns_server)
            / UDP(dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain))
        )
        send(pkt, verbose=False)
        time.sleep(0.1)


# Scenario-Registry
SCENARIOS: dict[str, tuple[str, callable]] = {
    "TEST_001":    ("TEST_001",    scenario_test_001),
    "SCAN_001":    ("SCAN_001",    scenario_scan_001),
    "DOS_SYN_001": ("DOS_SYN_001", scenario_dos_syn_001),
    "RECON_003":   ("RECON_003",   scenario_recon_003),
    "DNS_DGA_001": ("DNS_DGA_001", scenario_dns_dga_001),
}
