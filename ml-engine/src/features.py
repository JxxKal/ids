"""
Feature-Extraktion: Flow-Dict → NumPy-Vektor.

Features (18 Dimensionen):
  0   duration_s          – Flow-Dauer in Sekunden
  1   pkt_count           – Anzahl Pakete
  2   byte_count          – Anzahl Bytes
  3   pps                 – Pakete pro Sekunde
  4   bps                 – Bytes pro Sekunde
  5   pkt_size_mean       – Mittlere Paketgröße
  6   pkt_size_std        – Standardabweichung Paketgröße
  7   iat_mean            – Mittlere Inter-Arrival-Time
  8   iat_std             – Standardabweichung IAT
  9   entropy_iat         – Shannon-Entropie der IAT-Verteilung
  10  syn_ratio           – Anteil SYN-Flags
  11  rst_ratio           – Anteil RST-Flags
  12  fin_ratio           – Anteil FIN-Flags
  13  dst_port_norm       – dst_port / 65535 (0 wenn kein Port)
  14  is_short_flow       – 1 wenn pkt_count <= 2 (Probe-Pattern)
  15  is_syn_only         – 1 wenn syn_ratio==1 und keine RST/FIN (Stealth-Scan)
  16  dst_port_known      – 1 wenn dst_port in {SSH,HTTP,HTTPS,DNS,SMTP,RDP,FTP,Telnet,POP3,IMAP,HTTP-alt,HTTPS-alt,Submission,SMTPS,SNMP}
  17  is_privileged_dst   – 1 wenn dst_port < 1024
"""
from __future__ import annotations

import numpy as np

FEATURE_DIM = 18
FEATURE_NAMES = [
    "duration_s", "pkt_count", "byte_count", "pps", "bps",
    "pkt_size_mean", "pkt_size_std",
    "iat_mean", "iat_std", "entropy_iat",
    "syn_ratio", "rst_ratio", "fin_ratio",
    "dst_port_norm",
    "is_short_flow", "is_syn_only", "dst_port_known", "is_privileged_dst",
]

_KNOWN_PORTS = {22, 80, 443, 53, 25, 3389, 21, 23, 110, 143, 8080, 8443, 587, 465, 161}


def extract(flow: dict) -> np.ndarray:
    """Extrahiert einen Feature-Vektor aus einem Flow-Dict. Gibt float32-Array zurück."""
    pkt_size  = flow.get("pkt_size")  or {}
    iat       = flow.get("iat")       or {}
    tcp_flags = flow.get("tcp_flags") or {}

    duration  = float(flow.get("duration_s") or 0.0)
    pkt_count = float(flow.get("pkt_count")  or 0.0)
    byte_count= float(flow.get("byte_count") or 0.0)
    pps       = float(flow.get("pps")        or 0.0)
    bps       = float(flow.get("bps")        or 0.0)

    dst_port  = flow.get("dst_port")
    dst_port_norm = float(dst_port) / 65535.0 if dst_port is not None else 0.0

    syn = float(tcp_flags.get("SYN") or 0.0)
    rst = float(tcp_flags.get("RST") or 0.0)
    fin = float(tcp_flags.get("FIN") or 0.0)

    is_short_flow      = 1.0 if pkt_count <= 2.0 else 0.0
    is_syn_only        = 1.0 if (syn >= 0.99 and rst < 0.01 and fin < 0.01) else 0.0
    dst_port_known     = 1.0 if (dst_port is not None and int(dst_port) in _KNOWN_PORTS) else 0.0
    is_privileged_dst  = 1.0 if (dst_port is not None and 0 < int(dst_port) < 1024) else 0.0

    vec = np.array([
        duration,
        pkt_count,
        byte_count,
        pps,
        bps,
        float(pkt_size.get("mean") or 0.0),
        float(pkt_size.get("std")  or 0.0),
        float(iat.get("mean")      or 0.0),
        float(iat.get("std")       or 0.0),
        float(flow.get("entropy_iat") or 0.0),
        syn, rst, fin,
        dst_port_norm,
        is_short_flow, is_syn_only, dst_port_known, is_privileged_dst,
    ], dtype=np.float32)

    np.nan_to_num(vec, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    return vec
