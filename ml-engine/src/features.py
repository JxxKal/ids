"""
Feature-Extraktion: Flow-Dict → NumPy-Vektor.

Features (14 Dimensionen):
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
  10  syn_ratio           – Anteil SYN-Flags (tcp_flags['SYN'])
  11  rst_ratio           – Anteil RST-Flags
  12  fin_ratio           – Anteil FIN-Flags
  13  dst_port_norm       – dst_port / 65535 (normiert, 0 wenn kein Port)
"""
from __future__ import annotations

import numpy as np

FEATURE_DIM = 14
FEATURE_NAMES = [
    "duration_s", "pkt_count", "byte_count", "pps", "bps",
    "pkt_size_mean", "pkt_size_std",
    "iat_mean", "iat_std", "entropy_iat",
    "syn_ratio", "rst_ratio", "fin_ratio",
    "dst_port_norm",
]


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
        float(tcp_flags.get("SYN") or 0.0),
        float(tcp_flags.get("RST") or 0.0),
        float(tcp_flags.get("FIN") or 0.0),
        dst_port_norm,
    ], dtype=np.float32)

    # NaN/Inf durch 0 ersetzen (defensiv)
    np.nan_to_num(vec, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    return vec
