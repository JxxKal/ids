"""
Minimaler PCAP-Datei-Writer (libpcap-Format, kein externe Abhängigkeit).

Format-Referenz: https://wiki.wireshark.org/Development/LibpcapFileFormat

Globaler Header (24 Bytes):
  magic_number  = 0xa1b2c3d4  (little-endian → timestamps in Sekunden+Mikrosekunden)
  version_major = 2
  version_minor = 4
  thiszone      = 0           (UTC)
  sigfigs       = 0
  snaplen       = 65535
  network       = 1           (LINKTYPE_ETHERNET)

Pro Paket (16 Bytes + Daten):
  ts_sec   – Sekunden-Anteil des Timestamps
  ts_usec  – Mikrosekunden-Anteil
  incl_len – tatsächlich gespeicherte Bytes
  orig_len – ursprüngliche Paketlänge (= incl_len da wir snaplen-limitiert aufzeichnen)
"""
from __future__ import annotations

import io
import struct

_PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,   # magic
    2,            # version major
    4,            # version minor
    0,            # thiszone (GMT)
    0,            # sigfigs
    65535,        # snaplen
    1,            # LINKTYPE_ETHERNET
)

_PKT_HEADER_FMT = "<IIII"


def build_pcap(packets: list[tuple[float, bytes]]) -> bytes:
    """
    Baut aus einer Liste von (timestamp, raw_bytes) ein PCAP-Byte-String.
    Pakete werden nach Timestamp sortiert.
    """
    buf = io.BytesIO()
    buf.write(_PCAP_GLOBAL_HEADER)

    for ts, raw in sorted(packets, key=lambda x: x[0]):
        ts_sec  = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        pkt_len = len(raw)
        buf.write(struct.pack(_PKT_HEADER_FMT, ts_sec, ts_usec, pkt_len, pkt_len))
        buf.write(raw)

    return buf.getvalue()
