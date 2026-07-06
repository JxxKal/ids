"""Gemeinsame Validierung für Werte, die in /opt/ids/.env geschrieben werden.

Jeder Wert, der host-seitig zeilenbasiert nach `.env` geht, muss frei von
Newlines/Steuerzeichen sein — sonst kann ein `\n` beliebige zusätzliche
.env-Zeilen injizieren (z.B. `\nPOSTGRES_PASSWORD=…`). Diese Helfer werden von
allen .env-Schreibpfaden genutzt (system.py Interface-Config, migration.py
Host-Migration-Import), damit die Prüfung an EINER Stelle lebt.
"""
import re

# Erlaubte Interface-Namen: nur alphanumerisch + _ . : - , 1–32 Zeichen.
# Newlines/Steuerzeichen werden durch fullmatch implizit abgelehnt.
IFACE_NAME_RE = re.compile(r"[A-Za-z0-9_.:-]{1,32}")

# IPv4/IPv6-Adresse (grob) — nur Hex/Ziffern, '.', ':', 1–45 Zeichen. Deckt
# MANAGEMENT_IP ab; die exakte Adress-Semantik prüft nachgelagert ip -j addr.
IP_ADDR_RE = re.compile(r"[0-9A-Fa-f.:]{1,45}")


def valid_iface_name(name: str) -> bool:
    """True, wenn `name` ein sicherer, .env-schreibbarer Interface-Name ist."""
    return bool(name) and IFACE_NAME_RE.fullmatch(name) is not None


def valid_ip_addr(value: str) -> bool:
    """True, wenn `value` eine .env-schreibbare IP-Adresse ist (keine Steuerzeichen)."""
    return bool(value) and IP_ADDR_RE.fullmatch(value) is not None
