"""Secret-Masking für den Config-Store.

GET liefert statt gespeicherter Secrets den Sentinel; PATCH merged den
Sentinel zurück auf den gespeicherten Wert — sonst würde jeder
Settings-Save das Secret mit der Maske überschreiben.
"""
from __future__ import annotations

from copy import deepcopy

SENTINEL = "•••"

# Pro Config-Key: welche Felder im JSONB sind Secrets.
SECRET_FIELDS: dict[str, tuple[str, ...]] = {
    "fmg": ("token", "password"),
    "itop": ("password",),
}


def mask_secrets(key: str, value: dict) -> dict:
    """Ersetzt gesetzte Secret-Felder durch den Sentinel (für GET)."""
    fields = SECRET_FIELDS.get(key)
    if not fields:
        return value
    out = deepcopy(value)
    for f in fields:
        if out.get(f):
            out[f] = SENTINEL
    return out


def merge_secrets(key: str, incoming: dict, stored: dict | None) -> dict:
    """Merged eingehende Werte (für PATCH): Sentinel ⇒ gespeicherten Wert behalten."""
    fields = SECRET_FIELDS.get(key)
    if not fields:
        return incoming
    out = deepcopy(incoming)
    stored = stored or {}
    for f in fields:
        if out.get(f) == SENTINEL:
            out[f] = stored.get(f, "")
    return out
