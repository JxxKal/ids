"""Secret-Masking: GET maskiert, PATCH-Sentinel überschreibt nicht."""
from __future__ import annotations

from secrets_mask import SENTINEL, mask_secrets, merge_secrets


def test_mask_replaces_set_secrets():
    masked = mask_secrets("fmg", {"host": "fmg.local", "token": "s3cret", "password": ""})
    assert masked["token"] == SENTINEL
    assert masked["password"] == ""       # leere Secrets bleiben leer
    assert masked["host"] == "fmg.local"  # Nicht-Secrets unangetastet


def test_mask_unknown_key_is_noop():
    value = {"resolvers": ["10.0.0.53"]}
    assert mask_secrets("dns", value) == value


def test_merge_keeps_stored_secret_on_sentinel():
    stored = {"host": "fmg.local", "token": "s3cret"}
    incoming = {"host": "fmg.new", "token": SENTINEL}
    merged = merge_secrets("fmg", incoming, stored)
    assert merged["token"] == "s3cret"
    assert merged["host"] == "fmg.new"


def test_merge_accepts_new_secret():
    merged = merge_secrets("fmg", {"token": "brand-new"}, {"token": "old"})
    assert merged["token"] == "brand-new"


def test_roundtrip_get_patch_get():
    """Der kritische Fall: GET → (unverändert zurück-PATCHen) → Secret intakt."""
    stored = {"host": "fmg.local", "token": "s3cret", "password": "pw"}
    ui_view = mask_secrets("fmg", stored)
    merged = merge_secrets("fmg", ui_view, stored)
    assert merged == stored


def test_merge_without_stored_state():
    merged = merge_secrets("fmg", {"token": SENTINEL}, None)
    assert merged["token"] == ""  # kein Alt-Wert vorhanden → leer, nie der Sentinel
