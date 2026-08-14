"""Konfigurations-Auflösung: ENV ist Bootstrap, die DB überlagert.

Vertrag: docs/internal-api.md, Abschnitt „Konfiguration: DB schlägt ENV".
"""
from __future__ import annotations

import pytest

from config import CONNECTION_FIELDS, Config, env_dict, merge_db_overlay
from db_config import ConfigStore


def make_env(**over) -> dict:
    """Deterministisches ENV-Dict — unabhängig davon, was im Testrunner
    zufällig an HTTPS_PROXY o.ä. gesetzt ist."""
    d = env_dict()
    d.update({
        "enabled": True,
        "proxy_url": "",
        "device_token": "",
        "sentry_name": "cyjan-master",
        "https_proxy": "",
        "no_proxy": "",
        "ca_file": "",
        "tls_insecure": False,
        "allow_triage": False,
        "severity_min": "medium",
        "api_secret_key": "",
        "postgres_dsn": "",
        "internal_host": "127.0.0.1",
        "internal_port": 8090,
    })
    d.update(over)
    return d


def cfg(env_over: dict | None = None, db: dict | None = None) -> Config:
    return Config.from_dict(merge_db_overlay(make_env(**(env_over or {})), db))


# ── Präzedenz ────────────────────────────────────────────────────────────────


def test_ohne_db_gilt_env():
    c = cfg({"proxy_url": "wss://env.example/tunnel"})
    assert c.proxy_url == "wss://env.example/tunnel"
    assert c.config_source == "env"
    assert c.db_fields == ()


def test_db_schlaegt_env():
    c = cfg({"proxy_url": "wss://env.example/tunnel", "sentry_name": "aus-env"},
            {"proxy_url": "wss://db.example/tunnel", "sentry_name": "aus-db"})
    assert c.proxy_url == "wss://db.example/tunnel"
    assert c.sentry_name == "aus-db"
    assert c.config_source == "db"
    assert set(c.db_fields) == {"proxy_url", "sentry_name"}


@pytest.mark.parametrize("empty", ["", "   "])
def test_leerer_db_wert_faellt_auf_env_zurueck(empty):
    """Sonst bekäme man einen per ENV gesetzten Proxy in der GUI nie mehr los."""
    c = cfg({"https_proxy": "http://env-proxy:3128"}, {"https_proxy": empty})
    assert c.https_proxy == "http://env-proxy:3128"
    assert "https_proxy" not in c.db_fields
    assert c.egress_source == "env"


def test_fehlendes_db_feld_laesst_env_stehen():
    c = cfg({"ca_file": "/etc/cyjan/certs/corp-ca.pem"}, {"proxy_url": "wss://db/t"})
    assert c.ca_file == "/etc/cyjan/certs/corp-ca.pem"


def test_enabled_false_schaltet_ab():
    c = cfg({"proxy_url": "wss://env/t", "device_token": "tok"},
            {"enabled": False})
    assert c.enabled is False
    assert c.has_credentials is True      # eingerichtet …
    assert c.configured is False          # … aber bewusst abgeschaltet


def test_enabled_true_aus_db_ueberschreibt_env_false():
    c = cfg({"enabled": False}, {"enabled": True})
    assert c.enabled is True


def test_enabled_akzeptiert_string_boolean():
    assert cfg({}, {"enabled": "false"}).enabled is False
    assert cfg({"enabled": False}, {"enabled": "true"}).enabled is True


def test_muell_im_db_wert_wird_ignoriert():
    c = cfg({"proxy_url": "wss://env/t", "severity_min": "high"},
            {"proxy_url": 42, "severity_min": "gigantisch", "enabled": "vielleicht"})
    assert c.proxy_url == "wss://env/t"
    assert c.severity_min == "high"
    assert c.enabled is True
    assert c.db_fields == ()


def test_overlay_none_oder_kein_dict():
    for db in (None, {}, [], "kaputt"):
        c = Config.from_dict(merge_db_overlay(make_env(proxy_url="wss://env/t"), db))
        assert c.proxy_url == "wss://env/t"
        assert c.db_fields == ()


def test_severity_wird_kleingeschrieben():
    assert cfg({}, {"severity_min": "HIGH"}).severity_min == "high"


def test_egress_source():
    assert cfg().egress_source == "none"
    assert cfg({"https_proxy": "http://p:3128"}).egress_source == "env"
    assert cfg({}, {"https_proxy": "http://p:3128"}).egress_source == "db"


# ── Reconnect-Felder ─────────────────────────────────────────────────────────


def test_connection_fields_entsprechen_dem_vertrag():
    assert set(CONNECTION_FIELDS) == {
        "proxy_url", "device_token", "https_proxy", "no_proxy",
        "ca_file", "tls_insecure",
    }


@pytest.mark.parametrize("field,value", [
    ("proxy_url", "wss://anders/tunnel"),
    ("device_token", "neues-token"),
    ("https_proxy", "http://anderer-proxy:3128"),
    ("no_proxy", "10.0.0.0/8"),
    ("ca_file", "/etc/cyjan/certs/andere.pem"),
    ("tls_insecure", True),
])
def test_reconnect_feld_erkannt(field, value):
    base = cfg({"proxy_url": "wss://a/tunnel", "device_token": "t"})
    changed = cfg({"proxy_url": "wss://a/tunnel", "device_token": "t"},
                  {field: value})
    assert changed.differs_in_connection(base) is True
    assert changed.needs_restart(base) is True


@pytest.mark.parametrize("field,value", [
    ("severity_min", "critical"),
    ("allow_triage", True),
    ("sentry_name", "anderer-name"),
])
def test_live_feld_erzwingt_keinen_reconnect(field, value):
    base = cfg({"proxy_url": "wss://a/tunnel", "device_token": "t"})
    changed = cfg({"proxy_url": "wss://a/tunnel", "device_token": "t"},
                  {field: value})
    assert changed != base                      # Änderung wird bemerkt …
    assert changed.differs_in_connection(base) is False   # … aber live
    assert changed.needs_restart(base) is False


def test_enabled_wechsel_ist_ein_neustart():
    base = cfg({"proxy_url": "wss://a/t", "device_token": "t"})
    off = cfg({"proxy_url": "wss://a/t", "device_token": "t"}, {"enabled": False})
    assert off.differs_in_connection(base) is False
    assert off.needs_restart(base) is True


def test_herkunft_allein_ist_keine_aenderung():
    """Derselbe Wert, einmal aus ENV und einmal aus der DB: kein Reconnect."""
    from_env = cfg({"proxy_url": "wss://a/tunnel"})
    from_db = cfg({}, {"proxy_url": "wss://a/tunnel"})
    assert from_env == from_db
    assert from_db.differs_in_connection(from_env) is False
    assert from_env.config_source == "env" and from_db.config_source == "db"


# ── ConfigStore ──────────────────────────────────────────────────────────────


async def test_config_store_effective(monkeypatch):
    env = make_env(proxy_url="wss://env/tunnel")
    store = ConfigStore(dsn="", env=env)

    async def fake_overlay():
        return {"proxy_url": "wss://db/tunnel", "allow_triage": True}

    monkeypatch.setattr(store, "read_overlay", fake_overlay)
    c = await store.effective()
    assert c.proxy_url == "wss://db/tunnel"
    assert c.allow_triage is True
    assert c.config_source == "db"


async def test_config_store_ohne_dsn_liefert_env():
    store = ConfigStore(dsn="", env=make_env(proxy_url="wss://env/tunnel"))
    assert await store.read_overlay() is None
    c = await store.effective()
    assert c.proxy_url == "wss://env/tunnel"
    assert c.config_source == "env"
