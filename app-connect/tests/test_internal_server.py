"""Interne HTTP-API (docs/internal-api.md).

Geprüft wird das, was die api-Seite als Vertrag annimmt: Bearer-Auth, die
Antwortform von `/status` — auch und gerade im Ruhezustand —, die
Fehlercodes von `/pair` und dass in **keiner** Antwort ein Device-Token
oder ein Proxy-Passwort auftaucht.
"""
from __future__ import annotations

import pytest
from aiohttp.test_utils import TestClient, TestServer

import server as srv
from config import Config, env_dict, merge_db_overlay
from egress_check import EgressResult, Step
from proxy_api import CloudProxyError
from server import ServiceRuntime, create_app
from state import StateWriter

SECRET = "test-secret-key"
TOKEN = "geheimes-device-token"
PROXY_PASS = "s3cret-pass"
AUTH = {"Authorization": f"Bearer {SECRET}"}


def make_cfg(**over) -> Config:
    d = env_dict()
    d.update({
        "enabled": True,
        "proxy_url": "",
        "device_token": "",
        "sentry_name": "cyjan-master",
        "version": "9.9.9",
        "https_proxy": "",
        "no_proxy": "",
        "ca_file": "",
        "tls_insecure": False,
        "allow_triage": False,
        "severity_min": "medium",
        "api_secret_key": SECRET,
        "postgres_dsn": "",
        "internal_host": "127.0.0.1",
        "internal_port": 8090,
    })
    db = over.pop("_db", None)
    d.update(over)
    return Config.from_dict(merge_db_overlay(d, db))


@pytest.fixture
async def client(tmp_path):
    """Server im dormanten Zustand — der Default-Fall auf einem frischen
    Master."""
    runtime = ServiceRuntime(make_cfg(), StateWriter(str(tmp_path / "state.json")))
    async with TestClient(TestServer(create_app(runtime))) as c:
        c.runtime = runtime          # Tests dürfen die Config umschalten
        yield c


def configured_cfg(**over) -> Config:
    return make_cfg(proxy_url="wss://proxy.cyjan.dev/tunnel",
                    device_token=TOKEN, **over)


# ── Auth ─────────────────────────────────────────────────────────────────────


async def test_ohne_token_401(client):
    resp = await client.get("/status")
    assert resp.status == 401
    assert "Bearer" in (await resp.json())["detail"]


async def test_falsches_token_401(client):
    resp = await client.get("/status", headers={"Authorization": "Bearer falsch"})
    assert resp.status == 401


async def test_falsches_schema_401(client):
    resp = await client.get("/status", headers={"Authorization": f"Basic {SECRET}"})
    assert resp.status == 401


async def test_richtiges_token_200(client):
    assert (await client.get("/status", headers=AUTH)).status == 200


async def test_alle_endpunkte_verlangen_auth(client):
    for method, path in (("get", "/status"), ("post", "/pair"),
                         ("get", "/devices"), ("delete", "/devices/abc"),
                         ("post", "/test-egress")):
        resp = await getattr(client, method)(path)
        assert resp.status == 401, f"{method.upper()} {path} ohne Auth"


async def test_ohne_api_secret_key_503(client):
    client.runtime.cfg = make_cfg(api_secret_key="")
    resp = await client.get("/status", headers=AUTH)
    assert resp.status == 503
    assert "API_SECRET_KEY" in (await resp.json())["detail"]


# ── /status ──────────────────────────────────────────────────────────────────


async def test_status_im_ruhezustand(client):
    """Ein nicht eingerichtetes app-connect ist kein Fehler."""
    resp = await client.get("/status", headers=AUTH)
    assert resp.status == 200
    body = await resp.json()
    assert body["configured"] is False
    assert body["enabled"] is True
    assert body["connection"] == "dormant"
    assert body["connected_since"] is None
    assert body["egress"] is None
    assert body["egress_source"] == "none"
    assert body["config_source"] == "env"
    assert body["events_sent"] == 0 and body["rpc_ok"] == 0


async def test_status_abgeschaltet_bleibt_dormant(client):
    client.runtime.cfg = configured_cfg(_db={"enabled": False})
    body = await (await client.get("/status", headers=AUTH)).json()
    assert body["enabled"] is False
    assert body["configured"] is True
    assert body["connection"] == "dormant"
    assert body["config_source"] == "db"


async def test_status_uebernimmt_tunnelzustand(client):
    client.runtime.cfg = configured_cfg()
    client.runtime.state.write(connection="connected", connected_since=1755172800.0,
                               proxy_version="1.0.0", push_enabled=True,
                               events_sent=5, rpc_ok=2, event_severity_min="high")
    body = await (await client.get("/status", headers=AUTH)).json()
    assert body["connection"] == "connected"
    assert body["connected_since"] == 1755172800.0
    assert body["proxy_version"] == "1.0.0"
    assert body["push_enabled"] is True
    assert body["events_sent"] == 5 and body["rpc_ok"] == 2
    assert body["event_severity_min"] == "high"


async def test_status_unterscheidet_starting_und_reconnecting(client):
    client.runtime.cfg = configured_cfg()
    client.runtime.state.write(connection="connecting")
    body = await (await client.get("/status", headers=AUTH)).json()
    assert body["connection"] == "starting"

    client.runtime.state.write(connection="connected")
    client.runtime.state.write(connection="connecting")
    body = await (await client.get("/status", headers=AUTH)).json()
    assert body["connection"] == "reconnecting"


async def test_status_meldet_egress_ohne_credentials(client):
    client.runtime.cfg = configured_cfg(
        _db={"https_proxy": f"http://geheimuser:{PROXY_PASS}@proxy.kunde.local:3128"}
    )
    body = await (await client.get("/status", headers=AUTH)).json()
    assert body["egress"] == "http://proxy.kunde.local:3128"
    assert body["egress_source"] == "db"


async def test_status_liefert_niemals_das_device_token(client):
    client.runtime.cfg = configured_cfg(
        _db={"https_proxy": f"http://geheimuser:{PROXY_PASS}@proxy.kunde.local:3128"}
    )
    raw = await (await client.get("/status", headers=AUTH)).text()
    assert TOKEN not in raw
    assert PROXY_PASS not in raw
    assert "geheimuser" not in raw
    assert "device_token" not in raw
    # …aber „vorhanden ja/nein" muss beantwortet sein.
    assert (await (await client.get("/status", headers=AUTH)).json())["configured"] is True


async def test_status_meldet_no_proxy_bypass_als_direkt(client):
    client.runtime.cfg = configured_cfg(
        _db={"https_proxy": "http://proxy.kunde.local:3128",
             "no_proxy": "proxy.cyjan.dev"})
    body = await (await client.get("/status", headers=AUTH)).json()
    assert body["egress"] is None
    assert body["egress_source"] == "none"


# ── /pair ────────────────────────────────────────────────────────────────────


async def test_pair_ohne_einrichtung_409(client):
    resp = await client.post("/pair", headers=AUTH, json={"label": "iPhone Jan"})
    assert resp.status == 409
    assert "nicht eingerichtet" in (await resp.json())["detail"]


async def test_pair_ohne_label_400(client):
    client.runtime.cfg = configured_cfg()
    resp = await client.post("/pair", headers=AUTH, json={})
    assert resp.status == 400


async def test_pair_erfolg(client, monkeypatch):
    client.runtime.cfg = configured_cfg()
    seen = {}

    async def fake_create(cfg, label, ttl_s):
        seen["label"] = label
        seen["ttl_s"] = ttl_s
        return {"code": "K7MHQ2XR", "expires_at": "2026-08-14T15:40:00Z"}

    monkeypatch.setattr(srv, "create_enroll_code", fake_create)
    resp = await client.post("/pair", headers=AUTH,
                             json={"label": "iPhone Jan", "ttl_s": 600})
    assert resp.status == 200
    body = await resp.json()
    assert seen == {"label": "iPhone Jan", "ttl_s": 600}
    assert body["code"] == "K7MHQ2XR"
    assert body["expires_at"] == "2026-08-14T15:40:00Z"
    # REST-Basis im deep_link, nicht die Tunnel-URL.
    assert body["deep_link"] == (
        "cyjan://enroll?proxy=https%3A%2F%2Fproxy.cyjan.dev&code=K7MHQ2XR"
    )
    assert body["qr_svg"].startswith("<svg")
    assert TOKEN not in await resp.text()


async def test_pair_epoch_wird_zu_iso(client, monkeypatch):
    client.runtime.cfg = configured_cfg()

    async def fake_create(cfg, label, ttl_s):
        return {"code": "ABCD1234", "expires_at": 1755178800}

    monkeypatch.setattr(srv, "create_enroll_code", fake_create)
    body = await (await client.post("/pair", headers=AUTH,
                                    json={"label": "x"})).json()
    assert body["expires_at"].endswith("Z")
    assert body["expires_at"].startswith("2025-")


async def test_pair_proxy_fehler_502(client, monkeypatch):
    client.runtime.cfg = configured_cfg()

    async def fake_create(cfg, label, ttl_s):
        raise CloudProxyError("Cloud-Proxy nicht erreichbar (ConnectError).")

    monkeypatch.setattr(srv, "create_enroll_code", fake_create)
    resp = await client.post("/pair", headers=AUTH, json={"label": "x"})
    assert resp.status == 502
    assert "Cloud-Proxy" in (await resp.json())["detail"]


async def test_pair_ohne_code_502(client, monkeypatch):
    client.runtime.cfg = configured_cfg()

    async def fake_create(cfg, label, ttl_s):
        return {}

    monkeypatch.setattr(srv, "create_enroll_code", fake_create)
    assert (await client.post("/pair", headers=AUTH,
                              json={"label": "x"})).status == 502


async def test_pair_kaputtes_json_400(client):
    client.runtime.cfg = configured_cfg()
    resp = await client.post(
        "/pair",
        headers={**AUTH, "Content-Type": "application/json"},
        data="{kein json",
    )
    assert resp.status == 400


# ── /devices ─────────────────────────────────────────────────────────────────


async def test_devices_liste(client, monkeypatch):
    client.runtime.cfg = configured_cfg()

    async def fake_list(cfg):
        return [{"id": "abc", "label": "iPhone Jan", "platform": "ios",
                 "push_registered": True}]

    monkeypatch.setattr(srv, "list_devices", fake_list)
    resp = await client.get("/devices", headers=AUTH)
    assert resp.status == 200
    assert (await resp.json())[0]["label"] == "iPhone Jan"


async def test_devices_ohne_einrichtung_409(client):
    assert (await client.get("/devices", headers=AUTH)).status == 409


async def test_revoke_204(client, monkeypatch):
    client.runtime.cfg = configured_cfg()
    seen = {}

    async def fake_revoke(cfg, device_id):
        seen["id"] = device_id

    monkeypatch.setattr(srv, "revoke_device", fake_revoke)
    resp = await client.delete("/devices/abc-123", headers=AUTH)
    assert resp.status == 204
    assert seen["id"] == "abc-123"


async def test_revoke_unbekannt_404(client, monkeypatch):
    client.runtime.cfg = configured_cfg()

    async def fake_revoke(cfg, device_id):
        raise CloudProxyError("Gerät x ist dem Cloud-Proxy unbekannt.", status=404)

    monkeypatch.setattr(srv, "revoke_device", fake_revoke)
    assert (await client.delete("/devices/x", headers=AUTH)).status == 404


# ── /test-egress ─────────────────────────────────────────────────────────────


async def test_test_egress_nutzt_uebergebene_konfiguration(client, monkeypatch):
    """Ein Admin muss einen Proxy prüfen können, BEVOR er ihn speichert."""
    client.runtime.cfg = configured_cfg(_db={"https_proxy": "http://alt:3128"})
    seen = {}

    async def fake_check(**kwargs):
        seen.update(kwargs)
        return EgressResult(ok=True, stage="ok", detail="frei",
                            steps=[Step("dns", True, "ok")])

    monkeypatch.setattr(srv, "check_egress", fake_check)
    resp = await client.post("/test-egress", headers=AUTH, json={
        "https_proxy": f"http://geheimuser:{PROXY_PASS}@neu.kunde.local:3128",
        "no_proxy": "10.0.0.0/8",
        "ca_file": "/etc/cyjan/certs/corp-ca.pem",
    })
    assert resp.status == 200
    assert seen["https_proxy"].endswith("@neu.kunde.local:3128")
    assert seen["no_proxy"] == "10.0.0.0/8"
    assert seen["ca_file"] == "/etc/cyjan/certs/corp-ca.pem"
    # Nicht übergebenes Feld kommt aus der aktiven Konfig.
    assert seen["url"] == "wss://proxy.cyjan.dev/tunnel"


async def test_test_egress_ohne_ziel_400(client):
    resp = await client.post("/test-egress", headers=AUTH, json={})
    assert resp.status == 400


async def test_test_egress_antwortet_200_auch_bei_fehlschlag(client):
    client.runtime.cfg = configured_cfg()
    resp = await client.post("/test-egress", headers=AUTH,
                             json={"proxy_url": "wss://127.0.0.1:1/tunnel"})
    assert resp.status == 200
    body = await resp.json()
    assert body["ok"] is False
    assert body["stage"] == "connect"
    assert body["steps"][0]["name"] == "dns"


async def test_test_egress_gibt_keine_credentials_zurueck(client):
    client.runtime.cfg = configured_cfg()
    resp = await client.post("/test-egress", headers=AUTH, json={
        "proxy_url": "wss://proxy.cyjan.dev/tunnel",
        "https_proxy": f"http://geheimuser:{PROXY_PASS}@127.0.0.1:1",
    })
    raw = await resp.text()
    assert PROXY_PASS not in raw
    assert "geheimuser" not in raw


async def test_status_frisch_konfiguriert_meldet_starting(client):
    """Konfiguration da, Tunnel noch nicht: `starting`. Ein veralteter
    `dormant`-Eintrag im State-File darf das nicht überstimmen."""
    client.runtime.state.write(connection="dormant")
    client.runtime.cfg = configured_cfg()
    body = await (await client.get("/status", headers=AUTH)).json()
    assert body["connection"] == "starting"
