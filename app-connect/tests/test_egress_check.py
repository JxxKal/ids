"""Stufenlogik des Egress-Tests (DNS → CONNECT/TCP → TLS → Zertifikat).

Der Wert dieses Tests liegt in der *Stufe*: „Proxy-Passwort falsch" und
„Firewall blockt CONNECT" sehen von außen gleich aus, brauchen aber
verschiedene Leute zur Behebung. Und in der Redaktion: in keinem Feld der
Antwort dürfen Proxy-Credentials landen.
"""
from __future__ import annotations

import asyncio
import socket

import pytest

from egress_check import (
    STAGES,
    _redact,
    check_egress,
    classify_connect_error,
)
from proxy_egress import ProxyTarget

PROXY = ProxyTarget(host="proxy.kunde.local", port=3128,
                    username="geheimuser", password="s3cret-pass")


# ── Klassifikation ───────────────────────────────────────────────────────────


def test_407_wird_als_auth_problem_erklaert():
    detail, hint = classify_connect_error(
        "Proxy lehnte CONNECT ab: HTTP 407", PROXY)
    assert "407" in detail
    assert "Passwort" in hint


def test_403_verweist_auf_die_freigabeliste():
    _, hint = classify_connect_error("Proxy lehnte CONNECT ab: HTTP 403", PROXY)
    assert "Freigabeliste" in hint


def test_netzfehler_verweist_auf_firewall():
    _, hint = classify_connect_error(
        "CONNECT über http://proxy.kunde.local:3128 fehlgeschlagen: "
        "[Errno 111] Connection refused", PROXY)
    assert "Firewall" in hint


def test_ohne_proxy_wird_direkter_ausgang_erklaert():
    _, hint = classify_connect_error("[Errno 111] Connection refused", None)
    assert "direkte Ausgang" in hint


def test_redact_entfernt_userinfo():
    text = "CONNECT über http://geheimuser:s3cret-pass@proxy:3128 fehlgeschlagen"
    out = _redact(text, "s3cret-pass", "geheimuser")
    assert "s3cret-pass" not in out
    assert "geheimuser" not in out
    assert "proxy:3128" in out


def test_classify_gibt_keine_credentials_zurueck():
    for text in ("HTTP 407", "HTTP 403", "[Errno 111] Connection refused",
                 "irgendwas anderes"):
        detail, hint = classify_connect_error(text, PROXY)
        assert "s3cret-pass" not in detail + hint
        assert "geheimuser" not in detail + hint


# ── Echte Stufen-Durchläufe ──────────────────────────────────────────────────


async def test_url_ohne_host_scheitert_in_der_dns_stufe():
    res = await check_egress(url="nur-ein-string")
    assert res.ok is False
    assert res.stage == "dns"
    assert "Host" in res.detail


async def test_geschlossener_port_scheitert_in_der_connect_stufe():
    # Port 1 auf Loopback: DNS trivial, TCP sofort abgewiesen.
    res = await check_egress(url="wss://127.0.0.1:1/tunnel", timeout=5.0)
    assert res.ok is False
    assert res.stage == "connect"
    assert res.steps[0].name == "dns" and res.steps[0].ok is True
    assert res.steps[-1].name == "connect" and res.steps[-1].ok is False


async def test_tcp_ohne_tls_scheitert_in_der_tls_stufe():
    """Ein Server, der die Verbindung annimmt und sofort schließt: TCP steht,
    TLS nicht — genau die Situation „falscher Port / kein TLS dahinter"."""
    async def handler(reader, writer):
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        res = await check_egress(url=f"wss://127.0.0.1:{port}/tunnel", timeout=5.0)
    finally:
        server.close()
        await server.wait_closed()

    assert res.ok is False
    assert res.stage in ("tls", "cert")
    names = [s.name for s in res.steps]
    assert names[:2] == ["dns", "connect"]
    assert res.steps[1].ok is True


async def test_unaufloesbarer_proxy_scheitert_in_der_dns_stufe():
    res = await check_egress(
        url="wss://proxy.cyjan.dev/tunnel",
        https_proxy="http://geheimuser:s3cret-pass@nicht-existent.invalid:3128",
        timeout=5.0,
    )
    assert res.ok is False
    assert res.stage == "dns"
    body = str(res.to_dict())
    assert "s3cret-pass" not in body and "geheimuser" not in body


async def test_no_proxy_umgeht_den_proxy():
    """Greift no_proxy, wird direkt verbunden — der (unerreichbare) Proxy
    darf dann gar nicht erst auftauchen."""
    res = await check_egress(
        url="wss://127.0.0.1:1/tunnel",
        https_proxy="http://geheimuser:s3cret-pass@nicht-existent.invalid:3128",
        no_proxy="127.0.0.0/8",
        timeout=5.0,
    )
    assert res.stage == "connect"       # DNS lief lokal, nicht über den Proxy
    assert "nicht-existent" not in str(res.to_dict())


async def test_ergebnis_hat_die_vertragsform():
    res = await check_egress(url="wss://127.0.0.1:1/tunnel", timeout=5.0)
    d = res.to_dict()
    assert set(d) == {"ok", "stage", "detail", "hint", "steps"}
    assert d["stage"] in (*STAGES, "ok")
    for step in d["steps"]:
        assert set(step) == {"name", "ok", "detail"}
        assert step["name"] in STAGES


async def test_keine_credentials_bei_proxy_fehler(monkeypatch):
    """Der Proxy ist erreichbar-adressiert, aber tot: der Fehlertext kommt
    aus proxy_egress und muss redigiert durchkommen."""
    res = await check_egress(
        url="wss://proxy.cyjan.dev/tunnel",
        https_proxy="http://geheimuser:s3cret-pass@127.0.0.1:1",
        timeout=5.0,
    )
    assert res.ok is False
    body = str(res.to_dict())
    assert "s3cret-pass" not in body
    assert "geheimuser" not in body
    assert "127.0.0.1:1" in body        # Adresse ja, Zugangsdaten nein


def test_socket_wird_nicht_offen_gelassen():
    """Regressionsschutz: der Test oben würde auch mit einem geleakten FD
    grün — hier zählen wir die offenen Sockets vor und nach dem Lauf."""
    import gc

    async def run():
        for _ in range(5):
            await check_egress(url="wss://127.0.0.1:1/tunnel", timeout=5.0)

    gc.collect()
    before = len([o for o in gc.get_objects() if isinstance(o, socket.socket)])
    asyncio.run(run())
    gc.collect()
    after = len([o for o in gc.get_objects() if isinstance(o, socket.socket)])
    assert after - before <= 1


@pytest.mark.asyncio
async def test_klartext_ziel_ueberspringt_die_tls_stufen():
    """`ws://` hat kein TLS — der Test darf einen laufenden Lab-Tunnel nicht
    als Fehlschlag melden.

    Aufgefallen beim Bring-up auf dem Dev-Host: der Tunnel stand und lief,
    der Egress-Test meldete trotzdem rot mit „kein TLS dahinter" und schickte
    damit auf die falsche Fährte.
    """
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        result = await check_egress(f"ws://127.0.0.1:{port}/tunnel", timeout=5.0)
    finally:
        server.close()

    assert result.ok is True
    assert result.stage == "ok"
    assert "unverschlüsselt" in result.detail.lower()

    stages = {s.name: s for s in result.steps}
    assert stages["dns"].ok and stages["connect"].ok
    # Die Stufen tauchen weiterhin auf — die UI rendert eine feste Leiter und
    # soll keine Lücke zeigen —, aber als übersprungen markiert.
    assert stages["tls"].ok and "übersprungen" in stages["tls"].detail
    assert stages["cert"].ok and "übersprungen" in stages["cert"].detail
