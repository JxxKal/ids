"""Deep-Link + QR für die Kopplung.

Der teuerste Fehler in diesem Bereich ist eine falsche Basis-URL im QR-Code:
app-connect selbst spricht den *Tunnel*-Endpunkt (`wss://…/tunnel`), die App
dagegen die *REST-Basis* (`https://…`). Wer die Tunnel-URL durchreicht,
erzeugt einen Code, mit dem die App `POST /tunnel/api/v1/enroll` aufruft —
und eine Fehlermeldung, die auf alles Mögliche hindeutet, nur nicht auf die
Ursache.
"""
from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from proxy_api import build_deep_link, qr_svg, rest_base_url


@pytest.mark.parametrize("tunnel,expected", [
    ("wss://proxy.cyjan.dev/tunnel", "https://proxy.cyjan.dev"),
    ("ws://10.0.0.5:8000/tunnel", "http://10.0.0.5:8000"),
    # Nicht-Standard-Port bleibt erhalten, auch bei TLS.
    ("wss://proxy.kunde.local:8443/tunnel", "https://proxy.kunde.local:8443"),
    ("ws://127.0.0.1:9000/tunnel", "http://127.0.0.1:9000"),
    # Tieferer Pfad und Query fallen weg.
    ("wss://proxy.cyjan.dev/v1/tunnel?x=1", "https://proxy.cyjan.dev"),
    # Ohne Pfad ändert sich nur das Schema.
    ("wss://proxy.cyjan.dev", "https://proxy.cyjan.dev"),
    # https/http werden unverändert übernommen (jemand hat die REST-Basis
    # in das Feld geschrieben).
    ("https://proxy.cyjan.dev/tunnel", "https://proxy.cyjan.dev"),
    ("http://10.0.0.5:8000/tunnel", "http://10.0.0.5:8000"),
    # Schemalos → wss angenommen, also https-Basis.
    ("proxy.cyjan.dev/tunnel", "https://proxy.cyjan.dev"),
])
def test_rest_base_url(tunnel, expected):
    assert rest_base_url(tunnel) == expected


def test_rest_base_url_leer():
    assert rest_base_url("") == ""
    assert rest_base_url("   ") == ""


def test_deep_link_traegt_rest_basis_und_code():
    link = build_deep_link(rest_base_url("wss://proxy.cyjan.dev/tunnel"), "K7MHQ2XR")
    assert link.startswith("cyjan://enroll?")
    q = parse_qs(urlparse(link).query)
    assert q["proxy"] == ["https://proxy.cyjan.dev"]
    assert q["code"] == ["K7MHQ2XR"]
    # Die Tunnel-URL darf im Link nicht auftauchen.
    assert "wss://" not in link and "/tunnel" not in link


def test_deep_link_ist_urlkodiert():
    link = build_deep_link("http://10.0.0.5:8000", "AB12CD34")
    assert "proxy=http%3A%2F%2F10.0.0.5%3A8000" in link


def test_qr_svg_ist_svg_ohne_pillow():
    svg = qr_svg("cyjan://enroll?proxy=https%3A%2F%2Fproxy.cyjan.dev&code=K7MHQ2XR")
    assert svg.startswith("<svg")
    assert "<path" in svg          # SvgPathImage — keine Rasterbibliothek
    assert svg.rstrip().endswith("</svg>")
    assert len(svg) > 200


def test_qr_svg_unterscheidet_sich_je_inhalt():
    assert qr_svg("cyjan://enroll?code=AAA") != qr_svg("cyjan://enroll?code=BBB")
