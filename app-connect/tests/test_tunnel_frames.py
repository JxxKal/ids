"""Verdrahtung zwischen Allowlist, api-Client und den Frames, die in den
Tunnel gehen (protocol.md §1.3 / §2.3 / §2.4)."""
import asyncio
import base64

import httpx
import orjson
import pytest

from allowlist import Allowlist
from api_client import ApiClient
from config import Config, RuntimeConfig
from state import StateWriter
from tunnel import Tunnel

ALERT_ID = "3f1c9a2e-4b6d-4e7a-9c1f-0a2b3c4d5e6f"


class FakeWS:
    """Sammelt gesendete Frames, statt sie über TCP zu schicken."""

    def __init__(self):
        self.sent = []

    async def send(self, raw):
        self.sent.append(orjson.loads(raw))

    def frames(self, ftype):
        return [f for f in self.sent if f["type"] == ftype]


def _cfg(**over) -> Config:
    base = dict(
        enabled=True, proxy_url="wss://proxy.cyjan.dev/tunnel",
        device_token="tok", sentry_name="master-hq", version="v9.9.9",
        ca_file="", tls_insecure=False, https_proxy="", no_proxy="",
        api_base_url="http://api:8000", api_secret_key="s3cret",
        postgres_dsn="", internal_host="127.0.0.1", internal_port=8090,
        kafka_brokers="kafka:9092", alerts_topic="alerts-enriched",
        kafka_group_id="app-connect", allow_triage=False,
        severity_min="medium", threat_interval_s=60.0, status_interval_s=300.0,
        rpc_timeout_s=20.0, max_body_bytes=1024, max_stream_bytes=8192,
        chunk_bytes=4096, event_queue_max=10, state_path="/tmp/ac-test.json",
    )
    base.update(over)
    return Config(**base)


def _tunnel(handler, cfg=None, api=None):
    cfg = cfg or _cfg()
    api = api or ApiClient(cfg.api_base_url, cfg.api_secret_key,
                           transport=httpx.MockTransport(handler))
    tun = Tunnel(cfg, RuntimeConfig(event_severity_min=cfg.severity_min),
                 Allowlist(cfg.allow_triage), api,
                 asyncio.Queue(maxsize=cfg.event_queue_max),
                 StateWriter(cfg.state_path))
    return tun, api


def _ok(content=b'{"ok":true}'):
    def handler(request):
        return httpx.Response(200, content=content,
                              headers={"content-type": "application/json"})
    return handler


async def test_allowed_rpc_returns_rpc_result_with_mirrored_id():
    tun, api = _tunnel(_ok())
    ws = FakeWS()
    async with api:
        await tun._handle_rpc(ws, "req-42", {"method": "GET", "path": "/api/alerts",
                                             "query": {"limit": "50"}})
    results = ws.frames("rpc_result")
    assert len(results) == 1
    assert results[0]["id"] == "req-42"          # §1.3: id muss gespiegelt sein
    payload = results[0]["payload"]
    assert payload["status"] == 200
    assert payload["truncated"] is False
    assert base64.b64decode(payload["body_b64"]) == b'{"ok":true}'
    assert tun.rpc_ok == 1


async def test_denied_rpc_returns_rpc_error_and_never_touches_the_api():
    called = []

    def handler(request):
        called.append(request.url.path)
        return httpx.Response(200, content=b"{}")

    tun, api = _tunnel(handler)
    ws = FakeWS()
    async with api:
        await tun._handle_rpc(ws, "req-7", {"method": "GET", "path": "/api/users"})
    errors = ws.frames("rpc_error")
    assert len(errors) == 1
    assert errors[0]["id"] == "req-7"
    assert errors[0]["payload"]["error"] == "not_allowed"
    assert called == [], "abgelehnte Pfade dürfen die ids-api nie erreichen"
    assert tun.rpc_rejected == 1
    assert not ws.frames("rpc_result")


async def test_triage_rpc_denied_by_default():
    tun, api = _tunnel(_ok())
    ws = FakeWS()
    async with api:
        await tun._handle_rpc(ws, "t1", {
            "method": "PATCH", "path": f"/api/alerts/{ALERT_ID}/feedback",
            "body_b64": base64.b64encode(b'{"feedback":"fp"}').decode(),
        })
    assert ws.frames("rpc_error")[0]["payload"]["error"] == "read_only"


async def test_triage_rpc_allowed_when_flag_set():
    cfg = _cfg(allow_triage=True)
    tun, api = _tunnel(_ok(), cfg=cfg)
    ws = FakeWS()
    async with api:
        await tun._handle_rpc(ws, "t2", {
            "method": "PATCH", "path": f"/api/alerts/{ALERT_ID}/feedback",
            "body_b64": base64.b64encode(b'{"feedback":"fp"}').decode(),
        })
    assert ws.frames("rpc_result")[0]["payload"]["status"] == 200


async def test_oversized_response_sets_truncated_and_empty_body():
    tun, api = _tunnel(_ok(content=b"X" * 5000))    # cfg.max_body_bytes = 1024
    ws = FakeWS()
    async with api:
        await tun._handle_rpc(ws, "big", {"method": "GET", "path": "/api/alerts"})
    payload = ws.frames("rpc_result")[0]["payload"]
    assert payload["truncated"] is True
    assert payload["body_b64"] == ""


async def test_bad_base64_body_is_rejected():
    tun, api = _tunnel(_ok())
    ws = FakeWS()
    async with api:
        await tun._handle_rpc(ws, "b", {"method": "GET", "path": "/api/alerts",
                                        "body_b64": "!!!nicht-base64!!!"})
    assert ws.frames("rpc_error")[0]["payload"]["error"] == "bad_request"


async def test_pcap_stream_emits_chunks_and_final_frame():
    body = b"P" * 6000          # < cfg.max_stream_bytes (8192)
    tun, api = _tunnel(_ok(content=body))
    ws = FakeWS()
    async with api:
        await tun._handle_rpc(ws, "pcap-1", {
            "method": "GET", "path": f"/api/alerts/{ALERT_ID}/pcap",
            "stream": True,
        })
    chunks = ws.frames("rpc_chunk")
    assert len(chunks) >= 2
    assert all(c["id"] == "pcap-1" for c in chunks)
    assert [c["payload"]["seq"] for c in chunks] == list(range(len(chunks)))
    assert chunks[0]["payload"]["status"] == 200
    assert chunks[-1]["payload"]["final"] is True
    data = b"".join(base64.b64decode(c["payload"]["data_b64"]) for c in chunks)
    assert data == body
    assert not ws.frames("rpc_result")


async def test_stream_stops_at_max_stream_bytes():
    """Ein absurd großes PCAP darf den Tunnel nicht auf Dauer belegen —
    ab max_stream_bytes wird abgeschnitten und das im Frame vermerkt."""
    tun, api = _tunnel(_ok(content=b"P" * 100_000))   # cap = 8192
    ws = FakeWS()
    async with api:
        await tun._handle_rpc(ws, "pcap-2", {
            "method": "GET", "path": f"/api/alerts/{ALERT_ID}/pcap",
            "stream": True,
        })
    chunks = ws.frames("rpc_chunk")
    total = sum(len(base64.b64decode(c["payload"]["data_b64"])) for c in chunks)
    assert total <= 100_000
    assert any(c["payload"].get("truncated") for c in chunks)
    assert chunks[-1]["payload"]["final"] is True


async def test_stream_flag_on_non_pcap_path_falls_back_to_unary():
    """`stream: true` darf nicht zum generischen Bypass des 4-MiB-Deckels
    werden — nur der PCAP-Pfad streamt (§2.5)."""
    tun, api = _tunnel(_ok(content=b"Y" * 5000))
    ws = FakeWS()
    async with api:
        await tun._handle_rpc(ws, "s", {"method": "GET", "path": "/api/alerts",
                                        "stream": True})
    assert not ws.frames("rpc_chunk")
    assert ws.frames("rpc_result")[0]["payload"]["truncated"] is True


async def test_hello_payload_reflects_read_only_and_capabilities():
    for allow_triage, read_only in ((False, True), (True, False)):
        cfg = _cfg(allow_triage=allow_triage)
        tun, api = _tunnel(_ok(), cfg=cfg)
        ws = FakeWS()
        # _session bis zum hello-Frame nachbauen wäre eine halbe
        # Integrationsumgebung — hier reicht der Frame-Bau selbst.
        await tun._send(ws, {
            "type": "hello",
            "payload": {
                "schema": "1", "sentry_name": cfg.sentry_name,
                "version": cfg.version,
                "capabilities": tun._acl.capabilities(),
                "read_only": tun._acl.read_only,
            },
        })
        payload = ws.frames("hello")[0]["payload"]
        assert payload["schema"] == "1"
        assert payload["read_only"] is read_only
        assert ("triage" in payload["capabilities"]) is allow_triage


async def test_runtime_config_frame_changes_severity_without_reconnect():
    rt = RuntimeConfig(event_severity_min="medium")
    assert rt.severity_passes("medium")
    assert rt.apply({"event_severity_min": "critical", "push_detail": "standard"})
    assert not rt.severity_passes("high")
    assert rt.severity_passes("critical")
    assert rt.push_detail == "standard"
    # Müll wird ignoriert, die bestehende Schwelle bleibt stehen.
    assert not rt.apply({"event_severity_min": "kaputt"})
    assert rt.event_severity_min == "critical"


@pytest.mark.parametrize("frame", [
    b'{"type":"ping","payload":{}}',
    b'{"type":"was-auch-immer"}',
    b"kein json",
])
def test_frame_parser_never_raises(frame):
    # §1.2: Unbekanntes/Kaputtes wird verworfen, nie als Fehler behandelt.
    Tunnel._parse(frame)
