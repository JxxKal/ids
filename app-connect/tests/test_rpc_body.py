"""Body-Deckel (protocol.md §2.4: 4 MiB, dann truncated) und das
Service-JWT (§2.2: role=viewer, nicht admin)."""
import httpx
import pytest
from jose import jwt as jose_jwt

from api_client import ApiClient, _mint_service_token, filter_response_headers

SECRET = "test-secret"
CAP = 1024   # kleiner Deckel, damit die Tests keine 4-MiB-Puffer bauen


def _client(handler) -> ApiClient:
    return ApiClient("http://api:8000", SECRET,
                     transport=httpx.MockTransport(handler))


def _body_handler(size: int, headers=None):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"A" * size, headers=headers or {})
    return handler


# ── Service-JWT ──────────────────────────────────────────────────────────────


def test_service_token_is_viewer_not_admin():
    token = _mint_service_token(SECRET)
    claims = jose_jwt.decode(token, SECRET, algorithms=["HS256"])
    assert claims["role"] == "viewer", (
        "role=admin würde alle require_admin-Router öffnen und die zweite "
        "Verteidigungslinie hinter der Allowlist aushebeln"
    )
    assert claims["sub"] == "app-connect"
    assert claims["exp"] > 0


# ── Unary-Body ───────────────────────────────────────────────────────────────


async def test_small_body_passes_through():
    async with _client(_body_handler(100)) as api:
        r = await api.execute("GET", "/api/alerts", max_bytes=CAP)
    assert r.status == 200
    assert r.truncated is False
    assert r.body == b"A" * 100


async def test_body_exactly_at_cap_is_not_truncated():
    async with _client(_body_handler(CAP)) as api:
        r = await api.execute("GET", "/api/alerts", max_bytes=CAP)
    assert r.truncated is False
    assert len(r.body) == CAP


async def test_body_over_cap_is_truncated_and_emptied():
    """§2.4: leerer Body statt der ersten 4 MiB — ein halbes JSON wäre für
    die App nur ein Parse-Fehler."""
    async with _client(_body_handler(CAP + 1)) as api:
        r = await api.execute("GET", "/api/alerts", max_bytes=CAP)
    assert r.truncated is True
    assert r.body == b""
    assert r.status == 200


async def test_far_over_cap_is_truncated():
    async with _client(_body_handler(CAP * 50)) as api:
        r = await api.execute("GET", "/api/alerts", max_bytes=CAP)
    assert r.truncated is True
    assert r.body == b""


async def test_default_cap_is_four_mib():
    from config import DEFAULT_MAX_BODY_BYTES
    assert DEFAULT_MAX_BODY_BYTES == 4 * 1024 * 1024


# ── Header-Whitelist ─────────────────────────────────────────────────────────


def test_response_header_whitelist():
    out = filter_response_headers({
        "Content-Type": "application/json",
        "Content-Disposition": 'attachment; filename="a.pcap"',
        "Set-Cookie": "session=geheim",
        "Server": "uvicorn",
        "X-Internal-Trace": "abc",
    })
    assert out == {
        "content-type": "application/json",
        "content-disposition": 'attachment; filename="a.pcap"',
    }


async def test_execute_forwards_only_whitelisted_headers():
    handler = _body_handler(10, headers={"set-cookie": "s=1",
                                         "content-type": "application/json"})
    async with _client(handler) as api:
        r = await api.execute("GET", "/api/alerts", max_bytes=CAP)
    assert "set-cookie" not in r.headers
    assert r.headers["content-type"] == "application/json"


# ── Streaming (§2.5) ─────────────────────────────────────────────────────────


async def test_stream_chunks_and_caps():
    payload = b"A" * 1000   # _body_handler füllt mit "A"
    async with _client(_body_handler(len(payload))) as api:
        chunks = [
            (status, headers, chunk, trunc)
            async for status, headers, chunk, trunc in api.stream(
                "GET", "/api/alerts/x/pcap", chunk_bytes=256, max_bytes=10_000
            )
        ]
    assert chunks[0][0] == 200
    # Header nur am ersten Frame (seq=0), danach leer.
    assert chunks[0][1]
    assert all(c[1] == {} for c in chunks[1:])
    assert b"".join(c[2] for c in chunks) == payload
    assert not any(c[3] for c in chunks)
    assert len(chunks) == 4   # 1000 Bytes / 256 = 3 volle + 1 Rest


async def test_stream_marks_truncation_at_cap():
    async with _client(_body_handler(5000)) as api:
        chunks = [
            item
            async for item in api.stream(
                "GET", "/api/alerts/x/pcap", chunk_bytes=256, max_bytes=512
            )
        ]
    assert chunks[-1][3] is True
    assert sum(len(c[2]) for c in chunks) <= 5000


async def test_stream_empty_body_still_yields_status():
    async with _client(_body_handler(0)) as api:
        chunks = [item async for item in api.stream("GET", "/api/alerts/x/pcap")]
    assert len(chunks) == 1
    assert chunks[0][0] == 200
    assert chunks[0][2] == b""


@pytest.mark.parametrize("status", [401, 404, 500])
async def test_stream_surfaces_error_status(status):
    def handler(request):
        return httpx.Response(status, content=b"")
    async with _client(handler) as api:
        items = [item async for item in api.stream("GET", "/api/alerts/x/pcap")]
    assert items[0][0] == status
