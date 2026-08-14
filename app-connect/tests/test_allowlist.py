"""Allowlist ist fail-closed (protocol.md §2.3) — der wichtigste Test im
Modul. Wenn hier etwas durchrutscht, ist der Tunnel eine offene Tür in die
ids-api."""
import pytest

from allowlist import Allowlist, RejectedPath

ALERT_ID = "3f1c9a2e-4b6d-4e7a-9c1f-0a2b3c4d5e6f"


@pytest.fixture
def acl():
    return Allowlist(allow_triage=False)


@pytest.fixture
def acl_triage():
    return Allowlist(allow_triage=True)


# ── Akzeptanz ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/alerts"),
    ("GET", f"/api/alerts/{ALERT_ID}"),
    ("GET", f"/api/alerts/{ALERT_ID}/pcap"),
    ("GET", "/api/stats/threat-level"),
    ("GET", "/api/hosts"),
    ("GET", "/api/hosts/10.0.0.5"),
    ("GET", "/api/hosts/10.0.0.5/connections"),
    ("GET", "/api/hosts/unknown"),
    ("GET", "/api/networks"),
    ("GET", "/api/flows"),
    ("GET", "/api/flows/graph"),
    ("GET", "/api/ml/status"),
    ("GET", "/api/system/stats"),
    ("GET", "/api/system/version"),
    ("GET", "/api/system/feature-flags"),
    ("GET", "/api/auth/me"),
])
def test_read_endpoints_allowed(acl, method, path):
    assert acl.is_allowed(method, path)
    clean, extra = acl.check(method, path)
    assert clean == path
    assert extra == {}


def test_query_string_is_split_off_and_path_validated(acl):
    clean, extra = acl.check("GET", "/api/alerts?limit=50&severity=critical")
    assert clean == "/api/alerts"
    assert extra == {"limit": "50", "severity": "critical"}


# ── Ablehnung (fail-closed) ──────────────────────────────────────────────────


@pytest.mark.parametrize("method,path", [
    # Admin-Router — nie erreichbar
    ("GET", "/api/sig-rules/list"),
    ("PUT", "/api/sig-rules/overrides"),
    ("GET", "/api/users"),
    ("POST", "/api/maintenance/backup"),
    ("GET", "/api/taps"),
    ("GET", "/api/notifications"),
    ("GET", "/api/system/config"),
    # Richtiger Pfad, falsche Methode
    ("POST", "/api/alerts"),
    ("DELETE", "/api/alerts"),
    ("PUT", "/api/hosts"),
    # Präfix-/Suffix-Anhängsel dürfen nicht durchrutschen
    ("GET", "/api/alerts/"),
    ("GET", "/api/alertsX"),
    ("GET", "/api/alerts/extra/path"),
    ("GET", "/x/api/alerts"),
    (
        "GET",
        f"/api/alerts/{ALERT_ID}/pcap/raw",
    ),
    # UUID-Form wird erzwungen
    ("GET", "/api/alerts/not-a-uuid"),
    ("GET", "/api/alerts/1"),
    # Unbekanntes
    ("GET", "/api/"),
    ("GET", "/"),
    ("GET", "/health"),
])
def test_rejected(acl, method, path):
    assert not acl.is_allowed(method, path)
    with pytest.raises(RejectedPath):
        acl.check(method, path)


@pytest.mark.parametrize("path", [
    "api/alerts",                       # kein führender Slash
    "/api/alerts/../../etc/passwd",     # Traversal
    "/api/hosts/%2e%2e%2f",             # encodierte Traversal
    "/api/hosts/a%2Fb",                 # encodierter Slash
    "/api/alerts#frag",                 # Fragment
    "/api/alerts\nHost: evil",          # Request-Smuggling
    "/api/ alerts",                     # Whitespace
    "/api/alerts\\x",                   # Backslash
])
def test_malformed_paths_rejected(acl, path):
    with pytest.raises(RejectedPath) as exc:
        acl.check("GET", path)
    assert exc.value.reason in ("bad_path", "not_allowed")


def test_rejection_is_logged_with_path(acl, caplog):
    with caplog.at_level("WARNING"):
        with pytest.raises(RejectedPath):
            acl.check("GET", "/api/users")
    assert "/api/users" in caplog.text
    assert "abgelehnt" in caplog.text


# ── Triage-Flag ──────────────────────────────────────────────────────────────


def test_triage_is_off_by_default(acl):
    """Default = read-only. Das ist der in §2.3 zugesagte Auslieferzustand."""
    assert acl.allow_triage is False
    assert acl.read_only is True
    assert "triage" not in acl.capabilities()
    for method in ("PATCH", "DELETE"):
        assert not acl.is_allowed(method, f"/api/alerts/{ALERT_ID}/feedback")


def test_triage_rejection_names_the_flag(acl):
    with pytest.raises(RejectedPath) as exc:
        acl.check("PATCH", f"/api/alerts/{ALERT_ID}/feedback")
    assert exc.value.reason == "read_only"
    assert "APP_CONNECT_ALLOW_TRIAGE" in exc.value.detail


def test_triage_enabled(acl_triage):
    assert acl_triage.read_only is False
    assert "triage" in acl_triage.capabilities()
    for method in ("PATCH", "DELETE"):
        assert acl_triage.is_allowed(method, f"/api/alerts/{ALERT_ID}/feedback")
    # Der Rest bleibt trotzdem zu — Triage öffnet genau zwei Endpoints.
    assert not acl_triage.is_allowed("DELETE", f"/api/alerts/{ALERT_ID}")
    assert not acl_triage.is_allowed("PATCH", "/api/alerts")
    assert not acl_triage.is_allowed("POST", f"/api/alerts/{ALERT_ID}/feedback")


def test_capabilities_stable(acl, acl_triage):
    assert acl.capabilities() == ["pcap", "flows", "ml"]
    assert acl_triage.capabilities() == ["pcap", "flows", "ml", "triage"]


# ── Streaming-Pfad (§2.5) ────────────────────────────────────────────────────


def test_only_pcap_is_streamable(acl):
    assert Allowlist.is_streamable(f"/api/alerts/{ALERT_ID}/pcap")
    assert not Allowlist.is_streamable("/api/alerts")
    assert not Allowlist.is_streamable(f"/api/alerts/{ALERT_ID}")
    assert not Allowlist.is_streamable("/api/flows")
