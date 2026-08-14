"""no_proxy-Matching und CONNECT-Request-Bau.

Der CIDR-Teil ist der Grund, warum das hier selbst gebaut ist: der
ids-setup-Wizard schreibt CIDRs nach /etc/environment, und weder curl noch
httpx werten die aus.
"""
import pytest

from proxy_egress import (
    ProxyError,
    ProxyTarget,
    build_connect_request,
    bypass_proxy,
    parse_connect_response,
    parse_proxy_url,
    proxy_for_url,
    split_no_proxy,
    target_from_url,
)

CIDRS = "192.168.0.0/16,10.0.0.0/8,127.0.0.1"
NAMES = ".intern.example,example.org,localhost"


# ── Parsing ──────────────────────────────────────────────────────────────────


def test_parse_full_proxy_url():
    p = parse_proxy_url("http://user:pa%3Ass@proxy.corp:3128")
    assert (p.host, p.port, p.scheme) == ("proxy.corp", 3128, "http")
    assert p.username == "user" and p.password == "pa:ss"
    assert p.auth_header().startswith("Basic ")


def test_parse_schemeless_proxy():
    p = parse_proxy_url("proxy.corp:8080")
    assert (p.host, p.port, p.scheme) == ("proxy.corp", 8080, "http")
    assert p.auth_header() is None


def test_parse_empty_and_garbage():
    assert parse_proxy_url("") is None
    assert parse_proxy_url("   ") is None
    assert parse_proxy_url("socks5://proxy:1080") is None


def test_str_never_leaks_credentials():
    p = parse_proxy_url("http://user:supersecret@proxy.corp:3128")
    assert "supersecret" not in str(p)
    assert "supersecret" in p.as_url()   # httpx braucht sie


def test_split_no_proxy_separators():
    assert split_no_proxy("a, b;c  d") == ["a", "b", "c", "d"]
    assert split_no_proxy("") == []
    assert split_no_proxy(" , ,") == []


def test_target_from_url_defaults():
    assert target_from_url("wss://proxy.cyjan.dev/tunnel") == ("proxy.cyjan.dev", 443)
    assert target_from_url("ws://proxy.local/tunnel") == ("proxy.local", 80)
    assert target_from_url("wss://proxy.local:8443/tunnel") == ("proxy.local", 8443)


# ── no_proxy: CIDR ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("host", ["192.168.1.81", "192.168.255.9", "10.4.3.2",
                                  "127.0.0.1"])
def test_cidr_entries_match_inside(host):
    assert bypass_proxy(host, 443, CIDRS)


@pytest.mark.parametrize("host", ["8.8.8.8", "172.16.0.1", "193.168.1.81",
                                  "11.0.0.1"])
def test_cidr_entries_do_not_match_outside(host):
    assert not bypass_proxy(host, 443, CIDRS)


def test_bare_ip_entry_is_host_route():
    assert bypass_proxy("203.0.113.7", 443, "203.0.113.7")
    assert not bypass_proxy("203.0.113.8", 443, "203.0.113.7")


def test_hostname_never_matches_cidr_without_dns():
    """Wir lösen für die Proxy-Entscheidung bewusst kein DNS auf."""
    assert not bypass_proxy("proxy.cyjan.dev", 443, CIDRS)


def test_ipv6_cidr():
    assert bypass_proxy("fd00::5", 443, "fd00::/8")
    assert not bypass_proxy("2001:db8::5", 443, "fd00::/8")
    # Cross-Family darf nie matchen
    assert not bypass_proxy("192.168.1.1", 443, "fd00::/8")
    assert not bypass_proxy("fd00::5", 443, "192.168.0.0/16")


def test_ipv6_literal_in_brackets():
    assert bypass_proxy("[fd00::5]", 443, "fd00::/8")


# ── no_proxy: Hostname-Suffixe ───────────────────────────────────────────────


@pytest.mark.parametrize("host", ["example.org", "www.example.org",
                                  "a.b.intern.example", "intern.example",
                                  "localhost"])
def test_suffix_entries_match(host):
    assert bypass_proxy(host, 443, NAMES)


@pytest.mark.parametrize("host", ["example.org.evil.com", "notexample.org",
                                  "example.com", "proxy.cyjan.dev"])
def test_suffix_entries_do_not_overmatch(host):
    assert not bypass_proxy(host, 443, NAMES)


def test_suffix_is_case_insensitive_and_ignores_root_dot():
    assert bypass_proxy("WWW.Example.ORG.", 443, NAMES)


def test_wildcard_bypasses_everything():
    assert bypass_proxy("proxy.cyjan.dev", 443, "*")


def test_port_qualified_entry():
    assert bypass_proxy("example.com", 8080, "example.com:8080")
    assert not bypass_proxy("example.com", 443, "example.com:8080")


def test_mixed_list_of_cidrs_and_names():
    mixed = f"{CIDRS},{NAMES}"
    assert bypass_proxy("10.9.9.9", 443, mixed)
    assert bypass_proxy("www.example.org", 443, mixed)
    assert not bypass_proxy("proxy.cyjan.dev", 443, mixed)


# ── Auflösung Proxy vs. Direktverbindung ─────────────────────────────────────


def test_proxy_for_url_respects_no_proxy():
    url = "wss://proxy.cyjan.dev/tunnel"
    assert proxy_for_url(url, "http://fw:3128", "") is not None
    assert proxy_for_url(url, "http://fw:3128", "proxy.cyjan.dev") is None
    assert proxy_for_url(url, "", "") is None


def test_proxy_for_local_api_url_is_bypassed_by_cidr():
    """Der klassische ids-setup-Fall: Wizard schreibt CIDRs, das interne
    Ziel darf nicht durch den Egress-Proxy."""
    assert proxy_for_url("http://192.168.1.81:8000/api/alerts",
                         "http://fw:3128", "192.168.0.0/16") is None


# ── CONNECT ──────────────────────────────────────────────────────────────────


def test_connect_request_shape():
    p = ProxyTarget(host="fw", port=3128)
    raw = build_connect_request("proxy.cyjan.dev", 443, p).decode()
    assert raw.startswith("CONNECT proxy.cyjan.dev:443 HTTP/1.1\r\n")
    assert "Host: proxy.cyjan.dev:443\r\n" in raw
    assert raw.endswith("\r\n\r\n")
    assert "Proxy-Authorization" not in raw


def test_connect_request_with_auth_and_ipv6_target():
    p = ProxyTarget(host="fw", port=3128, username="u", password="p")
    raw = build_connect_request("fd00::1", 443, p).decode()
    assert "CONNECT [fd00::1]:443 HTTP/1.1" in raw
    assert "Proxy-Authorization: Basic dTpw" in raw


def test_parse_connect_response():
    assert parse_connect_response(b"HTTP/1.1 200 Connection established") == 200
    assert parse_connect_response(b"HTTP/1.0 407 Proxy Auth Required\r\nX: y") == 407
    with pytest.raises(ProxyError):
        parse_connect_response(b"nonsense")
    with pytest.raises(ProxyError):
        parse_connect_response(b"HTTP/1.1 zweihundert OK")
