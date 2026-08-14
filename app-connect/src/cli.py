"""`cyjan-app` — Operator-CLI im app-connect-Container (protocol.md §6).

    docker compose exec app-connect cyjan-app pair --label "iPhone Jan"
    docker compose exec app-connect cyjan-app devices
    docker compose exec app-connect cyjan-app revoke <device_id>
    docker compose exec app-connect cyjan-app status

Bewusst dem `cyjan-tap`-Muster nachempfunden: Maschine-lokale Diagnose ohne
Web-UI, Pairing über ein Einmal-Token mit TTL.

`status` liest ausschließlich das State-File des Tunnels — es funktioniert
also gerade dann, wenn der Tunnel unten ist. Die anderen Kommandos reden
mit dem Proxy und respektieren dabei HTTPS_PROXY/no_proxy inklusive
CIDR-Einträgen (httpx alleine könnte das nicht).
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys
from urllib.parse import urlparse, urlunparse

import httpx

from config import Config
from proxy_egress import proxy_for_url
from state import read_state

# Der Proxy-seitige Enrollment-Pfad steht in protocol.md §6. Die
# Verwaltungs-Endpoints (Liste/Revoke) sind dort nur als CLI-Verhalten
# beschrieben, nicht als HTTP-Pfad — wir spiegeln sie unter /internal/,
# analog zu /internal/enroll-codes.
ENROLL_PATH = "/internal/enroll-codes"
DEVICES_PATH = "/internal/devices"


def _api_base(cfg: Config) -> str:
    """wss://proxy.cyjan.dev/tunnel → https://proxy.cyjan.dev"""
    p = urlparse(cfg.proxy_url)
    scheme = "https" if p.scheme in ("wss", "https") else "http"
    return urlunparse((scheme, p.netloc, "", "", "", ""))


def _client(cfg: Config) -> httpx.Client:
    base = _api_base(cfg)
    proxy = proxy_for_url(base, cfg.https_proxy, cfg.no_proxy)
    return httpx.Client(
        base_url=base,
        timeout=httpx.Timeout(30.0, connect=10.0),
        headers={"Authorization": f"Bearer {cfg.device_token}"},
        verify=(cfg.ca_file or not cfg.tls_insecure),
        proxy=(proxy.as_url() if proxy else None),
        trust_env=False,   # no_proxy-CIDRs kann httpx nicht — wir schon
    )


def _require_config(cfg: Config) -> None:
    if not cfg.proxy_url or not cfg.device_token:
        missing = ", ".join(cfg.missing())
        print(f"Fehler: app-connect ist nicht konfiguriert ({missing} fehlt).",
              file=sys.stderr)
        print("        In der .env am Master setzen und den Container neu "
              "starten.", file=sys.stderr)
        raise SystemExit(2)


def _fmt_ts(value) -> str:
    if not value:
        return "–"
    if isinstance(value, (int, float)):
        return dt.datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
    return str(value)


# ── ASCII-QR ─────────────────────────────────────────────────────────────────


def _print_qr(data: str) -> None:
    try:
        import qrcode
    except ImportError:
        print("(qrcode-Modul nicht installiert — bitte den Code abtippen)")
        return
    qr = qrcode.QRCode(border=2)
    qr.add_data(data)
    qr.make(fit=True)
    # print_ascii nutzt Halbblock-Zeichen; invert=True liefert dunkle Module
    # auf hellem Grund, was in typischen (dunklen) Terminals scanbar ist.
    qr.print_ascii(out=sys.stdout, invert=True)


# ── Kommandos ────────────────────────────────────────────────────────────────


def cmd_pair(cfg: Config, args) -> int:
    _require_config(cfg)
    with _client(cfg) as client:
        resp = client.post(ENROLL_PATH, json={"label": args.label})
    if resp.status_code >= 400:
        print(f"Proxy lehnte ab: HTTP {resp.status_code} {resp.text[:400]}",
              file=sys.stderr)
        return 1

    body = resp.json()
    code = body.get("code") or ""
    if not code:
        print(f"Proxy lieferte keinen Code: {body}", file=sys.stderr)
        return 1

    # Wenn der Proxy eine fertige Scan-Payload liefert, gewinnt die —
    # sonst der nackte Code (die App akzeptiert beides, §6).
    qr_payload = body.get("qr") or body.get("enroll_url") or code

    print()
    print(f"  Enrollment-Code:  {code}")
    print(f"  Label:            {args.label}")
    print(f"  Gültig bis:       {_fmt_ts(body.get('expires_at'))}")
    print()
    _print_qr(qr_payload)
    print()
    print("  In der CYJAN-App: QR scannen oder Code eintippen.")
    print("  Der Code ist einmalig und verfällt nach Ablauf der TTL.")
    print()
    return 0


def cmd_devices(cfg: Config, args) -> int:
    _require_config(cfg)
    with _client(cfg) as client:
        resp = client.get(DEVICES_PATH)
    if resp.status_code >= 400:
        print(f"Proxy lehnte ab: HTTP {resp.status_code} {resp.text[:400]}",
              file=sys.stderr)
        return 1
    body = resp.json()
    devices = body.get("devices") if isinstance(body, dict) else body
    if not devices:
        print("Keine Geräte enrolled.")
        return 0

    print(f"{'DEVICE_ID':38} {'LABEL':22} {'PLATFORM':9} {'LAST_SEEN':20} STATUS")
    for d in devices:
        status = "revoked" if d.get("revoked_at") else "aktiv"
        print(f"{str(d.get('id', '')):38} {str(d.get('label', '')):22} "
              f"{str(d.get('platform', '')):9} {_fmt_ts(d.get('last_seen')):20} {status}")
    return 0


def cmd_revoke(cfg: Config, args) -> int:
    _require_config(cfg)
    with _client(cfg) as client:
        resp = client.delete(f"{DEVICES_PATH}/{args.device_id}")
    if resp.status_code == 404:
        print(f"Gerät {args.device_id} unbekannt.", file=sys.stderr)
        return 1
    if resp.status_code >= 400:
        print(f"Proxy lehnte ab: HTTP {resp.status_code} {resp.text[:400]}",
              file=sys.stderr)
        return 1
    print(f"Gerät {args.device_id} widerrufen — offene App-Verbindungen "
          f"werden vom Proxy sofort geschlossen (4403).")
    return 0


def cmd_status(cfg: Config, args) -> int:
    st = read_state(cfg.state_path)
    proxy = proxy_for_url(cfg.proxy_url, cfg.https_proxy, cfg.no_proxy) if cfg.proxy_url else None

    print()
    print("  CYJAN app-connect")
    print(f"    Proxy-URL        {cfg.proxy_url or '(nicht gesetzt)'}")
    print(f"    Device-Token     {'gesetzt' if cfg.device_token else 'FEHLT'}")
    print(f"    Sentry-Name      {cfg.sentry_name}")
    print(f"    Version          {cfg.version}")
    print(f"    Egress           {proxy if proxy else 'direkt (kein HTTPS_PROXY / no_proxy greift)'}")
    print(f"    Triage           {'aktiv' if cfg.allow_triage else 'aus (read-only)'}")
    print()

    if not st:
        print(f"    Kein State-File unter {cfg.state_path} —")
        print("    läuft der Tunnel-Prozess? `docker compose logs app-connect`")
        print()
        return 1

    print(f"    Verbindung       {st.get('connection', '?')}")
    print(f"    Verbunden seit   {_fmt_ts(st.get('connected_since'))}")
    print(f"    Proxy-Version    {st.get('proxy_version') or '–'}")
    print(f"    Push aktiv       {st.get('push_enabled')}")
    print(f"    Severity-Min     {st.get('event_severity_min') or '–'}")
    print(f"    Events gesendet  {st.get('events_sent', 0)} "
          f"(verworfen: {st.get('events_dropped', 0)})")
    print(f"    RPCs             ok={st.get('rpc_ok', 0)} "
          f"abgelehnt={st.get('rpc_rejected', 0)} fehler={st.get('rpc_failed', 0)}")
    print(f"    Letzter Fehler   {st.get('last_error') or '–'}")
    print(f"    State-Stand      {_fmt_ts(st.get('updated_at'))}")
    print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyjan-app",
        description="CYJAN App-Connect — Enrollment und Diagnose am Master.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    pair = sub.add_parser("pair", help="Enrollment-Code + QR für ein neues Gerät")
    pair.add_argument("--label", required=True,
                      help='Anzeigename des Geräts, z.B. "iPhone Jan"')
    pair.set_defaults(func=cmd_pair)

    devices = sub.add_parser("devices", help="Enrollte Geräte auflisten")
    devices.set_defaults(func=cmd_devices)

    revoke = sub.add_parser("revoke", help="Gerät widerrufen")
    revoke.add_argument("device_id")
    revoke.set_defaults(func=cmd_revoke)

    status = sub.add_parser("status", help="Tunnel-Zustand anzeigen")
    status.set_defaults(func=cmd_status)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = Config.from_env()
    try:
        return args.func(cfg, args)
    except SystemExit:
        raise
    except httpx.HTTPError as exc:
        print(f"Netzwerkfehler beim Proxy-Zugriff: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
