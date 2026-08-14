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

Die Konfiguration wird genauso aufgelöst wie im Dienst selbst: ENV als
Bootstrap, `system_config['app_connect']` überlagert feldweise. Sonst würde
die CLI „nicht konfiguriert" melden, sobald jemand die Einrichtung über die
GUI gemacht hat. Ist die DB nicht erreichbar, bleibt es bei der ENV.
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys

import httpx

from config import Config, env_dict, merge_db_overlay
from proxy_api import (
    DEVICES_PATH,
    ENROLL_PATH,
    build_deep_link,
    client_kwargs,
    rest_base_url,
)
from proxy_egress import proxy_for_url
from state import read_state


def load_config() -> Config:
    """Effektive Konfiguration (ENV + DB-Overlay), fehlertolerant."""
    env = env_dict()
    fallback = Config.from_dict(merge_db_overlay(env, None))
    if not env.get("postgres_dsn"):
        return fallback
    try:
        import asyncio

        from db_config import ConfigStore

        async def _read() -> Config:
            store = ConfigStore(env["postgres_dsn"], env)
            try:
                return await store.effective()
            finally:
                await store.close()

        return asyncio.run(_read())
    except Exception as exc:
        print(f"Hinweis: GUI-Konfiguration nicht lesbar ({type(exc).__name__}) — "
              f"es gilt die ENV.", file=sys.stderr)
        return fallback


def _client(cfg: Config) -> httpx.Client:
    """Sync-Variante desselben Clients, den die interne API async nutzt —
    Basis-URL, Proxy-Entscheidung und CA-Handling kommen aus proxy_api."""
    return httpx.Client(**client_kwargs(cfg))


def _require_config(cfg: Config) -> None:
    if not cfg.proxy_url or not cfg.device_token:
        missing = ", ".join(cfg.missing())
        print(f"Fehler: app-connect ist nicht konfiguriert ({missing} fehlt).",
              file=sys.stderr)
        print("        Einrichtung normalerweise über die Web-GUI "
              "(Einstellungen → Integrationen → CYJAN App);", file=sys.stderr)
        print("        die .env am Master ist nur noch der Bootstrap-Weg.",
              file=sys.stderr)
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

    # Kodiert wird der Deep-Link, damit die App Proxy-Adresse UND Code aus
    # einem Scan bekommt. Der `proxy`-Parameter ist die REST-Basis, nicht
    # die Tunnel-URL (siehe proxy_api.rest_base_url).
    deep_link = str(body.get("deep_link") or "").strip() or build_deep_link(
        rest_base_url(cfg.proxy_url), code
    )

    print()
    print(f"  Enrollment-Code:  {code}")
    print(f"  Label:            {args.label}")
    print(f"  Gültig bis:       {_fmt_ts(body.get('expires_at'))}")
    print(f"  Deep-Link:        {deep_link}")
    print()
    _print_qr(deep_link)
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


def cmd_test_proxy(cfg: Config, args) -> int:
    """Egress-Pfad Stufe für Stufe prüfen.

    Im OT-Netz kann man nicht eben curl durchprobieren, und der Tunnel meldet
    im Fehlerfall nur „geht nicht". Dieser Befehl sagt, an welcher Stufe es
    hängt — das ist der Unterschied zwischen „Proxy-Passwort falsch" und
    „Firewall lässt CONNECT nicht durch", die sonst beide gleich aussehen.

    Die Stufenlogik selbst liegt in `egress_check`; dieselbe Prüfung liefert
    `POST /test-egress` an die GUI. Hier wird sie nur hübsch gedruckt.
    """
    import asyncio

    from egress_check import STAGES, check_egress
    from proxy_egress import target_from_url

    url = args.url or cfg.proxy_url
    if not url:
        print("Keine Ziel-URL. APP_CONNECT_PROXY_URL setzen oder --url angeben.")
        return 2

    proxy = proxy_for_url(url, cfg.https_proxy, cfg.no_proxy)
    host, port = target_from_url(url)

    print()
    print("  CYJAN app-connect — Egress-Test")
    print(f"    Ziel             {host}:{port}")
    if proxy is None:
        if cfg.https_proxy:
            print(f"    Egress           direkt (no_proxy greift für {host})")
        else:
            print("    Egress           direkt (kein Proxy konfiguriert)")
    else:
        print(f"    Proxy            {proxy}")          # __str__ redigiert Credentials
        print(f"    Proxy-Auth       {'ja' if proxy.auth_header() else 'nein'}")
    print(f"    Eigene CA        {cfg.ca_file or '(System-Trust-Store)'}")
    if cfg.tls_insecure:
        print("    TLS-Prüfung      AUS (APP_CONNECT_TLS_INSECURE=true)")
    print()

    timeout = float(args.timeout)

    labels = {"dns": "DNS", "connect": "CONNECT" if proxy else "TCP",
              "tls": "TLS", "cert": "Zertifikat"}

    async def run() -> int:
        result = await check_egress(
            url=url,
            https_proxy=cfg.https_proxy,
            no_proxy=cfg.no_proxy,
            ca_file=cfg.ca_file,
            tls_insecure=cfg.tls_insecure,
            timeout=timeout,
        )
        done = {step.name for step in result.steps}
        for step in result.steps:
            idx = STAGES.index(step.name) + 1
            label = labels.get(step.name, step.name)
            marker = "ok" if step.ok else "FEHLER"
            print(f"    [{idx}/{len(STAGES)}] {label:<10} {marker} — {step.detail}")
        # Nicht erreichte Stufen sichtbar machen, damit klar ist, wo Schluss war.
        for name in STAGES:
            if name not in done:
                idx = STAGES.index(name) + 1
                print(f"    [{idx}/{len(STAGES)}] {labels.get(name, name):<10} –")

        print()
        if result.ok:
            print(f"    {result.detail}")
            if result.hint:
                print(f"    Hinweis: {result.hint}")
            print("    Fehlt danach noch die Verbindung, liegt es am")
            print("    Device-Token, nicht am Netz.")
            return 0

        print(f"    {result.detail}")
        if result.hint:
            print(f"    {result.hint}")
        return 1

    try:
        return asyncio.run(run())
    except KeyboardInterrupt:
        return 130


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

    test = sub.add_parser(
        "test-proxy",
        help="Egress prüfen: DNS → CONNECT/TCP → TLS → Zertifikat",
    )
    test.add_argument("--url", default="",
                      help="Abweichendes Ziel statt APP_CONNECT_PROXY_URL")
    test.add_argument("--timeout", default=15.0, type=float,
                      help="Sekunden pro Stufe (Default 15)")
    test.set_defaults(func=cmd_test_proxy)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = load_config()
    try:
        return args.func(cfg, args)
    except SystemExit:
        raise
    except httpx.HTTPError as exc:
        print(f"Netzwerkfehler beim Proxy-Zugriff: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
