"""FmgClient aus system_config['fmg'] bauen (inkl. SSRF-Guard + Fixture-Modi)."""
from __future__ import annotations

from fastapi import HTTPException

from config import Config
from fmg.client import FmgClient
from fmg.transport import FixtureTransport, HttpTransport, RecordingTransport, Transport
from netguard import guard_egress_host


def build_fmg_client(fmg_cfg: dict, app_cfg: Config) -> FmgClient:
    if not fmg_cfg or not fmg_cfg.get("host"):
        raise HTTPException(400, "FortiManager nicht konfiguriert – bitte zuerst speichern.")

    if fmg_cfg.get("fixture_mode"):
        # Demo/Test ohne Lab: Antworten kommen aus aufgezeichneten Fixtures.
        transport: Transport = FixtureTransport(app_cfg.fixture_dir)
        return FmgClient(transport, auth_mode="token")

    host = fmg_cfg["host"]
    guard_egress_host(host, "FortiManager-Host")
    base_url = host if host.startswith("http") else f"https://{host}"

    auth_mode = fmg_cfg.get("auth_mode", "token")
    transport = HttpTransport(
        base_url,
        ssl_verify=fmg_cfg.get("ssl_verify", True),
        bearer_token=fmg_cfg.get("token") if auth_mode == "token" else None,
    )
    if app_cfg.record_fixtures:
        transport = RecordingTransport(transport, app_cfg.fixture_dir)
    return FmgClient(
        transport,
        auth_mode=auth_mode,
        username=fmg_cfg.get("username"),
        password=fmg_cfg.get("password"),
    )
