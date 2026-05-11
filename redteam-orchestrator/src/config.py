"""Config aus env-Vars."""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    api_base:    str
    api_token:   str            # statischer Token, falls gesetzt
    api_secret_key: str         # shared JWT-Secret (für Service-Token-Minting)
    mcp_auth_required: bool     # /mcp/* erzwingen Bearer-JWT
    test_iface:  str
    allowed_src_cidrs: tuple[str, ...]
    max_timeout_sec:   int
    kali_container:    str
    postgres_dsn:      str

    @classmethod
    def from_env(cls) -> "Settings":
        raw = os.environ.get("ALLOWED_SRC_CIDRS",
                              "192.0.2.0/24,198.51.100.0/24,203.0.113.0/24").strip()
        cidrs = tuple(c.strip() for c in raw.split(",") if c.strip())
        # Sanity-Check: alle müssen parsen
        for c in cidrs:
            ipaddress.ip_network(c)
        return cls(
            api_base       = os.environ.get("CYJAN_API_BASE", "http://localhost:8001"),
            api_token      = os.environ.get("CYJAN_API_TOKEN", ""),
            api_secret_key = os.environ.get("API_SECRET_KEY", ""),
            mcp_auth_required = os.environ.get("MCP_AUTH_REQUIRED", "false").lower() in ("1", "true", "yes"),
            test_iface     = os.environ.get("CYJAN_TEST_IFACE", "cyjan-inject"),
            allowed_src_cidrs = cidrs,
            max_timeout_sec   = int(os.environ.get("MAX_TIMEOUT_SEC", "120")),
            kali_container    = os.environ.get("KALI_CONTAINER", "ids-kali"),
            postgres_dsn      = os.environ.get("POSTGRES_DSN",
                                                "postgres://ids:ids@localhost:5432/ids"),
        )


settings = Settings.from_env()
