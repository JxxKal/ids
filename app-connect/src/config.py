"""app-connect — Konfiguration.

Reine env-var-Konfiguration (kein DB-Overlay wie mqtt-bridge — der
Live-Konfig-Kanal ist hier das `config`-Frame vom Proxy, siehe
protocol.md §1.3, und das wirkt ohne Reconnect direkt im RuntimeConfig).

Dormanz-Regel: fehlt `APP_CONNECT_PROXY_URL` oder das Device-Token, ist
`configured` False. main.py loggt das dann EINMAL und geht in eine
Idle-Schleife — der Container darf nicht crash-loopen, nur weil der
Betreiber das Feature nie eingeschaltet hat. Es gibt deshalb bewusst
KEINE `${VAR:?}`-Fail-Closed-Variable im Compose-Block.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

SEVERITY_ORDER = ["low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# protocol.md §1.2 — max_size 8 MiB in beide Richtungen.
WS_MAX_SIZE = 8 * 1024 * 1024
# protocol.md §2.4 — rpc_result.body_b64 ist auf 4 MiB gedeckelt.
DEFAULT_MAX_BODY_BYTES = 4 * 1024 * 1024
# protocol.md §1.4 — Reconnect-Backoff 1 s → 60 s, ±20 % Jitter.
RECONNECT_MIN_S = 1.0
RECONNECT_MAX_S = 60.0
RECONNECT_JITTER = 0.20
# protocol.md §1.4 — Proxy pingt alle 30 s, schließt bei 75 s Stille.
# Wir erwarten spiegelbildlich innerhalb 75 s Verkehr.
HEARTBEAT_TIMEOUT_S = 75.0
# protocol.md §8 — hello.schema
SCHEMA_VERSION = "1"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name, "true" if default else "false").lower()
    return raw in ("1", "true", "yes", "on")


def _env_int(name: str, default: int, lo: int | None = None, hi: int | None = None) -> int:
    try:
        v = int(_env(name, str(default)) or default)
    except ValueError:
        log.warning("%s=%r ungültig — nutze Default %d", name, os.environ.get(name), default)
        v = default
    if lo is not None:
        v = max(lo, v)
    if hi is not None:
        v = min(hi, v)
    return v


def _env_float(name: str, default: float, lo: float | None = None) -> float:
    try:
        v = float(_env(name, str(default)) or default)
    except ValueError:
        log.warning("%s=%r ungültig — nutze Default %s", name, os.environ.get(name), default)
        v = default
    if lo is not None:
        v = max(lo, v)
    return v


def _read_secret(value: str, file_path: str) -> str:
    """Token aus env ODER aus einer Datei (Docker-Secret / Bind-Mount).
    env gewinnt, wenn beides gesetzt ist."""
    if value:
        return value
    if not file_path:
        return ""
    try:
        return Path(file_path).read_text().strip()
    except OSError:
        return ""


@dataclass(frozen=True)
class Config:
    # ── Tunnel ────────────────────────────────────────────────────────────
    enabled: bool
    proxy_url: str
    device_token: str
    sentry_name: str
    version: str
    ca_file: str
    tls_insecure: bool

    # ── Egress-Proxy (protocol.md §1.1) ──────────────────────────────────
    https_proxy: str
    no_proxy: str

    # ── Lokale ids-api ───────────────────────────────────────────────────
    api_base_url: str
    api_secret_key: str

    # ── Kafka ────────────────────────────────────────────────────────────
    kafka_brokers: str
    alerts_topic: str
    kafka_group_id: str

    # ── Verhalten ────────────────────────────────────────────────────────
    allow_triage: bool
    severity_min: str
    threat_interval_s: float
    status_interval_s: float
    rpc_timeout_s: float
    max_body_bytes: int
    max_stream_bytes: int
    chunk_bytes: int
    event_queue_max: int
    state_path: str

    @property
    def configured(self) -> bool:
        """Alles da, um den Tunnel überhaupt aufzubauen?"""
        return bool(self.enabled and self.proxy_url and self.device_token)

    def missing(self) -> list[str]:
        out: list[str] = []
        if not self.proxy_url:
            out.append("APP_CONNECT_PROXY_URL")
        if not self.device_token:
            out.append("APP_CONNECT_DEVICE_TOKEN (oder APP_CONNECT_DEVICE_TOKEN_FILE)")
        return out

    @classmethod
    def from_env(cls) -> "Config":
        sev = _env("APP_CONNECT_SEVERITY_MIN", "medium").lower()
        if sev not in SEVERITY_RANK:
            log.warning("APP_CONNECT_SEVERITY_MIN=%r ungültig — nutze 'medium'", sev)
            sev = "medium"

        version_file = _env("APP_CONNECT_VERSION_FILE", "/etc/cyjan/version")
        version = _env("APP_CONNECT_VERSION")
        if not version:
            try:
                version = Path(version_file).read_text().strip()
            except OSError:
                version = "unknown"

        sentry_name = _env("APP_CONNECT_SENTRY_NAME")
        if not sentry_name:
            sentry_name = _env("HOSTNAME") or "cyjan-master"

        return cls(
            enabled=_env_bool("APP_CONNECT_ENABLED", True),
            proxy_url=_env("APP_CONNECT_PROXY_URL"),
            device_token=_read_secret(
                _env("APP_CONNECT_DEVICE_TOKEN"),
                _env("APP_CONNECT_DEVICE_TOKEN_FILE"),
            ),
            sentry_name=sentry_name,
            version=version,
            ca_file=_env("APP_CONNECT_CA_FILE"),
            tls_insecure=_env_bool("APP_CONNECT_TLS_INSECURE", False),
            https_proxy=(
                _env("APP_CONNECT_HTTPS_PROXY")
                or _env("HTTPS_PROXY")
                or _env("https_proxy")
            ),
            no_proxy=_env("NO_PROXY") or _env("no_proxy"),
            api_base_url=_env("APP_CONNECT_API_BASE_URL", "http://api:8000"),
            api_secret_key=_env("API_SECRET_KEY"),
            kafka_brokers=_env("KAFKA_BROKERS", "kafka:9092"),
            alerts_topic=_env("APP_CONNECT_ALERTS_TOPIC", "alerts-enriched"),
            kafka_group_id=_env("KAFKA_GROUP_ID", "app-connect"),
            allow_triage=_env_bool("APP_CONNECT_ALLOW_TRIAGE", False),
            severity_min=sev,
            threat_interval_s=_env_float("APP_CONNECT_THREAT_INTERVAL_S", 60.0, 10.0),
            status_interval_s=_env_float("APP_CONNECT_STATUS_INTERVAL_S", 300.0, 30.0),
            rpc_timeout_s=_env_float("APP_CONNECT_RPC_TIMEOUT_S", 20.0, 1.0),
            max_body_bytes=_env_int("APP_CONNECT_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES, 1024),
            max_stream_bytes=_env_int(
                "APP_CONNECT_MAX_STREAM_BYTES", 32 * 1024 * 1024, 1024
            ),
            chunk_bytes=_env_int("APP_CONNECT_CHUNK_BYTES", 192 * 1024, 4096, 4 * 1024 * 1024),
            event_queue_max=_env_int("APP_CONNECT_EVENT_QUEUE_MAX", 1000, 10),
            state_path=_env("APP_CONNECT_STATE_PATH", "/run/cyjan/app-connect.state.json"),
        )


@dataclass
class RuntimeConfig:
    """Live-Konfig aus dem `config`-Frame (protocol.md §1.3). Mutable und
    bewusst NICHT Teil von Config: eine Änderung darf keinen Reconnect
    auslösen ("ohne Reconnect anwendbar")."""

    event_severity_min: str
    push_detail: str = "minimal"

    def severity_passes(self, severity: str) -> bool:
        rank = SEVERITY_RANK.get((severity or "low").lower(), 0)
        return rank >= SEVERITY_RANK.get(self.event_severity_min, 0)

    def apply(self, payload: dict) -> bool:
        """Übernimmt ein `config`-Frame. Liefert True, wenn sich etwas
        geändert hat. Ungültige Werte werden ignoriert (fail-safe: die
        bestehende, vom Operator gesetzte Schwelle bleibt stehen)."""
        changed = False
        sev = str(payload.get("event_severity_min") or "").lower()
        if sev and sev in SEVERITY_RANK and sev != self.event_severity_min:
            self.event_severity_min = sev
            changed = True
        detail = str(payload.get("push_detail") or "").lower()
        if detail in ("minimal", "standard") and detail != self.push_detail:
            self.push_detail = detail
            changed = True
        return changed
