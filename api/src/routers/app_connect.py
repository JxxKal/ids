"""api/src/routers/app_connect.py — GUI-Backend für den app-connect-Dienst.

Zwei Aufgaben, sauber getrennt:

1. **Konfiguration** (`GET`/`PUT /api/app-connect/config`) — liest und schreibt
   den Block `app_connect` in `system_config`. Genau wie bei der mqtt-bridge
   ist die DB die Quelle der Wahrheit; ENV ist nur Bootstrap (ISO, Air-Gap).
   Der app-connect-Container pollt die Tabelle alle 30 s selbst — wir stoßen
   hier bewusst keinen Restart an.

2. **Durchreichen** (`/status`, `/pair`, `/devices`, `/test-egress`) an
   `http://app-connect:8090`. Kopplungscodes und Gerätelisten liegen beim
   Cloud-Proxy, nicht lokal — nur app-connect hat den Tunnel dorthin und
   kennt den Egress-Weg (Firmen-Proxy, Firmen-CA).

   Vorbild: `routers/redteam_proxy.py`. Vertrag: `app-connect/docs/internal-api.md`.

Zwei Dinge, die hier bewusst NICHT passieren:

* Das `device_token` wird **nie** zurückgeliefert — `GET /config` meldet nur
  `device_token_set: bool`. Ein Token, das man in der GUI wieder auslesen
  kann, landet im Browser-Cache und im Screenshot.
* Ein nicht laufender app-connect-Container ist **kein 500**. Der Dienst ist
  im Normalfall dormant (kein Proxy-URL, kein Token) oder per Compose-Profil
  gar nicht gestartet. Alle Proxy-Endpunkte antworten dann mit `503` und
  einem deutschen Text, den die GUI direkt anzeigen kann.
"""
from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urlparse

import asyncpg
import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from database import get_pool
from deps import require_admin

router = APIRouter(prefix="/api/app-connect", tags=["app-connect"])
log = logging.getLogger(__name__)

APP_CONNECT_URL = os.environ.get("APP_CONNECT_URL", "http://app-connect:8090").rstrip("/")
API_SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")

CONFIG_KEY = "app_connect"

# Status/Devices sind billig, Pair und Egress-Test gehen über die Leitung
# nach draußen (DNS + CONNECT + TLS-Handshake über einen evtl. langsamen
# Firmen-Proxy) — deshalb zwei Timeout-Profile.
TIMEOUT_FAST = httpx.Timeout(8.0, connect=3.0)
TIMEOUT_SLOW = httpx.Timeout(45.0, connect=5.0)

SEVERITIES = ("low", "medium", "high", "critical")

# Der `app_connect`-Block in system_config, wie ihn der Vertrag beschreibt.
# `device_token` ist Teil des Blocks, wird aber nie ausgeliefert — siehe
# _public_config().
_DEFAULT_BLOCK: dict[str, Any] = {
    "enabled":       False,
    "proxy_url":     "",
    "device_token":  "",
    "sentry_name":   "",
    "https_proxy":   "",
    "no_proxy":      "",
    "ca_file":       "",
    "allow_triage":  False,
    "severity_min":  "medium",
}

_SERVICE_DOWN = "App-Connect-Dienst läuft nicht"


# ── Modelle ──────────────────────────────────────────────────────────────────

class AppConnectConfig(BaseModel):
    """Der Konfigurationsblock, wie ihn die GUI sieht — ohne device_token."""
    enabled:      bool = False
    proxy_url:    str = ""
    sentry_name:  str = ""
    https_proxy:  str = ""
    no_proxy:     str = ""
    ca_file:      str = ""
    allow_triage: bool = False
    severity_min: str = "medium"


class AppConnectConfigResponse(BaseModel):
    config:            AppConnectConfig
    device_token_set:  bool
    # Felder, die in der DB leer sind, aber vom laufenden Dienst mit einem
    # Wert gemeldet werden ⇒ sie stammen aus der ENV (Bootstrap/ISO).
    env_fields:        list[str] = Field(default_factory=list)
    # Der effektive ENV-Wert je Feld — für den Platzhalter im Eingabefeld.
    # `https_proxy` kommt vom Dienst bereits ohne Credentials redigiert.
    env_values:        dict[str, str] = Field(default_factory=dict)
    service_reachable: bool = False
    config_source:     str | None = None    # db | env | None (Dienst nicht erreichbar)


class AppConnectConfigUpdate(BaseModel):
    enabled:      bool = False
    proxy_url:    str = Field(default="", max_length=512)
    # Leer = gespeichertes Token bleibt unangetastet. Sonst würde jedes
    # Speichern aus der GUI das Token löschen, weil die GUI es nie kennt.
    device_token: str = Field(default="", max_length=4096)
    clear_device_token: bool = False
    sentry_name:  str = Field(default="", max_length=128)
    https_proxy:  str = Field(default="", max_length=512)
    no_proxy:     str = Field(default="", max_length=2048)
    ca_file:      str = Field(default="", max_length=512)
    allow_triage: bool = False
    severity_min: str = "medium"

    @field_validator("proxy_url")
    @classmethod
    def _check_proxy_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            return v          # leer = fällt auf ENV zurück (Vertrag §Konfiguration)
        parsed = urlparse(v)
        if parsed.scheme not in ("ws", "wss"):
            raise ValueError("Proxy-URL muss mit wss:// oder ws:// beginnen")
        if not parsed.netloc:
            raise ValueError("Proxy-URL enthält keinen Host")
        return v

    @field_validator("https_proxy")
    @classmethod
    def _check_https_proxy(cls, v: str) -> str:
        v = v.strip()
        if not v:
            return v
        parsed = urlparse(v)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(
                "Egress-Proxy muss eine vollständige URL sein, z.B. "
                "http://proxy.kunde.local:3128"
            )
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Egress-Proxy muss http:// oder https:// sein")
        return v

    @field_validator("ca_file")
    @classmethod
    def _check_ca_file(cls, v: str) -> str:
        v = v.strip()
        if v and not v.startswith("/"):
            raise ValueError("CA-Pfad muss ein absoluter Pfad im Container sein")
        return v

    @field_validator("severity_min")
    @classmethod
    def _check_severity(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in SEVERITIES:
            raise ValueError("Mindest-Severity muss low, medium, high oder critical sein")
        return v


class PairRequest(BaseModel):
    label: str = Field(default="", max_length=64)
    ttl_s: int = Field(default=600, ge=60, le=3600)


class TestEgressRequest(BaseModel):
    """Alle Felder optional — fehlende ergänzt app-connect aus der aktiven
    Konfiguration. Damit lässt sich ein Proxy testen, BEVOR er gespeichert
    wird (genau der Punkt, an dem ein Admin ihn braucht)."""
    proxy_url:   str | None = None
    https_proxy: str | None = None
    no_proxy:    str | None = None
    ca_file:     str | None = None


# ── DB-Helfer ────────────────────────────────────────────────────────────────

async def _load_block(pool: asyncpg.Pool) -> tuple[dict[str, Any], bool]:
    """Liefert (Block, existiert_in_der_DB). Das zweite Flag entscheidet, ob
    die GUI Defaults oder den ENV-Stand des Dienstes anzeigen soll — sonst
    würde ein Formular, das nie gespeichert wurde, ein per ENV aktiviertes
    App-Connect beim ersten Speichern versehentlich abschalten."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT value FROM system_config WHERE key = $1", CONFIG_KEY
        )
    block = dict(_DEFAULT_BLOCK)
    if not row or not row["value"]:
        return block, False
    stored = dict(row["value"])
    # Unbekannte Felder (z.B. tls_insecure, das die GUI nicht anfasst)
    # bleiben erhalten — der Block gehört nicht allein diesem Formular.
    block.update(stored)
    return block, True


async def _store_block(pool: asyncpg.Pool, block: dict[str, Any]) -> dict[str, Any]:
    # asyncpg-Codec: dict direkt übergeben — weder json.dumps davor noch
    # ein ::jsonb-Cast in der Query (sonst Double-Encoding).
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO system_config (key, value) VALUES ($1, $2)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            RETURNING value
            """,
            CONFIG_KEY, block,
        )
    return dict(row["value"])


def _public_config(block: dict[str, Any]) -> AppConnectConfig:
    return AppConnectConfig(
        enabled=bool(block.get("enabled", False)),
        proxy_url=str(block.get("proxy_url") or ""),
        sentry_name=str(block.get("sentry_name") or ""),
        https_proxy=str(block.get("https_proxy") or ""),
        no_proxy=str(block.get("no_proxy") or ""),
        ca_file=str(block.get("ca_file") or ""),
        allow_triage=bool(block.get("allow_triage", False)),
        severity_min=str(block.get("severity_min") or "medium"),
    )


# ── HTTP-Helfer (Proxy zu app-connect) ───────────────────────────────────────

def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {API_SECRET_KEY}"}


def _detail_of(resp: httpx.Response) -> str:
    """Fehlertext aus der Antwort ziehen. app-connect nutzt dieselbe Form wie
    die ids-API (`{"detail": "..."}`), fällt aber auf den Rohtext zurück."""
    try:
        body = resp.json()
        if isinstance(body, dict) and isinstance(body.get("detail"), str):
            return body["detail"]
    except ValueError:
        pass
    return (resp.text or "").strip()[:400] or f"HTTP {resp.status_code}"


async def _call(
    method: str,
    path: str,
    *,
    json_body: Any | None = None,
    timeout: httpx.Timeout = TIMEOUT_FAST,
) -> httpx.Response:
    """Ruft app-connect auf. Übersetzt Transportfehler in ein 503 mit
    deutschem Text und Fachfehler (4xx/5xx) 1:1 weiter."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as cli:
            resp = await cli.request(
                method, f"{APP_CONNECT_URL}{path}",
                headers=_headers(), json=json_body,
            )
    except httpx.HTTPError as exc:
        # Container gestoppt, Profil nicht aktiv, DNS-Name unbekannt … der
        # Normalfall, solange App-Connect nicht eingerichtet ist.
        log.info("app-connect nicht erreichbar (%s %s): %s", method, path, exc)
        raise HTTPException(status_code=503, detail=_SERVICE_DOWN)

    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=_detail_of(resp))
    return resp


async def _try_status() -> dict[str, Any] | None:
    """Status holen, ohne zu scheitern — für die ENV-Herkunftserkennung im
    Config-Endpoint. Ein toter Dienst darf das Formular nicht blockieren."""
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_FAST) as cli:
            resp = await cli.get(f"{APP_CONNECT_URL}/status", headers=_headers())
        if resp.status_code >= 400:
            return None
        body = resp.json()
        return body if isinstance(body, dict) else None
    except (httpx.HTTPError, ValueError):
        return None


# Welches Status-Feld gehört zu welchem Config-Feld? `https_proxy` heißt im
# Status `egress` (und ist dort bereits ohne Credentials redigiert).
_STATUS_FIELD_MAP = {
    "proxy_url":    "proxy_url",
    "sentry_name":  "sentry_name",
    "https_proxy":  "egress",
    "ca_file":      "ca_file",
    "severity_min": "event_severity_min",
}


def _env_origin(
    block: dict[str, Any], status: dict[str, Any], block_exists: bool,
) -> tuple[list[str], dict[str, str]]:
    """Welche Felder sind aus der ENV vorbelegt?

    Heuristik entlang des Vertrags: DB leer + Dienst meldet trotzdem einen
    Wert ⇒ der Wert kommt aus der ENV. Sauberer als raten, weil die api den
    ENV-Block von app-connect gar nicht sieht (andere Container-Umgebung).
    """
    fields: list[str] = []
    values: dict[str, str] = {}
    for cfg_field, status_field in _STATUS_FIELD_MAP.items():
        if str(block.get(cfg_field) or "").strip():
            continue                                    # DB gewinnt, kein ENV-Hinweis
        eff = status.get(status_field)
        if isinstance(eff, str) and eff.strip():
            fields.append(cfg_field)
            values[cfg_field] = eff.strip()

    # Das Token meldet der Dienst nie im Klartext. `configured` heißt aber:
    # proxy_url UND device_token liegen vor. Ist die DB leer, kann es nur
    # aus der ENV stammen.
    if not str(block.get("device_token") or "").strip() and status.get("configured"):
        fields.append("device_token")

    # Booleans lassen sich nicht am "leer"-Kriterium erkennen. Nur solange
    # es überhaupt keinen DB-Block gibt, stammen sie zwangsläufig aus der ENV.
    if not block_exists:
        fields.extend(("enabled", "allow_triage"))

    return fields, values


def _seed_from_status(block: dict[str, Any], status: dict[str, Any] | None) -> dict[str, Any]:
    """Ohne DB-Block zeigt die GUI den tatsächlich laufenden ENV-Stand statt
    generischer Defaults. Sonst stünde im Formular `Aktiv: aus`, während der
    Dienst per ENV längst läuft — und der erste Klick auf Speichern würde ihn
    abschalten, ohne dass jemand das wollte."""
    if status is None:
        return block
    seeded = dict(block)
    seeded["enabled"] = bool(status.get("enabled", block.get("enabled", False)))
    seeded["allow_triage"] = bool(status.get("allow_triage", block.get("allow_triage", False)))
    sev = status.get("event_severity_min")
    if isinstance(sev, str) and sev in SEVERITIES:
        seeded["severity_min"] = sev
    return seeded


# ── Endpunkte: Konfiguration ─────────────────────────────────────────────────

@router.get("/config", response_model=AppConnectConfigResponse,
            dependencies=[Depends(require_admin)])
async def get_config(pool: asyncpg.Pool = Depends(get_pool)) -> AppConnectConfigResponse:
    block, exists = await _load_block(pool)
    status = await _try_status()

    env_fields: list[str] = []
    env_values: dict[str, str] = {}
    config_source: str | None = None
    if status is not None:
        env_fields, env_values = _env_origin(block, status, exists)
        src = status.get("config_source")
        config_source = src if isinstance(src, str) else None

    shown = block if exists else _seed_from_status(block, status)

    return AppConnectConfigResponse(
        config=_public_config(shown),
        device_token_set=bool(str(block.get("device_token") or "").strip()),
        env_fields=env_fields,
        env_values=env_values,
        service_reachable=status is not None,
        config_source=config_source,
    )


@router.put("/config", response_model=AppConnectConfigResponse,
            dependencies=[Depends(require_admin)])
async def put_config(
    body: AppConnectConfigUpdate,
    pool: asyncpg.Pool = Depends(get_pool),
) -> AppConnectConfigResponse:
    current, _exists = await _load_block(pool)

    # Token-Regel: leeres Feld = unverändert; explizites clear_device_token
    # löscht. Sonst löscht jedes Speichern der GUI das Token, weil die GUI
    # den Wert nie zu sehen bekommt und deshalb auch nie zurücksenden kann.
    if body.clear_device_token:
        token = ""
    elif body.device_token.strip():
        token = body.device_token.strip()
    else:
        token = str(current.get("device_token") or "")

    # Auf dem bestehenden Block aufsetzen, damit Felder, die diese GUI nicht
    # kennt (z.B. tls_insecure), beim Speichern nicht verloren gehen.
    block: dict[str, Any] = dict(current)
    block.update({
        "enabled":      body.enabled,
        "proxy_url":    body.proxy_url.strip(),
        "device_token": token,
        "sentry_name":  body.sentry_name.strip(),
        "https_proxy":  body.https_proxy.strip(),
        "no_proxy":     body.no_proxy.strip(),
        "ca_file":      body.ca_file.strip(),
        "allow_triage": body.allow_triage,
        "severity_min": body.severity_min,
    })
    stored = await _store_block(pool, block)
    log.info(
        "app-connect-Konfig gespeichert (enabled=%s, triage=%s, severity_min=%s, token=%s)",
        block["enabled"], block["allow_triage"], block["severity_min"],
        "gesetzt" if token else "leer",
    )

    status = await _try_status()
    env_fields: list[str] = []
    env_values: dict[str, str] = {}
    config_source: str | None = None
    if status is not None:
        env_fields, env_values = _env_origin(stored, status, True)
        src = status.get("config_source")
        config_source = src if isinstance(src, str) else None

    return AppConnectConfigResponse(
        config=_public_config(stored),
        device_token_set=bool(str(stored.get("device_token") or "").strip()),
        env_fields=env_fields,
        env_values=env_values,
        service_reachable=status is not None,
        config_source=config_source,
    )


# ── Endpunkte: Durchreichen an app-connect ───────────────────────────────────

@router.get("/status", dependencies=[Depends(require_admin)])
async def status() -> dict[str, Any]:
    resp = await _call("GET", "/status")
    body = resp.json()
    if not isinstance(body, dict):
        raise HTTPException(502, "App-Connect lieferte eine unerwartete Antwort")
    return body


@router.post("/pair", dependencies=[Depends(require_admin)])
async def pair(req: PairRequest) -> dict[str, Any]:
    """Erzeugt beim Cloud-Proxy einen Kopplungscode. Antwort enthält Code,
    Ablaufzeitpunkt, Deep-Link und das QR-SVG. Das SVG wird im Frontend als
    `<img src="data:image/svg+xml;base64,…">` gerendert, nicht per
    dangerouslySetInnerHTML — ein QR-Bild rechtfertigt keinen DOM-Injektionspfad."""
    label = req.label.strip() or "Neues Gerät"
    resp = await _call("POST", "/pair", json_body={"label": label, "ttl_s": req.ttl_s},
                       timeout=TIMEOUT_SLOW)
    body = resp.json()
    if not isinstance(body, dict):
        raise HTTPException(502, "App-Connect lieferte eine unerwartete Antwort")
    return body


@router.get("/devices", dependencies=[Depends(require_admin)])
async def devices() -> list[dict[str, Any]]:
    resp = await _call("GET", "/devices")
    body = resp.json()
    if not isinstance(body, list):
        raise HTTPException(502, "App-Connect lieferte eine unerwartete Geräteliste")
    return [d for d in body if isinstance(d, dict)]


@router.delete("/devices/{device_id}", status_code=204, response_model=None,
               dependencies=[Depends(require_admin)])
async def revoke_device(device_id: str) -> None:
    if not device_id.strip():
        raise HTTPException(400, "Geräte-ID fehlt")
    await _call("DELETE", f"/devices/{device_id}", timeout=TIMEOUT_SLOW)


@router.post("/test-egress", dependencies=[Depends(require_admin)])
async def test_egress(req: TestEgressRequest) -> dict[str, Any]:
    """Prüft DNS → CONNECT → TLS → Zertifikat gegen die ÜBERGEBENE Konfig,
    damit ein Admin einen Proxy testen kann, bevor er ihn speichert.
    Antwortet auch bei Fehlschlag mit 200 — das Ergebnis steckt in `ok`."""
    payload = {k: v for k, v in req.model_dump().items() if v is not None}
    resp = await _call("POST", "/test-egress", json_body=payload, timeout=TIMEOUT_SLOW)
    body = resp.json()
    if not isinstance(body, dict):
        raise HTTPException(502, "App-Connect lieferte eine unerwartete Antwort")
    return body
