"""SAML 2.0 SSO – SP-initiated Login über FortiAuthenticator (oder beliebigen IdP).

Endpunkte (alle PUBLIC – kein JWT erforderlich):
  GET  /api/auth/saml/enabled   – SAML aktiviert?
  GET  /api/auth/saml/login     – SP-initiierter Login → Redirect zum IdP
  POST /api/auth/saml/acs       – Assertion Consumer Service (IdP POST hier hin)
  GET  /api/auth/saml/metadata  – SP-Metadata XML zum Download / Eintragen beim IdP
  GET  /api/auth/saml/sls       – Single Logout Service (Redirect-Binding)
  POST /api/auth/saml/sls       – Single Logout Service (POST-Binding)

Flow:
  1. Browser → GET /login → 302 → IdP-SSO-URL
  2. IdP authenticiert → POST /acs (SAMLResponse)
  3. ACS validiert, erstellt/aktualisiert User, gibt JWT aus
  4. 302 → /?saml_token=<JWT>
  5. React-App liest Parameter, speichert Token, entfernt ihn aus der URL
"""
from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from config import Config
from database import get_pool
from jwt_utils import create_token

router = APIRouter(prefix="/api/auth/saml", tags=["saml"])


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def _app_cfg() -> Config:
    from main import cfg
    return cfg


async def _get_saml_cfg(pool: asyncpg.Pool) -> dict:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT value FROM system_config WHERE key = 'saml'"
        )
    if not row:
        raise HTTPException(503, "SAML nicht konfiguriert.")
    cfg = dict(row["value"])
    if not cfg.get("enabled"):
        raise HTTPException(503, "SAML ist deaktiviert.")
    for field in ("idp_entity_id", "idp_sso_url", "idp_x509_cert", "sp_entity_id", "acs_url"):
        if not cfg.get(field):
            raise HTTPException(503, f"SAML-Konfiguration unvollständig: Feld '{field}' fehlt.")
    return cfg


def _build_saml_settings(cfg: dict) -> dict:
    """Baut das python3-saml settings-Dict aus der DB-Konfiguration."""
    return {
        "strict": True,
        "debug":  False,
        "sp": {
            "entityId": cfg["sp_entity_id"],
            "assertionConsumerService": {
                "url":     cfg["acs_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url":     cfg.get("slo_url", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified",
            "x509cert":  "",
            "privateKey": "",
        },
        "idp": {
            "entityId": cfg["idp_entity_id"],
            "singleSignOnService": {
                "url":     cfg["idp_sso_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url":     cfg.get("idp_slo_url", cfg["idp_sso_url"]),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            # Zertifikat ohne PEM-Header (nur Base64-Inhalt, wie in Metadata-XML)
            "x509cert": cfg["idp_x509_cert"].strip()
                          .replace("-----BEGIN CERTIFICATE-----", "")
                          .replace("-----END CERTIFICATE-----", "")
                          .replace("\n", "")
                          .strip(),
        },
    }


def _prepare_request(request: Request, form_data: dict | None = None) -> dict:
    """Baut das request_data-Dict für python3-saml aus dem FastAPI-Request."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host   = request.headers.get("x-forwarded-host",
              request.headers.get("host", "localhost"))
    # Host kann host:port enthalten – trennen
    if ":" in host:
        http_host, port = host.rsplit(":", 1)
    else:
        http_host = host
        port = "443" if scheme == "https" else "80"

    return {
        "https":       "on" if scheme == "https" else "off",
        "http_host":   http_host,
        "script_name": str(request.url.path),
        "server_port": port,
        "get_data":    dict(request.query_params),
        "post_data":   form_data or {},
        "query_string": str(request.url.query),
    }


async def _upsert_saml_user(
    pool: asyncpg.Pool,
    username: str,
    email: str,
    display_name: str,
    default_role: str,
) -> asyncpg.Record:
    """Legt SAML-User an oder aktualisiert ihn. Lehnt Konflikt mit lokalem User ab."""
    async with pool.acquire() as conn:
        existing = await conn.fetchrow(
            "SELECT * FROM users WHERE username = $1", username
        )
        if existing:
            if existing["source"] == "local":
                raise HTTPException(
                    409,
                    f"Benutzername '{username}' ist als lokaler Account registriert "
                    "und kann nicht per SAML verwendet werden.",
                )
            if not existing["active"]:
                raise HTTPException(403, "Benutzer ist deaktiviert.")

        row = await conn.fetchrow(
            """
            INSERT INTO users
              (username, email, display_name, role, source, active)
            VALUES ($1, $2, $3, $4, 'saml', true)
            ON CONFLICT (username) DO UPDATE SET
              email        = COALESCE(EXCLUDED.email,        users.email),
              display_name = COALESCE(EXCLUDED.display_name, users.display_name),
              last_login   = now()
            RETURNING *
            """,
            username,
            email or None,
            display_name or username,
            default_role or "viewer",
        )
    return row


# ── Endpunkte ─────────────────────────────────────────────────────────────────

@router.get("/enabled", summary="Prüft ob SAML aktiviert ist")
async def saml_enabled(pool: asyncpg.Pool = Depends(get_pool)) -> dict:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT value FROM system_config WHERE key = 'saml'"
        )
    enabled = bool(row and row["value"].get("enabled"))
    return {"enabled": enabled, "login_url": "/api/auth/saml/login"}


@router.get("/login", summary="SP-initiierter SAML-Login → Redirect zum IdP")
async def saml_login(
    request: Request,
    pool:    asyncpg.Pool = Depends(get_pool),
) -> RedirectResponse:
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
    except ImportError:
        raise HTTPException(500, "python3-saml nicht installiert.")

    cfg      = await _get_saml_cfg(pool)
    settings = _build_saml_settings(cfg)
    req_data = _prepare_request(request)

    auth         = OneLogin_Saml2_Auth(req_data, old_settings=settings)
    redirect_url = auth.login(return_to="/")
    return RedirectResponse(redirect_url, status_code=302)


@router.post("/acs", summary="Assertion Consumer Service – empfängt SAML Response vom IdP")
async def saml_acs(
    request:  Request,
    pool:     asyncpg.Pool = Depends(get_pool),
    app_cfg:  Config       = Depends(_app_cfg),
) -> RedirectResponse:
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
    except ImportError:
        raise HTTPException(500, "python3-saml nicht installiert.")

    form_data = dict(await request.form())
    cfg       = await _get_saml_cfg(pool)
    settings  = _build_saml_settings(cfg)
    req_data  = _prepare_request(request, form_data)

    auth = OneLogin_Saml2_Auth(req_data, old_settings=settings)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        reason = auth.get_last_error_reason() or str(errors)
        raise HTTPException(400, f"SAML-Validierungsfehler: {reason}")

    if not auth.is_authenticated():
        raise HTTPException(401, "SAML-Authentifizierung fehlgeschlagen.")

    # Attribute aus der Assertion extrahieren
    attrs       = auth.get_attributes()
    name_id     = auth.get_nameid() or ""

    attr_user    = cfg.get("attribute_username",     "uid")
    attr_email   = cfg.get("attribute_email",        "email")
    attr_display = cfg.get("attribute_display_name", "displayName")

    username     = (attrs.get(attr_user,    [None])[0] or
                    attrs.get("uid",        [None])[0] or
                    attrs.get("username",   [None])[0] or
                    name_id)
    email        = attrs.get(attr_email,   [None])[0] or ""
    display_name = attrs.get(attr_display, [None])[0] or username

    if not username:
        raise HTTPException(400, "SAML-Assertion enthält keinen Benutzernamen.")

    user = await _upsert_saml_user(
        pool, username, email, display_name, cfg.get("default_role", "viewer")
    )

    token = create_token(
        app_cfg.secret_key,
        str(user["id"]),
        user["username"],
        user["role"],
    )

    return RedirectResponse(f"/?saml_token={token}", status_code=302)


@router.get("/metadata", summary="SP-Metadata XML für den IdP")
async def sp_metadata(
    request: Request,
    pool:    asyncpg.Pool = Depends(get_pool),
) -> Response:
    try:
        from onelogin.saml2.settings import OneLogin_Saml2_Settings
    except ImportError:
        raise HTTPException(500, "python3-saml nicht installiert.")

    cfg      = await _get_saml_cfg(pool)
    settings = _build_saml_settings(cfg)
    sp_name  = cfg["sp_entity_id"].replace("https://", "").replace("http://", "").split("/")[0]

    sp_settings = OneLogin_Saml2_Settings(settings=settings, sp_validation_only=True)
    metadata    = sp_settings.get_sp_metadata()
    errors      = sp_settings.validate_metadata(metadata)
    if errors:
        raise HTTPException(500, f"SP-Metadata-Fehler: {errors}")

    return Response(
        content=metadata,
        media_type="application/xml; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="sp-metadata-{sp_name}.xml"'},
    )


@router.get("/sls", summary="Single Logout Service (Redirect-Binding)")
@router.post("/sls", summary="Single Logout Service (POST-Binding)")
async def saml_sls(
    request: Request,
    pool:    asyncpg.Pool = Depends(get_pool),
) -> Response:
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
    except ImportError:
        raise HTTPException(500, "python3-saml nicht installiert.")

    form_data = {}
    if request.method == "POST":
        form_data = dict(await request.form())

    cfg      = await _get_saml_cfg(pool)
    settings = _build_saml_settings(cfg)
    req_data = _prepare_request(request, form_data)

    auth = OneLogin_Saml2_Auth(req_data, old_settings=settings)
    # keep_local_session=True – wir verwalten keine Server-Sessions (nur JWTs)
    url = auth.process_slo(keep_local_session=True)
    errors = auth.get_errors()
    if errors:
        raise HTTPException(400, f"SLO-Fehler: {errors}")

    redirect = url or "/"
    return RedirectResponse(redirect, status_code=302)
