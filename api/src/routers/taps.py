"""
Remote-Tap Admin-Endpunkte + Pairing.

Workflow:

  1. Admin erzeugt einen einmalig verwendbaren Pairing-Token mit
     POST /api/taps/pairing-tokens. Im Response steht der KLARTEXT-Token
     genau ein Mal – der Admin kopiert ihn in den Wizard auf der Tap-Seite.
  2. Der Tap startet, generiert lokal einen RSA-Key + CSR, ruft
     POST /api/taps/pair {token, csr_pem, name, site} auf.
  3. Master prüft Token (sha256-hash, used_at IS NULL, expires_at > now),
     signiert die CSR mit der Master-CA, legt einen taps-Eintrag an,
     markiert das Token als used.
  4. Im Response: das signierte Tap-Cert + die Master-CA als PEM. Damit
     hat der Tap alles was er für den späteren mTLS-Uplink braucht.

Sicherheit: Pairing-Endpoint ist NICHT JWT-geschützt – sonst müsste der
Admin sein eigenes JWT an den Tap geben. Stattdessen ist der Token selbst
das Authentisierungsmittel, mit 60min TTL und einmaliger Verwendung.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

import asyncpg
from cryptography import x509
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import master_ca
from database import get_pool
from deps import require_admin

log = logging.getLogger("routers.taps")
router = APIRouter(prefix="/api/taps", tags=["taps"])

# Default-TTL für Pairing-Tokens: 60min, gerade lang genug für einen
# Wizard-Lauf, kurz genug damit ein verlorener Token nicht zur tickenden
# Bombe wird.
DEFAULT_TOKEN_TTL_MIN = 60


# ── Schemas ──────────────────────────────────────────────────────────────


class TapEntry(BaseModel):
    id:               UUID
    name:             str
    site:             str | None = None
    cert_fingerprint: str
    cert_expires_at:  datetime
    status:           str
    paired_at:        datetime
    paired_by:        str | None = None
    last_seen:        datetime | None = None
    alerts_received:  int


class PairingTokenCreate(BaseModel):
    name:    str = Field(min_length=1, max_length=80)
    site:    str | None = Field(default=None, max_length=80)
    ttl_min: int = Field(default=DEFAULT_TOKEN_TTL_MIN, ge=5, le=24 * 60)


class PairingTokenResponse(BaseModel):
    token:      str           # Klartext, nur 1× sichtbar
    expires_at: datetime
    name:       str
    site:       str | None = None


class PairRequest(BaseModel):
    token:   str = Field(min_length=20)
    csr_pem: str = Field(min_length=100)


class PairResponse(BaseModel):
    tap_id:        UUID
    cert_pem:      str
    master_ca_pem: str
    expires_at:    datetime


# ── Helpers ──────────────────────────────────────────────────────────────


def _hash_token(token: str) -> str:
    """SHA-256 ist hier ausreichend: Token sind 256-bit kryptografisch
    zufällig (siehe `secrets.token_urlsafe(32)`), kein Brute-Force-Risiko
    wie bei Passwörtern. bcrypt würde nichts verbessern."""
    return hashlib.sha256(token.encode()).hexdigest()


def _row_to_tap(row: asyncpg.Record) -> TapEntry:
    return TapEntry(
        id=row["id"],
        name=row["name"],
        site=row["site"],
        cert_fingerprint=row["cert_fingerprint"],
        cert_expires_at=row["cert_expires_at"],
        status=row["status"],
        paired_at=row["paired_at"],
        paired_by=row["paired_by"],
        last_seen=row["last_seen"],
        alerts_received=row["alerts_received"],
    )


# ── Admin-CRUD ───────────────────────────────────────────────────────────


@router.get("", response_model=list[TapEntry])
async def list_taps(_admin: dict = Depends(require_admin)) -> list[TapEntry]:
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, name, site, cert_fingerprint, cert_expires_at,
                   status, paired_at, paired_by, last_seen, alerts_received
              FROM taps
             ORDER BY paired_at DESC
            """
        )
    return [_row_to_tap(r) for r in rows]


@router.post("/pairing-tokens", response_model=PairingTokenResponse, status_code=201)
async def create_pairing_token(
    body: PairingTokenCreate,
    admin: dict = Depends(require_admin),
) -> PairingTokenResponse:
    """Erzeugt einen Bootstrap-Token. Klartext ist ausschließlich im
    Response sichtbar – wir speichern nur den sha256-Hash in der DB."""
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(minutes=body.ttl_min)

    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO tap_pairing_tokens
                (token_hash, tap_name, tap_site, expires_at, created_by)
            VALUES ($1, $2, $3, $4, $5)
            """,
            _hash_token(token), body.name, body.site, expires, admin.get("sub"),
        )

    log.info("Pairing-Token erzeugt: name=%s ttl=%dmin von=%s",
             body.name, body.ttl_min, admin.get("sub"))
    return PairingTokenResponse(
        token=token,
        expires_at=expires,
        name=body.name,
        site=body.site,
    )


@router.delete("/{tap_id}", status_code=204)
async def revoke_tap(
    tap_id: UUID,
    admin: dict = Depends(require_admin),
) -> None:
    pool = get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE taps
               SET status='revoked', revoked_at=now(), revoked_by=$2
             WHERE id=$1 AND status='active'
            """,
            tap_id, admin.get("sub"),
        )
    if result.endswith(" 0"):
        raise HTTPException(404, "Tap nicht gefunden oder bereits revoked")
    log.warning("Tap %s revoked von %s", tap_id, admin.get("sub"))


# ── Pairing (öffentlich, Token-authentisiert) ────────────────────────────


@router.post("/pair", response_model=PairResponse)
async def pair_tap(body: PairRequest) -> PairResponse:
    """Token + CSR → signiertes Cert. Idempotent NICHT – jeder Token ist
    one-shot. Wenn der Tap das Pairing wiederholen muss (z.B. weil das
    Cert verloren ging), erzeugt der Admin einen neuen Token und revoked
    den alten Tap."""
    token_hash = _hash_token(body.token)

    pool = get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT id, tap_name, tap_site, expires_at, used_at
                  FROM tap_pairing_tokens
                 WHERE token_hash=$1
                 FOR UPDATE
                """,
                token_hash,
            )
            if not row:
                raise HTTPException(401, "Token ungültig")
            if row["used_at"] is not None:
                raise HTTPException(409, "Token wurde bereits verwendet")
            if row["expires_at"] < datetime.utcnow():
                raise HTTPException(401, "Token abgelaufen")

            # Tap-Datensatz vorbereiten – id wird hier generiert, damit die
            # CSR bereits mit dem korrekten Subject CN signiert werden kann.
            tap_id_row = await conn.fetchrow("SELECT uuid_generate_v4() AS id")
            tap_id = tap_id_row["id"]

            try:
                ca = master_ca.get_master_ca()
                cert, cert_pem = ca.sign_tap_csr(
                    body.csr_pem.encode(),
                    tap_id=str(tap_id),
                    tap_name=row["tap_name"],
                )
            except ValueError as exc:
                raise HTTPException(400, f"CSR ungültig: {exc}")

            from cryptography.hazmat.primitives import hashes
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()

            await conn.execute(
                """
                INSERT INTO taps
                    (id, name, site, cert_fingerprint, cert_expires_at,
                     status, paired_at, paired_by)
                VALUES ($1, $2, $3, $4, $5, 'active', now(), $6)
                """,
                tap_id, row["tap_name"], row["tap_site"],
                fingerprint, cert.not_valid_after,
                "pairing-token",  # paired_by: kein User-Kontext beim Pair-Call
            )
            await conn.execute(
                """
                UPDATE tap_pairing_tokens
                   SET used_at=now(), used_by_tap=$2
                 WHERE id=$1
                """,
                row["id"], tap_id,
            )

    log.warning("Tap gepairt: id=%s name=%s fingerprint=%s",
                tap_id, row["tap_name"], fingerprint)

    return PairResponse(
        tap_id=tap_id,
        cert_pem=cert_pem.decode(),
        master_ca_pem=ca.cert_pem.decode(),
        expires_at=cert.not_valid_after,
    )
