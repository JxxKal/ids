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
import ipaddress
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from uuid import UUID
from typing import Any

import asyncpg
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
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
    id:                  UUID
    name:                str
    site:                str | None = None
    cert_fingerprint:    str
    cert_expires_at:     datetime
    status:              str
    paired_at:           datetime
    paired_by:           str | None = None
    last_seen:           datetime | None = None
    alerts_received:     int
    # Vom Tap selbst gemeldete Version (hello-Frame beim Connect, gefüttert
    # aus /opt/ids/VERSION via Bind-Mount). None auf alten Taps die noch
    # kein hello senden — Frontend zeigt dort "?".
    version:             str | None = None
    version_reported_at: datetime | None = None


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
        version=row.get("version") if hasattr(row, "get") else (row["version"] if "version" in row.keys() else None),
        version_reported_at=row.get("version_reported_at") if hasattr(row, "get") else (row["version_reported_at"] if "version_reported_at" in row.keys() else None),
    )


# ── Admin-CRUD ───────────────────────────────────────────────────────────


@router.get("", response_model=list[TapEntry])
async def list_taps(_admin: dict = Depends(require_admin)) -> list[TapEntry]:
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, name, site, cert_fingerprint, cert_expires_at,
                   status, paired_at, paired_by, last_seen, alerts_received,
                   version, version_reported_at
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
    expires = datetime.now(timezone.utc) + timedelta(minutes=body.ttl_min)

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


@router.delete("/{tap_id}", status_code=204, response_class=Response)
async def revoke_tap(
    tap_id: UUID,
    admin: dict = Depends(require_admin),
) -> Response:
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
    return Response(status_code=204)


@router.post("/{tap_id}/trigger-update", status_code=202)
async def trigger_tap_update(
    tap_id: UUID,
    admin: dict = Depends(require_admin),
) -> dict:
    """Setzt update_requested_at — master-uplink sieht das in seinem
    trigger_loop und sendet einen update_now-Frame an die WebSocket-
    Connection des Taps. Tap-uplink schreibt dann ein Trigger-File,
    systemd-path auf dem Tap-Host führt cyjan-tap update --from-master
    aus.

    Idempotent: zweiter Aufruf re-bumpt update_requested_at, master-
    uplink sendet erneut. Kein "schon getriggert"-Lock — falls der
    erste Trigger nicht durchkam (Tap offline, Update-Run gefailt),
    soll der nächste klick sofort wieder feuern."""
    pool = get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE taps
               SET update_requested_at = now(),
                   update_requested_by = $2::uuid,
                   update_acked_at     = NULL
             WHERE id=$1 AND status='active'
            """,
            tap_id, admin.get("sub"),
        )
    if result.endswith(" 0"):
        raise HTTPException(404, "Tap nicht gefunden oder revoked")
    log.info("Update-Trigger für Tap %s von Admin %s", tap_id, admin.get("sub"))
    return {"queued": True, "tap_id": str(tap_id)}


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
                SELECT id, tap_name, tap_site, expires_at, used_at, created_by
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
            if row["expires_at"] < datetime.now(timezone.utc):
                raise HTTPException(401, "Token abgelaufen")

            # Tap-Datensatz vorbereiten – id wird hier generiert, damit die
            # CSR bereits mit dem korrekten Subject CN signiert werden kann.
            tap_id = uuid.uuid4()

            try:
                ca = master_ca.get_master_ca()
                cert, cert_pem = ca.sign_tap_csr(
                    body.csr_pem.encode(),
                    tap_id=str(tap_id),
                    tap_name=row["tap_name"],
                )
            except ValueError as exc:
                raise HTTPException(400, f"CSR ungültig: {exc}")

            fingerprint = cert.fingerprint(hashes.SHA256()).hex()

            await conn.execute(
                """
                INSERT INTO taps
                    (id, name, site, cert_fingerprint, cert_expires_at,
                     status, paired_at, paired_by)
                VALUES ($1, $2, $3, $4, $5, 'active', now(), $6)
                """,
                tap_id, row["tap_name"], row["tap_site"],
                fingerprint, cert.not_valid_after_utc,
                # paired_by = der Admin der das Token erzeugt hat – Audit-Trail
                # bleibt erhalten, obwohl der Pair-Call selbst Token-authed ist.
                row["created_by"],
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
        expires_at=cert.not_valid_after_utc,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Auto-Pairing: Token-frei, Admin-bestätigt
#
# Tap kennt nur die Master-URL (kein Token). Er meldet sich mit POST /announce —
# wenn die Source-IP in known_networks UND in einer privaten IP-Range ist, landet
# er in pending_taps. Admin sieht im UI eine "Pending Taps"-Liste und drückt
# approve/reject. Tap pollt /announce-status und kriegt dort sein signiertes
# Cert + die Master-CA, sobald approved.
#
# Sicherheit:
#   - Source-IP MUSS RFC1918/ULA sein (nie Public-Internet).
#   - Source-IP MUSS in known_networks stehen (deine OT-Zone).
#   - Rate-Limit: pro IP max. 1 Announce / 60s.
#   - Hardware-ID + Fingerprint als Identität — re-announces werden gemerged.
# ══════════════════════════════════════════════════════════════════════════════

# Strikte Allowlist: nur RFC1918 + IPv6-ULA. Loopback/Link-local sind nicht
# inkludiert, weil Tap und Master in unterschiedlichen Subnets sitzen — wenn
# der Tap den Master via 127.0.0.1 anspricht ist es derselbe Host und das
# wäre kein realer Tap-Pair-Use-Case.
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETS)


async def _ip_in_known_networks(conn: asyncpg.Connection, ip_str: str) -> bool:
    """Match gegen die known_networks-Tabelle (CIDR-Spalte). Wenn die Tabelle
    leer ist, gibt's keinen Treffer — der Operator muss erst Schritt 1 aus der
    Erste-Schritte-Anleitung erledigen."""
    row = await conn.fetchrow(
        "SELECT 1 FROM known_networks WHERE $1::inet <<= cidr LIMIT 1",
        ip_str,
    )
    return row is not None


async def _audit(
    conn: asyncpg.Connection,
    *,
    event: str,
    source_ip: str | None = None,
    hardware_id: str | None = None,
    name: str | None = None,
    pending_id: UUID | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    import json
    await conn.execute(
        """
        INSERT INTO tap_audit_log (event, source_ip, hardware_id, name, pending_id, details)
        VALUES ($1, $2, $3, $4, $5, $6::jsonb)
        """,
        event, source_ip, hardware_id, name, pending_id,
        json.dumps(details or {}),
    )


def _csr_fingerprint(csr_pem: str) -> str:
    """SHA256 des CSR-public-keys. Identifiziert den Tap eindeutig auch wenn
    die Box hardware_id wechselt (z.B. nach Reinstall mit gleichem Key)."""
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    pub = csr.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(pub).hexdigest()


# ── Schemas ──


class AnnounceRequest(BaseModel):
    name:        str = Field(min_length=1, max_length=80)
    hardware_id: str = Field(min_length=4, max_length=128)
    csr_pem:     str = Field(min_length=100)
    hostname:    str | None = Field(default=None, max_length=128)
    version:     str | None = Field(default=None, max_length=64)


class AnnounceResponse(BaseModel):
    status:     str       # 'pending' | 'approved' | 'rejected'
    pending_id: UUID | None = None
    message:    str       # menschenlesbarer Hint (für CLI/Wizard)


class AnnounceStatusResponse(BaseModel):
    status:        str    # 'pending' | 'approved' | 'rejected' | 'unknown'
    tap_id:        UUID | None    = None
    cert_pem:      str | None     = None
    master_ca_pem: str | None     = None
    expires_at:    datetime | None = None
    message:       str | None = None


class PendingTapEntry(BaseModel):
    id:           UUID
    name:         str
    hardware_id:  str
    source_ip:    str
    hostname:     str | None
    version:      str | None
    fingerprint:  str
    announced_at: datetime
    status:       str


class PendingApproveRequest(BaseModel):
    # Optional: Admin kann den Namen umschreiben (z.B. der Tap meldet sich als
    # "tap-default", Admin nennt ihn "site-A-rack-3").
    name: str | None = Field(default=None, min_length=1, max_length=80)
    site: str | None = Field(default=None, max_length=80)


class AuditLogEntry(BaseModel):
    id:           int
    ts:           datetime
    event:        str
    source_ip:    str | None
    hardware_id:  str | None
    name:         str | None
    pending_id:   UUID | None
    details:      dict[str, Any]


# ── Public Endpoints (keine Auth — IP-Validierung als Schutz) ──


_ANNOUNCE_RATE_LIMIT_S = 60


@router.post("/announce", response_model=AnnounceResponse)
async def announce_tap(body: AnnounceRequest, request: Request) -> AnnounceResponse:
    """Tap meldet sich beim Master. Validierung:
    1. Source-IP muss RFC1918/ULA sein (keine Public-IPs).
    2. Source-IP muss in known_networks stehen.
    3. Rate-Limit: 1 Announce pro IP / 60 s.
    Bei Erfolg landet der Tap in pending_taps mit status='pending'."""
    source_ip = request.client.host if request.client else None
    if not source_ip:
        raise HTTPException(400, "Source-IP nicht ermittelbar")

    pool = get_pool()
    async with pool.acquire() as conn:
        # Audit für jeden Versuch — auch abgelehnte (das ist der Sinn des Logs).
        if not _is_private_ip(source_ip):
            await _audit(conn, event="rejected_ip_not_private",
                         source_ip=source_ip, hardware_id=body.hardware_id, name=body.name,
                         details={"hostname": body.hostname, "version": body.version})
            raise HTTPException(403, "Auto-Pair nur aus privaten IP-Ranges (RFC1918/ULA)")

        if not await _ip_in_known_networks(conn, source_ip):
            await _audit(conn, event="rejected_ip_not_known",
                         source_ip=source_ip, hardware_id=body.hardware_id, name=body.name,
                         details={"hostname": body.hostname, "version": body.version})
            raise HTTPException(
                403,
                "Source-IP nicht in known_networks. Trag das OT-Subnet im Master "
                "unter Netzwerke ein, dann probier es nochmal.",
            )

        # Rate-Limit pro IP.
        recent = await conn.fetchval(
            """
            SELECT 1 FROM tap_audit_log
             WHERE event='announce' AND source_ip=$1::inet
               AND ts > now() - ($2 || ' seconds')::interval
             LIMIT 1
            """,
            source_ip, str(_ANNOUNCE_RATE_LIMIT_S),
        )
        if recent:
            await _audit(conn, event="rejected_rate_limit",
                         source_ip=source_ip, hardware_id=body.hardware_id, name=body.name)
            raise HTTPException(429, "Rate-Limit: 1 Announce pro IP / 60 s")

        try:
            fingerprint = _csr_fingerprint(body.csr_pem)
        except Exception as exc:
            await _audit(conn, event="rejected_csr_invalid",
                         source_ip=source_ip, hardware_id=body.hardware_id, name=body.name,
                         details={"error": str(exc)})
            raise HTTPException(400, f"CSR ungültig: {exc}")

        # UPSERT: gleicher hardware_id+fingerprint = Re-Announce, wir aktualisieren
        # die meta-Daten und behalten den status (außer er war 'rejected', dann
        # blockieren wir weiter — Admin muss explizit den Reject aufheben).
        existing = await conn.fetchrow(
            """
            SELECT id, status FROM pending_taps
             WHERE hardware_id=$1 AND fingerprint=$2
            """,
            body.hardware_id, fingerprint,
        )
        if existing:
            if existing["status"] == "rejected":
                await _audit(conn, event="poll", source_ip=source_ip,
                             hardware_id=body.hardware_id, pending_id=existing["id"],
                             details={"note": "re-announce nach reject ignoriert"})
                return AnnounceResponse(
                    status="rejected", pending_id=existing["id"],
                    message="Tap wurde zuvor abgelehnt. Admin muss zuerst entsperren.",
                )
            if existing["status"] == "approved":
                # Cert ist eventuell noch nicht abgeholt — Tap soll auf
                # check-status pollen.
                return AnnounceResponse(
                    status="approved", pending_id=existing["id"],
                    message="Bereits approved — bitte /announce-status pollen.",
                )
            # status='pending' → wir aktualisieren nur die meta-Felder.
            await conn.execute(
                """
                UPDATE pending_taps
                   SET name=$2, hostname=$3, version=$4, source_ip=$5::inet,
                       announced_at=now()
                 WHERE id=$1
                """,
                existing["id"], body.name, body.hostname, body.version, source_ip,
            )
            await _audit(conn, event="announce", source_ip=source_ip,
                         hardware_id=body.hardware_id, name=body.name,
                         pending_id=existing["id"],
                         details={"re_announce": True, "fingerprint": fingerprint[:16]})
            return AnnounceResponse(
                status="pending", pending_id=existing["id"],
                message="Re-announce. Bitte auf Admin-Approval warten.",
            )

        # Neu — Eintrag anlegen.
        new_id = uuid.uuid4()
        await conn.execute(
            """
            INSERT INTO pending_taps
                (id, hardware_id, name, source_ip, hostname, version,
                 csr_pem, fingerprint, status)
            VALUES ($1, $2, $3, $4::inet, $5, $6, $7, $8, 'pending')
            """,
            new_id, body.hardware_id, body.name, source_ip,
            body.hostname, body.version, body.csr_pem, fingerprint,
        )
        await _audit(conn, event="announce", source_ip=source_ip,
                     hardware_id=body.hardware_id, name=body.name,
                     pending_id=new_id,
                     details={"fingerprint": fingerprint[:16],
                              "hostname": body.hostname, "version": body.version})

    log.warning("Tap-Announce: %s aus %s (hardware_id=%s, fp=%s)",
                body.name, source_ip, body.hardware_id, fingerprint[:16])

    return AnnounceResponse(
        status="pending", pending_id=new_id,
        message="Announce erfasst. Warte auf Admin-Approval.",
    )


@router.get("/announce-status/{hardware_id}/{fingerprint}", response_model=AnnounceStatusResponse)
async def announce_status(hardware_id: str, fingerprint: str) -> AnnounceStatusResponse:
    """Tap pollt diesen Endpoint alle ~30 s nach einem Announce. Bei Status
    'approved' kommt das signierte Cert + Master-CA zurück (genau ein Mal —
    danach ist cert_picked_up_at gesetzt und der Tap soll seinen normalen
    mTLS-Uplink aufbauen)."""
    pool = get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT id, status, approved_tap_id, cert_pem, cert_expires_at,
                       cert_picked_up_at
                  FROM pending_taps
                 WHERE hardware_id=$1 AND fingerprint=$2
                 FOR UPDATE
                """,
                hardware_id, fingerprint,
            )
            if not row:
                return AnnounceStatusResponse(status="unknown")

            if row["status"] == "pending":
                return AnnounceStatusResponse(status="pending",
                                              message="Warte auf Admin-Approval.")
            if row["status"] == "rejected":
                return AnnounceStatusResponse(status="rejected",
                                              message="Vom Admin abgelehnt.")
            if row["status"] == "approved":
                if not row["cert_pem"]:
                    return AnnounceStatusResponse(
                        status="approved",
                        message="Approval läuft — Cert wird gerade signiert.",
                    )
                # Cert wird bei der Auslieferung als abgeholt markiert.
                if not row["cert_picked_up_at"]:
                    await conn.execute(
                        "UPDATE pending_taps SET cert_picked_up_at=now() WHERE id=$1",
                        row["id"],
                    )
                ca = master_ca.get_master_ca()
                return AnnounceStatusResponse(
                    status="approved",
                    tap_id=row["approved_tap_id"],
                    cert_pem=row["cert_pem"],
                    master_ca_pem=ca.cert_pem.decode(),
                    expires_at=row["cert_expires_at"],
                )
            return AnnounceStatusResponse(status="unknown")


# ── Admin-Endpoints (Pending-Liste, Approve/Reject, Audit-Log) ──


@router.get("/pending", response_model=list[PendingTapEntry])
async def list_pending_taps(_admin: dict = Depends(require_admin)) -> list[PendingTapEntry]:
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, name, hardware_id, host(source_ip) AS source_ip,
                   hostname, version, fingerprint, announced_at, status
              FROM pending_taps
             WHERE status='pending'
             ORDER BY announced_at DESC
            """
        )
    return [
        PendingTapEntry(
            id=r["id"], name=r["name"], hardware_id=r["hardware_id"],
            source_ip=r["source_ip"], hostname=r["hostname"], version=r["version"],
            fingerprint=r["fingerprint"], announced_at=r["announced_at"],
            status=r["status"],
        )
        for r in rows
    ]


@router.post("/pending/{pending_id}/approve")
async def approve_pending_tap(
    pending_id: UUID,
    body: PendingApproveRequest,
    admin: dict = Depends(require_admin),
) -> dict:
    """CSR aus dem pending-Eintrag signieren, taps-Eintrag anlegen, Cert
    cachen damit der Tap es per Polling abholen kann."""
    pool = get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT id, hardware_id, name, csr_pem, status
                  FROM pending_taps
                 WHERE id=$1 FOR UPDATE
                """,
                pending_id,
            )
            if not row:
                raise HTTPException(404, "Pending-Eintrag nicht gefunden")
            if row["status"] != "pending":
                raise HTTPException(409, f"Status ist bereits '{row['status']}'")

            tap_name = body.name or row["name"]
            tap_id = uuid.uuid4()
            try:
                ca = master_ca.get_master_ca()
                cert, cert_pem = ca.sign_tap_csr(
                    row["csr_pem"].encode(), tap_id=str(tap_id), tap_name=tap_name,
                )
            except ValueError as exc:
                raise HTTPException(400, f"CSR ungültig: {exc}")

            fingerprint_cert = cert.fingerprint(hashes.SHA256()).hex()
            expires_at = cert.not_valid_after_utc

            await conn.execute(
                """
                INSERT INTO taps
                    (id, name, site, cert_fingerprint, cert_expires_at,
                     status, paired_at, paired_by)
                VALUES ($1, $2, $3, $4, $5, 'active', now(), $6)
                """,
                tap_id, tap_name, body.site, fingerprint_cert, expires_at,
                admin.get("sub"),
            )
            await conn.execute(
                """
                UPDATE pending_taps
                   SET status='approved', reviewed_at=now(), reviewed_by=$2,
                       approved_tap_id=$3, cert_pem=$4, cert_expires_at=$5
                 WHERE id=$1
                """,
                pending_id, admin.get("sub"), tap_id, cert_pem.decode(), expires_at,
            )
            await _audit(conn, event="approved", hardware_id=row["hardware_id"],
                         name=tap_name, pending_id=pending_id,
                         details={"admin": admin.get("sub"),
                                  "tap_id": str(tap_id),
                                  "cert_fingerprint": fingerprint_cert[:16]})

    log.warning("Tap auto-pair approved: %s → tap_id=%s (admin=%s)",
                tap_name, tap_id, admin.get("sub"))
    return {"tap_id": str(tap_id), "name": tap_name, "expires_at": expires_at.isoformat()}


@router.post("/pending/{pending_id}/reject", status_code=204)
async def reject_pending_tap(
    pending_id: UUID,
    admin: dict = Depends(require_admin),
) -> Response:
    pool = get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                "SELECT hardware_id, name, status FROM pending_taps WHERE id=$1 FOR UPDATE",
                pending_id,
            )
            if not row:
                raise HTTPException(404, "Pending-Eintrag nicht gefunden")
            if row["status"] != "pending":
                raise HTTPException(409, f"Status ist bereits '{row['status']}'")
            await conn.execute(
                """
                UPDATE pending_taps
                   SET status='rejected', reviewed_at=now(), reviewed_by=$2
                 WHERE id=$1
                """,
                pending_id, admin.get("sub"),
            )
            await _audit(conn, event="rejected", hardware_id=row["hardware_id"],
                         name=row["name"], pending_id=pending_id,
                         details={"admin": admin.get("sub")})
    log.warning("Tap auto-pair rejected: pending_id=%s (admin=%s)",
                pending_id, admin.get("sub"))
    return Response(status_code=204)


@router.get("/audit-log", response_model=list[AuditLogEntry])
async def get_tap_audit_log(
    limit: int = 200,
    _admin: dict = Depends(require_admin),
) -> list[AuditLogEntry]:
    limit = max(1, min(1000, limit))
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, ts, event, host(source_ip) AS source_ip,
                   hardware_id, name, pending_id, details
              FROM tap_audit_log
             ORDER BY ts DESC
             LIMIT $1
            """,
            limit,
        )
    return [
        AuditLogEntry(
            id=r["id"], ts=r["ts"], event=r["event"], source_ip=r["source_ip"],
            hardware_id=r["hardware_id"], name=r["name"], pending_id=r["pending_id"],
            details=r["details"] or {},
        )
        for r in rows
    ]
