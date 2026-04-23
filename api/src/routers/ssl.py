"""SSL/TLS-Zertifikatsverwaltung."""
from __future__ import annotations

import datetime
import ipaddress
import os
import subprocess

from fastapi import APIRouter, Form, HTTPException, UploadFile, File
from pydantic import BaseModel

router = APIRouter(prefix="/api/ssl", tags=["ssl"])

CERT_DIR      = os.getenv("CERT_DIR", "/certs")
CERT_FILE     = os.path.join(CERT_DIR, "cert.pem")
KEY_FILE      = os.path.join(CERT_DIR, "key.pem")
HOSTNAME_FILE = os.path.join(CERT_DIR, ".hostname")


class SslStatusResponse(BaseModel):
    mode:      str
    active:    bool
    subject:   str | None = None
    issuer:    str | None = None
    not_after: str | None = None
    domains:   list[str] | None = None
    hostname:  str | None = None


class SelfSignedRequest(BaseModel):
    common_name: str
    days:        int = 365
    country:     str | None = "DE"
    org:         str | None = "Cyjan IDS"


class AcmeConfig(BaseModel):
    domains: list[str]
    email:   str
    ca_url:  str | None = "https://acme-v02.api.letsencrypt.org/directory"


def _cert_info() -> SslStatusResponse:
    """Liest Zertifikat-Metadaten aus vorhandenem cert.pem."""
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        return SslStatusResponse(mode="none", active=False)
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        with open(CERT_FILE, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        subject  = cert.subject.rfc4514_string()
        issuer   = cert.issuer.rfc4514_string()
        not_after = cert.not_valid_after_utc.isoformat()
        domains: list[str] = []
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            domains = [str(n.value) for n in san.value]
        except x509.ExtensionNotFound:
            pass
        # Mode aus gespeichertem Flag lesen
        mode_file = os.path.join(CERT_DIR, ".mode")
        mode = open(mode_file).read().strip() if os.path.exists(mode_file) else "upload"
        hostname = open(HOSTNAME_FILE).read().strip() if os.path.exists(HOSTNAME_FILE) else None
        return SslStatusResponse(
            mode=mode, active=True,
            subject=subject, issuer=issuer,
            not_after=not_after, domains=domains or None,
            hostname=hostname or None,
        )
    except Exception:
        return SslStatusResponse(mode="upload", active=True)


@router.get("/status", response_model=SslStatusResponse)
async def ssl_status() -> SslStatusResponse:
    return _cert_info()


@router.post("/upload", response_model=SslStatusResponse)
async def ssl_upload(
    cert: UploadFile = File(...),
    key:  UploadFile = File(...),
    ca:   UploadFile | None = File(default=None),
) -> SslStatusResponse:
    os.makedirs(CERT_DIR, exist_ok=True)
    cert_data = await cert.read()
    key_data  = await key.read()
    # Wenn CA vorhanden: ans Zertifikat anhängen (chain)
    if ca:
        ca_data = await ca.read()
        cert_data = cert_data.rstrip() + b"\n" + ca_data
    with open(CERT_FILE, "wb") as f:
        f.write(cert_data)
    with open(KEY_FILE, "wb") as f:
        f.write(key_data)
    with open(os.path.join(CERT_DIR, ".mode"), "w") as f:
        f.write("upload")
    return _cert_info()


@router.post("/upload-pfx", response_model=SslStatusResponse)
async def ssl_upload_pfx(
    pfx:      UploadFile = File(...),
    password: str        = Form(""),
) -> SslStatusResponse:
    """Importiert ein PFX/PKCS#12-Zertifikat (z.B. von Windows CA). Extrahiert Zertifikat und privaten Schlüssel."""
    os.makedirs(CERT_DIR, exist_ok=True)
    pfx_data = await pfx.read()
    try:
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat,
        )
        pwd_bytes = password.encode() if password else None
        private_key, cert, additional_certs = load_key_and_certificates(pfx_data, pwd_bytes)
    except Exception as e:
        raise HTTPException(400, f"PFX konnte nicht geladen werden: {e}")

    if not cert or not private_key:
        raise HTTPException(400, "PFX enthält kein Zertifikat oder keinen privaten Schlüssel.")

    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    cert_pem = cert.public_bytes(Encoding.PEM)
    if additional_certs:
        for ca_cert in additional_certs:
            cert_pem += ca_cert.public_bytes(Encoding.PEM)

    key_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())

    with open(CERT_FILE, "wb") as f:
        f.write(cert_pem)
    with open(KEY_FILE, "wb") as f:
        f.write(key_pem)
    with open(os.path.join(CERT_DIR, ".mode"), "w") as f:
        f.write("upload")
    return _cert_info()


class HostnameRequest(BaseModel):
    hostname: str


@router.get("/hostname", summary="Konfigurierten Hostnamen lesen")
async def get_hostname() -> dict:
    hostname = open(HOSTNAME_FILE).read().strip() if os.path.exists(HOSTNAME_FILE) else ""
    return {"hostname": hostname}


@router.post("/hostname", summary="Hostnamen für nginx server_name setzen")
async def set_hostname(body: HostnameRequest) -> dict:
    os.makedirs(CERT_DIR, exist_ok=True)
    hostname = body.hostname.strip()
    with open(HOSTNAME_FILE, "w") as f:
        f.write(hostname)
    return {"hostname": hostname}


@router.post("/self-signed", response_model=SslStatusResponse)
async def ssl_self_signed(body: SelfSignedRequest) -> SslStatusResponse:
    os.makedirs(CERT_DIR, exist_ok=True)
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, body.common_name)]
        if body.country:
            subject_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, body.country[:2]))
        if body.org:
            subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, body.org))
        name = x509.Name(subject_attrs)

        san_list: list = [x509.DNSName(body.common_name)]
        try:
            ipaddress.ip_address(body.common_name)
            san_list.append(x509.IPAddress(ipaddress.ip_address(body.common_name)))
        except ValueError:
            pass

        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=body.days))
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(os.path.join(CERT_DIR, ".mode"), "w") as f:
            f.write("self-signed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Zertifikat-Generierung fehlgeschlagen: {e}")
    return _cert_info()


@router.post("/acme", response_model=SslStatusResponse)
async def ssl_acme(body: AcmeConfig) -> SslStatusResponse:
    """Speichert ACME-Konfiguration. Zertifikat-Bezug via certbot/acme.sh muss manuell oder per Cronjob erfolgen."""
    os.makedirs(CERT_DIR, exist_ok=True)
    import json
    with open(os.path.join(CERT_DIR, "acme.json"), "w") as f:
        json.dump(body.model_dump(), f)
    with open(os.path.join(CERT_DIR, ".mode"), "w") as f:
        f.write("acme")
    return _cert_info()
