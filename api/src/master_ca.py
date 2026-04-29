"""
Master-CA für die mTLS-Authentifizierung von Remote-Taps.

Bei API-Startup wird in `MASTER_CA_DIR` geprüft, ob bereits ein Root-CA
existiert. Falls nicht, wird einer angelegt: 10 Jahre gültig, RSA-4096,
Subject 'Cyjan IDS Master CA'. Die privaten Schlüssel werden mit Mode 0600
geschrieben, das Cert mit 0644.

Die CA wird benutzt, um beim Pairing die CSR eines neuen Tap-Knotens zu
signieren. Tap-Cert-Lifetime: 365 Tage. Tap-CN = `tap:<uuid>`, damit der
Uplink-Endpoint den Tap eindeutig identifizieren kann.

Wir bewusst keinen externen PKI-Stack: ein selbstsignierter Root pro
Master-Deployment ist die kürzeste Strecke. Keine Cross-Signing-Story,
keine OCSP-Server, keine CRL-Distribution. Stattdessen: revoked-Status
in der DB führen, Uplink-Endpoint prüft beim Auth-Handshake gegen
`taps.status='active'`.
"""
from __future__ import annotations

import datetime as _dt
import logging
import os
from datetime import timezone as _tz
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

log = logging.getLogger("master_ca")

CA_KEY_FILE  = "master-ca.key"
CA_CERT_FILE = "master-ca.pem"

CA_VALIDITY_DAYS  = 365 * 10
TAP_VALIDITY_DAYS = 365


@dataclass
class MasterCA:
    """Ein bereits geladener oder frisch erzeugter Master-CA-Bundle."""
    cert: x509.Certificate
    key: rsa.RSAPrivateKey
    cert_pem: bytes

    @property
    def fingerprint_sha256_hex(self) -> str:
        return self.cert.fingerprint(hashes.SHA256()).hex()

    def sign_tap_csr(
        self,
        csr_pem: bytes,
        tap_id: str,
        tap_name: str,
    ) -> tuple[x509.Certificate, bytes]:
        """Signiert einen Tap-CSR und gibt (Cert, PEM) zurück.

        Erzwingt Subject CN = 'tap:<uuid>' und einen klar markierten
        Organizational-Unit-Eintrag mit dem konfigurierten Tap-Namen,
        damit man im Cert ohne DB-Lookup sieht woher er kommt.
        """
        csr = x509.load_pem_x509_csr(csr_pem)
        if not csr.is_signature_valid:
            raise ValueError("CSR-Signatur ist ungültig")

        # Wir verwenden timezone-aware UTC-Datetimes durchgängig; das wirft
        # in Python 3.12 keine DeprecationWarnings mehr.
        now = _dt.datetime.now(_tz.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"tap:{tap_id}"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, tap_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cyjan IDS Remote Tap"),
            ]))
            .issuer_name(self.cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=TAP_VALIDITY_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
        )
        cert = builder.sign(private_key=self.key, algorithm=hashes.SHA256())
        return cert, cert.public_bytes(serialization.Encoding.PEM)


def load_or_create(ca_dir: str) -> MasterCA:
    """Lädt CA aus `ca_dir`, erzeugt sie beim ersten Start.

    Wird beim API-Startup einmal aufgerufen und in app.state geparkt.
    """
    Path(ca_dir).mkdir(parents=True, exist_ok=True)
    key_path  = Path(ca_dir) / CA_KEY_FILE
    cert_path = Path(ca_dir) / CA_CERT_FILE

    if key_path.exists() and cert_path.exists():
        log.info("Master-CA aus %s geladen", ca_dir)
        return _read_existing(key_path, cert_path)

    log.warning("Keine Master-CA gefunden – generiere neue in %s", ca_dir)
    return _generate_new(key_path, cert_path)


def _read_existing(key_path: Path, cert_path: Path) -> MasterCA:
    key_pem  = key_path.read_bytes()
    cert_pem = cert_path.read_bytes()
    key = serialization.load_pem_private_key(key_pem, password=None)
    cert = x509.load_pem_x509_certificate(cert_pem)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise RuntimeError("Master-CA-Key ist kein RSA-Key (unerwartet)")
    return MasterCA(cert=cert, key=key, cert_pem=cert_pem)


def _generate_new(key_path: Path, cert_path: Path) -> MasterCA:
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    now = _dt.datetime.now(_tz.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Cyjan IDS Master CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cyjan IDS"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    key_path.write_bytes(key_pem)
    os.chmod(key_path, 0o600)
    cert_path.write_bytes(cert_pem)
    os.chmod(cert_path, 0o644)

    log.info("Master-CA erzeugt: %s (Fingerprint %s)",
             cert_path,
             cert.fingerprint(hashes.SHA256()).hex())

    return MasterCA(cert=cert, key=key, cert_pem=cert_pem)


_singleton: Optional[MasterCA] = None


def get_master_ca() -> MasterCA:
    if _singleton is None:
        raise RuntimeError("Master-CA noch nicht initialisiert (init() vor Verwendung aufrufen)")
    return _singleton


def init(ca_dir: str) -> MasterCA:
    global _singleton
    _singleton = load_or_create(ca_dir)
    return _singleton
