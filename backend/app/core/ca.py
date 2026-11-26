"""Internal Certificate Authority (CA) and X.509 certificate workflow.

Provides:
- CA root creation or loading
- Per-agent X.509 client certificate issuance
- Certificate verification and fingerprint computation (SHA-256)
- Revocation list management
"""

from __future__ import annotations

import datetime
import hashlib
from pathlib import Path
from typing import Optional, Set

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID


class InternalCA:
    """Lightweight in-process CA for Ram Antivirus mTLS agent-backend authentication."""

    def __init__(
        self,
        ca_cert: Optional[x509.Certificate] = None,
        ca_key: Optional[rsa.RSAPrivateKey] = None,
    ):
        self._ca_cert = ca_cert
        self._ca_key = ca_key
        self._revoked_fingerprints: Set[str] = set()
        self._auto_init_from_env()

    def _auto_init_from_env(self) -> None:
        """Attempt to load existing CA from AEGIS_CA_DIR/RAM_CA_DIR if available."""
        import os
        ca_dir_str = os.getenv("RAM_CA_DIR") or os.getenv("AEGIS_CA_DIR")
        if ca_dir_str and self._ca_cert is None:
            ca_dir = Path(ca_dir_str)
            cert_path = ca_dir / "ca.crt"
            key_path = ca_dir / "ca.key"
            if cert_path.exists() and key_path.exists():
                try:
                    self.load_ca(cert_path, key_path)
                except Exception:
                    pass

    @property
    def ca_cert(self) -> Optional[x509.Certificate]:
        return self._ca_cert

    @property
    def ca_cert_pem(self) -> bytes:
        if not self._ca_cert:
            raise ValueError("CA certificate not initialized")
        return self._ca_cert.public_bytes(serialization.Encoding.PEM)

    def initialize_ca(
        self,
        common_name: str = "Ram Antivirus Internal Root CA",
        days_valid: int = 3650,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Generate a fresh self-signed root CA certificate and private key."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ram Antivirus"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days_valid))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        self._ca_cert = cert
        self._ca_key = private_key
        return cert, private_key

    def save_ca(self, ca_dir: Path) -> None:
        """Persist CA cert and key to disk."""
        if not self._ca_cert or not self._ca_key:
            raise ValueError("CA is not initialized")
        ca_dir.mkdir(parents=True, exist_ok=True)
        cert_path = ca_dir / "ca.crt"
        key_path = ca_dir / "ca.key"

        cert_path.write_bytes(self._ca_cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            self._ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    def load_ca(self, cert_path: Path, key_path: Path) -> None:
        """Load an existing CA from disk."""
        cert_bytes = cert_path.read_bytes()
        key_bytes = key_path.read_bytes()

        self._ca_cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        self._ca_key = serialization.load_pem_private_key(
            key_bytes, password=None, backend=default_backend()
        )

    def issue_agent_cert(
        self,
        agent_id: str,
        days_valid: int = 90,
    ) -> tuple[bytes, bytes, str]:
        """Issue an X.509 client certificate for a given agent_id.

        Returns:
            (cert_pem, key_pem, cert_fingerprint_hex)
        """
        if not self._ca_cert or not self._ca_key:
            raise ValueError("CA not initialized")

        agent_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ram Antivirus"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Endpoint Agents"),
            x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(agent_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days_valid))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256(), default_backend())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = agent_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        fingerprint = self.compute_fingerprint(cert)
        return cert_pem, key_pem, fingerprint

    @staticmethod
    def compute_fingerprint(cert: x509.Certificate) -> str:
        """Compute uppercase SHA256 hex fingerprint."""
        return cert.fingerprint(hashes.SHA256()).hex().lower()

    @staticmethod
    def compute_pem_fingerprint(cert_pem: bytes | str) -> str:
        """Compute SHA256 fingerprint from PEM certificate."""
        if isinstance(cert_pem, str):
            cert_pem = cert_pem.encode("utf-8")
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        return InternalCA.compute_fingerprint(cert)

    def revoke_fingerprint(self, fingerprint: str) -> None:
        """Add fingerprint to revoked list."""
        self._revoked_fingerprints.add(fingerprint.lower())

    def is_revoked(self, fingerprint: str) -> bool:
        """Check if fingerprint is revoked."""
        return fingerprint.lower() in self._revoked_fingerprints

    def verify_client_cert(
        self,
        cert_pem: bytes | str,
        expected_ca_cert: Optional[x509.Certificate] = None,
    ) -> tuple[bool, str, str, str]:
        """Verify client certificate against CA, validity window, and revocation list.

        Returns:
            (is_valid, common_name, fingerprint, error_message)
        """
        ca = expected_ca_cert or self._ca_cert
        if not ca:
            return False, "", "", "No CA certificate configured to verify against"

        if isinstance(cert_pem, str):
            cert_pem = cert_pem.encode("utf-8")

        try:
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        except Exception as e:
            return False, "", "", f"Malformed PEM certificate: {e}"

        fp = self.compute_fingerprint(cert)
        if self.is_revoked(fp):
            return False, "", fp, "Certificate has been revoked"

        # Check validity window
        now = datetime.datetime.now(datetime.timezone.utc)
        if now < cert.not_valid_before_utc:
            return False, "", fp, "Certificate is not yet valid"
        if now > cert.not_valid_after_utc:
            return False, "", fp, "Certificate has expired"

        # Verify signature against CA public key
        try:
            ca.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,  # type: ignore[arg-type]
            )
        except Exception:
            return False, "", fp, "Certificate signature verification failed: not issued by trusted CA"

        # Extract Common Name
        cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = cns[0].value if cns else ""

        return True, str(cn), fp, ""


# Default singleton instance
default_ca = InternalCA()
