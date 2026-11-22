"""Station key store (Weeks 5, 7, 8): RSA-3072, DSA-3072 and Ed25519 keys, each with a
self-signed X.509 certificate for the "AEGIS Scanner Station".

Keys are generated on first use and persisted (mode 0600). In production the private keys
would live in an HSM/KMS and the certificates would chain to a real CA; here a self-signed
certificate only binds the public key to a name, it does not make anyone trust it.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ed25519, rsa
from cryptography.x509.oid import NameOID

ALGORITHMS = ("rsa-pss", "dsa", "ed25519")
PrivateKey = rsa.RSAPrivateKey | dsa.DSAPrivateKey | ed25519.Ed25519PrivateKey
STATION_NAME = "AEGIS Scanner Station"


@dataclass(frozen=True)
class StationKey:
    algorithm: str
    private_key: PrivateKey
    public_key_pem: str
    certificate_pem: str
    fingerprint_sha256: str  # of the DER SubjectPublicKeyInfo


def _generate(algorithm: str) -> PrivateKey:
    if algorithm == "rsa-pss":
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    if algorithm == "dsa":
        return dsa.generate_private_key(key_size=3072)
    if algorithm == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(f"unsupported algorithm: {algorithm}")


def public_key_fingerprint(public_key: object) -> str:
    """SHA-256 over the DER SubjectPublicKeyInfo: the value to pin out-of-band."""
    der = public_key.public_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()


def _self_signed_cert(key: PrivateKey) -> x509.Certificate:
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, STATION_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AEGIS USB (IS-353 course project)"),
    ])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    )
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(key, algorithm)


class KeyStore:
    """Lazy, persistent, thread-safe key provider."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self._lock = threading.Lock()
        self._cache: dict[str, StationKey] = {}

    def get(self, algorithm: str) -> StationKey:
        if algorithm not in ALGORITHMS:
            raise ValueError(f"unsupported algorithm: {algorithm}")
        with self._lock:
            if algorithm not in self._cache:
                self._cache[algorithm] = self._load_or_create(algorithm)
            return self._cache[algorithm]

    def _load_or_create(self, algorithm: str) -> StationKey:
        self.directory.mkdir(parents=True, exist_ok=True)
        key_path = self.directory / f"{algorithm}.key.pem"
        cert_path = self.directory / f"{algorithm}.cert.pem"
        if key_path.exists() and cert_path.exists():
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            cert_pem = cert_path.read_text()
        else:
            key = _generate(algorithm)
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ))
            cert_pem = _self_signed_cert(key).public_bytes(serialization.Encoding.PEM).decode()
            cert_path.write_text(cert_pem)
        public = key.public_key()
        public_pem = public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        return StationKey(algorithm, key, public_pem, cert_pem, public_key_fingerprint(public))  # type: ignore[arg-type]
