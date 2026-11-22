"""Sign and verify canonical-JSON scan reports (Week 7).

RSA-PSS (SHA-256, salt 32) is the default; Ed25519 is the modern alternative; DSA-3072 is
kept for comparison only (FIPS 186-5 no longer approves DSA for new signatures).
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ed25519, padding, rsa

from .keystore import ALGORITHMS, KeyStore

PSS_SALT = 32  # = SHA-256 digest length; `openssl ... -sigopt rsa_pss_saltlen:32`


def canonical_report_bytes(report: dict[str, Any]) -> bytes:
    """The exact bytes that are signed: sorted keys, no whitespace, UTF-8."""
    return json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=PSS_SALT)


def sign_report(report: dict[str, Any], algorithm: str, keystore: KeyStore) -> dict[str, Any]:
    """Return ``{report, signature_b64, algorithm, public_key_pem, certificate_pem}``."""
    if algorithm not in ALGORITHMS:
        raise ValueError(f"algorithm must be one of {ALGORITHMS}")
    station = keystore.get(algorithm)
    data = canonical_report_bytes(report)
    key = station.private_key
    if isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(data, _pss(), hashes.SHA256())
    elif isinstance(key, dsa.DSAPrivateKey):
        signature = key.sign(data, hashes.SHA256())
    else:
        signature = key.sign(data)
    return {
        "report": copy.deepcopy(report),  # never alias the caller's object
        "signature_b64": base64.b64encode(signature).decode(),
        "algorithm": algorithm,
        "public_key_pem": station.public_key_pem,
        "certificate_pem": station.certificate_pem,
    }


def verify_report(
    report: dict[str, Any], signature_b64: str, algorithm: str, public_key_pem: str
) -> tuple[bool, str]:
    """Verify a signature. Never raises on bad input: returns ``(False, reason)``."""
    if algorithm not in ALGORITHMS:
        return False, "unsupported algorithm"
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        key = serialization.load_pem_public_key(public_key_pem.encode())
        data = canonical_report_bytes(report)
    except (binascii.Error, ValueError, TypeError):
        return False, "malformed signature, key or report"
    try:
        if algorithm == "rsa-pss" and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, data, _pss(), hashes.SHA256())
        elif algorithm == "dsa" and isinstance(key, dsa.DSAPublicKey):
            key.verify(signature, data, hashes.SHA256())
        elif algorithm == "ed25519" and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, data)
        else:
            return False, "public key type does not match the algorithm"
    except InvalidSignature:
        return False, "signature does not match: the report was altered or signed by another key"
    return True, "signature valid"
