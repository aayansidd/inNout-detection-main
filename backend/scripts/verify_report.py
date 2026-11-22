#!/usr/bin/env python3
"""Offline verification of an AEGIS USB signed report. No server and no `app` package needed.

Usage:
    python verify_report.py signed_report.json [--fingerprint HEX] [--export DIR]

Exit status: 0 valid, 1 invalid, 2 usage/input error.

A valid signature proves the report was not changed since it was signed by the holder of the
printed key. It does NOT prove who that is: compare the key fingerprint with one you obtained
out-of-band (--fingerprint does this check). A self-signed certificate does not change that.

--export DIR writes report.json, signature.bin and public.pem so the result can be re-checked
with OpenSSL, e.g. for RSA-PSS:
    openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
        -verify public.pem -signature signature.bin report.json
and for Ed25519:  openssl pkeyutl -verify -pubin -inkey public.pem -rawin -in report.json \
        -sigfile signature.bin
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ed25519, padding, rsa


def canonical(report: dict) -> bytes:
    """Sorted keys, no whitespace, UTF-8: identical to what the server signed."""
    return json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def fingerprint(key: object) -> str:
    der = key.public_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()


def verify(signed: dict) -> tuple[bool, str, str]:
    """Return (valid, reason, key_fingerprint)."""
    try:
        alg = signed["algorithm"]
        signature = base64.b64decode(signed["signature_b64"], validate=True)
        key = serialization.load_pem_public_key(signed["public_key_pem"].encode())
        data = canonical(signed["report"])
    except (KeyError, binascii.Error, ValueError, TypeError) as exc:
        return False, f"malformed input ({type(exc).__name__})", ""
    fp = fingerprint(key)
    try:
        if alg == "rsa-pss" and isinstance(key, rsa.RSAPublicKey):
            pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
            key.verify(signature, data, pss, hashes.SHA256())
        elif alg == "dsa" and isinstance(key, dsa.DSAPublicKey):
            key.verify(signature, data, hashes.SHA256())
        elif alg == "ed25519" and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, data)
        else:
            return False, "key type does not match the algorithm", fp
    except InvalidSignature:
        return False, "signature does not match the report", fp
    return True, "signature valid", fp


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("signed_report", type=Path)
    ap.add_argument("--fingerprint", help="expected SHA-256 key fingerprint (hex) to pin")
    ap.add_argument("--export", type=Path, help="write report.json/signature.bin/public.pem here")
    args = ap.parse_args()
    try:
        signed = json.loads(args.signed_report.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"cannot read {args.signed_report}: {exc}", file=sys.stderr)
        return 2
    valid, reason, fp = verify(signed)
    print(f"algorithm   : {signed.get('algorithm')}")
    print(f"key SHA-256 : {fp or 'n/a'}")
    print(f"result      : {'VALID' if valid else 'INVALID'} ({reason})")
    if valid and args.fingerprint:
        if args.fingerprint.lower().replace(":", "") != fp:
            print("pinned fingerprint does NOT match: do not trust this key", file=sys.stderr)
            return 1
        print("fingerprint : matches the pinned value")
    if args.export and valid:
        args.export.mkdir(parents=True, exist_ok=True)
        (args.export / "report.json").write_bytes(canonical(signed["report"]))
        (args.export / "signature.bin").write_bytes(base64.b64decode(signed["signature_b64"]))
        (args.export / "public.pem").write_text(signed["public_key_pem"])
        print(f"exported    : {args.export}")
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
