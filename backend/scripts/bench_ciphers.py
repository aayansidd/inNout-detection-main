#!/usr/bin/env python3
"""Weeks 4 and 7: measure cipher throughput and signature speed on this machine.

Part 1: AES-256-GCM, AES-256-CBC and 3DES-CBC encryption speed (MiB/s). 3DES lives in the
`cryptography` package's `decrepit` module precisely because it should not be used.
Part 2: sign/verify operations per second for RSA-PSS, RSA PKCS#1 v1.5, DSA and Ed25519.
Usage: python bench_ciphers.py [MiB] [repeats]
"""

import os
import platform
import sys
import time

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MIB = 1024 * 1024


def best_rate(fn, size_mib: int, repeats: int) -> float:
    best = 0.0
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        best = max(best, size_mib / (time.perf_counter() - start))
    return best


def main() -> None:
    size = int(sys.argv[1]) if len(sys.argv) > 1 else 32
    repeats = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    data = os.urandom(size * MIB)
    key32, key24 = os.urandom(32), os.urandom(24)

    def gcm() -> None:
        AESGCM(key32).encrypt(os.urandom(12), data, None)

    def aes_cbc() -> None:
        enc = Cipher(algorithms.AES(key32), modes.CBC(os.urandom(16))).encryptor()
        enc.update(data) + enc.finalize()

    def tdes_cbc() -> None:
        enc = Cipher(TripleDES(key24), modes.CBC(os.urandom(8))).encryptor()
        enc.update(data) + enc.finalize()

    rows = [
        ("AES-256-GCM", "256-bit", "128-bit", "authenticated", gcm),
        ("AES-256-CBC", "256-bit", "128-bit", "no (needs HMAC)", aes_cbc),
        ("3DES-CBC", "168-bit nominal (112 effective)", "64-bit", "no (needs HMAC)", tdes_cbc),
    ]
    print(f"Machine: {platform.platform()} / {platform.machine()}, {size} MiB, best of {repeats}\n")
    print("| Cipher | Key | Block | Integrity built in | Encrypt MiB/s |")
    print("|---|---|---|---|---|")
    results = {}
    for name, key, block, auth, fn in rows:
        results[name] = best_rate(fn, size, repeats)
        print(f"| {name} | {key} | {block} | {auth} | {results[name]:,.0f} |")
    ratio = results["AES-256-GCM"] / results["3DES-CBC"]
    print(f"\nAES-256-GCM is {ratio:.0f}x faster than 3DES-CBC here.")


def ops_per_second(fn, seconds: float = 1.0) -> float:
    count, start = 0, time.perf_counter()
    while time.perf_counter() - start < seconds:
        fn()
        count += 1
    return count / (time.perf_counter() - start)


def bench_signatures() -> None:
    msg = os.urandom(4096)
    sha = hashes.SHA256()
    pss = padding.PSS(mgf=padding.MGF1(sha), salt_length=32)
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    dsa_key = dsa.generate_private_key(key_size=3072)
    ed_key = ed25519.Ed25519PrivateKey.generate()
    pss_sig = rsa_key.sign(msg, pss, sha)
    v15_sig = rsa_key.sign(msg, padding.PKCS1v15(), sha)
    dsa_sig = dsa_key.sign(msg, sha)
    ed_sig = ed_key.sign(msg)
    rsa_pub, dsa_pub, ed_pub = rsa_key.public_key(), dsa_key.public_key(), ed_key.public_key()
    rows = [
        ("RSA-3072 PSS", "3072-bit", 384,
         lambda: rsa_key.sign(msg, pss, sha), lambda: rsa_pub.verify(pss_sig, msg, pss, sha)),
        ("RSA-3072 PKCS#1 v1.5", "3072-bit", 384,
         lambda: rsa_key.sign(msg, padding.PKCS1v15(), sha),
         lambda: rsa_pub.verify(v15_sig, msg, padding.PKCS1v15(), sha)),
        ("DSA-3072", "3072-bit (q 256)", 64,
         lambda: dsa_key.sign(msg, sha), lambda: dsa_pub.verify(dsa_sig, msg, sha)),
        ("Ed25519", "256-bit", 64, lambda: ed_key.sign(msg), lambda: ed_pub.verify(ed_sig, msg)),
    ]
    print("\n| Signature scheme | Key | Signature bytes | Sign ops/s | Verify ops/s |")
    print("|---|---|---|---|---|")
    for name, key, sig_len, sign, verify in rows:
        print(f"| {name} | {key} | {sig_len} | {ops_per_second(sign):,.0f} | "
              f"{ops_per_second(verify):,.0f} |")


if __name__ == "__main__":
    main()
    bench_signatures()
