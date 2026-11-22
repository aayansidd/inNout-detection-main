#!/usr/bin/env python3
"""Week 6: the avalanche effect. Flip ONE input bit and count how many output bits change.

A good hash changes about half of its output bits. CRC-32 does too, so avalanche alone does
not separate them. What does: CRC-32 is linear and only 32 bits, so an attacker can *construct*
a different message with the same CRC. It detects accidents, not tampering. SHA-256 is not
linear and has 256 bits, so no practical forgery exists.
"""

import hashlib
import zlib

MESSAGE = b"AEGIS USB report: 1 critical file, scan 3ec9bae7"


def bits_changed(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b, strict=True))


def main() -> None:
    sha_total = crc_total = trials = 0
    for i in range(len(MESSAGE) * 8):
        flipped = bytearray(MESSAGE)
        flipped[i // 8] ^= 1 << (i % 8)
        sha_total += bits_changed(
            hashlib.sha256(MESSAGE).digest(), hashlib.sha256(flipped).digest()
        )
        crc_total += bits_changed(
            zlib.crc32(MESSAGE).to_bytes(4, "big"), zlib.crc32(bytes(flipped)).to_bytes(4, "big")
        )
        trials += 1
    print(f"message: {MESSAGE.decode()!r}  ({trials} single-bit flips)")
    print(f"SHA-256 : {sha_total / trials:6.1f} of 256 output bits change on average (ideal 128)")
    print(f"CRC-32  : {crc_total / trials:6.1f} of  32 output bits change on average (ideal 16)")
    print("Both avalanche well; only SHA-256 also resists deliberate forgery.")
    one = bytearray(MESSAGE)
    one[0] ^= 1
    print("\nbefore:", hashlib.sha256(MESSAGE).hexdigest())
    print("after :", hashlib.sha256(bytes(one)).hexdigest())


if __name__ == "__main__":
    main()
