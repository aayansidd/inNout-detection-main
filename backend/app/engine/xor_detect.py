"""Single-byte XOR de-obfuscation of hidden PE headers (Week 2: classical ciphers).

Real malware often XORs an embedded payload with one byte. We brute-force all 255 keys on the
first 512 bytes. This is a 1-byte keyspace, so it is trivially breakable, which is the lesson.
"""

from __future__ import annotations

_DOS_MESSAGE = b"This program cannot be run"
_TABLES = {k: bytes(b ^ k for b in range(256)) for k in range(1, 256)}


def find_xor_pe(header: bytes) -> int | None:
    """Return the XOR key (1-255) that reveals a DOS/PE stub in ``header[:512]``, else None."""
    window = header[:512]
    if len(window) < 2:
        return None
    for key, table in _TABLES.items():
        decoded = window.translate(table)
        if decoded.startswith(b"MZ") and _DOS_MESSAGE in decoded:
            return key
    return None
