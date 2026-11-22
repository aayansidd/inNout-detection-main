"""Authenticode *presence and structure* check for PE files (Week 7).

We verify that the PE has a certificate table and that the WIN_CERTIFICATE record is
well-formed. We do NOT validate the certificate chain or the file digest; that needs the
optional ``signify`` package plus a trust store. The result is therefore a risk signal
("unsigned executable"), not proof of trust.
"""

from __future__ import annotations

import struct

import pefile

_SECURITY_DIR = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]


def check_authenticode(path: str) -> str:
    """Return ``signed``, ``unsigned`` or ``invalid`` for a PE at ``path``."""
    try:
        pe = pefile.PE(path, fast_load=True)
    except (pefile.PEFormatError, OSError, ValueError):
        return "invalid"
    try:
        dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(dirs) <= _SECURITY_DIR:
            return "unsigned"
        entry = dirs[_SECURITY_DIR]
        if entry.VirtualAddress == 0 and entry.Size == 0:
            return "unsigned"
        data_len = len(pe.__data__)
        offset, size = entry.VirtualAddress, entry.Size  # for security dir this is a file offset
        if size < 8 or offset + size > data_len:
            return "invalid"
        length, revision, cert_type = struct.unpack_from("<IHH", pe.__data__, offset)
        valid = revision in (0x0100, 0x0200) and cert_type in (1, 2)
        if length < 8 or length > size or not valid:
            return "invalid"
        return "signed"
    except (struct.error, AttributeError):
        return "invalid"
    finally:
        pe.close()
