"""Detection-engine acceptance tests (§10)."""

import os
import random
import struct

import generate_payloads as gp
import pytest
from app.core.usb_monitor import DriveInfo, EventSink, ScanJob, is_removable
from app.core.walker import WalkCounters, iter_files
from app.engine import magic_bytes as mb
from app.engine import yara_scanner
from app.engine.analyzer import analyze_file
from app.engine.authenticode import check_authenticode
from app.engine.entropy import shannon_entropy_bytes
from app.engine.xor_detect import find_xor_pe

BIG = 50 * 1024 * 1024


def even(values: int, reps: int = 64) -> bytes:
    return bytes(range(values)) * reps


def test_entropy_thresholds():
    assert shannon_entropy_bytes(even(137)) == pytest.approx(7.10, abs=0.01)
    assert shannon_entropy_bytes(even(158)) == pytest.approx(7.30, abs=0.01)
    assert shannon_entropy_bytes(b"") == 0.0


def test_entropy_flagging_via_analyzer(tmp_path):
    low, high, empty = tmp_path / "a.bin", tmp_path / "b.bin", tmp_path / "c.bin"
    low.write_bytes(even(137))
    high.write_bytes(even(158))
    empty.write_bytes(b"")
    assert analyze_file(str(low), max_size_bytes=BIG).tier == "SAFE"
    assert analyze_file(str(high), max_size_bytes=BIG).tier == "SUSPICIOUS"
    assert analyze_file(str(empty), max_size_bytes=BIG).entropy == 0.0


def test_magic_and_names():
    mz = mb.identify(b"MZ\x90\x00")
    assert mb.has_extension_mismatch(mz, "pdf")
    assert not mb.has_extension_mismatch(mz, "exe")
    assert mb.has_double_extension("report.pdf.exe")
    assert not mb.has_double_extension("backup.2024.exe")
    assert mb.has_rtlo("invoice\u202efdp.exe")
    assert mb.identify(b"\x7fELF").family == "elf"
    assert mb.identify(b"\x00\x00\x00\x18ftypmp42").family == "mp4"


def test_xor_detection_finds_key():
    for key in (0x01, 0x5A, 0xFF, random.Random(7).randrange(1, 256)):
        blob = bytes(b ^ key for b in gp.dos_stub())
        assert find_xor_pe(blob) == key
    assert find_xor_pe(os.urandom(512)) is None
    assert find_xor_pe(gp.dos_stub()) is None  # unobfuscated PE is not "hidden"


def test_yara_rules_compile():
    assert yara_scanner.rule_count() == 6


def test_clean_text_hits_nothing(tmp_path):
    f = tmp_path / "readme.txt"
    f.write_text("hello world, nothing to see here")
    assert yara_scanner.scan_file(str(f), "readme.txt", "txt") == []


@pytest.mark.parametrize("rel", list(gp.EXPECTED))
def test_each_payload_expected_tier_and_rules(drive, rel):
    tier, rules = gp.EXPECTED[rel]
    r = analyze_file(str(drive / rel), max_size_bytes=BIG)
    assert r.tier == tier, r.reasons
    assert sorted(r.yara_matches) == sorted(rules)
    assert r.risk_score == r.likelihood * r.impact
    assert r.reasons


def test_png_exempt_and_xor_reported(drive):
    png = analyze_file(str(drive / "Photos/team_photo.png"), max_size_bytes=BIG)
    assert png.entropy > 7.2 and png.entropy_exempt
    blob = analyze_file(str(drive / "cache/blob.dat"), max_size_bytes=BIG)
    assert blob.xor_key == gp.XOR_KEY
    assert "T1027" in blob.mitre


def test_invoice_matches_contract_example(drive):
    r = analyze_file(str(drive / "invoice.pdf"), max_size_bytes=BIG)
    assert r.extension_mismatch and r.magic_hex.startswith("4d5a9000")
    assert r.risk_score == 25 and "T1036.008" in r.mitre
    assert "Magic bytes (MZ) mismatch claimed .pdf extension" in r.reasons


def test_rtlo_exe_is_critical(tmp_path):
    f = tmp_path / "invoice\u202efdp.exe"
    f.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    assert analyze_file(str(f), max_size_bytes=BIG).tier == "CRITICAL"


def test_oversize_file_is_partial(tmp_path):
    f = tmp_path / "big.pdf"
    f.write_bytes(b"MZ" + b"\x00" * 4096)
    r = analyze_file(str(f), max_size_bytes=1024)
    assert r.scan_status == "PARTIAL" and r.sha256 is None and r.tier == "CRITICAL"


def _pe(cert: bytes | None, bad: bool = False) -> bytes:
    """Minimal PE32 with a security directory entry (for Authenticode tests)."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 64)
    coff = struct.pack("<HHIIIHH", 0x14C, 0, 0, 0, 0, 224, 0x102)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 92, 16)  # NumberOfRvaAndSizes
    body_len = 64 + 4 + len(coff) + 224
    if cert is not None:
        struct.pack_into("<II", opt, 96 + 4 * 8, body_len, len(cert) + (999 if bad else 0))
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + (cert or b"")


def test_authenticode_states(tmp_path):
    cert = struct.pack("<IHH", 16, 0x0200, 2) + b"\x00" * 8
    for name, data, want in [
        ("unsigned", _pe(None), "unsigned"),
        ("signed", _pe(cert), "signed"),
        ("bad", _pe(cert, bad=True), "invalid"),
        ("garbage", b"MZ\x00\x00", "invalid"),
    ]:
        p = tmp_path / f"{name}.exe"
        p.write_bytes(data)
        assert check_authenticode(str(p)) == want, name


def test_walker_skips_symlinks_and_system_dirs(tmp_path):
    import threading

    (tmp_path / "System Volume Information").mkdir()
    (tmp_path / "System Volume Information" / "x").write_text("x")
    (tmp_path / "$RECYCLE.BIN").mkdir()
    (tmp_path / ".hidden").write_text("h")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.txt").write_text("a")
    os.symlink(tmp_path / "sub", tmp_path / "link")
    counters = WalkCounters()
    names = sorted(os.path.basename(p) for p, _ in iter_files(str(tmp_path), threading.Event(), counters))
    assert names == [".hidden", "a.txt"]
    assert counters.skipped == 1


def test_is_removable_rules():
    P = lambda **k: type("P", (), k)()  # noqa: E731
    assert is_removable(P(opts="rw,removable", mountpoint="E:\\"), "Windows")
    assert not is_removable(P(opts="rw,cdrom", mountpoint="D:\\"), "Windows")
    assert is_removable(P(opts="rw", mountpoint="/media/u/USB", device="/dev/sdb1"), "Linux")
    assert is_removable(P(opts="rw", mountpoint="/run/media/u/USB", device="/dev/sdb1"), "Linux")
    assert not is_removable(P(opts="rw", mountpoint="/mnt/c", device="C:\\"), "Linux")
    assert not is_removable(P(opts="rw", mountpoint="/System/Volumes/Data"), "Darwin")


class _Sink(EventSink):
    def __init__(self):
        self.files, self.done, self.connected = [], [], []

    def usb_connected(self, drive, scan_id): self.connected.append(drive)
    def usb_disconnected(self, drive): pass
    def scan_progress(self, *a): pass
    def file_scanned(self, scan_id, drive, result): self.files.append(result)
    def scan_complete(self, scan_id, drive, counts, duration_s, cancelled): self.done.append((counts, cancelled))


def test_scan_job_full_drive_counts(drive):
    sink = _Sink()
    job = ScanJob(str(drive), DriveInfo("Z:\\", "DEMO", "sim", 0, True), sink)
    job.start()
    job.join(30)
    counts, cancelled = sink.done[0]
    assert not cancelled and counts["total"] == len(gp.EXPECTED) == len(sink.files)
    assert counts["safe"] == 3 and counts["suspicious"] == 2 and counts["critical"] == 7


def test_scan_job_cancel_drops_results(drive):
    sink = _Sink()
    job = ScanJob(str(drive), DriveInfo("Z:\\", "DEMO", "sim", 0, True), sink)
    job.cancel.set()
    job.start()
    job.join(10)
    assert sink.done[0][1] is True and sink.files == []


def _plist(**kw) -> bytes:
    import plistlib

    return plistlib.dumps(kw)


@pytest.mark.parametrize(
    ("info", "expected"),
    [
        ({"BusProtocol": "USB", "RemovableMedia": False}, True),
        ({"BusProtocol": "Secure Digital", "RemovableMedia": True}, True),
        ({"BusProtocol": "Disk Image", "RemovableMedia": True}, False),  # a mounted .dmg
        ({"BusProtocol": "Apple Fabric", "RemovableMedia": False, "Internal": True}, False),
    ],
)
def test_darwin_diskutil_rule(monkeypatch, info, expected):
    import subprocess

    from app.core import usb_monitor as um

    um._darwin_cache.clear()
    monkeypatch.setattr(
        um.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=_plist(**info)),
    )
    assert um._darwin_is_usb("/Volumes/X") is expected
    um._darwin_cache.clear()


def test_darwin_diskutil_failure_is_not_usb_and_not_cached(monkeypatch):
    from app.core import usb_monitor as um

    um._darwin_cache.clear()

    def boom(*a, **k):
        raise OSError("no diskutil")

    monkeypatch.setattr(um.subprocess, "run", boom)
    assert um._darwin_is_usb("/Volumes/X") is False
    assert "/Volumes/X" not in um._darwin_cache
