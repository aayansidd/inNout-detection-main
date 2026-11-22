"""Orchestrates all static checks for one file and produces a deterministic verdict.

Risk model (Weeks 11-13): risk_score = likelihood x impact, each 1-5.
Tier rules are deterministic and unit-tested.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field

from ..config import CHUNK_SIZE, ENTROPY_THRESHOLD
from . import magic_bytes as mb
from .authenticode import check_authenticode
from .entropy import ByteStats
from .hasher import StreamDigest
from .intel.base import IntelVerdict
from .xor_detect import find_xor_pe
from .yara_scanner import YaraHit, scan_file

HEADER_BYTES = 512
_MARKER = {"pe": "MZ", "elf": "ELF", "macho": "Mach-O", "lnk": "LNK"}


@dataclass
class ScanResult:
    """Static-analysis result for one file (maps onto the FILE_SCANNED event)."""

    file: str
    filename: str
    size_bytes: int
    sha256: str | None
    md5_legacy: str | None
    sha1_legacy: str | None
    entropy: float
    chi_square: float
    magic_type: str
    magic_hex: str
    extension_mismatch: bool
    double_extension: bool
    rtlo: bool
    xor_key: int | None
    yara_matches: list[str]
    authenticode: str
    likelihood: int
    impact: int
    risk_score: int
    tier: str
    mitre: list[str]
    reasons: list[str]
    scan_status: str
    entropy_exempt: bool = False
    known_good: bool = False
    intel: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class _Verdict:
    tier: str
    likelihood: int
    impact: int
    mitre: list[str]
    reasons: list[str]


def _add(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def classify(
    *,
    ext: str,
    filename: str,
    info: mb.MagicInfo,
    entropy: float,
    entropy_checked: bool,
    exempt: bool,
    mismatch: bool,
    double_ext: bool,
    rtlo: bool,
    xor_key: int | None,
    yara_hits: list[YaraHit],
    authenticode: str,
) -> _Verdict:
    """Pure tier/risk decision. CRITICAL > SUSPICIOUS > SAFE."""
    crit: list[str] = []
    susp: list[str] = []
    mitre: list[str] = []
    is_exec_file = info.is_executable or ext in mb.EXEC_EXTS

    for hit in yara_hits:
        crit.append(f"YARA rule {hit.rule} matched")
        _add(mitre, hit.mitre)
    if mismatch:
        marker = _MARKER.get(info.family, info.family)
        crit.append(f"Magic bytes ({marker}) mismatch claimed .{ext} extension")
        _add(mitre, "T1036.008")
    if double_ext:
        crit.append(f"Double extension in filename '{filename}'")
        _add(mitre, "T1036.007")
    if rtlo:
        msg = "Right-to-left override character (U+202E) in filename"
        (crit if is_exec_file else susp).append(msg)
        _add(mitre, "T1036.002")
    if xor_key is not None:
        crit.append(f"XOR-obfuscated PE (key 0x{xor_key:02X})")
        _add(mitre, "T1027")

    high_entropy = entropy_checked and entropy > ENTROPY_THRESHOLD
    if high_entropy and exempt:
        susp_note = (
            f"High entropy ({entropy:.2f}) expected for compressed .{ext} "
            f"({info.label}); not escalated"
        )
    else:
        susp_note = ""
    if high_entropy and not exempt:
        susp.append(f"High Shannon entropy ({entropy:.2f} > {ENTROPY_THRESHOLD})")
        _add(mitre, "T1027.002")
        if info.family == "pe" and authenticode in ("unsigned", "invalid"):
            susp.append(f"Executable is {authenticode} and has high entropy (likely packed)")
    if ext in mb.SCRIPT_EXTS:
        susp.append(f"Script/autorun-capable extension .{ext}")
        _add(mitre, "T1059.001" if ext == "ps1" else "T1204.002")

    if crit:
        indicators = len(crit) + (1 if high_entropy and not exempt else 0)
        return _Verdict("CRITICAL", 5 if indicators >= 2 else 4, 5, mitre, crit + susp)
    if susp:
        return _Verdict("SUSPICIOUS", 4 if len(susp) >= 2 else 3, 3, mitre, susp)
    reasons = [susp_note] if susp_note else ["No indicators found"]
    return _Verdict("SAFE", 1, 2, mitre, reasons)


def analyze_file(path: str, *, max_size_bytes: int) -> ScanResult:
    """Analyze one file. Raises OSError if the file cannot be read (caller counts it skipped).

    Files are read once in 64 KB chunks feeding the hasher and byte histogram together.
    Files larger than ``max_size_bytes`` get header + name checks only (``PARTIAL``).
    """
    filename = os.path.basename(path)
    ext = mb.get_extension(filename)
    size = os.stat(path, follow_symlinks=False).st_size
    partial = size > max_size_bytes

    digest = StreamDigest()
    stats = ByteStats()
    header = b""
    with open(path, "rb") as fh:  # read-only; never executed or imported
        if partial:
            header = fh.read(HEADER_BYTES)
        else:
            while chunk := fh.read(CHUNK_SIZE):
                if not header:
                    header = chunk[:HEADER_BYTES]
                digest.update(chunk)
                stats.update(chunk)

    info = mb.identify(header[:16])
    mismatch = mb.has_extension_mismatch(info, ext)
    double_ext = mb.has_double_extension(filename)
    rtlo = mb.has_rtlo(filename)
    xor_key = find_xor_pe(header)
    entropy = stats.entropy()
    exempt = mb.is_entropy_exempt(info, ext)

    yara_hits: list[YaraHit] = [] if partial else scan_file(path, filename, ext)
    authenticode = "not_applicable"
    if info.family == "pe" and not partial:
        authenticode = check_authenticode(path)

    verdict = classify(
        ext=ext, filename=filename, info=info, entropy=entropy, entropy_checked=not partial,
        exempt=exempt, mismatch=mismatch, double_ext=double_ext, rtlo=rtlo, xor_key=xor_key,
        yara_hits=yara_hits, authenticode=authenticode,
    )
    reasons = list(verdict.reasons)
    if partial:
        reasons.append(
            f"File exceeds {max_size_bytes // (1024 * 1024)} MB: header and name checks only"
        )
    return ScanResult(
        file=path, filename=filename, size_bytes=size,
        sha256=None if partial else digest.sha256,
        md5_legacy=None if partial else digest.md5_legacy,
        sha1_legacy=None if partial else digest.sha1_legacy,
        entropy=round(entropy, 4), chi_square=round(stats.chi_square(), 2),
        magic_type=info.label, magic_hex=header[:16].hex(),
        extension_mismatch=mismatch, double_extension=double_ext, rtlo=rtlo, xor_key=xor_key,
        yara_matches=[h.rule for h in yara_hits], authenticode=authenticode,
        likelihood=verdict.likelihood, impact=verdict.impact,
        risk_score=verdict.likelihood * verdict.impact, tier=verdict.tier,
        mitre=verdict.mitre, reasons=reasons,
        scan_status="PARTIAL" if partial else "COMPLETE", entropy_exempt=exempt,
    )


@dataclass
class IntelOutcome:
    """Tier/risk after folding threat-intel verdicts into a static-analysis result."""

    tier: str
    likelihood: int
    impact: int
    reasons: list[str]
    mitre: list[str]
    known_good: bool


def is_entropy_only_alert(tier: str, filename: str, rtlo: bool, entropy: float) -> bool:
    """SUSPICIOUS purely because of high entropy (no script extension, no RTLO trick)."""
    return (
        tier == "SUSPICIOUS"
        and mb.get_extension(filename) not in mb.SCRIPT_EXTS
        and not rtlo
        and entropy > ENTROPY_THRESHOLD
    )


def apply_intel(
    *,
    tier: str,
    likelihood: int,
    impact: int,
    reasons: list[str],
    mitre: list[str],
    filename: str,
    rtlo: bool,
    entropy: float,
    verdicts: list[IntelVerdict],
) -> IntelOutcome:
    """Escalate on malicious intel; downgrade entropy-only alerts for known-good files.

    * any ``malicious`` verdict -> CRITICAL (5 x 5); malicious always wins over known-good
    * ``known_good`` (CIRCL/NSRL) downgrades SUSPICIOUS to SAFE only when entropy was the sole
      reason (no script extension, no RTLO), and the reason is shown
    * ``suspicious`` intel lifts a SAFE file to SUSPICIOUS
    """
    new_reasons = list(reasons)
    new_mitre = list(mitre)
    known_good = any(v.status == "known_good" for v in verdicts)
    malicious = [v for v in verdicts if v.status == "malicious"]
    flagged = [v for v in verdicts if v.status == "suspicious"]

    if malicious:
        intel_reasons = [f"Threat intel ({v.provider}): {v.summary}" for v in malicious]
        _add(new_mitre, "T1204.002")
        return IntelOutcome("CRITICAL", 5, 5, intel_reasons + new_reasons, new_mitre, known_good)
    if known_good and is_entropy_only_alert(tier, filename, rtlo, entropy):
        good = next(v for v in verdicts if v.status == "known_good")
        note = f"Downgraded: {good.summary}. High entropy alone is not suspicious here"
        return IntelOutcome("SAFE", 1, 2, [note] + new_reasons, new_mitre, True)
    if flagged and tier == "SAFE":
        note = f"Threat intel ({flagged[0].provider}): {flagged[0].summary}"
        return IntelOutcome("SUSPICIOUS", 3, 3, [note] + new_reasons, new_mitre, known_good)
    return IntelOutcome(tier, likelihood, impact, new_reasons, new_mitre, known_good)
