"""Header signatures, extension mismatch, double extensions and RTLO filename tricks."""

from __future__ import annotations

from dataclasses import dataclass

EXEC_FAMILIES = {"pe", "elf", "macho", "lnk"}
# Executable header hiding behind one of these extensions => extension_mismatch (T1036.008)
BENIGN_EXTS = {
    "pdf", "docx", "xlsx", "pptx", "jpg", "jpeg", "png", "gif", "txt", "csv", "mp3", "mp4",
}
EXEC_EXTS = {
    "exe", "scr", "com", "bat", "cmd", "vbs", "js", "ps1", "lnk", "hta", "msi", "pif", "jar",
}
SCRIPT_EXTS = {"vbs", "js", "ps1", "bat", "cmd", "scr", "lnk", "hta"}
DOC_EXTS = BENIGN_EXTS | {"doc", "xls", "ppt", "zip", "rtf"}
RTLO_CHARS = {"‮", "‭"}

# Families whose content is legitimately high-entropy (compressed), and the extensions that fit.
COMPRESSED_EXTS: dict[str, set[str]] = {
    "jpeg": {"jpg", "jpeg"},
    "png": {"png"},
    "zip": {"zip", "docx", "xlsx", "pptx", "odt", "ods"},
    "pdf": {"pdf"},
    "mp4": {"mp4", "m4a", "mov"},
    "7z": {"7z"},
    "gzip": {"gz", "tgz"},
}

_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"MZ", "PE32 executable (MZ)", "pe"),
    (b"\x7fELF", "ELF executable", "elf"),
    (b"\xfe\xed\xfa\xce", "Mach-O executable", "macho"),
    (b"\xfe\xed\xfa\xcf", "Mach-O executable", "macho"),
    (b"\xce\xfa\xed\xfe", "Mach-O executable", "macho"),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable", "macho"),
    (b"%PDF-", "PDF document", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "PNG image", "png"),
    (b"\xff\xd8\xff", "JPEG image", "jpeg"),
    (b"GIF87a", "GIF image", "gif"),
    (b"GIF89a", "GIF image", "gif"),
    (b"PK\x03\x04", "ZIP archive / OOXML", "zip"),
    (b"PK\x05\x06", "ZIP archive (empty)", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document", "ole"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "7z"),
    (b"Rar!\x1a\x07", "RAR archive", "rar"),
    (b"\x1f\x8b", "gzip archive", "gzip"),
    (b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F",
     "Windows shortcut (LNK)", "lnk"),
]


@dataclass(frozen=True)
class MagicInfo:
    label: str
    family: str
    is_executable: bool


def identify(header: bytes) -> MagicInfo:
    """Identify a file type from its first bytes (callers pass up to 16+ bytes)."""
    for sig, label, family in _SIGNATURES:
        if header.startswith(sig):
            return MagicInfo(label, family, family in EXEC_FAMILIES)
    if header[4:8] == b"ftyp":
        return MagicInfo("MP4 / ISO media", "mp4", False)
    return MagicInfo("unknown / text", "unknown", False)


def get_extension(filename: str) -> str:
    """Lower-case final extension without the dot ('' if none)."""
    return filename.rsplit(".", 1)[1].lower() if "." in filename.strip(".") else ""


def has_extension_mismatch(info: MagicInfo, ext: str) -> bool:
    """Executable header behind a benign extension."""
    return info.is_executable and ext in BENIGN_EXTS


def has_double_extension(filename: str) -> bool:
    """`name.<doc-ext>.<exec-ext>` such as invoice.pdf.exe (T1036.007)."""
    parts = filename.lower().split(".")
    return len(parts) >= 3 and parts[-1] in EXEC_EXTS and parts[-2] in DOC_EXTS


def has_rtlo(filename: str) -> bool:
    """True when a bidi override char (U+202E) is present in the filename."""
    return any(ch in filename for ch in RTLO_CHARS)


def is_entropy_exempt(info: MagicInfo, ext: str) -> bool:
    """High entropy is expected for compressed formats whose extension matches the header."""
    return ext in COMPRESSED_EXTS.get(info.family, set())
