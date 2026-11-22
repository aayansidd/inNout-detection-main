"""Environment-driven settings (AEGIS_* variables)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

ENTROPY_THRESHOLD = 7.2
CHUNK_SIZE = 64 * 1024
VAULT_CIPHER = "aes-256-gcm"
# Refused on purpose (Week 4): short keys, 64-bit blocks (Sweet32) or broken designs.
LEGACY_CIPHERS = {
    "des": "56-bit key, brute-forceable",
    "3des": "64-bit block: Sweet32 birthday attacks; NIST deprecated TDEA",
    "tripledes": "64-bit block: Sweet32 birthday attacks; NIST deprecated TDEA",
    "des-ede3": "64-bit block: Sweet32 birthday attacks; NIST deprecated TDEA",
    "rc4": "biased keystream",
    "blowfish": "64-bit block: Sweet32 birthday attacks",
}


class ConfigError(ValueError):
    """Invalid configuration: raised at startup so a bad setting never runs silently."""


def validate_cipher(name: str) -> str:
    """Return the normalised cipher or raise ConfigError for legacy/unknown ciphers."""
    key = name.strip().lower()
    if key in LEGACY_CIPHERS:
        raise ConfigError(
            f"AEGIS_VAULT_CIPHER={name!r} is refused ({LEGACY_CIPHERS[key]}). "
            f"Use {VAULT_CIPHER}."
        )
    if key != VAULT_CIPHER:
        raise ConfigError(f"Unsupported AEGIS_VAULT_CIPHER={name!r}; only {VAULT_CIPHER} exists.")
    return key


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """Runtime configuration. Secrets come only from the environment / .env."""

    max_scan_file_size_mb: int
    scan_workers: int
    data_dir: Path
    retention_days: int
    redact_filenames: bool
    demo_mode: bool
    vault_passphrase: str
    hmac_secret: str
    local_ioc_path: Path
    mb_auth_key: str
    vt_api_key: str
    demo_drive_path: Path
    watch_usb: bool
    port: int
    vault_cipher: str
    allowed_origins: tuple[str, ...]
    intel_offline: bool
    vt_daily_quota: int

    @property
    def max_scan_file_size_bytes(self) -> int:
        return self.max_scan_file_size_mb * 1024 * 1024


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load settings once (reads backend/.env if present)."""
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    return Settings(
        max_scan_file_size_mb=int(os.getenv("AEGIS_MAX_SCAN_FILE_SIZE_MB", "50")),
        scan_workers=int(os.getenv("AEGIS_SCAN_WORKERS", "4")),
        data_dir=Path(os.getenv("AEGIS_DATA_DIR", "./data")).resolve(),
        retention_days=int(os.getenv("AEGIS_RETENTION_DAYS", "30")),
        redact_filenames=_bool("AEGIS_REDACT_FILENAMES", False),
        demo_mode=_bool("AEGIS_DEMO_MODE", True),
        vault_passphrase=os.getenv("AEGIS_VAULT_PASSPHRASE", ""),
        hmac_secret=os.getenv("AEGIS_HMAC_SECRET", ""),
        local_ioc_path=Path(os.getenv("AEGIS_LOCAL_IOC_PATH", "../qa_demo/local_ioc.txt")),
        mb_auth_key=os.getenv("AEGIS_MB_AUTH_KEY", ""),
        vt_api_key=os.getenv("AEGIS_VT_API_KEY", ""),
        demo_drive_path=Path(
            os.getenv("AEGIS_DEMO_DRIVE_PATH", "../qa_demo/sample_usb_drive")
        ).resolve(),
        watch_usb=_bool("AEGIS_WATCH_USB", True),
        port=int(os.getenv("AEGIS_PORT", "8000")),
        vault_cipher=validate_cipher(os.getenv("AEGIS_VAULT_CIPHER", VAULT_CIPHER)),
        allowed_origins=(
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            *[o.strip() for o in os.getenv("AEGIS_EXTRA_ORIGINS", "").split(",") if o.strip()],
        ),
        intel_offline=_bool("AEGIS_INTEL_OFFLINE", False),
        vt_daily_quota=int(os.getenv("AEGIS_VT_DAILY_QUOTA", "500")),
    )
