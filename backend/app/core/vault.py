"""AES-256-GCM quarantine vault (Week 3).

Flagged files are *copied* here and encrypted, so they cannot be executed from the vault. The
key is derived per blob with scrypt from ``AEGIS_VAULT_PASSPHRASE`` and a random salt; the
96-bit nonce is random; the file's SHA-256 is bound in as associated data, so a swapped or
edited blob or metadata file fails authentication. Restore re-checks the hash.

Blob layout (``.aegisq``): ``b"AEGQ1" | salt(16) | nonce(12) | ciphertext+tag``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"AEGQ1"
SALT_LEN, NONCE_LEN = 16, 12
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
MAX_VAULT_BYTES = 256 * 1024 * 1024
_ID = re.compile(r"^[0-9a-f]{32}$")


class VaultError(Exception):
    """Clean, user-presentable vault failure (never leaks key material)."""


def _derive(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
        passphrase.encode()
    )


def _check_id(entry_id: str) -> str:
    if not _ID.match(entry_id):
        raise VaultError("invalid vault id")
    return entry_id


class Vault:
    """File-backed encrypted quarantine."""

    def __init__(self, directory: Path, passphrase: str) -> None:
        self.directory = directory
        self._passphrase = passphrase

    @property
    def configured(self) -> bool:
        return bool(self._passphrase)

    def _require(self) -> None:
        if not self._passphrase:
            raise VaultError("Vault passphrase not set (AEGIS_VAULT_PASSPHRASE)")
        self.directory.mkdir(parents=True, exist_ok=True)

    def _paths(self, entry_id: str) -> tuple[Path, Path]:
        _check_id(entry_id)
        return self.directory / f"{entry_id}.aegisq", self.directory / f"{entry_id}.json"

    def quarantine(self, src: Path, entry_id: str, meta: dict[str, Any]) -> dict[str, Any]:
        """Copy ``src`` into the vault, encrypted. The original is left untouched."""
        self._require()
        blob_path, meta_path = self._paths(entry_id)
        if blob_path.exists():
            raise VaultError("already quarantined")
        try:
            size = src.stat().st_size
            if size > MAX_VAULT_BYTES:
                raise VaultError("file too large for the vault")
            plaintext = src.read_bytes()
        except OSError as exc:
            raise VaultError(f"cannot read source file ({type(exc).__name__})") from exc
        sha256 = hashlib.sha256(plaintext).hexdigest()
        expected = meta.get("sha256")
        if expected and expected != sha256:
            raise VaultError("file changed since it was scanned; rescan before quarantining")
        salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
        ciphertext = AESGCM(_derive(self._passphrase, salt)).encrypt(
            nonce, plaintext, sha256.encode()
        )
        blob_path.write_bytes(MAGIC + salt + nonce + ciphertext)
        entry = {
            **meta, "id": entry_id, "sha256": sha256, "size_bytes": len(plaintext),
            "quarantined_at": datetime.now(UTC)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "original_deleted": False,
        }
        meta_path.write_text(json.dumps(entry, indent=2))
        return entry

    def get(self, entry_id: str) -> dict[str, Any]:
        _, meta_path = self._paths(entry_id)
        try:
            return json.loads(meta_path.read_text())
        except (OSError, ValueError) as exc:
            raise VaultError("not found in the vault") from exc

    def update(self, entry_id: str, **changes: Any) -> dict[str, Any]:
        entry = {**self.get(entry_id), **changes}
        self._paths(entry_id)[1].write_text(json.dumps(entry, indent=2))
        return entry

    def list(self) -> list[dict[str, Any]]:
        if not self.directory.is_dir():
            return []
        entries = []
        for meta in sorted(self.directory.glob("*.json")):
            try:
                entries.append(json.loads(meta.read_text()))
            except (OSError, ValueError):
                continue
        return sorted(entries, key=lambda e: e.get("quarantined_at", ""), reverse=True)

    def restore(self, entry_id: str, dest_dir: Path) -> dict[str, Any]:
        """Decrypt into ``dest_dir`` and verify the SHA-256. Fails cleanly on any mismatch."""
        self._require()
        entry = self.get(entry_id)
        blob_path, _ = self._paths(entry_id)
        try:
            blob = blob_path.read_bytes()
        except OSError as exc:
            raise VaultError("encrypted blob is missing") from exc
        if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + SALT_LEN + NONCE_LEN + 16:
            raise VaultError("not a valid vault blob")
        body = blob[len(MAGIC):]
        salt = body[:SALT_LEN]
        nonce = body[SALT_LEN : SALT_LEN + NONCE_LEN]
        ciphertext = body[SALT_LEN + NONCE_LEN :]
        try:
            plaintext = AESGCM(_derive(self._passphrase, salt)).decrypt(
                nonce, ciphertext, str(entry.get("sha256", "")).encode()
            )
        except InvalidTag as exc:
            raise VaultError(
                "decryption failed: wrong passphrase or the vault data was altered"
            ) from exc
        if hashlib.sha256(plaintext).hexdigest() != entry.get("sha256"):
            raise VaultError("integrity check failed: restored data has a different SHA-256")
        dest_dir.mkdir(parents=True, exist_ok=True)
        base = os.path.basename(str(entry.get("filename", "file")))
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", base)
        out = dest_dir / f"{entry_id[:8]}_{safe_name}"
        out.write_bytes(plaintext)
        return {
            "id": entry_id, "restored_path": str(out), "sha256": entry["sha256"], "verified": True,
        }
