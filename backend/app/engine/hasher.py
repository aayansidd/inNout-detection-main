"""Streaming digests. SHA-256 is the primary ID; MD5/SHA-1 exist only for intel feeds."""

from __future__ import annotations

import hashlib


class StreamDigest:
    """Feed chunks once; read SHA-256 plus legacy digests at the end.

    MD5 and SHA-1 are collision-prone (SHAttered, 2017) and are kept solely because some
    threat-intel providers index by them. Never use them for integrity decisions.
    """

    def __init__(self) -> None:
        self._sha256 = hashlib.sha256()
        self._md5 = hashlib.md5(usedforsecurity=False)
        self._sha1 = hashlib.sha1(usedforsecurity=False)

    def update(self, chunk: bytes) -> None:
        self._sha256.update(chunk)
        self._md5.update(chunk)
        self._sha1.update(chunk)

    @property
    def sha256(self) -> str:
        return self._sha256.hexdigest()

    @property
    def md5_legacy(self) -> str:
        return self._md5.hexdigest()

    @property
    def sha1_legacy(self) -> str:
        return self._sha1.hexdigest()
