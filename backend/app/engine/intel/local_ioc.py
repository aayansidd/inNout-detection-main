"""Offline IOC provider: a plain-text hash list plus hashes from the recent-malware feed."""

from __future__ import annotations

import re
from pathlib import Path

from .base import IntelVerdict
from .cache import IntelCache

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


class LocalIocProvider:
    """Works with no internet. File format: one SHA-256 per line, ``#`` comments allowed."""

    name = "local_ioc"
    network = False
    enabled = True

    def __init__(self, path: Path, cache: IntelCache) -> None:
        self.path = path
        self.cache = cache
        self._mtime: float | None = None
        self._hashes: set[str] = set()

    def _load(self) -> set[str]:
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            self._hashes, self._mtime = set(), None
            return self._hashes
        if mtime != self._mtime:
            found = set()
            for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
                token = line.strip().split("#", 1)[0].strip().split(" ", 1)[0]
                if _HEX64.match(token):
                    found.add(token.lower())
            self._hashes, self._mtime = found, mtime
        return self._hashes

    async def lookup(self, sha256: str) -> IntelVerdict:
        sha256 = sha256.lower()
        if sha256 in self._load():
            return IntelVerdict(
                provider=self.name, status="malicious",
                summary="Listed in the local IOC file (offline)",
            )
        hit = await self.cache.recent_hit(sha256)
        if hit:
            family = hit.get("signature") or "unknown family"
            return IntelVerdict(
                provider=self.name, status="malicious",
                summary=f"In the cached MalwareBazaar recent feed ({family})",
                link=f"https://bazaar.abuse.ch/sample/{sha256}/",
            )
        return IntelVerdict(provider=self.name, status="not_found", summary="Not in local IOC data")
