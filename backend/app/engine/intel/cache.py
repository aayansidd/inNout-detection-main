"""SQLite cache (TTL), daily quota counter, recent-malware store and a token-bucket limiter."""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .base import IntelVerdict

HIT_TTL = timedelta(hours=24)
MISS_TTL = timedelta(hours=1)  # "not found" today can be "found" tomorrow


def _now() -> float:
    return datetime.now(UTC).timestamp()


class TokenBucket:
    """Async token bucket. ``acquire`` waits until a token is available."""

    def __init__(
        self,
        capacity: int,
        refill_per_second: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.capacity = float(capacity)
        self.rate = refill_per_second
        self._tokens = float(capacity)
        self._clock = clock
        self._sleep = sleep
        self._last = clock()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = self._clock()
                self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                await self._sleep((1.0 - self._tokens) / self.rate)


class IntelCache:
    """Thread-safe SQLite store; async wrappers keep the event loop free."""

    def __init__(self, path: Path | str) -> None:
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._db:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS intel_cache(
                    provider TEXT NOT NULL, sha256 TEXT NOT NULL,
                    verdict TEXT NOT NULL, fetched_at REAL NOT NULL,
                    PRIMARY KEY(provider, sha256));
                CREATE TABLE IF NOT EXISTS quota(
                    provider TEXT NOT NULL, day TEXT NOT NULL, count INTEGER NOT NULL,
                    PRIMARY KEY(provider, day));
                CREATE TABLE IF NOT EXISTS recent(
                    sha256 TEXT PRIMARY KEY, file_name TEXT, file_type TEXT,
                    signature TEXT, first_seen TEXT, fetched_at REAL NOT NULL);
                """
            )

    # -- sync primitives (run via to_thread) ------------------------------------------------
    def _get(self, provider: str, sha256: str) -> IntelVerdict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT verdict, fetched_at FROM intel_cache WHERE provider=? AND sha256=?",
                (provider, sha256),
            ).fetchone()
        if row is None:
            return None
        verdict = IntelVerdict.model_validate_json(row[0])
        ttl = MISS_TTL if verdict.status == "not_found" else HIT_TTL
        if _now() - row[1] > ttl.total_seconds():
            return None
        return verdict.model_copy(update={"cached": True})

    def _put(self, provider: str, sha256: str, verdict: IntelVerdict) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO intel_cache VALUES(?,?,?,?)",
                (provider, sha256, verdict.model_copy(update={"cached": False}).model_dump_json(),
                 _now()),
            )

    def _quota_used(self, provider: str) -> int:
        day = datetime.now(UTC).strftime("%Y-%m-%d")
        with self._lock:
            row = self._db.execute(
                "SELECT count FROM quota WHERE provider=? AND day=?", (provider, day)
            ).fetchone()
        return int(row[0]) if row else 0

    def _quota_bump(self, provider: str) -> None:
        day = datetime.now(UTC).strftime("%Y-%m-%d")
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO quota VALUES(?,?,1) "
                "ON CONFLICT(provider, day) DO UPDATE SET count=count+1",
                (provider, day),
            )

    def _save_recent(self, items: list[dict[str, Any]]) -> None:
        with self._lock, self._db:
            self._db.executemany(
                "INSERT OR REPLACE INTO recent VALUES(?,?,?,?,?,?)",
                [(i["sha256"], i.get("file_name"), i.get("file_type"), i.get("signature"),
                  i.get("first_seen"), _now()) for i in items],
            )

    def _recent(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT sha256,file_name,file_type,signature,first_seen FROM recent "
                "ORDER BY first_seen DESC, fetched_at DESC LIMIT ?", (limit,),
            ).fetchall()
        keys = ("sha256", "file_name", "file_type", "signature", "first_seen")
        return [dict(zip(keys, r, strict=True)) for r in rows]

    def _recent_hit(self, sha256: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT signature, file_type FROM recent WHERE sha256=?", (sha256,)
            ).fetchone()
        return {"signature": row[0], "file_type": row[1]} if row else None

    def purge(self, retention_days: int) -> int:
        """Delete cached data older than the retention window (storage limitation)."""
        cutoff = _now() - retention_days * 86400
        with self._lock, self._db:
            n = self._db.execute("DELETE FROM intel_cache WHERE fetched_at<?", (cutoff,)).rowcount
            n += self._db.execute("DELETE FROM recent WHERE fetched_at<?", (cutoff,)).rowcount
        return n

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- async API --------------------------------------------------------------------------
    async def get(self, provider: str, sha256: str) -> IntelVerdict | None:
        return await asyncio.to_thread(self._get, provider, sha256)

    async def put(self, provider: str, sha256: str, verdict: IntelVerdict) -> None:
        await asyncio.to_thread(self._put, provider, sha256, verdict)

    async def quota_used(self, provider: str) -> int:
        return await asyncio.to_thread(self._quota_used, provider)

    async def quota_bump(self, provider: str) -> None:
        await asyncio.to_thread(self._quota_bump, provider)

    async def save_recent(self, items: list[dict[str, Any]]) -> None:
        await asyncio.to_thread(self._save_recent, items)

    async def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._recent, limit)

    async def recent_hit(self, sha256: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self._recent_hit, sha256)
