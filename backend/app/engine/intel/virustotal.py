"""VirusTotal v3 hash lookup (``GET /files/{sha256}``). Public API: 4 req/min, 500/day."""

from __future__ import annotations

import asyncio

import httpx

from .base import IntelVerdict, Sleep, error_verdict, request_with_backoff
from .cache import IntelCache, TokenBucket

API = "https://www.virustotal.com/api/v3/files"
MALICIOUS_AT = 3  # >= 3 engines flag it; 1-2 is treated as "suspicious" (single-engine noise)


class VirusTotalProvider:
    name = "virustotal"
    network = True

    def __init__(
        self,
        client: httpx.AsyncClient,
        api_key: str,
        cache: IntelCache,
        daily_quota: int = 500,
        bucket: TokenBucket | None = None,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self.client, self._key, self.cache = client, api_key, cache
        self.daily_quota, self.sleep = daily_quota, sleep
        self.bucket = bucket or TokenBucket(4, 4 / 60)  # 4 requests per minute

    @property
    def enabled(self) -> bool:
        return bool(self._key)

    async def quota_remaining(self) -> int:
        return max(0, self.daily_quota - await self.cache.quota_used(self.name))

    async def lookup(self, sha256: str) -> IntelVerdict:
        if await self.quota_remaining() <= 0:
            return IntelVerdict(
                provider=self.name, status="skipped", summary="Daily VirusTotal quota exhausted"
            )
        await self.bucket.acquire()
        await self.cache.quota_bump(self.name)
        resp = await request_with_backoff(
            self.client, "GET", f"{API}/{sha256}", sleep=self.sleep,
            headers={"x-apikey": self._key, "Accept": "application/json"},
        )
        link = f"https://www.virustotal.com/gui/file/{sha256}"
        if resp.status_code == 404:
            return IntelVerdict(
                provider=self.name, status="not_found", summary="Never seen by VirusTotal"
            )
        if resp.status_code in (401, 403):
            return error_verdict(self.name, "authentication rejected (check AEGIS_VT_API_KEY)")
        if resp.status_code == 429:
            return error_verdict(self.name, "rate limited by VirusTotal; try again later")
        if resp.status_code != 200:
            return error_verdict(self.name, f"HTTP {resp.status_code}")
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        engines = sum(int(v) for v in stats.values())
        summary = f"{malicious}/{engines} engines flag this file as malicious"
        if malicious >= MALICIOUS_AT:
            status = "malicious"
        elif malicious >= 1 or suspicious >= 1:
            status = "suspicious"
            summary = f"{malicious + suspicious}/{engines} engines are unsure or flag it"
        else:
            status = "clean"
        return IntelVerdict(
            provider=self.name, status=status, summary=summary, link=link,
            detections=malicious, engines=engines,
        )
