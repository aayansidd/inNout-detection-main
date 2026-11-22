"""CIRCL hashlookup (NSRL and other known-good corpora) to reduce false positives."""

from __future__ import annotations

import asyncio

import httpx

from .base import IntelVerdict, Sleep, error_verdict, request_with_backoff

BASE = "https://hashlookup.circl.lu/lookup/sha256"
MIN_TRUST = 50  # CIRCL's hashlookup:trust is 0-100


class HashLookupProvider:
    name = "circl"
    network = True
    enabled = True  # keyless public service

    def __init__(self, client: httpx.AsyncClient, sleep: Sleep = asyncio.sleep) -> None:
        self.client, self.sleep = client, sleep

    async def lookup(self, sha256: str) -> IntelVerdict:
        url = f"{BASE}/{sha256}"
        resp = await request_with_backoff(
            self.client, "GET", url, sleep=self.sleep, headers={"Accept": "application/json"}
        )
        if resp.status_code == 404:
            return IntelVerdict(
                provider=self.name, status="not_found", summary="Unknown to CIRCL hashlookup"
            )
        if resp.status_code != 200:
            return error_verdict(self.name, f"HTTP {resp.status_code}")
        data = resp.json()
        trust = data.get("hashlookup:trust")
        source = data.get("source") or "known-file corpus"
        name = data.get("FileName") or "known file"
        if trust is not None and int(trust) < MIN_TRUST:
            return IntelVerdict(
                provider=self.name, status="not_found", link=url,
                summary=f"Seen in {source} but low trust ({trust}); not treated as known-good",
            )
        return IntelVerdict(
            provider=self.name, status="known_good", link=url,
            summary=f"Known-good: {name} ({source})",
        )
