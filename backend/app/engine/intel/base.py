"""Threat-intel provider contract, verdict model and a 429-aware request helper.

Privacy (GDPR Art. 5(1)(c), data minimisation): providers only ever receive a file hash.
File contents and filenames never leave the machine, and `get_file`-style downloads are
forbidden by the project's safety rules.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Literal, Protocol

import httpx
from pydantic import BaseModel

Status = Literal[
    "malicious", "suspicious", "clean", "known_good", "not_found", "error", "skipped"
]
MAX_BACKOFF_SECONDS = 60.0


class IntelVerdict(BaseModel):
    """One provider's answer for one hash."""

    provider: str
    status: Status
    summary: str
    link: str | None = None
    detections: int | None = None
    engines: int | None = None
    cached: bool = False


class Provider(Protocol):
    """A hash-only lookup source."""

    name: str
    network: bool
    enabled: bool

    async def lookup(self, sha256: str) -> IntelVerdict: ...


Sleep = Callable[[float], Awaitable[None]]


async def request_with_backoff(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    retries: int = 3,
    sleep: Sleep = asyncio.sleep,
    **kwargs: object,
) -> httpx.Response:
    """Send a request; on HTTP 429 wait (Retry-After or exponential 1s, 2s, 4s) and retry."""
    delay = 1.0
    for attempt in range(retries + 1):
        resp = await client.request(method, url, **kwargs)  # type: ignore[arg-type]
        if resp.status_code != 429 or attempt == retries:
            return resp
        wait = delay
        retry_after = resp.headers.get("Retry-After", "")
        if retry_after.replace(".", "", 1).isdigit():
            wait = float(retry_after)
        await sleep(min(wait, MAX_BACKOFF_SECONDS))
        delay *= 2
    raise AssertionError("unreachable")  # pragma: no cover


def error_verdict(provider: str, summary: str) -> IntelVerdict:
    return IntelVerdict(provider=provider, status="error", summary=summary)
