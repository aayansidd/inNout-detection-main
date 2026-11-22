"""Orchestrates intel providers: cache -> local IOC -> CIRCL -> MalwareBazaar -> VirusTotal.

Lookups run in background worker tasks so scanning is never blocked by the network.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

import httpx

from ...config import Settings
from .. import magic_bytes as mb
from ..analyzer import apply_intel, is_entropy_only_alert
from .base import IntelVerdict, Provider, Sleep, error_verdict
from .cache import IntelCache
from .hashlookup import HashLookupProvider
from .local_ioc import LocalIocProvider
from .malwarebazaar import MalwareBazaarProvider
from .virustotal import VirusTotalProvider

log = logging.getLogger("aegis.intel")
WORKERS = 3
RECENT_REFRESH_SECONDS = 600
VT_LOW_QUOTA = 50  # below this, VirusTotal is reserved for SUSPICIOUS/CRITICAL files


def worth_network_lookup(event: dict[str, Any]) -> bool:
    """Only non-SAFE files, executables and scripts are worth a network lookup."""
    ext = mb.get_extension(event.get("filename", ""))
    magic = str(event.get("magic_type", ""))
    return (
        event.get("tier") != "SAFE"
        or ext in mb.EXEC_EXTS
        or any(k in magic for k in ("PE32", "ELF", "Mach-O", "LNK"))
    )


class IntelService:
    """Hash-only enrichment with caching, rate limiting and an offline mode."""

    def __init__(
        self,
        settings: Settings,
        *,
        client: httpx.AsyncClient | None = None,
        sleep: Sleep = asyncio.sleep,
        audit: Any = None,
    ) -> None:
        self.settings = settings
        self.audit = audit
        self.offline = settings.intel_offline
        self._owns_client = client is None
        self.client = client or httpx.AsyncClient(timeout=10.0)  # TLS verification stays ON
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.cache = IntelCache(settings.data_dir / "intel.db")
        self.cache.purge(settings.retention_days)
        self.local = LocalIocProvider(settings.local_ioc_path, self.cache)
        self.circl = HashLookupProvider(self.client, sleep)
        self.mb = MalwareBazaarProvider(self.client, settings.mb_auth_key, sleep)
        self.vt = VirusTotalProvider(
            self.client, settings.vt_api_key, self.cache, settings.vt_daily_quota, sleep=sleep
        )
        self.providers: list[Provider] = [self.local, self.circl, self.mb, self.vt]
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._tasks: list[asyncio.Task[None]] = []
        self._publish: Callable[[Any], None] | None = None

    # ---- status ---------------------------------------------------------------------------
    def enabled_names(self) -> list[str]:
        """Providers that will actually be used (network ones vanish in offline mode)."""
        return [p.name for p in self.providers if p.enabled and (not p.network or not self.offline)]

    # ---- lookup ---------------------------------------------------------------------------
    async def lookup(
        self, sha256: str, *, network: bool = True, stop_on_known_good: bool = False,
        vt_priority: bool = True,
    ) -> list[IntelVerdict]:
        """Query providers in order. Never raises: failures become ``error`` verdicts."""
        sha256 = sha256.lower()
        verdicts: list[IntelVerdict] = []
        for provider in self.providers:
            if not provider.enabled or (provider.network and (self.offline or not network)):
                continue
            if provider.network:
                cached = await self.cache.get(provider.name, sha256)
                if cached is not None:
                    verdicts.append(cached)
                    if stop_on_known_good and cached.status == "known_good":
                        break
                    continue
            if provider is self.vt and not vt_priority:
                if await self.vt.quota_remaining() < VT_LOW_QUOTA:
                    verdicts.append(IntelVerdict(
                        provider=self.vt.name, status="skipped",
                        summary="VirusTotal quota is low: reserved for flagged files",
                    ))
                    continue
            try:
                verdict = await provider.lookup(sha256)
            except httpx.HTTPError as exc:
                verdict = error_verdict(provider.name, f"network error ({type(exc).__name__})")
            except (ValueError, KeyError, TypeError):
                verdict = error_verdict(provider.name, "unexpected response format")
            if provider.network and verdict.status not in ("error", "skipped"):
                await self.cache.put(provider.name, sha256, verdict)
            verdicts.append(verdict)
            if stop_on_known_good and verdict.status == "known_good":
                break
        return verdicts

    async def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        return await self.cache.recent(limit)

    async def refresh_recent(self) -> int:
        """Pull MalwareBazaar get_recent into the local IOC cache. Returns items stored."""
        if self.offline or not self.mb.enabled:
            return 0
        try:
            items = await self.mb.recent()
        except (httpx.HTTPError, ValueError, KeyError):
            log.warning("recent-malware refresh failed")
            return 0
        if items:
            await self.cache.save_recent(items)
        return len(items)

    # ---- background enrichment ------------------------------------------------------------
    def start(self, publish: Callable[[Any], None]) -> None:
        """Start workers. ``publish`` gets FileEnrichedEvent objects (hub.publish)."""
        self._publish = publish
        loop = asyncio.get_running_loop()
        self._tasks = [loop.create_task(self._worker()) for _ in range(WORKERS)]
        self._tasks.append(loop.create_task(self._recent_loop()))

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._owns_client:
            await self.client.aclose()
        self.cache.close()

    def submit(self, event: dict[str, Any]) -> None:
        """Queue a FILE_SCANNED payload for enrichment (called on the event loop)."""
        if event.get("sha256") and event.get("size_bytes", 0) > 0:
            self._queue.put_nowait(event)

    async def _recent_loop(self) -> None:
        while True:
            await self.refresh_recent()
            await asyncio.sleep(RECENT_REFRESH_SECONDS)

    async def _worker(self) -> None:
        while True:
            event = await self._queue.get()
            try:
                await self._enrich(event)
            except Exception:  # noqa: BLE001 - one bad lookup must not kill the worker
                log.exception("enrichment failed")

    async def lookup_for_event(self, event: dict[str, Any]) -> tuple[list[IntelVerdict], bool]:
        """The exact lookups the live pipeline does for one scanned file.

        Returns ``(verdicts, worth_network)``. ``warm_cache`` calls this too, so a warmed cache
        holds precisely the keys the live demo will ask for.
        """
        worth = worth_network_lookup(event)
        # A known-good hit only short-circuits the paid lookups for entropy-only alerts, the
        # false positives it exists to clear. Everything else keeps going: NSRL also lists
        # test files (EICAR is in it), so "known" must never hide a malicious verdict.
        fp_candidate = is_entropy_only_alert(
            event["tier"], event["filename"], event["rtlo"], event["entropy"]
        )
        verdicts = await self.lookup(
            event["sha256"], network=worth, stop_on_known_good=fp_candidate,
            vt_priority=event["tier"] != "SAFE",
        )
        return verdicts, worth

    async def _enrich(self, event: dict[str, Any]) -> None:
        from ...api.schemas import FileEnrichedEvent  # local: avoids an import cycle

        verdicts, worth = await self.lookup_for_event(event)
        interesting = any(v.status not in ("not_found", "skipped") for v in verdicts)
        network_answered = any(v.provider != "local_ioc" for v in verdicts)
        # Quiet by design: offline "not found" results are noise, so emit only when a network
        # provider replied for a file worth looking up, or when any provider found something.
        if not verdicts or not (interesting or (worth and network_answered)):
            return
        outcome = apply_intel(
            tier=event["tier"], likelihood=event["likelihood"], impact=event["impact"],
            reasons=event["reasons"], mitre=event["mitre"], filename=event["filename"],
            rtlo=event["rtlo"], entropy=event["entropy"], verdicts=verdicts,
        )
        enriched = FileEnrichedEvent(
            scan_id=event["scan_id"], drive=event["drive"], file_event_id=event["event_id"],
            sha256=event["sha256"], verdicts=verdicts, known_good=outcome.known_good,
            previous_tier=event["tier"], tier=outcome.tier, likelihood=outcome.likelihood,
            impact=outcome.impact, risk_score=outcome.likelihood * outcome.impact,
            reasons=outcome.reasons, mitre=outcome.mitre,
        )
        if self.audit is not None:
            await asyncio.to_thread(  # SQLite write: keep it off the event loop (AD-2)
                self.audit.save_enrichment,
                enriched.file_event_id, enriched.scan_id, enriched.model_dump_json(),
            )
        if self._publish is not None:
            self._publish(enriched)
