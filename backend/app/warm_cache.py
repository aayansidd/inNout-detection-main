"""Pre-fill the intel cache for the demo files so VirusTotal results are instant on stage.

Run it ~10 minutes before the presentation:  ``python -m app warm_cache``

It scans the demo drive with the normal analyzer, then performs the same lookups the live
pipeline would (paced by the VirusTotal rate limit), plus the EICAR hash used in the Intel tab.
Only hashes are sent. Cache lifetime: found/malicious 24 h, "not found" 1 h (see cache.py).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .config import Settings
from .engine.analyzer import analyze_file
from .engine.intel.service import IntelService

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@dataclass
class WarmReport:
    files: int = 0
    network_lookups: int = 0  # provider answers fetched live (not from cache)
    cached_answers: int = 0
    errors: int = 0
    recent_items: int = 0
    lines: list[str] = field(default_factory=list)


async def warm(
    settings: Settings, drive: Path, *, service: IntelService | None = None,
    say: Callable[[str], None] = print,
) -> WarmReport:
    """Warm the cache for every file under ``drive``. Raises if intel is offline or no drive."""
    if settings.intel_offline:
        raise RuntimeError("AEGIS_INTEL_OFFLINE=true: there is nothing to warm")
    if not drive.is_dir():
        raise RuntimeError(
            f"Demo drive not found: {drive}. Run: python qa_demo/generate_payloads.py"
        )
    svc = service or IntelService(settings)
    report = WarmReport()

    def tally(label: str, verdicts: list) -> None:
        for v in verdicts:
            if v.provider == "local_ioc":
                continue
            if v.status in ("error", "skipped"):
                report.errors += v.status == "error"
            elif v.cached:
                report.cached_answers += 1
            else:
                report.network_lookups += 1
        summary = ", ".join(f"{v.provider}:{v.status}{'*' if v.cached else ''}" for v in verdicts)
        report.lines.append(f"{label}  ->  {summary}")
        say(report.lines[-1])

    try:
        say(f"Providers in use: {', '.join(svc.enabled_names())}")
        if "virustotal" in svc.enabled_names():
            say("VirusTotal is paced at 4 requests/minute: this can take a few minutes.")
        report.recent_items = await svc.refresh_recent()
        say(f"Latest-malware feed: {report.recent_items} samples cached")
        for root, _dirs, names in os.walk(drive):
            for name in sorted(names):
                path = os.path.join(root, name)
                result = analyze_file(path, max_size_bytes=settings.max_scan_file_size_bytes)
                report.files += 1
                event = result.to_dict()
                if not event["sha256"] or event["size_bytes"] == 0:
                    continue
                verdicts, worth = await svc.lookup_for_event(event)
                tally(f"{result.tier:10} {name}" + ("" if worth else " (local only)"), verdicts)
        tally("EICAR test hash (Intel tab)", await svc.lookup(EICAR_SHA256))
    finally:
        if service is None:
            await svc.stop()
    say(
        f"\nDone: {report.files} files, {report.network_lookups} live answers, "
        f"{report.cached_answers} already cached, {report.errors} errors. "
        "(* = served from cache)"
    )
    return report
