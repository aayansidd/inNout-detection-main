"""USB insertion/removal monitor and scan coordinator (M1).

A daemon thread polls ``psutil.disk_partitions`` once per second, diffs the removable mounts
and runs one ScanJob per drive. Results are pushed to an ``EventSink`` (the realtime hub in
Phase 3), keeping this module independent of the API layer.
"""

from __future__ import annotations

import logging
import os
import platform
import plistlib
import re
import subprocess
import threading
import time
import uuid
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Protocol

import psutil

from ..config import get_settings
from ..engine.analyzer import ScanResult, analyze_file
from .walker import WalkCounters, iter_files

log = logging.getLogger("aegis.monitor")
POLL_SECONDS = 1.0
PROGRESS_INTERVAL = 0.25


@dataclass(frozen=True)
class DriveInfo:
    drive: str
    label: str
    fs_type: str
    total_bytes: int
    simulated: bool = False


class EventSink(Protocol):
    """Receiver of monitor events (implemented by the realtime hub)."""

    def usb_connected(self, drive: DriveInfo, scan_id: str) -> None: ...
    def usb_disconnected(self, drive: str) -> None: ...
    def scan_progress(
        self, scan_id: str, drive: str, discovered: int, scanned: int, skipped: int
    ) -> None: ...
    def file_scanned(self, scan_id: str, drive: str, result: ScanResult) -> None: ...
    def scan_complete(
        self, scan_id: str, drive: str, counts: dict[str, int], duration_s: float, cancelled: bool
    ) -> None: ...


def is_removable(part: object, system: str | None = None) -> bool:
    """Decide whether a psutil partition is removable media on the given OS."""
    system = system or platform.system()
    opts = str(getattr(part, "opts", "")).lower().split(",")
    mount = str(getattr(part, "mountpoint", ""))
    if system == "Windows":
        return "removable" in opts and "cdrom" not in opts
    if system == "Linux":  # /mnt is deliberately NOT removable (WSL mounts C: there)
        if mount.startswith(("/media", "/run/media")):
            return True
        return _linux_sysfs_removable(str(getattr(part, "device", "")))
    if system == "Darwin":
        name = mount.removeprefix("/Volumes/")
        return (
            mount.startswith("/Volumes/")
            and os.path.realpath(mount) != "/"
            and not name.startswith(("com.apple", "Recovery", "Preboot", "Update", "VM"))
            and _darwin_is_usb(mount)
        )
    return False


_darwin_cache: dict[str, bool] = {}


def _darwin_is_usb(mount: str) -> bool:
    """True if ``diskutil info`` says the volume is on a USB bus or is removable media.

    Disk images (.dmg) report ``RemovableMedia = true`` too, so they are rejected first by
    their ``BusProtocol`` of "Disk Image". Results are cached per mount point so the 1 s poll
    does not spawn a process every second; a failed lookup is treated as "not USB".
    """
    if mount in _darwin_cache:
        return _darwin_cache[mount]
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["/usr/sbin/diskutil", "info", "-plist", mount],
            capture_output=True, timeout=5, check=True,
        ).stdout
        info = plistlib.loads(out)
    except (OSError, subprocess.SubprocessError, plistlib.InvalidFileException, ValueError):
        return False  # not cached: retry on the next poll
    bus = str(info.get("BusProtocol") or info.get("Protocol") or "")
    if bus == "Disk Image":
        result = False
    else:
        result = bus == "USB" or bool(info.get("RemovableMedia") or info.get("Removable"))
    _darwin_cache[mount] = result
    return result


def forget_mount(mount: str) -> None:
    """Drop a cached diskutil verdict (called when a drive disappears)."""
    _darwin_cache.pop(mount, None)


def _linux_sysfs_removable(device: str) -> bool:
    dev = os.path.basename(device)
    if not re.fullmatch(r"[a-z0-9]+", dev):
        return False
    try:
        real = os.path.realpath(f"/sys/class/block/{dev}")
        candidates = (
            os.path.join(real, "removable"),
            os.path.join(os.path.dirname(real), "removable"),
        )
        for candidate in candidates:
            if os.path.exists(candidate):
                with open(candidate) as fh:
                    return fh.read().strip() == "1"
    except OSError:
        pass
    return False


class ScanJob(threading.Thread):
    """Scans one drive root; cancellable; drops in-flight results when cancelled."""

    def __init__(self, root: str, info: DriveInfo, sink: EventSink, scan_id: str | None = None):
        super().__init__(daemon=True, name=f"scan-{info.drive}")
        self.root, self.info, self.sink = root, info, sink
        self.scan_id = scan_id or uuid.uuid4().hex
        self.cancel = threading.Event()
        self.counters = WalkCounters()

    def run(self) -> None:
        settings = get_settings()
        start = time.monotonic()
        tally = {"total": 0, "safe": 0, "suspicious": 0, "critical": 0}
        last_progress = 0.0
        pending: deque[Future[ScanResult]] = deque()
        window = max(1, settings.scan_workers) * 4

        def drain(limit: int) -> None:
            while len(pending) > limit:
                self._collect(pending.popleft(), tally)

        with ThreadPoolExecutor(max_workers=settings.scan_workers) as pool:
            for path, _size in iter_files(self.root, self.cancel, self.counters):
                pending.append(
                    pool.submit(
                        analyze_file, path, max_size_bytes=settings.max_scan_file_size_bytes
                    )
                )
                drain(window)
                now = time.monotonic()
                if now - last_progress >= PROGRESS_INTERVAL and not self.cancel.is_set():
                    last_progress = now
                    self.sink.scan_progress(
                        self.scan_id, self.info.drive, *self.counters.snapshot()
                    )
            drain(0)
        if not self.cancel.is_set():
            self.sink.scan_progress(self.scan_id, self.info.drive, *self.counters.snapshot())
        self.sink.scan_complete(
            self.scan_id, self.info.drive, tally, round(time.monotonic() - start, 3),
            self.cancel.is_set(),
        )

    def _collect(self, fut: Future[ScanResult], tally: dict[str, int]) -> None:
        try:
            result = fut.result()
        except OSError:
            self.counters.add("skipped")
            return
        except Exception:  # noqa: BLE001 - one bad file must not kill the scan
            log.exception("analysis failed")
            self.counters.add("skipped")
            return
        if self.cancel.is_set():
            return  # drive removed: drop in-flight results
        self.counters.add("scanned")
        tally["total"] += 1
        tally[result.tier.lower()] += 1
        self.sink.file_scanned(self.scan_id, self.info.drive, result)


class UsbMonitor:
    """Polls mounts, starts a ScanJob on insertion and cancels it on removal."""

    def __init__(self, sink: EventSink) -> None:
        self.sink = sink
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="usb-monitor")

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            for job in self._jobs.values():
                job.cancel.set()

    def job(self, drive: str) -> ScanJob | None:
        """The current job for ``drive`` (running or finished), if any."""
        with self._lock:
            return self._jobs.get(drive)

    def active_drives(self) -> list[DriveInfo]:
        with self._lock:
            return [j.info for j in self._jobs.values()]

    def start_scan(self, root: str, info: DriveInfo) -> ScanJob:
        """Begin scanning ``root`` as ``info.drive`` (used for real and simulated drives)."""
        job = ScanJob(root, info, self.sink)
        with self._lock:
            self._jobs[info.drive] = job
        self.sink.usb_connected(info, job.scan_id)
        job.start()
        return job

    def eject(self, drive: str) -> bool:
        """Cancel and forget a drive; emits USB_DISCONNECTED."""
        with self._lock:
            job = self._jobs.pop(drive, None)
        if job is None:
            return False
        job.cancel.set()
        self.sink.usb_disconnected(drive)
        return True

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception:  # noqa: BLE001
                log.exception("poll failed")
            self._stop.wait(POLL_SECONDS)

    def _poll(self) -> None:
        current = {p.mountpoint: p for p in psutil.disk_partitions(all=False) if is_removable(p)}
        with self._lock:
            known = {d for d, j in self._jobs.items() if not j.info.simulated}
        for mount in current.keys() - known:
            part = current[mount]
            try:
                total = psutil.disk_usage(mount).total
            except OSError:
                total = 0
            label = os.path.basename(mount.rstrip("/\\")) or mount
            self.start_scan(mount, DriveInfo(mount, label, part.fstype, total))
        for mount in known - current.keys():
            self.eject(mount)
            forget_mount(mount)
