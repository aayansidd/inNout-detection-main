"""Realtime hub: thread-safe event bus, history/stats, and per-client WebSocket queues.

Worker threads call the EventSink methods; each one hops onto the asyncio loop with
``call_soon_threadsafe``. A single broadcaster task fans events out to per-client queues, so a
slow client only ever hurts itself (its queue overflows and it is dropped).
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from collections.abc import Callable
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from ..core.usb_monitor import DriveInfo
from ..crypto.audit_chain import AuditChain
from ..engine.analyzer import ScanResult
from .schemas import (
    DriveState,
    FileScannedEvent,
    HeartbeatEvent,
    ScanCompleteEvent,
    ScanProgressEvent,
    SnapshotEvent,
    Stats,
    UsbConnectedEvent,
    UsbDisconnectedEvent,
    _Event,
)

log = logging.getLogger("aegis.hub")
HISTORY_SIZE = 500
CLIENT_QUEUE_SIZE = 2000
HEARTBEAT_SECONDS = 15
_HISTORY_TYPES = {
    "USB_CONNECTED", "USB_DISCONNECTED", "FILE_SCANNED", "FILE_ENRICHED", "SCAN_COMPLETE",
}


class Client:
    """One WebSocket subscriber with its own bounded send queue."""

    def __init__(self) -> None:
        self.queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=CLIENT_QUEUE_SIZE)

    def offer(self, payload: str) -> bool:
        """Queue a message; on overflow drop the backlog and signal close. Returns success."""
        try:
            self.queue.put_nowait(payload)
            return True
        except asyncio.QueueFull:
            self.close()
            return False


    def close(self) -> None:
        """Ask the writer to finish: drop any backlog and queue the close sentinel."""
        while not self.queue.empty():
            self.queue.get_nowait()
        self.queue.put_nowait(None)


class Hub:
    """Event bus + in-memory state (history ring buffer, stats, active drives)."""

    def __init__(self, audit: AuditChain | None = None) -> None:
        self.audit = audit
        self.file_hooks: list[Callable[[dict[str, Any]], None]] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._queue: asyncio.Queue[_Event] = asyncio.Queue()
        self._tasks: list[asyncio.Task[None]] = []
        self._clients: set[Client] = set()
        self.history: deque[dict[str, Any]] = deque(maxlen=HISTORY_SIZE)
        self.stats = Stats()
        self.drives: dict[str, DriveState] = {}
        self._seen_scans: set[str] = set()  # every scan_id announced since start-up
        self._stale_scans: set[str] = set()  # scans cleared by reset(): late intel is dropped

    # ---- lifecycle -------------------------------------------------------------------------
    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._tasks = [loop.create_task(self._broadcaster()), loop.create_task(self._heartbeat())]

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        for client in list(self._clients):
            client.close()

    @property
    def client_count(self) -> int:
        return len(self._clients)

    # ---- publishing (any thread) -----------------------------------------------------------
    def publish(self, event: _Event) -> None:
        """Queue an event for broadcast. Safe to call from worker threads."""
        if self._loop is None or self._loop.is_closed():
            return
        try:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, event)
        except RuntimeError:  # loop shut down between the check and the call
            log.debug("event dropped: loop closed")

    # EventSink protocol ------------------------------------------------------------------
    def usb_connected(self, drive: DriveInfo, scan_id: str) -> None:
        self.publish(UsbConnectedEvent(
            scan_id=scan_id, drive=drive.drive, label=drive.label, fs_type=drive.fs_type,
            total_bytes=drive.total_bytes, simulated=drive.simulated,
        ))

    def usb_disconnected(self, drive: str) -> None:
        self.publish(UsbDisconnectedEvent(drive=drive))

    def scan_progress(
        self, scan_id: str, drive: str, discovered: int, scanned: int, skipped: int
    ) -> None:
        self.publish(ScanProgressEvent(
            scan_id=scan_id, drive=drive, files_discovered=discovered,
            files_scanned=scanned, files_skipped=skipped,
        ))

    def file_scanned(self, scan_id: str, drive: str, result: ScanResult) -> None:
        fields = {k: v for k, v in result.to_dict().items() if k in FileScannedEvent.model_fields}
        event = FileScannedEvent(scan_id=scan_id, drive=drive, **fields)
        if self.audit is None:
            self.publish(event)
            return
        # Append + publish under one lock so chain order == broadcast order.
        with self.audit.lock:
            try:
                payload = event.model_dump(mode="json", exclude={"chain_index", "chain_hash"})
                event.chain_index, event.chain_hash = self.audit.append(payload)
            except Exception:  # noqa: BLE001 - a log failure must not stop scanning
                log.exception("audit append failed")
            self.publish(event)

    def scan_complete(
        self, scan_id: str, drive: str, counts: dict[str, int], duration_s: float, cancelled: bool
    ) -> None:
        self.publish(ScanCompleteEvent(
            scan_id=scan_id, drive=drive, total=counts["total"], safe=counts["safe"],
            suspicious=counts["suspicious"], critical=counts["critical"],
            duration_s=duration_s, cancelled=cancelled,
        ))

    # ---- event-loop side -------------------------------------------------------------------
    def add_client(self) -> Client:
        """Register a client and queue its SNAPSHOT first.

        Runs synchronously on the loop (no await), so no event can slip between the snapshot
        and the subscription: the client sees every event exactly once or dedupes by event_id.
        """
        client = Client()
        snapshot = SnapshotEvent(
            events=list(self.history),
            stats=self.stats.model_copy(),
            drives=[d.model_copy() for d in self.drives.values()],
        )
        client.offer(snapshot.model_dump_json())
        self._clients.add(client)
        return client

    def scanning(self) -> bool:
        """True while any drive is still being scanned (loop side)."""
        return any(d.scanning for d in self.drives.values())

    def reset(self) -> None:
        """Demo reset: clear counters and history, then give every client a fresh SNAPSHOT.

        Runs on the loop (AD-2). Connected drives stay. The audit chain is NOT touched (it is
        evidence). Intel that finishes later for a cleared scan is dropped, so counters cannot
        drift back up.
        """
        self._stale_scans |= self._seen_scans
        self.history.clear()
        self.stats = Stats()
        snapshot = SnapshotEvent(
            events=[], stats=self.stats.model_copy(),
            drives=[d.model_copy() for d in self.drives.values()],
        ).model_dump_json()
        for client in list(self._clients):
            if not client.offer(snapshot):
                log.warning("slow websocket client dropped")
                self._clients.discard(client)

    def remove_client(self, client: Client) -> None:
        self._clients.discard(client)

    def _apply(self, event: _Event, data: dict[str, Any]) -> None:
        kind = data["type"]
        if kind == "USB_CONNECTED":
            self._seen_scans.add(data["scan_id"])
            self.drives[data["drive"]] = DriveState(
                drive=data["drive"], label=data["label"], fs_type=data["fs_type"],
                total_bytes=data["total_bytes"], simulated=data["simulated"],
                scan_id=data["scan_id"],
            )
        elif kind == "USB_DISCONNECTED":
            self.drives.pop(data["drive"], None)
        elif kind == "SCAN_PROGRESS" and data["drive"] in self.drives:
            d = self.drives[data["drive"]]
            d.files_discovered = data["files_discovered"]
            d.files_scanned = data["files_scanned"]
            d.files_skipped = data["files_skipped"]
        elif kind == "FILE_SCANNED":
            self.stats.total += 1
            tier = data["tier"].lower()
            setattr(self.stats, tier, getattr(self.stats, tier) + 1)
        elif kind == "FILE_ENRICHED":
            old, new = data["previous_tier"].lower(), data["tier"].lower()
            if old != new:
                setattr(self.stats, old, max(0, getattr(self.stats, old) - 1))
                setattr(self.stats, new, getattr(self.stats, new) + 1)
        elif kind == "SCAN_COMPLETE":
            self.stats.scans_completed += 1
            drive = self.drives.get(data["drive"])
            if drive and drive.scan_id == data["scan_id"]:
                drive.scanning = False
        if kind in _HISTORY_TYPES:
            self.history.append(data)

    async def _broadcaster(self) -> None:
        while True:
            event = await self._queue.get()
            try:
                data = event.model_dump(mode="json")
                if data["type"] == "FILE_ENRICHED" and data["scan_id"] in self._stale_scans:
                    continue  # intel for a scan the operator already reset away
                self._apply(event, data)
                payload = json.dumps(data)
                if data["type"] == "FILE_SCANNED":
                    for hook in self.file_hooks:
                        hook(data)
                for client in list(self._clients):
                    if not client.offer(payload):
                        log.warning("slow websocket client dropped")
                        self._clients.discard(client)
            except Exception:  # noqa: BLE001 - never let one bad event kill the hub
                log.exception("broadcast failed")

    async def _heartbeat(self) -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            self.publish(HeartbeatEvent(clients=len(self._clients)))


async def serve_client(ws: WebSocket, hub: Hub) -> None:
    """Run one WebSocket session: SNAPSHOT, live events, until either side goes away."""
    await ws.accept()
    client = hub.add_client()

    async def writer() -> None:
        try:
            while (msg := await client.queue.get()) is not None:
                await ws.send_text(msg)
            await ws.close(code=1013)  # try again later: client was too slow
        except (WebSocketDisconnect, RuntimeError):
            return  # peer went away mid-send

    async def reader() -> None:
        try:
            while True:
                await ws.receive_text()  # input is ignored; this detects the disconnect
        except WebSocketDisconnect:
            return

    tasks = [asyncio.create_task(writer()), asyncio.create_task(reader())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        # Cancel without awaiting: awaiting here would swallow/leak the cancellation the
        # server uses to stop this handler. Both tasks handle their own disconnect errors.
        for task in tasks:
            task.cancel()
        hub.remove_client(client)
