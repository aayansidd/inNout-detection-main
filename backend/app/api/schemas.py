"""Pydantic v2 event and REST models. Must match frontend/src/types/telemetry.ts exactly."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from ..course_map import CourseRow
from ..engine.intel.base import IntelVerdict

TierName = Literal["SAFE", "SUSPICIOUS", "CRITICAL"]


def _new_id() -> str:
    return uuid.uuid4().hex


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


class _Event(BaseModel):
    event_id: str = Field(default_factory=_new_id)
    timestamp: str = Field(default_factory=_now)


class Stats(BaseModel):
    total: int = 0
    safe: int = 0
    suspicious: int = 0
    critical: int = 0
    scans_completed: int = 0


class DriveState(BaseModel):
    drive: str
    label: str
    fs_type: str
    total_bytes: int
    simulated: bool
    scan_id: str
    scanning: bool = True
    files_discovered: int = 0
    files_scanned: int = 0
    files_skipped: int = 0


class UsbConnectedEvent(_Event):
    type: Literal["USB_CONNECTED"] = "USB_CONNECTED"
    scan_id: str
    drive: str
    label: str
    fs_type: str
    total_bytes: int
    simulated: bool


class UsbDisconnectedEvent(_Event):
    type: Literal["USB_DISCONNECTED"] = "USB_DISCONNECTED"
    drive: str


class ScanProgressEvent(_Event):
    type: Literal["SCAN_PROGRESS"] = "SCAN_PROGRESS"
    scan_id: str
    drive: str
    files_discovered: int
    files_scanned: int
    files_skipped: int


class FileScannedEvent(_Event):
    """FILE_SCANNED contract (extra fields allowed for forward compatibility)."""

    model_config = ConfigDict(extra="allow")
    type: Literal["FILE_SCANNED"] = "FILE_SCANNED"
    scan_id: str
    drive: str
    file: str
    filename: str
    size_bytes: int
    sha256: str | None
    md5_legacy: str | None
    sha1_legacy: str | None
    entropy: float
    chi_square: float
    entropy_exempt: bool
    magic_type: str
    magic_hex: str
    extension_mismatch: bool
    double_extension: bool
    rtlo: bool
    xor_key: int | None
    yara_matches: list[str]
    authenticode: str
    likelihood: int
    impact: int
    risk_score: int
    tier: Literal["SAFE", "SUSPICIOUS", "CRITICAL"]
    mitre: list[str]
    reasons: list[str]
    scan_status: Literal["COMPLETE", "PARTIAL"]
    chain_index: int | None = None
    chain_hash: str | None = None


class FileEnrichedEvent(_Event):
    """Threat-intel result that updates an existing FILE_SCANNED row."""

    type: Literal["FILE_ENRICHED"] = "FILE_ENRICHED"
    scan_id: str
    drive: str
    file_event_id: str
    sha256: str
    verdicts: list[IntelVerdict]
    known_good: bool
    previous_tier: TierName
    tier: TierName
    likelihood: int
    impact: int
    risk_score: int
    reasons: list[str]
    mitre: list[str]


class ScanCompleteEvent(_Event):
    type: Literal["SCAN_COMPLETE"] = "SCAN_COMPLETE"
    scan_id: str
    drive: str
    total: int
    safe: int
    suspicious: int
    critical: int
    duration_s: float
    cancelled: bool


class AuditStatusEvent(_Event):
    type: Literal["AUDIT_STATUS"] = "AUDIT_STATUS"
    valid: bool
    length: int
    broken_at: int | None


class HeartbeatEvent(_Event):
    type: Literal["HEARTBEAT"] = "HEARTBEAT"
    clients: int


class SnapshotEvent(_Event):
    type: Literal["SNAPSHOT"] = "SNAPSHOT"
    events: list[dict[str, Any]]
    stats: Stats
    drives: list[DriveState]


Event = Annotated[
    UsbConnectedEvent
    | UsbDisconnectedEvent
    | ScanProgressEvent
    | FileScannedEvent
    | FileEnrichedEvent
    | ScanCompleteEvent
    | AuditStatusEvent
    | HeartbeatEvent
    | SnapshotEvent,
    Field(discriminator="type"),
]
EVENT_ADAPTER: TypeAdapter[Event] = TypeAdapter(Event)


class HealthResponse(BaseModel):
    status: str
    yara_rules: int
    intel_providers_online: list[str]
    ws_clients: int
    demo_mode: bool


class SimulateResponse(BaseModel):
    scan_id: str
    drive: str


class ResetResponse(BaseModel):
    cleared_events: int


class EjectResponse(BaseModel):
    ejected: bool


class IntelLookupRequest(BaseModel):
    hash: str = Field(pattern=r"^[0-9a-fA-F]{64}$", description="SHA-256 (hash-only lookups)")


class IntelLookupResponse(BaseModel):
    sha256: str
    verdicts: list[IntelVerdict]
    malicious: bool
    known_good: bool


class RecentMalware(BaseModel):
    sha256: str
    file_name: str | None
    file_type: str | None
    signature: str | None
    first_seen: str | None


class AuditVerifyResult(BaseModel):
    valid: bool
    length: int
    broken_at: int | None


class TamperResponse(BaseModel):
    tampered_index: int


class UndoTamperResponse(BaseModel):
    restored: bool


class SignedReport(BaseModel):
    report: dict[str, Any]
    signature_b64: str
    algorithm: str
    public_key_pem: str
    certificate_pem: str


class VerifyRequest(BaseModel):
    report: dict[str, Any]
    signature_b64: str
    algorithm: str
    public_key_pem: str


class VerifyResult(BaseModel):
    valid: bool
    reason: str
    algorithm: str
    key_fingerprint_sha256: str | None
    matches_station_key: bool


class QuarantineEntry(BaseModel):
    id: str
    filename: str
    original_path: str
    size_bytes: int
    sha256: str
    tier: str
    scan_id: str
    drive: str
    simulated: bool
    quarantined_at: str
    original_deleted: bool


class CourseMapResponse(BaseModel):
    rows: list[CourseRow]


class RestoreResult(BaseModel):
    id: str
    restored_path: str
    sha256: str
    verified: bool


# Every model mirrored in telemetry.ts (used by the contract test).
CONTRACT_MODELS: list[type[BaseModel]] = [
    Stats, DriveState, UsbConnectedEvent, UsbDisconnectedEvent, ScanProgressEvent,
    FileScannedEvent, ScanCompleteEvent, AuditStatusEvent, HeartbeatEvent, SnapshotEvent,
    HealthResponse, SimulateResponse, ResetResponse, EjectResponse, IntelVerdict, FileEnrichedEvent,
    IntelLookupRequest, IntelLookupResponse, RecentMalware, AuditVerifyResult, TamperResponse,
    UndoTamperResponse, SignedReport, VerifyRequest, VerifyResult, QuarantineEntry,
    RestoreResult, CourseRow, CourseMapResponse,
]
