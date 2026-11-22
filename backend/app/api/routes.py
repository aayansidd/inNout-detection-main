"""REST endpoints (§7.3)."""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, WebSocket
from fastapi.responses import PlainTextResponse

from ..config import get_settings
from ..core.usb_monitor import DriveInfo
from ..core.vault import Vault, VaultError
from ..course_map import ROWS, read_public_file
from ..crypto.keystore import ALGORITHMS, STATION_NAME
from ..crypto.signer import sign_report, verify_report
from ..engine import yara_scanner
from .schemas import (
    AuditStatusEvent,
    AuditVerifyResult,
    CourseMapResponse,
    EjectResponse,
    HealthResponse,
    IntelLookupRequest,
    IntelLookupResponse,
    QuarantineEntry,
    RecentMalware,
    ResetResponse,
    RestoreResult,
    SignedReport,
    SimulateResponse,
    Stats,
    TamperResponse,
    UndoTamperResponse,
    VerifyRequest,
    VerifyResult,
)
from .ws_manager import serve_client

router = APIRouter()
SIM_DRIVE = "Z:\\"
_EVENT_ID = re.compile(r"^[0-9a-f]{32}$")


def _require_demo() -> None:
    if not get_settings().demo_mode:
        raise HTTPException(403, "Demo endpoints are disabled (AEGIS_DEMO_MODE=false)")


def _check_event_id(event_id: str) -> str:
    if not _EVENT_ID.match(event_id):
        raise HTTPException(422, "invalid id")
    return event_id


@router.get("/api/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    """Liveness plus YARA rule count, intel providers in use and WS client count."""
    state = request.app.state
    return HealthResponse(
        status="ok",
        yara_rules=yara_scanner.rule_count(),
        intel_providers_online=state.intel.enabled_names(),
        ws_clients=state.hub.client_count,
        demo_mode=get_settings().demo_mode,
    )


@router.get("/api/stats", response_model=Stats)
async def stats(request: Request) -> Stats:
    """Cumulative tier counters for this server session."""
    return request.app.state.hub.stats


@router.get("/api/history")
async def history(request: Request, limit: int = Query(500, ge=1, le=500)) -> list[dict]:
    """Most recent events (oldest first), same data as the WebSocket SNAPSHOT."""
    return list(request.app.state.hub.history)[-limit:]


# ---- demo -----------------------------------------------------------------------------------
@router.post("/api/demo/simulate", response_model=SimulateResponse)
async def simulate(request: Request) -> SimulateResponse:
    """Scan the demo folder as virtual drive Z:\\ (no real USB needed)."""
    _require_demo()
    root = get_settings().demo_drive_path
    if not root.is_dir():
        raise HTTPException(409, "Demo drive missing. Run: python qa_demo/generate_payloads.py")
    monitor = request.app.state.monitor
    existing = monitor.job(SIM_DRIVE)
    if existing is not None:
        if existing.is_alive():
            raise HTTPException(409, "Simulated drive is already being scanned")
        monitor.eject(SIM_DRIVE)
    info = DriveInfo(SIM_DRIVE, "AEGIS_DEMO", "simulated", 0, simulated=True)
    job = monitor.start_scan(str(root), info)
    return SimulateResponse(scan_id=job.scan_id, drive=SIM_DRIVE)


@router.post("/api/demo/reset", response_model=ResetResponse)
async def reset_stats(request: Request) -> ResetResponse:
    """DEMO ONLY: clear counters, history and the risk matrix on every dashboard.

    The audit chain, vault and intel cache are untouched. Refused while a scan is running.
    """
    _require_demo()
    hub = request.app.state.hub
    if hub.scanning():
        raise HTTPException(409, "A scan is running: wait for it to finish or eject first")
    cleared = len(hub.history)
    hub.reset()
    return ResetResponse(cleared_events=cleared)


@router.post("/api/demo/eject", response_model=EjectResponse)
async def eject(request: Request, drive: str = SIM_DRIVE) -> EjectResponse:
    """Remove the simulated drive, cancelling any scan in progress."""
    _require_demo()
    return EjectResponse(ejected=request.app.state.monitor.eject(drive))


# ---- audit chain ----------------------------------------------------------------------------
def _publish_audit(request: Request, result: AuditVerifyResult) -> None:
    request.app.state.hub.publish(
        AuditStatusEvent(valid=result.valid, length=result.length, broken_at=result.broken_at)
    )


@router.get("/api/audit/verify", response_model=AuditVerifyResult)
async def audit_verify(request: Request) -> AuditVerifyResult:
    """Recompute the whole hash chain + HMACs; also pushes AUDIT_STATUS to every client."""
    outcome = await asyncio.to_thread(request.app.state.audit.verify)
    result = AuditVerifyResult(
        valid=outcome.valid, length=outcome.length, broken_at=outcome.broken_at
    )
    _publish_audit(request, result)
    return result


@router.post("/api/demo/tamper", response_model=TamperResponse)
async def tamper(request: Request) -> TamperResponse:
    """DEMO ONLY: silently edit one stored audit record, then re-verify so the badge flips."""
    _require_demo()
    audit = request.app.state.audit
    idx = await asyncio.to_thread(audit.tamper)
    if idx is None:
        raise HTTPException(409, "Nothing to tamper with yet: run a scan first")
    await audit_verify(request)
    return TamperResponse(tampered_index=idx)


@router.post("/api/demo/tamper/undo", response_model=UndoTamperResponse)
async def undo_tamper(request: Request) -> UndoTamperResponse:
    """DEMO ONLY: put the edited record back so the chain verifies again."""
    _require_demo()
    restored = await asyncio.to_thread(request.app.state.audit.undo_tamper)
    await audit_verify(request)
    return UndoTamperResponse(restored=restored)


# ---- intel ----------------------------------------------------------------------------------
@router.post("/api/intel/lookup", response_model=IntelLookupResponse)
async def intel_lookup(request: Request, body: IntelLookupRequest) -> IntelLookupResponse:
    """Manual hash lookup against every enabled provider (hash only leaves this machine)."""
    sha = body.hash.lower()
    verdicts = await request.app.state.intel.lookup(sha)
    return IntelLookupResponse(
        sha256=sha, verdicts=verdicts,
        malicious=any(v.status == "malicious" for v in verdicts),
        known_good=any(v.status == "known_good" for v in verdicts),
    )


@router.get("/api/intel/recent", response_model=list[RecentMalware])
async def intel_recent(
    request: Request, limit: int = Query(25, ge=1, le=200)
) -> list[dict[str, Any]]:
    """Latest MalwareBazaar samples cached locally (refreshed every 10 minutes)."""
    return await request.app.state.intel.recent(limit)


# ---- signed reports -------------------------------------------------------------------------
def _build_report(request: Request, scan_id: str) -> dict[str, Any] | None:
    audit = request.app.state.audit
    events = audit.events_for_scan(scan_id)
    if not events:
        return None
    enriched = audit.enrichments_for_scan(scan_id)
    redact = get_settings().redact_filenames
    files: list[dict[str, Any]] = []
    for e in events:
        extra = enriched.get(e["event_id"], {})
        name = e["filename"]
        if redact:  # privacy mode: keep the extension and hash, drop the name and path
            ext = name.rsplit(".", 1)[1] if "." in name else ""
            name = f"redacted-{(e['sha256'] or 'nohash')[:8]}" + (f".{ext}" if ext else "")
        files.append({
            "filename": name,
            **({} if redact else {"file": e["file"]}),
            # Exactly the chained record: tier, scores and reasons equal what the audit chain
            # attests for this scan (AD-5). Later intel is reported separately below.
            "sha256": e["sha256"], "size_bytes": e["size_bytes"], "tier": e["tier"],
            "likelihood": e["likelihood"], "impact": e["impact"], "risk_score": e["risk_score"],
            "entropy": e["entropy"], "magic_type": e["magic_type"],
            "yara_matches": e["yara_matches"], "authenticode": e["authenticode"],
            "mitre": e["mitre"], "reasons": e["reasons"],
            "final_tier": extra.get("tier", e["tier"]),
            "final_risk_score": extra.get("risk_score", e["risk_score"]),
            "final_reasons": extra.get("reasons", e["reasons"]),
            "final_mitre": extra.get("mitre", e["mitre"]),
            "intel": [
                {"provider": v["provider"], "status": v["status"], "summary": v["summary"]}
                for v in extra.get("verdicts", [])
            ],
            "chain_index": e["chain_index"], "chain_hash": e["chain_hash"],
        })
    tiers = ("safe", "suspicious", "critical")
    counts = {t: sum(1 for f in files if f["tier"] == t.upper()) for t in tiers}
    final_counts = {t: sum(1 for f in files if f["final_tier"] == t.upper()) for t in tiers}
    return {
        "schema": "aegis-usb-report/1",
        "scan_id": scan_id,
        "drive": events[0]["drive"],
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "station": STATION_NAME,
        "summary": {"total": len(files), **counts, "final": final_counts},
        "audit_range": {
            "first_index": events[0]["chain_index"], "last_index": events[-1]["chain_index"],
            "last_chain_hash": events[-1]["chain_hash"],
        },
        "files": files,
    }


@router.post("/api/reports/{scan_id}/sign", response_model=SignedReport)
async def sign(request: Request, scan_id: str, alg: str = Query("rsa-pss")) -> SignedReport:
    """Sign a scan session report (canonical JSON) with RSA-PSS, DSA or Ed25519."""
    if alg not in ALGORITHMS:
        raise HTTPException(422, f"alg must be one of {', '.join(ALGORITHMS)}")
    report = await asyncio.to_thread(_build_report, request, scan_id)
    if report is None:
        raise HTTPException(404, "No scan with that id")
    signed = await asyncio.to_thread(sign_report, report, alg, request.app.state.keystore)
    return SignedReport(**signed)


@router.post("/api/reports/verify", response_model=VerifyResult)
async def verify(request: Request, body: VerifyRequest) -> VerifyResult:
    """Verify a signed report against the public key supplied with it."""
    ok, reason = verify_report(body.report, body.signature_b64, body.algorithm, body.public_key_pem)
    fingerprint: str | None = None
    matches = False
    if body.algorithm in ALGORITHMS:
        try:
            from cryptography.hazmat.primitives import serialization

            from ..crypto.keystore import public_key_fingerprint

            fingerprint = public_key_fingerprint(
                serialization.load_pem_public_key(body.public_key_pem.encode())
            )
            station = request.app.state.keystore.get(body.algorithm)
            matches = fingerprint == station.fingerprint_sha256
        except (ValueError, TypeError):
            fingerprint = None
    return VerifyResult(
        valid=ok, reason=reason, algorithm=body.algorithm,
        key_fingerprint_sha256=fingerprint, matches_station_key=matches,
    )


# ---- quarantine -----------------------------------------------------------------------------
def _vault(request: Request) -> Vault:
    vault: Vault = request.app.state.vault
    if not vault.configured:
        raise HTTPException(503, "Vault passphrase not set: define AEGIS_VAULT_PASSPHRASE in .env")
    return vault


def _entry(raw: dict[str, Any]) -> QuarantineEntry:
    return QuarantineEntry(**{k: raw[k] for k in QuarantineEntry.model_fields})


@router.post("/api/quarantine/{event_id}", response_model=QuarantineEntry)
async def quarantine(request: Request, event_id: str) -> QuarantineEntry:
    """Copy the flagged file into the AES-256-GCM vault. The original is NOT deleted."""
    _check_event_id(event_id)
    vault = _vault(request)
    event = await asyncio.to_thread(request.app.state.audit.get_event, event_id)
    if event is None:
        raise HTTPException(404, "Unknown file event")
    if not event["sha256"]:
        raise HTTPException(409, "File was only partially scanned (no hash): cannot quarantine")
    drive = request.app.state.hub.drives.get(event["drive"])
    meta = {
        "filename": event["filename"], "original_path": event["file"], "sha256": event["sha256"],
        "tier": event["tier"], "scan_id": event["scan_id"], "drive": event["drive"],
        "simulated": bool(drive.simulated) if drive else event["drive"] == SIM_DRIVE,
    }
    try:
        entry = await asyncio.to_thread(vault.quarantine, Path(event["file"]), event_id, meta)
    except VaultError as exc:
        raise HTTPException(409, str(exc)) from exc
    return _entry(entry)


@router.get("/api/quarantine", response_model=list[QuarantineEntry])
async def quarantine_list(request: Request) -> list[QuarantineEntry]:
    """Everything currently in the vault (metadata only)."""
    return [_entry(e) for e in await asyncio.to_thread(_vault(request).list)]


@router.post("/api/quarantine/{entry_id}/restore", response_model=RestoreResult)
async def quarantine_restore(request: Request, entry_id: str) -> RestoreResult:
    """Decrypt into data/restored/ and re-check the SHA-256 (integrity + confidentiality)."""
    _check_event_id(entry_id)
    vault = _vault(request)
    try:
        result = await asyncio.to_thread(
            vault.restore, entry_id, get_settings().data_dir / "restored"
        )
    except VaultError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RestoreResult(**result)


@router.post("/api/quarantine/{entry_id}/delete-original", response_model=QuarantineEntry)
async def quarantine_delete_original(request: Request, entry_id: str) -> QuarantineEntry:
    """Delete the original file from the drive. Explicit action; refused for the demo drive."""
    _check_event_id(entry_id)
    vault = _vault(request)
    try:
        entry = vault.get(entry_id)
    except VaultError as exc:
        raise HTTPException(404, str(exc)) from exc
    if entry["simulated"]:
        raise HTTPException(403, "The simulated demo drive is protected: nothing is deleted")
    original = Path(entry["original_path"])
    try:
        import hashlib

        if hashlib.sha256(original.read_bytes()).hexdigest() != entry["sha256"]:
            raise HTTPException(409, "File on the drive changed since quarantine: not deleting")
        original.unlink()
    except FileNotFoundError:
        pass  # already gone: just record it
    except OSError as exc:
        raise HTTPException(500, f"Could not delete the original ({type(exc).__name__})") from exc
    return _entry(vault.update(entry_id, original_deleted=True))


# ---- about tab ------------------------------------------------------------------------------
@router.get("/api/course-map", response_model=CourseMapResponse)
async def course_map() -> CourseMapResponse:
    """Course week -> feature table shown in the About tab."""
    return CourseMapResponse(rows=ROWS)


@router.get("/api/files/{path:path}", response_class=PlainTextResponse)
async def public_file(path: str) -> PlainTextResponse:
    """Read-only text of a file linked from the About tab. Strict allowlist, nothing else."""
    text = read_public_file(path)
    if text is None:
        raise HTTPException(404, "Not available")
    return PlainTextResponse(text, headers={"X-Content-Type-Options": "nosniff"})


@router.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    """Live telemetry: SNAPSHOT first, then events."""
    origin = ws.headers.get("origin")
    if origin and origin not in get_settings().allowed_origins:
        await ws.close(code=1008)  # policy violation: cross-site WebSocket hijacking attempt
        return
    await serve_client(ws, ws.app.state.hub)
