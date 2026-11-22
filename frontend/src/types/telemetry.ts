// Mirrors backend/app/api/schemas.py field-for-field (checked by qa_demo/test_api.py).

export type Tier = "SAFE" | "SUSPICIOUS" | "CRITICAL";

export interface Stats {
  total: number;
  safe: number;
  suspicious: number;
  critical: number;
  scans_completed: number;
}

export interface DriveState {
  drive: string;
  label: string;
  fs_type: string;
  total_bytes: number;
  simulated: boolean;
  scan_id: string;
  scanning: boolean;
  files_discovered: number;
  files_scanned: number;
  files_skipped: number;
}

export interface UsbConnectedEvent {
  event_id: string;
  timestamp: string;
  type: "USB_CONNECTED";
  scan_id: string;
  drive: string;
  label: string;
  fs_type: string;
  total_bytes: number;
  simulated: boolean;
}

export interface UsbDisconnectedEvent {
  event_id: string;
  timestamp: string;
  type: "USB_DISCONNECTED";
  drive: string;
}

export interface ScanProgressEvent {
  event_id: string;
  timestamp: string;
  type: "SCAN_PROGRESS";
  scan_id: string;
  drive: string;
  files_discovered: number;
  files_scanned: number;
  files_skipped: number;
}

export interface FileScannedEvent {
  event_id: string;
  timestamp: string;
  type: "FILE_SCANNED";
  scan_id: string;
  drive: string;
  file: string;
  filename: string;
  size_bytes: number;
  sha256: string | null;
  md5_legacy: string | null;
  sha1_legacy: string | null;
  entropy: number;
  chi_square: number;
  entropy_exempt: boolean;
  magic_type: string;
  magic_hex: string;
  extension_mismatch: boolean;
  double_extension: boolean;
  rtlo: boolean;
  xor_key: number | null;
  yara_matches: string[];
  authenticode: string;
  likelihood: number;
  impact: number;
  risk_score: number;
  tier: Tier;
  mitre: string[];
  reasons: string[];
  scan_status: "COMPLETE" | "PARTIAL";
  chain_index: number | null;
  chain_hash: string | null;
}

export type IntelStatus =
  | "malicious"
  | "suspicious"
  | "clean"
  | "known_good"
  | "not_found"
  | "error"
  | "skipped";

export interface IntelVerdict {
  provider: string;
  status: IntelStatus;
  summary: string;
  link: string | null;
  detections: number | null;
  engines: number | null;
  cached: boolean;
}

export interface FileEnrichedEvent {
  event_id: string;
  timestamp: string;
  type: "FILE_ENRICHED";
  scan_id: string;
  drive: string;
  file_event_id: string;
  sha256: string;
  verdicts: IntelVerdict[];
  known_good: boolean;
  previous_tier: Tier;
  tier: Tier;
  likelihood: number;
  impact: number;
  risk_score: number;
  reasons: string[];
  mitre: string[];
}

export interface ScanCompleteEvent {
  event_id: string;
  timestamp: string;
  type: "SCAN_COMPLETE";
  scan_id: string;
  drive: string;
  total: number;
  safe: number;
  suspicious: number;
  critical: number;
  duration_s: number;
  cancelled: boolean;
}

export interface AuditStatusEvent {
  event_id: string;
  timestamp: string;
  type: "AUDIT_STATUS";
  valid: boolean;
  length: number;
  broken_at: number | null;
}

export interface HeartbeatEvent {
  event_id: string;
  timestamp: string;
  type: "HEARTBEAT";
  clients: number;
}

export interface SnapshotEvent {
  event_id: string;
  timestamp: string;
  type: "SNAPSHOT";
  events: Record<string, unknown>[];
  stats: Stats;
  drives: DriveState[];
}

export type TelemetryEvent =
  | UsbConnectedEvent
  | UsbDisconnectedEvent
  | ScanProgressEvent
  | FileScannedEvent
  | FileEnrichedEvent
  | ScanCompleteEvent
  | AuditStatusEvent
  | HeartbeatEvent
  | SnapshotEvent;

export interface HealthResponse {
  status: string;
  yara_rules: number;
  intel_providers_online: string[];
  ws_clients: number;
  demo_mode: boolean;
}

export interface SimulateResponse {
  scan_id: string;
  drive: string;
}

export interface ResetResponse {
  cleared_events: number;
}

export interface EjectResponse {
  ejected: boolean;
}

export interface IntelLookupRequest {
  hash: string;
}

export interface IntelLookupResponse {
  sha256: string;
  verdicts: IntelVerdict[];
  malicious: boolean;
  known_good: boolean;
}

export interface RecentMalware {
  sha256: string;
  file_name: string | null;
  file_type: string | null;
  signature: string | null;
  first_seen: string | null;
}

export interface AuditVerifyResult {
  valid: boolean;
  length: number;
  broken_at: number | null;
}

export interface TamperResponse {
  tampered_index: number;
}

export interface UndoTamperResponse {
  restored: boolean;
}

/** Tier counts in a signed report. */
export interface ReportTierCounts {
  safe: number;
  suspicious: number;
  critical: number;
}

/**
 * One file in a signed report. `tier`, scores, `mitre` and `reasons` are the exact audit-chain
 * record (scan time); the `final_*` fields are the result after threat intel (AD-5, AD-7).
 */
export interface ReportFile {
  filename: string;
  file?: string;
  sha256: string | null;
  size_bytes: number;
  tier: Tier;
  likelihood: number;
  impact: number;
  risk_score: number;
  final_tier: Tier;
  final_risk_score: number;
  final_reasons: string[];
  final_mitre: string[];
  chain_index: number;
  chain_hash: string;
}

/** Shape of `SignedReport.report` as built by the backend (`schema: aegis-usb-report/1`). */
export interface ReportBody {
  scan_id: string;
  summary: { total: number } & ReportTierCounts & { final: ReportTierCounts };
  files: ReportFile[];
}

export interface SignedReport {
  report: Record<string, unknown>;
  signature_b64: string;
  algorithm: string;
  public_key_pem: string;
  certificate_pem: string;
}

export interface VerifyRequest {
  report: Record<string, unknown>;
  signature_b64: string;
  algorithm: string;
  public_key_pem: string;
}

export interface VerifyResult {
  valid: boolean;
  reason: string;
  algorithm: string;
  key_fingerprint_sha256: string | null;
  matches_station_key: boolean;
}

export interface QuarantineEntry {
  id: string;
  filename: string;
  original_path: string;
  size_bytes: number;
  sha256: string;
  tier: string;
  scan_id: string;
  drive: string;
  simulated: boolean;
  quarantined_at: string;
  original_deleted: boolean;
}

export interface RestoreResult {
  id: string;
  restored_path: string;
  sha256: string;
  verified: boolean;
}

export type SigAlgorithm = "rsa-pss" | "dsa" | "ed25519";

export interface CourseRow {
  week: string;
  topic: string;
  feature: string;
  files: string[];
  cia: string;
  status: "implemented" | "partial" | "not_built";
  note: string | null;
}

export interface CourseMapResponse {
  rows: CourseRow[];
}
