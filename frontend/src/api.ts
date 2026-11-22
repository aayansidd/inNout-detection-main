import type {
  AuditVerifyResult,
  CourseMapResponse,
  EjectResponse,
  HealthResponse,
  IntelLookupResponse,
  QuarantineEntry,
  RecentMalware,
  ResetResponse,
  RestoreResult,
  SigAlgorithm,
  SignedReport,
  SimulateResponse,
  TamperResponse,
  UndoTamperResponse,
  VerifyResult,
} from "./types/telemetry";

async function request<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const data = (await res.json()) as { detail?: unknown };
      if (typeof data.detail === "string") detail = data.detail;
      else if (Array.isArray(data.detail)) detail = "Invalid input";
    } catch {
      /* non-JSON error body: keep the status text */
    }
    throw new Error(detail);
  }
  return (await res.json()) as T;
}

export const SIM_DRIVE = "Z:\\";

export const simulate = () => request<SimulateResponse>("POST", "/api/demo/simulate");
export const eject = () =>
  request<EjectResponse>("POST", `/api/demo/eject?drive=${encodeURIComponent(SIM_DRIVE)}`);
export const resetStats = () => request<ResetResponse>("POST", "/api/demo/reset");
export const getHealth = () => request<HealthResponse>("GET", "/api/health");

export const lookupHash = (hash: string) =>
  request<IntelLookupResponse>("POST", "/api/intel/lookup", { hash });
export const recentMalware = () => request<RecentMalware[]>("GET", "/api/intel/recent?limit=15");

export const verifyAudit = () => request<AuditVerifyResult>("GET", "/api/audit/verify");
export const tamper = () => request<TamperResponse>("POST", "/api/demo/tamper");
export const undoTamper = () => request<UndoTamperResponse>("POST", "/api/demo/tamper/undo");

export const signReport = (scanId: string, alg: SigAlgorithm) =>
  request<SignedReport>("POST", `/api/reports/${encodeURIComponent(scanId)}/sign?alg=${alg}`);
export const verifyReport = (signed: SignedReport) =>
  request<VerifyResult>("POST", "/api/reports/verify", {
    report: signed.report,
    signature_b64: signed.signature_b64,
    algorithm: signed.algorithm,
    public_key_pem: signed.public_key_pem,
  });

export const quarantine = (eventId: string) =>
  request<QuarantineEntry>("POST", `/api/quarantine/${eventId}`);
export const quarantineList = () => request<QuarantineEntry[]>("GET", "/api/quarantine");
export const restoreQuarantined = (id: string) =>
  request<RestoreResult>("POST", `/api/quarantine/${id}/restore`);
export const deleteOriginal = (id: string) =>
  request<QuarantineEntry>("POST", `/api/quarantine/${id}/delete-original`);

export const getCourseMap = () => request<CourseMapResponse>("GET", "/api/course-map");
/** Same-origin, read-only text of an allow-listed repo file (works offline). */
export const fileUrl = (path: string) => `/api/files/${path.split("/").map(encodeURIComponent).join("/")}`;
