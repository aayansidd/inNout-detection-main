import { useMemo, useState } from "react";
import { verifyReport } from "../api";
import type { Row } from "../hooks/useAegisSocket";
import type { SignedReport, VerifyResult } from "../types/telemetry";
import { clock } from "../lib/tier";
import SignReport from "./SignReport";

interface ScanItem {
  id: string;
  drive: string;
  count: number;
  at: string;
}

export default function ReportPanel({ files }: { files: Row[] }) {
  const scans = useMemo(() => {
    const map = new Map<string, ScanItem>();
    for (const f of files) {
      const s = map.get(f.scan_id);
      if (s) s.count += 1;
      else map.set(f.scan_id, { id: f.scan_id, drive: f.drive, count: 1, at: f.timestamp });
    }
    return [...map.values()].reverse(); // newest first
  }, [files]);
  const [picked, setPicked] = useState<string | null>(null);
  const [fileResult, setFileResult] = useState<{ name: string; result: VerifyResult } | { error: string } | null>(null);
  const scanId = picked && scans.some((s) => s.id === picked) ? picked : (scans[0]?.id ?? null);

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text()) as SignedReport;
      setFileResult({ name: file.name, result: await verifyReport(parsed) });
    } catch (e) {
      setFileResult({ error: e instanceof Error ? e.message : "Not a valid signed report" });
    }
  };

  return (
    <section className="rounded-lg border border-line bg-card p-4">
      <h2 className="text-sm font-medium text-slate-200">Signed scan reports</h2>
      <p className="mt-1 text-xs text-slate-400">
        The report is canonical JSON signed with the station key. Any change to it, even one
        digit, makes verification fail.
      </p>
      <label className="mt-3 block text-xs text-slate-400">
        Scan session
        <select value={scanId ?? ""} onChange={(e) => setPicked(e.target.value)} disabled={scans.length === 0}
          className="mt-1 block w-full rounded border border-line bg-bg px-2 py-1.5 text-sm text-slate-200">
          {scans.length === 0 && <option value="">No scans yet</option>}
          {scans.map((s) => (
            <option key={s.id} value={s.id}>{s.drive} · {s.count} files · {clock(s.at)} · {s.id.slice(0, 8)}</option>
          ))}
        </select>
      </label>
      <div className="mt-3"><SignReport key={scanId ?? "none"} scanId={scanId} /></div>

      <div className="mt-4 border-t border-line pt-3">
        <label className="text-xs text-slate-400">
          Verify a signed report file
          <input type="file" accept="application/json,.json" onChange={(e) => onFile(e.target.files?.[0])}
            className="mt-1 block text-xs text-slate-300 file:mr-3 file:rounded file:border file:border-line file:bg-bg file:px-2 file:py-1 file:text-slate-200" />
        </label>
        {fileResult && (
          <p className="mt-2 text-xs" role="status">
            {"error" in fileResult ? (
              <span className="text-critical">{fileResult.error}</span>
            ) : fileResult.result.valid ? (
              <span className="text-safe">{fileResult.name}: valid ✓ {fileResult.result.matches_station_key ? "(this station's key)" : "(different key)"}</span>
            ) : (
              <span className="text-critical">{fileResult.name}: INVALID — {fileResult.result.reason}</span>
            )}
          </p>
        )}
      </div>
    </section>
  );
}
