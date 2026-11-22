import { useEffect, useState } from "react";
import { eject, getHealth, resetStats, SIM_DRIVE, simulate, verifyAudit } from "../api";
import type { AuditVerifyResult, DriveState } from "../types/telemetry";
import { ChainChip } from "./AuditChainBadge";
import { formatBytes } from "../lib/tier";

interface Props {
  connected: boolean;
  drives: DriveState[];
  audit: AuditVerifyResult | null;
}

function DrivePill({ d }: { d: DriveState }) {
  const pct = d.files_discovered > 0 ? Math.min(100, (d.files_scanned / d.files_discovered) * 100) : 0;
  const done = !d.scanning;
  return (
    <div className="min-w-48 rounded-md border border-line bg-bg px-3 py-1.5" title={d.label}>
      <div className="flex items-center justify-between gap-3 font-mono text-xs">
        <span className="text-slate-200">
          {d.drive} {d.simulated && <span className="text-slate-500">(sim)</span>}
        </span>
        <span className={done ? "text-safe" : "text-live"}>
          {done ? "scanned" : `${d.files_scanned}/${d.files_discovered}`}
        </span>
      </div>
      <div className="mt-1 h-1 overflow-hidden rounded bg-line" role="progressbar"
        aria-valuenow={Math.round(done ? 100 : pct)} aria-valuemin={0} aria-valuemax={100}>
        <div className={`h-full transition-[width] duration-200 ${done ? "bg-safe" : "bg-live"}`}
          style={{ width: `${done ? 100 : pct}%` }} />
      </div>
      {d.total_bytes > 0 && (
        <div className="mt-0.5 text-[10px] text-slate-500">{formatBytes(d.total_bytes)}</div>
      )}
    </div>
  );
}

export default function HeaderStatus({ connected, drives, audit }: Props) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [demoMode, setDemoMode] = useState(false);
  const simDrive = drives.find((d) => d.drive === SIM_DRIVE);
  const scanning = simDrive?.scanning ?? false;

  // Demo-only controls appear only when the backend runs with AEGIS_DEMO_MODE.
  useEffect(() => {
    if (!connected) return;
    getHealth().then((h) => setDemoMode(h.demo_mode)).catch(() => setDemoMode(false));
  }, [connected]);

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <header className="border-b border-line bg-card">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-3 px-4 py-3">
        <div className="flex items-center gap-3">
          <span className="text-lg font-semibold tracking-wide text-slate-100">AEGIS&nbsp;USB</span>
          <span className="flex items-center gap-2 font-mono text-xs" role="status">
            <span className={`h-2.5 w-2.5 rounded-full ${connected ? "animate-pulse bg-live" : "bg-critical"}`} />
            <span className={connected ? "text-live" : "text-critical"}>
              {connected ? "LIVE" : "OFFLINE — reconnecting"}
            </span>
          </span>
        </div>

        <div className="flex flex-1 flex-wrap items-center gap-2">
          {drives.length === 0 ? (
            <span className="text-sm text-slate-500">No USB drive connected</span>
          ) : (
            drives.map((d) => <DrivePill key={d.drive} d={d} />)
          )}
        </div>

        <div className="flex items-center gap-3">
          <ChainChip audit={audit} />
          {error && <span className="max-w-64 text-xs text-critical" role="alert">{error}</span>}
          <button type="button" disabled={busy || scanning || !connected}
            onClick={() => run(simulate)}
            className="rounded-md border border-live/50 bg-live/10 px-3 py-1.5 text-sm text-live hover:bg-live/20 disabled:cursor-not-allowed disabled:opacity-40">
            Simulate USB
          </button>
          <button type="button" disabled={busy || !simDrive || !connected}
            onClick={() => run(eject)}
            className="rounded-md border border-line px-3 py-1.5 text-sm text-slate-300 hover:bg-line/60 disabled:cursor-not-allowed disabled:opacity-40">
            Eject
          </button>
          {demoMode && (
            <button type="button" disabled={busy || scanning || !connected}
              title="Demo only: clears counters, history and the risk matrix (the audit chain is kept)"
              onClick={() => run(async () => { await resetStats(); await verifyAudit(); })}
              className="rounded-md border border-line px-3 py-1.5 text-sm text-slate-300 hover:bg-line/60 disabled:cursor-not-allowed disabled:opacity-40">
              Reset stats
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
