import { useState } from "react";
import { tamper, undoTamper, verifyAudit } from "../api";
import type { AuditVerifyResult } from "../types/telemetry";

export function ChainChip({ audit }: { audit: AuditVerifyResult | null }) {
  if (!audit) return <span className="font-mono text-xs text-slate-500">chain: checking…</span>;
  return audit.valid ? (
    <span className="font-mono text-xs text-safe" title={`${audit.length} records, all hashes and HMACs verified`}>
      Chain verified ✓
    </span>
  ) : (
    <span className="animate-pulse font-mono text-xs font-semibold text-critical" role="alert">
      Chain BROKEN at #{audit.broken_at}
    </span>
  );
}

export default function AuditChainBadge({ audit }: { audit: AuditVerifyResult | null }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn(); // the server pushes AUDIT_STATUS to every client, so the badge updates itself
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setBusy(false);
    }
  };

  const broken = audit !== null && !audit.valid;
  return (
    <section className={`rounded-lg border p-4 ${broken ? "border-critical/60 bg-critical/5" : "border-line bg-card"}`}>
      <h2 className="text-sm font-medium text-slate-200">Tamper-evident audit log</h2>
      <p className="mt-1 text-xs text-slate-400">
        Every scan result is chained: hash = SHA-256(previous hash ‖ record), plus an HMAC. Editing
        any stored record breaks every later link.
      </p>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <span className={`text-lg font-semibold ${broken ? "text-critical" : audit ? "text-safe" : "text-slate-500"}`}>
          {!audit ? "Checking…" : audit.valid ? "Chain verified ✓" : `BROKEN at #${audit.broken_at}`}
        </span>
        {audit && <span className="font-mono text-xs text-slate-500">{audit.length} records</span>}
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <button type="button" disabled={busy} onClick={() => run(verifyAudit)}
          className="rounded border border-live/50 bg-live/10 px-3 py-1.5 text-sm text-live hover:bg-live/20 disabled:opacity-40">
          Verify now
        </button>
        <button type="button" disabled={busy} onClick={() => run(tamper)}
          className="rounded border border-critical/50 px-3 py-1.5 text-sm text-critical hover:bg-critical/10 disabled:opacity-40">
          Demo: tamper with a record
        </button>
        <button type="button" disabled={busy || !broken} onClick={() => run(undoTamper)}
          className="rounded border border-line px-3 py-1.5 text-sm text-slate-300 hover:bg-line/60 disabled:opacity-40">
          Undo tampering
        </button>
      </div>
      {error && <p className="mt-2 text-xs text-critical" role="alert">{error}</p>}
    </section>
  );
}
