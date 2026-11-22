import { useState } from "react";
import { signReport, verifyReport } from "../api";
import { downloadJson } from "../lib/download";
import { TIER_BADGE } from "../lib/tier";
import type { ReportBody, SigAlgorithm, SignedReport, Tier, VerifyResult } from "../types/telemetry";

function TierBadge({ tier }: { tier: Tier }) {
  return <span className={`rounded border px-1.5 py-0.5 text-[10px] ${TIER_BADGE[tier]}`}>{tier}</span>;
}

/** Scan-time tier (what the audit chain attests) next to the tier after threat intel. */
function ReportSummary({ report }: { report: ReportBody }) {
  const { summary, files } = report;
  const changed = files.filter((f) => f.final_tier !== f.tier);
  return (
    <div className="space-y-1.5 text-xs">
      <div className="text-slate-400">
        {summary.total} files · scan time (chained): {summary.safe} safe / {summary.suspicious} suspicious / {summary.critical} critical
      </div>
      <div className="text-slate-400">
        After threat intel: {summary.final.safe} safe / {summary.final.suspicious} suspicious / {summary.final.critical} critical
      </div>
      {changed.length > 0 ? (
        <ul className="space-y-1" aria-label="Files whose tier changed after threat intel">
          {changed.map((f) => (
            <li key={f.chain_index} className="flex flex-wrap items-center gap-1.5">
              <span className="min-w-0 break-all font-mono text-slate-300">{f.filename}</span>
              <TierBadge tier={f.tier} /><span aria-hidden="true">→</span><TierBadge tier={f.final_tier} />
            </li>
          ))}
        </ul>
      ) : (
        <div className="text-slate-500">Threat intel changed no tiers in this scan.</div>
      )}
      <p className="text-[11px] text-slate-500">
        Each file&apos;s <code className="font-mono">tier</code> equals its audit-chain record;
        <code className="font-mono"> final_tier</code> adds the intel result.
      </p>
    </div>
  );
}

const ALGS: { id: SigAlgorithm; label: string; note: string }[] = [
  { id: "rsa-pss", label: "RSA-PSS 3072 (default)", note: "Probabilistic padding, SHA-256." },
  { id: "ed25519", label: "Ed25519", note: "Modern, small, fast, deterministic." },
  { id: "dsa", label: "DSA 3072 (comparison only)", note: "FIPS 186-5 no longer approves DSA for new signatures." },
];

/** Sign one scan session, verify it straight away, and offer the JSON for offline checking. */
export default function SignReport({ scanId }: { scanId: string | null }) {
  const [alg, setAlg] = useState<SigAlgorithm>("rsa-pss");
  const [signed, setSigned] = useState<SignedReport | null>(null);
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [tampered, setTampered] = useState<VerifyResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async (fn: () => Promise<void>) => {
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

  const sign = () =>
    run(async () => {
      if (!scanId) throw new Error("Pick a scan first");
      setTampered(null);
      const s = await signReport(scanId, alg);
      setSigned(s);
      setResult(await verifyReport(s));
    });

  // Demo: change one number in the report and show that verification now fails.
  const flip = () =>
    run(async () => {
      if (!signed) return;
      const copy = structuredClone(signed);
      const summary = copy.report.summary as { total: number };
      summary.total += 1;
      setTampered(await verifyReport(copy));
    });

  const info = ALGS.find((a) => a.id === alg);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-xs text-slate-400">
          Algorithm
          <select value={alg} onChange={(e) => setAlg(e.target.value as SigAlgorithm)}
            className="mt-1 block rounded border border-line bg-bg px-2 py-1.5 text-sm text-slate-200">
            {ALGS.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
          </select>
        </label>
        <button type="button" disabled={busy || !scanId} onClick={sign}
          className="rounded border border-live/50 bg-live/10 px-3 py-1.5 text-sm text-live hover:bg-live/20 disabled:opacity-40">
          Sign report
        </button>
      </div>
      <p className="text-[11px] text-slate-500">{info?.note}</p>
      {error && <p className="text-xs text-critical" role="alert">{error}</p>}

      {signed && result && (
        <div className="space-y-2 rounded border border-line bg-bg p-3 text-sm">
          <div className={result.valid ? "text-safe" : "text-critical"}>
            {result.valid ? "Signature valid ✓" : `Invalid: ${result.reason}`}
            {result.valid && (
              <span className="ml-2 text-xs text-slate-400">
                {result.matches_station_key ? "key matches this station" : "key is NOT this station's key"}
              </span>
            )}
          </div>
          <dl className="grid grid-cols-[6rem_1fr] gap-x-2 gap-y-1 text-xs">
            <dt className="text-slate-500">Algorithm</dt><dd className="font-mono">{signed.algorithm}</dd>
            <dt className="text-slate-500">Key SHA-256</dt>
            <dd className="break-all font-mono">{result.key_fingerprint_sha256 ?? "n/a"}</dd>
            <dt className="text-slate-500">Signature</dt>
            <dd className="break-all font-mono text-slate-400">{signed.signature_b64.slice(0, 48)}…</dd>
          </dl>
          <ReportSummary report={signed.report as unknown as ReportBody} />
          <div className="flex flex-wrap gap-2">
            <button type="button" onClick={() => downloadJson(`aegis-report-${signed.report.scan_id as string}.${signed.algorithm}.json`, signed)}
              className="rounded border border-line px-2.5 py-1 text-xs text-slate-200 hover:bg-line/60">
              Download signed JSON
            </button>
            <button type="button" disabled={busy} onClick={flip}
              className="rounded border border-critical/40 px-2.5 py-1 text-xs text-critical hover:bg-critical/10 disabled:opacity-40">
              Demo: change one number &amp; re-verify
            </button>
          </div>
          {tampered && (
            <p className={`text-xs ${tampered.valid ? "text-suspicious" : "text-critical"}`} role="status">
              {tampered.valid ? "Unexpectedly valid" : `Rejected: ${tampered.reason}`}
            </p>
          )}
          <p className="text-[11px] text-slate-500">
            Verify offline: <code className="font-mono">python backend/scripts/verify_report.py file.json</code>
          </p>
        </div>
      )}
    </div>
  );
}
