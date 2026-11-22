import { useCallback, useEffect, useState } from "react";
import { getHealth, lookupHash, recentMalware } from "../api";
import type { HealthResponse, IntelLookupResponse, RecentMalware } from "../types/telemetry";
import VerdictList from "./VerdictList";

const EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const PROVIDER_LABEL: Record<string, string> = {
  local_ioc: "Local IOC", circl: "CIRCL hashlookup", malwarebazaar: "MalwareBazaar", virustotal: "VirusTotal",
};

export default function IntelPanel() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [recent, setRecent] = useState<RecentMalware[]>([]);
  const [hash, setHash] = useState("");
  const [result, setResult] = useState<IntelLookupResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setHealth(await getHealth());
      setRecent(await recentMalware());
    } catch {
      /* backend unreachable: the header already shows OFFLINE */
    }
  }, []);
  useEffect(() => {
    void refresh();
    const t = window.setInterval(refresh, 60000);
    return () => window.clearInterval(t);
  }, [refresh]);

  const lookup = async (h: string) => {
    const clean = h.trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(clean)) {
      setError("Enter a 64-character SHA-256 hash");
      return;
    }
    setHash(clean);
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await lookupHash(clean));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Lookup failed");
    } finally {
      setBusy(false);
    }
  };

  const providers = health?.intel_providers_online ?? [];
  const networkOnline = providers.some((p) => p !== "local_ioc");

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <section className="rounded-lg border border-line bg-card p-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-medium text-slate-200">Hash lookup</h2>
          <span className={`font-mono text-xs ${networkOnline ? "text-live" : "text-suspicious"}`}>
            {health ? (networkOnline ? "Intel: online" : "Intel: offline") : "Intel: …"}
          </span>
        </div>
        <p className="mt-1 text-xs text-slate-400">Only the hash is sent. File contents and names never leave this machine.</p>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {providers.map((p) => (
            <span key={p} className="rounded border border-line px-1.5 py-0.5 text-[11px] text-slate-300">{PROVIDER_LABEL[p] ?? p}</span>
          ))}
        </div>
        <form className="mt-3 flex gap-2" onSubmit={(e) => { e.preventDefault(); void lookup(hash); }}>
          <input value={hash} onChange={(e) => setHash(e.target.value)} spellCheck={false} aria-label="SHA-256 hash"
            placeholder="SHA-256 (64 hex characters)"
            className="min-w-0 flex-1 rounded border border-line bg-bg px-2 py-1.5 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-live/60 focus:outline-none" />
          <button type="submit" disabled={busy}
            className="rounded border border-live/50 bg-live/10 px-3 py-1.5 text-sm text-live hover:bg-live/20 disabled:opacity-40">
            {busy ? "Looking up…" : "Look up"}
          </button>
        </form>
        <button type="button" onClick={() => void lookup(EICAR)} className="mt-2 text-xs text-slate-400 underline decoration-dotted hover:text-live">
          Try the EICAR test file hash
        </button>
        {error && <p className="mt-2 text-xs text-critical" role="alert">{error}</p>}
        {result && (
          <div className="mt-3">
            <p className={`text-sm font-semibold ${result.malicious ? "text-critical" : result.known_good ? "text-safe" : "text-slate-300"}`}>
              {result.malicious ? "Flagged malicious by at least one source" : result.known_good ? "Known file (no malicious verdict)" : "No provider flags this hash"}
            </p>
            <VerdictList verdicts={result.verdicts} />
          </div>
        )}
      </section>

      <section className="rounded-lg border border-line bg-card p-4">
        <h2 className="text-sm font-medium text-slate-200">Latest malware (MalwareBazaar)</h2>
        <p className="mt-1 text-xs text-slate-400">Refreshed every 10 minutes into the local IOC cache, so it keeps working offline.</p>
        <ul className="mt-3 space-y-1.5">
          {recent.length === 0 && (
            <li className="text-sm text-slate-600">No feed yet. It needs AEGIS_MB_AUTH_KEY and a network connection.</li>
          )}
          {recent.map((m) => (
            <li key={m.sha256} className="flex items-center gap-2 rounded border border-line bg-bg px-2.5 py-1.5 text-xs">
              <span className="w-24 shrink-0 truncate font-semibold text-critical" title={m.signature ?? ""}>{m.signature ?? "unclassified"}</span>
              <span className="min-w-0 flex-1 truncate text-slate-300" title={m.file_name ?? ""}>{m.file_name ?? "—"}</span>
              <span className="shrink-0 text-slate-500">{m.file_type}</span>
              <button type="button" onClick={() => void lookup(m.sha256)} className="shrink-0 text-live underline decoration-dotted">look up</button>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
