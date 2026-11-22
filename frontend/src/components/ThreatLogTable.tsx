import { useMemo, useState } from "react";
import type { Row } from "../hooks/useAegisSocket";
import type { Tier } from "../types/telemetry";
import { clock, TIER_BADGE } from "../lib/tier";
import ForensicDrawer from "./ForensicDrawer";

type Filter = "ALL" | Tier;
const FILTERS: Filter[] = ["ALL", "CRITICAL", "SUSPICIOUS", "SAFE"];
const MAX_ROWS = 300;

export default function ThreatLogTable({ files, onVaultChange }: { files: Row[]; onVaultChange: () => void }) {
  const [filter, setFilter] = useState<Filter>("ALL");
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const out: Row[] = [];
    for (let i = files.length - 1; i >= 0 && out.length < MAX_ROWS; i--) {
      const f = files[i];
      if (filter !== "ALL" && f.tier !== filter) continue;
      if (q && !f.filename.toLowerCase().includes(q) && !(f.sha256 ?? "").startsWith(q)) continue;
      out.push(f);
    }
    return out; // newest first
  }, [files, filter, query]);

  const selected = selectedId ? files.find((f) => f.event_id === selectedId) ?? null : null;

  return (
    <section className="rounded-lg border border-line bg-card p-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <h2 className="mr-auto text-sm font-medium text-slate-200">Threat log</h2>
        <div role="group" aria-label="Filter by tier" className="flex gap-1">
          {FILTERS.map((f) => (
            <button key={f} type="button" aria-pressed={filter === f} onClick={() => setFilter(f)}
              className={`rounded border px-2.5 py-1 text-xs ${filter === f
                ? "border-live/60 bg-live/15 text-live" : "border-line text-slate-400 hover:bg-line/60"}`}>
              {f === "ALL" ? "All" : f[0] + f.slice(1).toLowerCase()}
            </button>
          ))}
        </div>
        <input type="search" value={query} onChange={(e) => setQuery(e.target.value)}
          placeholder="Search name or hash…" aria-label="Search files"
          className="w-48 rounded border border-line bg-bg px-2 py-1 text-xs text-slate-200 placeholder:text-slate-600 focus:border-live/60 focus:outline-none" />
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[40rem] text-left text-sm">
          <thead className="text-xs uppercase tracking-wider text-slate-500">
            <tr>
              <th className="py-2 pr-3 font-medium">Time</th>
              <th className="py-2 pr-3 font-medium">File</th>
              <th className="py-2 pr-3 font-medium">Tier</th>
              <th className="py-2 pr-3 text-right font-medium">Risk</th>
              <th className="py-2 pr-3 text-right font-medium">Entropy</th>
              <th className="py-2 pr-3 font-medium">Intel</th>
              <th className="py-2 font-medium">First reason</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <tr key={f.event_id} tabIndex={0} onClick={() => setSelectedId(f.event_id)}
                onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setSelectedId(f.event_id)}
                className="cursor-pointer border-t border-line/60 hover:bg-line/40 focus:bg-line/40 focus:outline-none">
                <td className="py-1.5 pr-3 font-mono text-xs text-slate-500">{clock(f.timestamp)}</td>
                <td className="max-w-56 truncate py-1.5 pr-3" title={f.file}>{f.filename}</td>
                <td className="py-1.5 pr-3">
                  <span className={`rounded border px-1.5 py-0.5 text-[11px] font-semibold ${TIER_BADGE[f.tier]}`}>{f.tier}</span>
                </td>
                <td className="py-1.5 pr-3 text-right font-mono">{f.risk_score}</td>
                <td className="py-1.5 pr-3 text-right font-mono">{f.entropy.toFixed(2)}</td>
                <td className="py-1.5 pr-3 text-xs">
                  {f.intel?.some((v) => v.status === "malicious") ? (
                    <span className="text-critical">flagged</span>
                  ) : f.known_good ? (
                    <span className="text-safe">known</span>
                  ) : f.intel ? (
                    <span className="text-slate-500">checked</span>
                  ) : (
                    <span className="text-slate-700">—</span>
                  )}
                </td>
                <td className="max-w-80 truncate py-1.5 text-slate-400" title={f.reasons.join(" • ")}>{f.reasons[0]}</td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr><td colSpan={7} className="py-8 text-center text-slate-600">
                {files.length === 0 ? "No files scanned yet. Plug in a drive or click Simulate USB." : "No files match this filter."}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
      {selected && <ForensicDrawer file={selected} onClose={() => setSelectedId(null)} onVaultChange={onVaultChange} />}
    </section>
  );
}
