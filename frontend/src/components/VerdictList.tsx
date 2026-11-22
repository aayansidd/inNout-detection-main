import type { IntelVerdict, IntelStatus } from "../types/telemetry";

const STYLE: Record<IntelStatus, string> = {
  malicious: "text-critical bg-critical/15 border-critical/40",
  suspicious: "text-suspicious bg-suspicious/15 border-suspicious/40",
  clean: "text-safe bg-safe/15 border-safe/40",
  known_good: "text-safe bg-safe/15 border-safe/40",
  not_found: "text-slate-400 bg-line/40 border-line",
  error: "text-suspicious bg-suspicious/10 border-suspicious/30",
  skipped: "text-slate-500 bg-line/30 border-line",
};
const NAME: Record<string, string> = {
  local_ioc: "Local IOC", circl: "CIRCL", malwarebazaar: "MalwareBazaar", virustotal: "VirusTotal",
};

export default function VerdictList({ verdicts }: { verdicts: IntelVerdict[] }) {
  return (
    <ul className="mt-2 space-y-1.5">
      {verdicts.map((v) => (
        <li key={v.provider} className="flex flex-wrap items-center gap-2 rounded border border-line bg-bg px-2.5 py-1.5 text-xs">
          <span className="w-24 shrink-0 text-slate-300">{NAME[v.provider] ?? v.provider}</span>
          <span className={`rounded border px-1.5 py-0.5 text-[11px] font-semibold ${STYLE[v.status]}`}>{v.status.replace("_", " ")}</span>
          <span className="min-w-0 flex-1 text-slate-400">{v.summary}{v.cached && <span className="ml-1 text-slate-600">(cached)</span>}</span>
          {v.link && (
            <a href={v.link} target="_blank" rel="noreferrer noopener" className="shrink-0 text-live underline decoration-dotted">source</a>
          )}
        </li>
      ))}
    </ul>
  );
}
