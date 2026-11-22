import { useEffect, useState } from "react";
import { fileUrl, getCourseMap } from "../api";
import type { CourseRow } from "../types/telemetry";

const STATUS: Record<CourseRow["status"], { label: string; cls: string }> = {
  implemented: { label: "Implemented", cls: "text-safe bg-safe/15 border-safe/40" },
  partial: { label: "Partial", cls: "text-suspicious bg-suspicious/15 border-suspicious/40" },
  not_built: { label: "Not built", cls: "text-critical bg-critical/15 border-critical/40" },
};

export default function AboutPanel() {
  const [rows, setRows] = useState<CourseRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getCourseMap()
      .then((r) => setRows(r.rows))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "Could not load the course map"));
  }, []);

  return (
    <section className="rounded-lg border border-line bg-card p-4">
      <h2 className="text-sm font-medium text-slate-200">What each lecture week became</h2>
      <p className="mt-1 text-xs text-slate-400">
        Plug in a drive. See the verdict (hashed, scored, checked against threat intel and
        cryptographically signed) before anyone opens a file. CIA = the security property each
        feature protects. File links open the source read-only, no internet needed.
      </p>
      {error && <p className="mt-3 text-sm text-critical" role="alert">{error}</p>}
      {!rows && !error && <p className="mt-3 text-sm text-slate-500">Loading…</p>}
      {rows && (
        <div className="mt-3 overflow-x-auto">
          <table className="w-full min-w-[56rem] text-left text-sm">
            <thead className="text-xs uppercase tracking-wider text-slate-500">
              <tr>
                <th className="py-2 pr-3 font-medium">Week</th>
                <th className="py-2 pr-3 font-medium">Topic</th>
                <th className="py-2 pr-3 font-medium">Where it lives in AEGIS USB</th>
                <th className="py-2 pr-3 font-medium">CIA</th>
                <th className="py-2 pr-3 font-medium">Status</th>
                <th className="py-2 font-medium">Files</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.week} className="border-t border-line/60 align-top">
                  <td className="py-2 pr-3 font-mono text-live">{r.week}</td>
                  <td className="py-2 pr-3 text-slate-200">{r.topic}</td>
                  <td className="py-2 pr-3 text-slate-300">
                    {r.feature}
                    {r.note && <span className="mt-1 block text-xs text-suspicious">Note: {r.note}</span>}
                  </td>
                  <td className="py-2 pr-3 font-mono text-xs text-slate-300">{r.cia}</td>
                  <td className="py-2 pr-3">
                    <span className={`whitespace-nowrap rounded border px-1.5 py-0.5 text-[11px] font-semibold ${STATUS[r.status].cls}`}>
                      {STATUS[r.status].label}
                    </span>
                  </td>
                  <td className="py-2">
                    <ul className="space-y-0.5">
                      {r.files.map((f) => (
                        <li key={f}>
                          <a href={fileUrl(f)} target="_blank" rel="noreferrer noopener"
                            className="break-all font-mono text-xs text-live underline decoration-dotted">
                            {f}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
