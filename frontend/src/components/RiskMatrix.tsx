import type { Row } from "../hooks/useAegisSocket";

// Risk = likelihood x impact (Weeks 11-13). Cell colour follows the score band.
function band(score: number): string {
  if (score >= 15) return "#ef4444";
  if (score >= 10) return "#f97316";
  if (score >= 5) return "#f59e0b";
  return "#10b981";
}

export default function RiskMatrix({ files }: { files: Row[] }) {
  const cells = new Map<string, Row[]>();
  for (const f of files) {
    const key = `${f.likelihood}-${f.impact}`;
    const list = cells.get(key);
    if (list) list.push(f);
    else cells.set(key, [f]);
  }
  return (
    <section className="rounded-lg border border-line bg-card p-4">
      <div className="mb-2 flex items-baseline justify-between">
        <h2 className="text-sm font-medium text-slate-200">Risk matrix</h2>
        <span className="text-xs text-slate-500">likelihood × impact</span>
      </div>
      <div className="grid grid-cols-[1.25rem_repeat(5,minmax(0,1fr))] gap-1" role="table" aria-label="5 by 5 risk matrix">
        {[5, 4, 3, 2, 1].map((l) => (
          <div key={l} className="contents" role="row">
            <div className="flex items-center justify-center text-[10px] text-slate-500">{l}</div>
            {[1, 2, 3, 4, 5].map((i) => {
              const list = cells.get(`${l}-${i}`) ?? [];
              const score = l * i;
              const names = list.slice(0, 6).map((f) => f.filename).join(", ");
              return (
                <div key={i} role="cell"
                  title={list.length ? `${score}/25: ${names}${list.length > 6 ? "…" : ""}` : `${score}/25`}
                  className="flex aspect-square items-center justify-center rounded text-sm font-semibold tabular-nums"
                  style={{
                    background: `${band(score)}${list.length ? "55" : "1a"}`,
                    border: `1px solid ${band(score)}${list.length ? "cc" : "33"}`,
                    color: list.length ? "#f8fafc" : "#475569",
                  }}>
                  {list.length || ""}
                </div>
              );
            })}
          </div>
        ))}
        <div />
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="text-center text-[10px] text-slate-500">{i}</div>
        ))}
      </div>
      <div className="mt-1 flex justify-between text-[10px] text-slate-500">
        <span>↑ likelihood</span>
        <span>impact →</span>
      </div>
    </section>
  );
}
