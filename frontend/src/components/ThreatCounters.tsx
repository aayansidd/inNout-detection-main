import { useEffect, useRef, useState } from "react";
import type { Stats } from "../types/telemetry";

function useAnimatedNumber(target: number, ms = 400): number {
  const [value, setValue] = useState(target);
  const current = useRef(target);
  useEffect(() => {
    const from = current.current;
    const start = performance.now();
    let raf = 0;
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / ms);
      current.current = Math.round(from + (target - from) * p);
      setValue(current.current);
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return value;
}

function Counter({ label, value, color }: { label: string; value: number; color: string }) {
  const shown = useAnimatedNumber(value);
  return (
    <div className="rounded-lg border border-line bg-card p-4">
      <div className="text-xs uppercase tracking-wider text-slate-400">{label}</div>
      <div className={`mt-1 font-mono text-4xl font-semibold tabular-nums ${color}`} aria-label={`${label}: ${value}`}>
        {shown}
      </div>
    </div>
  );
}

export default function ThreatCounters({ stats }: { stats: Stats }) {
  return (
    <section aria-label="Threat counters" className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <Counter label="Total scanned" value={stats.total} color="text-slate-100" />
      <Counter label="Safe" value={stats.safe} color="text-safe" />
      <Counter label="Suspicious" value={stats.suspicious} color="text-suspicious" />
      <Counter label="Critical" value={stats.critical} color="text-critical" />
    </section>
  );
}
