import { useEffect, useRef } from "react";
import type { FeedLine, FeedTone } from "../hooks/useAegisSocket";
import { clock } from "../lib/tier";

const TONE: Record<FeedTone, string> = {
  safe: "text-safe",
  suspicious: "text-suspicious",
  critical: "text-critical",
  info: "text-live",
};

export default function ScanQueueFeed({ lines }: { lines: FeedLine[] }) {
  const box = useRef<HTMLDivElement>(null);
  const pinned = useRef(true);

  useEffect(() => {
    const el = box.current;
    if (el && pinned.current) el.scrollTop = el.scrollHeight;
  }, [lines]);

  return (
    <section className="flex flex-col rounded-lg border border-line bg-card p-4">
      <h2 className="mb-2 text-sm font-medium text-slate-200">Scan queue</h2>
      <div ref={box} role="log" aria-live="off"
        onScroll={(e) => {
          const el = e.currentTarget;
          pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
        }}
        className="h-60 overflow-y-auto rounded bg-black/40 p-2 font-mono text-xs leading-5">
        {lines.length === 0 && <div className="text-slate-600">$ waiting for a drive…</div>}
        {lines.map((l) => (
          <div key={l.id} className="whitespace-pre">
            <span className="text-slate-600">{clock(l.ts)} </span>
            <span className={TONE[l.tone]}>{l.text}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
