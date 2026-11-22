import { useCallback, useEffect, useState } from "react";
import { quarantineList, restoreQuarantined } from "../api";
import type { QuarantineEntry } from "../types/telemetry";

export default function VaultPanel({ refreshKey }: { refreshKey: number }) {
  const [entries, setEntries] = useState<QuarantineEntry[]>([]);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setEntries(await quarantineList());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load the vault");
    }
  }, []);
  useEffect(() => { void load(); }, [load, refreshKey]);

  const restore = async (id: string) => {
    try {
      const r = await restoreQuarantined(id);
      setNote(`Decrypted and SHA-256 re-checked ✓ → ${r.restored_path}`);
    } catch (e) {
      setNote(e instanceof Error ? e.message : "Restore failed");
    }
  };

  return (
    <section className="rounded-lg border border-line bg-card p-4">
      <h2 className="text-sm font-medium text-slate-200">Quarantine vault (AES-256-GCM)</h2>
      <p className="mt-1 text-xs text-slate-400">Flagged files are copied here encrypted. The original stays untouched unless you delete it.</p>
      {error && <p className="mt-2 text-xs text-suspicious">{error}</p>}
      <ul className="mt-3 space-y-2">
        {entries.length === 0 && !error && <li className="text-sm text-slate-600">Nothing quarantined yet.</li>}
        {entries.map((e) => (
          <li key={e.id} className="flex flex-wrap items-center gap-2 rounded border border-line bg-bg px-3 py-2 text-sm">
            <span className="mr-auto min-w-0 truncate" title={e.original_path}>{e.filename}</span>
            <code className="font-mono text-[11px] text-slate-500">{e.sha256.slice(0, 12)}</code>
            {e.original_deleted && <span className="text-xs text-suspicious">original deleted</span>}
            <button type="button" onClick={() => restore(e.id)}
              className="rounded border border-line px-2 py-0.5 text-xs text-live hover:bg-line/60">Restore &amp; verify</button>
          </li>
        ))}
      </ul>
      {note && <p className="mt-2 break-all text-xs text-slate-300" role="status">{note}</p>}
    </section>
  );
}
