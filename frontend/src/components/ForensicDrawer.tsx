import { useEffect, useRef, useState, type ReactNode } from "react";
import { deleteOriginal, quarantine } from "../api";
import type { Row } from "../hooks/useAegisSocket";
import type { QuarantineEntry } from "../types/telemetry";
import { clock, formatBytes, TIER_BADGE } from "../lib/tier";
import SignReport from "./SignReport";
import VerdictList from "./VerdictList";

function extOf(name: string): string {
  const i = name.lastIndexOf(".");
  return i > 0 ? name.slice(i + 1).toLowerCase() : "(none)";
}

function entropyNote(f: Row): string {
  if (f.scan_status === "PARTIAL") return "Not measured: file exceeds the size cap (header and name checks only).";
  if (f.entropy <= 7.2) return "Below the 7.2 threshold: typical of text, code or structured data.";
  if (f.entropy_exempt) return "High, but expected: compressed format whose extension matches its header.";
  if (f.size_bytes >= 4096 && f.chi_square >= 200 && f.chi_square <= 320)
    return "Near-uniform byte distribution (chi-square close to 255): consistent with encrypted or random data.";
  return "High entropy without a uniform distribution: typical of compressed or packed content.";
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[8.5rem_1fr] gap-2 border-b border-line/60 py-2 text-sm">
      <dt className="text-slate-400">{label}</dt>
      <dd className="min-w-0 break-words text-slate-200">{children}</dd>
    </div>
  );
}

function QuarantineActions({ file, onChange }: { file: Row; onChange: () => void }) {
  const [entry, setEntry] = useState<QuarantineEntry | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      onChange();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setBusy(false);
    }
  };
  const simulated = file.drive === "Z:\\";

  return (
    <div className="space-y-2">
      {!entry && (
        <button type="button" disabled={busy || !file.sha256} onClick={() => run(async () => setEntry(await quarantine(file.event_id)))}
          className="rounded border border-suspicious/50 bg-suspicious/10 px-3 py-1.5 text-sm text-suspicious hover:bg-suspicious/20 disabled:opacity-40">
          Quarantine (encrypted copy)
        </button>
      )}
      {entry && (
        <div className="rounded border border-line bg-bg p-3 text-sm">
          <p className="text-safe">Copied into the AES-256-GCM vault ✓</p>
          <p className="mt-1 text-xs text-slate-400">The original is still on the drive. Vault id <code className="font-mono">{entry.id.slice(0, 8)}</code>.</p>
          {entry.original_deleted ? (
            <p className="mt-2 text-xs text-suspicious">The original was deleted from the drive.</p>
          ) : !confirming ? (
            <button type="button" disabled={simulated || busy} onClick={() => setConfirming(true)}
              title={simulated ? "The simulated demo drive is protected" : undefined}
              className="mt-2 rounded border border-critical/40 px-2.5 py-1 text-xs text-critical hover:bg-critical/10 disabled:cursor-not-allowed disabled:opacity-40">
              Delete original from drive…
            </button>
          ) : (
            <div className="mt-2 rounded border border-critical/50 p-2 text-xs">
              <p className="break-all text-slate-200">Permanently delete <b>{file.file}</b>? This cannot be undone.</p>
              <div className="mt-2 flex gap-2">
                <button type="button" disabled={busy} onClick={() => run(async () => { setEntry(await deleteOriginal(entry.id)); setConfirming(false); })}
                  className="rounded bg-critical px-2.5 py-1 font-semibold text-white disabled:opacity-40">Yes, delete it</button>
                <button type="button" onClick={() => setConfirming(false)} className="rounded border border-line px-2.5 py-1 text-slate-300">Cancel</button>
              </div>
            </div>
          )}
          {simulated && !entry.original_deleted && <p className="mt-1 text-[11px] text-slate-500">Deleting is disabled for the simulated demo drive.</p>}
        </div>
      )}
      {error && <p className="text-xs text-critical" role="alert">{error}</p>}
    </div>
  );
}

export default function ForensicDrawer({ file, onClose, onVaultChange }: { file: Row; onClose: () => void; onVaultChange: () => void }) {
  const [copied, setCopied] = useState(false);
  const closeBtn = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    closeBtn.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const copy = async () => {
    if (!file.sha256) return;
    try {
      await navigator.clipboard.writeText(file.sha256);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable (insecure context): the hash stays selectable */
    }
  };

  const ext = extOf(file.filename);
  const cell = `${file.likelihood} × ${file.impact}`;

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" onClick={onClose}>
      <aside role="dialog" aria-modal="true" aria-label={`Forensic details for ${file.filename}`}
        onClick={(e) => e.stopPropagation()}
        className="h-full w-full max-w-xl overflow-y-auto border-l border-line bg-card p-5 shadow-2xl">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="break-words text-lg font-semibold text-slate-100">{file.filename}</h2>
            <p className="break-all font-mono text-xs text-slate-500">{file.file}</p>
          </div>
          <button ref={closeBtn} type="button" onClick={onClose} aria-label="Close details"
            className="rounded border border-line px-2 py-1 text-slate-300 hover:bg-line/60">✕</button>
        </div>

        <div className="mt-3 flex items-center gap-3">
          <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${TIER_BADGE[file.tier]}`}>{file.tier}</span>
          <span className="font-mono text-sm text-slate-300">risk {cell} = {file.risk_score}/25</span>
          <span className="text-xs text-slate-500">{clock(file.timestamp)} · {formatBytes(file.size_bytes)}</span>
        </div>

        <h3 className="mt-5 text-xs font-semibold uppercase tracking-wider text-slate-400">Why</h3>
        <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-slate-200">
          {file.reasons.map((r) => <li key={r}>{r}</li>)}
        </ul>

        {file.intel && file.intel.length > 0 && (
          <>
            <h3 className="mt-5 text-xs font-semibold uppercase tracking-wider text-slate-400">
              Threat intel{file.known_good && <span className="ml-2 font-normal normal-case text-safe">known file</span>}
            </h3>
            <VerdictList verdicts={file.intel} />
          </>
        )}

        <dl className="mt-5">
          <Row label="SHA-256">
            {file.sha256 ? (
              <span className="flex items-start gap-2">
                <code className="select-all break-all font-mono text-xs">{file.sha256}</code>
                <button type="button" onClick={copy}
                  className="shrink-0 rounded border border-line px-2 py-0.5 text-xs text-live hover:bg-line/60">
                  {copied ? "Copied" : "Copy"}
                </button>
              </span>
            ) : <span className="text-slate-500">not computed (partial scan)</span>}
          </Row>
          <Row label="MD5 / SHA-1">
            <span className="font-mono text-xs text-slate-400">{file.md5_legacy ?? "—"}<br />{file.sha1_legacy ?? "—"}</span>
            <span className="mt-1 block text-[11px] text-slate-500">Legacy, collision-prone: kept only for threat-intel compatibility.</span>
          </Row>
          <Row label="Magic vs name">
            <span className="font-mono text-xs">{file.magic_hex || "—"}</span>
            <span className="block">{file.magic_type} · claimed extension <b>.{ext}</b>
              {file.extension_mismatch && <span className="ml-1 text-critical">(mismatch)</span>}</span>
          </Row>
          <Row label="Entropy">
            <span className="font-mono">{file.entropy.toFixed(3)}</span> bits/byte · χ² <span className="font-mono">{file.chi_square.toFixed(1)}</span>
            <span className="mt-1 block text-xs text-slate-400">{entropyNote(file)}</span>
          </Row>
          <Row label="YARA">
            {file.yara_matches.length ? file.yara_matches.map((m) => (
              <code key={m} className="mr-2 rounded bg-critical/15 px-1.5 py-0.5 text-xs text-critical">{m}</code>
            )) : <span className="text-slate-500">no matches</span>}
          </Row>
          <Row label="Authenticode">{file.authenticode.replace("_", " ")}</Row>
          {file.xor_key !== null && (
            <Row label="XOR key"><code className="font-mono">0x{file.xor_key.toString(16).toUpperCase().padStart(2, "0")}</code></Row>
          )}
          <Row label="Filename tricks">
            {file.double_extension || file.rtlo ? [
              file.double_extension && "double extension", file.rtlo && "RTLO character",
            ].filter(Boolean).join(", ") : <span className="text-slate-500">none</span>}
          </Row>
          <Row label="MITRE ATT&CK">
            {file.mitre.length ? file.mitre.map((t) => (
              <a key={t} href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`}
                target="_blank" rel="noreferrer noopener"
                className="mr-2 font-mono text-xs text-live underline decoration-dotted">{t}</a>
            )) : <span className="text-slate-500">none</span>}
          </Row>
          {file.chain_index !== null && (
            <Row label="Audit chain">#{file.chain_index} <code className="break-all font-mono text-xs text-slate-400">{file.chain_hash}</code></Row>
          )}
        </dl>

        <h3 className="mt-6 text-xs font-semibold uppercase tracking-wider text-slate-400">Actions</h3>
        <div className="mt-2 space-y-5">
          <QuarantineActions file={file} onChange={onVaultChange} />
          <div>
            <p className="mb-2 text-xs text-slate-400">Sign the report for this whole scan session:</p>
            <SignReport scanId={file.scan_id} />
          </div>
        </div>
      </aside>
    </div>
  );
}
