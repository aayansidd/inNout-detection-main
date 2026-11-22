import { useCallback, useEffect, useReducer } from "react";
import type {
  AuditVerifyResult,
  DriveState,
  FileEnrichedEvent,
  FileScannedEvent,
  IntelVerdict,
  Stats,
  TelemetryEvent,
} from "../types/telemetry";

/** A scanned file plus whatever threat intel has been learned about it since. */
export type Row = FileScannedEvent & { intel?: IntelVerdict[]; known_good?: boolean };

export type FeedTone = "safe" | "suspicious" | "critical" | "info";
export interface FeedLine {
  id: string;
  ts: string;
  text: string;
  tone: FeedTone;
}
export interface Toast {
  id: string;
  text: string;
}
export interface CriticalAlert {
  id: string;
  filename: string;
}

export interface AegisState {
  connected: boolean;
  stats: Stats;
  drives: Record<string, DriveState>;
  files: Row[]; // oldest -> newest
  audit: AuditVerifyResult | null;
  feed: FeedLine[];
  toast: Toast | null;
  alert: CriticalAlert | null;
}

const MAX_FILES = 2000;
const MAX_FEED = 300;
const ZERO_STATS: Stats = { total: 0, safe: 0, suspicious: 0, critical: 0, scans_completed: 0 };

export const initialState: AegisState = {
  connected: false,
  stats: ZERO_STATS,
  drives: {},
  files: [],
  audit: null,
  feed: [],
  toast: null,
  alert: null,
};

type Action =
  | { kind: "connected"; value: boolean }
  | { kind: "batch"; events: TelemetryEvent[] }
  | { kind: "dismissToast" }
  | { kind: "dismissAlert" };

const TYPES = new Set([
  "SNAPSHOT", "USB_CONNECTED", "USB_DISCONNECTED", "SCAN_PROGRESS", "FILE_SCANNED",
  "FILE_ENRICHED", "SCAN_COMPLETE", "AUDIT_STATUS", "HEARTBEAT",
]);

function isTelemetryEvent(v: unknown): v is TelemetryEvent {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return typeof o.type === "string" && TYPES.has(o.type) && typeof o.event_id === "string";
}

function lineFor(e: TelemetryEvent): FeedLine | null {
  switch (e.type) {
    case "USB_CONNECTED":
      return {
        id: e.event_id, ts: e.timestamp, tone: "info",
        text: `USB connected ${e.drive} "${e.label}" (${e.fs_type})${e.simulated ? " [simulated]" : ""}`,
      };
    case "USB_DISCONNECTED":
      return { id: e.event_id, ts: e.timestamp, tone: "info", text: `USB removed ${e.drive}` };
    case "FILE_SCANNED":
      return {
        id: e.event_id, ts: e.timestamp,
        tone: e.tier === "SAFE" ? "safe" : e.tier === "SUSPICIOUS" ? "suspicious" : "critical",
        text:
          `${e.tier.padEnd(10)} ${e.filename}  ` +
          `${e.sha256 ? e.sha256.slice(0, 12) : "no-hash"}  H=${e.entropy.toFixed(2)}`,
      };
    case "SCAN_COMPLETE":
      return {
        id: e.event_id, ts: e.timestamp, tone: "info",
        text: e.cancelled
          ? `Scan of ${e.drive} cancelled`
          : `Scan of ${e.drive} complete: ${e.total} files in ${e.duration_s.toFixed(2)}s`,
      };
    default:
      return null;
  }
}

function mergeEnrichment(files: Row[], e: FileEnrichedEvent): Row[] {
  const i = files.findIndex((f) => f.event_id === e.file_event_id);
  if (i < 0) return files;
  const next = files.slice();
  next[i] = {
    ...files[i], tier: e.tier, likelihood: e.likelihood, impact: e.impact,
    risk_score: e.risk_score, reasons: e.reasons, mitre: e.mitre, intel: e.verdicts,
    known_good: e.known_good,
  };
  return next;
}

function applySnapshot(e: Extract<TelemetryEvent, { type: "SNAPSHOT" }>): AegisState {
  const events: TelemetryEvent[] = [];
  for (const raw of e.events) if (isTelemetryEvent(raw)) events.push(raw);
  let files: Row[] = [];
  for (const x of events) {
    if (x.type === "FILE_SCANNED") files.push(x);
    else if (x.type === "FILE_ENRICHED") files = mergeEnrichment(files, x);
  }
  const feed = events.map(lineFor).filter((l): l is FeedLine => l !== null);
  const drives: Record<string, DriveState> = {};
  for (const d of e.drives) drives[d.drive] = d;
  return {
    connected: true, stats: e.stats, drives, audit: null,
    files: files.slice(-MAX_FILES), feed: feed.slice(-MAX_FEED), toast: null, alert: null,
  };
}

function reduceEvent(s: AegisState, e: TelemetryEvent): AegisState {
  switch (e.type) {
    case "SNAPSHOT":
      return applySnapshot(e);
    case "USB_CONNECTED": {
      const d: DriveState = {
        drive: e.drive, label: e.label, fs_type: e.fs_type, total_bytes: e.total_bytes,
        simulated: e.simulated, scan_id: e.scan_id, scanning: true,
        files_discovered: 0, files_scanned: 0, files_skipped: 0,
      };
      return { ...s, drives: { ...s.drives, [e.drive]: d }, feed: pushFeed(s.feed, e) };
    }
    case "USB_DISCONNECTED": {
      const { [e.drive]: _removed, ...rest } = s.drives;
      return { ...s, drives: rest, feed: pushFeed(s.feed, e) };
    }
    case "SCAN_PROGRESS": {
      const d = s.drives[e.drive];
      if (!d || d.scan_id !== e.scan_id) return s;
      return {
        ...s,
        drives: {
          ...s.drives,
          [e.drive]: {
            ...d, files_discovered: e.files_discovered, files_scanned: e.files_scanned,
            files_skipped: e.files_skipped,
          },
        },
      };
    }
    case "FILE_SCANNED": {
      const key = e.tier.toLowerCase() as "safe" | "suspicious" | "critical";
      const files = [...s.files, e];
      return {
        ...s,
        files: files.length > MAX_FILES ? files.slice(-MAX_FILES) : files,
        stats: { ...s.stats, total: s.stats.total + 1, [key]: s.stats[key] + 1 },
        feed: pushFeed(s.feed, e),
        alert: e.tier === "CRITICAL" ? { id: e.event_id, filename: e.filename } : s.alert,
      };
    }
    case "FILE_ENRICHED": {
      const row = s.files.find((f) => f.event_id === e.file_event_id);
      const changed = e.previous_tier !== e.tier;
      const stats = changed
        ? {
            ...s.stats,
            [e.previous_tier.toLowerCase()]: Math.max(0, s.stats[e.previous_tier.toLowerCase() as "safe"] - 1),
            [e.tier.toLowerCase()]: s.stats[e.tier.toLowerCase() as "safe"] + 1,
          }
        : s.stats;
      const top = e.verdicts.find((v) => v.status === "malicious") ?? e.verdicts.find((v) => v.status === "known_good");
      const line: FeedLine | null =
        changed || top
          ? {
              id: e.event_id, ts: e.timestamp,
              tone: e.tier === "CRITICAL" ? "critical" : e.tier === "SAFE" ? "safe" : "info",
              text: `INTEL      ${row?.filename ?? e.sha256.slice(0, 12)}  ${changed ? `${e.previous_tier} -> ${e.tier}  ` : ""}${top ? `${top.provider}: ${top.status}` : ""}`,
            }
          : null;
      return {
        ...s, stats, files: mergeEnrichment(s.files, e),
        feed: line ? [...s.feed, line].slice(-MAX_FEED) : s.feed,
        alert: changed && e.tier === "CRITICAL" ? { id: e.event_id, filename: row?.filename ?? "file" } : s.alert,
      };
    }
    case "AUDIT_STATUS":
      return { ...s, audit: { valid: e.valid, length: e.length, broken_at: e.broken_at } };
    case "SCAN_COMPLETE": {
      const d = s.drives[e.drive];
      const drives =
        d && d.scan_id === e.scan_id ? { ...s.drives, [e.drive]: { ...d, scanning: false } } : s.drives;
      const text = e.cancelled
        ? `Scan of ${e.drive} cancelled`
        : `Scan complete: ${e.total} files — ${e.safe} safe, ${e.suspicious} suspicious, ${e.critical} critical`;
      return {
        ...s, drives, stats: { ...s.stats, scans_completed: s.stats.scans_completed + 1 },
        feed: pushFeed(s.feed, e), toast: { id: e.event_id, text },
      };
    }
    default:
      return s; // HEARTBEAT needs no state
  }
}

function pushFeed(feed: FeedLine[], e: TelemetryEvent): FeedLine[] {
  const line = lineFor(e);
  if (!line) return feed;
  const next = [...feed, line];
  return next.length > MAX_FEED ? next.slice(-MAX_FEED) : next;
}

export function reducer(s: AegisState, a: Action): AegisState {
  switch (a.kind) {
    case "connected":
      return { ...s, connected: a.value };
    case "batch":
      return a.events.reduce(reduceEvent, s);
    case "dismissToast":
      return { ...s, toast: null };
    case "dismissAlert":
      return { ...s, alert: null };
  }
}

function socketUrl(): string {
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  return `${scheme}://${window.location.host}/ws`;
}

export function useAegisSocket() {
  const [state, dispatch] = useReducer(reducer, initialState);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let stopped = false;
    let attempt = 0;
    let timer: number | undefined;
    let raf = 0;
    const buffer: TelemetryEvent[] = [];
    const seen = new Set<string>();

    const remember = (id: string) => {
      seen.add(id);
      if (seen.size > 20000) {
        const oldest = seen.values().next().value;
        if (oldest !== undefined) seen.delete(oldest);
      }
    };
    // Batch everything that arrives within one animation frame into a single render.
    const flush = () => {
      raf = 0;
      if (buffer.length > 0) dispatch({ kind: "batch", events: buffer.splice(0) });
    };
    const schedule = () => {
      if (!raf) raf = requestAnimationFrame(flush);
    };

    const connect = () => {
      ws = new WebSocket(socketUrl());
      ws.onopen = () => {
        attempt = 0;
        dispatch({ kind: "connected", value: true });
      };
      ws.onmessage = (m: MessageEvent<string>) => {
        let ev: unknown;
        try {
          ev = JSON.parse(m.data);
        } catch {
          return;
        }
        if (!isTelemetryEvent(ev)) return;
        if (ev.type === "SNAPSHOT") {
          seen.clear();
          remember(ev.event_id);
          for (const e of ev.events) if (typeof e.event_id === "string") remember(e.event_id);
          buffer.length = 0; // anything buffered is older than the snapshot
          buffer.push(ev);
        } else {
          if (seen.has(ev.event_id)) return; // dedupe by event_id
          remember(ev.event_id);
          buffer.push(ev);
        }
        schedule();
      };
      ws.onclose = () => {
        dispatch({ kind: "connected", value: false });
        if (stopped) return;
        // exponential backoff with jitter: 0.5s, 1s, 2s ... capped at 10s
        const delay = Math.min(10000, 500 * 2 ** attempt) * (0.5 + Math.random() * 0.5);
        attempt += 1;
        timer = window.setTimeout(connect, delay);
      };
      ws.onerror = () => ws?.close();
    };

    connect();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      cancelAnimationFrame(raf);
      ws?.close();
    };
  }, []);

  // Stable identities: App's auto-dismiss timers depend on these, and a new function on every
  // render would restart the timer each time an event arrives (toasts would never expire).
  const dismissToast = useCallback(() => dispatch({ kind: "dismissToast" }), []);
  const dismissAlert = useCallback(() => dispatch({ kind: "dismissAlert" }), []);
  return { state, dismissToast, dismissAlert };
}
