import type { Tier } from "../types/telemetry";

// Full class names so Tailwind can see them at build time.
export const TIER_TEXT: Record<Tier, string> = {
  SAFE: "text-safe",
  SUSPICIOUS: "text-suspicious",
  CRITICAL: "text-critical",
};
export const TIER_BADGE: Record<Tier, string> = {
  SAFE: "text-safe bg-safe/15 border-safe/40",
  SUSPICIOUS: "text-suspicious bg-suspicious/15 border-suspicious/40",
  CRITICAL: "text-critical bg-critical/15 border-critical/40",
};
export const TIER_HEX: Record<Tier, string> = {
  SAFE: "#10b981",
  SUSPICIOUS: "#f59e0b",
  CRITICAL: "#ef4444",
};

export function clock(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "--:--:--" : d.toLocaleTimeString([], { hour12: false });
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}
