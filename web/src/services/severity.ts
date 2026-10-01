// Severity helpers shared by the dashboard pages.
//
// Events and rules carry a numeric severity (1-10); alerts carry its class.
// The class boundaries match the server's correlation.IntToSeverity, so a
// rule shown as "high" raises "high" alerts.

import type { AggregationBucket, Severity } from "../types/api";

export const SEVERITY_CLASSES: Severity[] = ["critical", "high", "medium", "low"];

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

/** Class of a numeric severity: 1-2 low, 3-5 medium, 6-8 high, 9-10 critical. */
export function severityClass(level: number): Severity {
  if (level <= 2) return "low";
  if (level <= 5) return "medium";
  if (level <= 8) return "high";
  return "critical";
}

export interface SeveritySlice {
  name: string;
  severity: Severity;
  value: number;
  color: string;
}

/**
 * Turns the by_severity buckets of /v1/stats (keys are numeric levels,
 * possibly as strings) into one slice per class, most severe first. Buckets
 * whose key is already a class name are counted under it; others are
 * ignored.
 */
export function severityBreakdown(
  buckets: AggregationBucket[] | undefined,
): SeveritySlice[] {
  const totals = new Map<Severity, number>();
  for (const b of buckets ?? []) {
    let cls: Severity | undefined;
    const level = typeof b.key === "number" ? b.key : Number(b.key);
    if (Number.isFinite(level) && String(b.key).trim() !== "") {
      cls = severityClass(level);
    } else if (SEVERITY_CLASSES.includes(String(b.key) as Severity)) {
      cls = String(b.key) as Severity;
    }
    if (!cls) continue;
    totals.set(cls, (totals.get(cls) ?? 0) + (b.count || 0));
  }
  return SEVERITY_CLASSES.filter((cls) => (totals.get(cls) ?? 0) > 0).map(
    (cls) => ({
      name: cls.charAt(0).toUpperCase() + cls.slice(1),
      severity: cls,
      value: totals.get(cls) ?? 0,
      color: SEVERITY_COLORS[cls],
    }),
  );
}

/**
 * Total and open alert counts from /v1/alerts/stats ({total, open,
 * by_status, ...}). Servers without "open" get it computed from by_status:
 * new, acknowledged and in_progress alerts are open.
 */
export function alertCounts(stats: Record<string, unknown> | undefined): {
  total: number;
  open: number;
} {
  const total = typeof stats?.total === "number" ? stats.total : 0;
  if (typeof stats?.open === "number") return { total, open: stats.open };
  const byStatus = (stats?.by_status ?? {}) as Record<string, unknown>;
  let open = 0;
  for (const status of ["new", "acknowledged", "in_progress"]) {
    const n = byStatus[status];
    if (typeof n === "number") open += n;
  }
  return { total, open };
}
