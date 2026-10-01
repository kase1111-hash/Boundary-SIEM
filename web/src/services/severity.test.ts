import { describe, expect, it } from "vitest";
import {
  alertCounts,
  severityBreakdown,
  severityClass,
  SEVERITY_COLORS,
} from "./severity";

describe("alertCounts", () => {
  // E2E round 1: the dashboard read total_alerts and open, which the server
  // never sent, so Total Alerts and Open Alerts always showed 0.
  it("reads the server's total and open", () => {
    expect(
      alertCounts({ total: 12, open: 10, by_status: { new: 10, resolved: 2 } }),
    ).toEqual({ total: 12, open: 10 });
  });

  it("computes open from by_status when the server does not send it", () => {
    expect(
      alertCounts({
        total: 12,
        by_status: { new: 7, acknowledged: 2, in_progress: 1, resolved: 1, suppressed: 1 },
      }),
    ).toEqual({ total: 12, open: 10 });
  });

  it("is zero without stats", () => {
    expect(alertCounts(undefined)).toEqual({ total: 0, open: 0 });
  });
});

describe("severityBreakdown", () => {
  // E2E round 1: by_severity keys are numbers (1-10) but the colours were
  // keyed critical/high/medium/low, so every slice was grey and unlabeled.
  it("groups numeric levels into coloured, labeled classes", () => {
    const slices = severityBreakdown([
      { key: 3, count: 4 },
      { key: 4, count: 6 },
      { key: 9, count: 1 },
      { key: "7", count: 2 },
    ]);
    expect(slices).toEqual([
      { name: "Critical", severity: "critical", value: 1, color: SEVERITY_COLORS.critical },
      { name: "High", severity: "high", value: 2, color: SEVERITY_COLORS.high },
      { name: "Medium", severity: "medium", value: 10, color: SEVERITY_COLORS.medium },
    ]);
    for (const s of slices) expect(s.color).not.toBe("#6b7280");
  });

  it("accepts class names and ignores unknown keys", () => {
    expect(
      severityBreakdown([
        { key: "low", count: 2 },
        { key: "bogus", count: 5 },
      ]),
    ).toEqual([{ name: "Low", severity: "low", value: 2, color: SEVERITY_COLORS.low }]);
  });
});

describe("severityClass", () => {
  it("matches the server's correlation.IntToSeverity", () => {
    expect([1, 2, 3, 5, 6, 8, 9, 10].map(severityClass)).toEqual([
      "low",
      "low",
      "medium",
      "medium",
      "high",
      "high",
      "critical",
      "critical",
    ]);
  });
});
