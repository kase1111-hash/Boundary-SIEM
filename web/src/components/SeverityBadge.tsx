import React from "react";
import type { Severity } from "../types/api";

const colors: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
};

export const SeverityBadge: React.FC<{ severity: Severity | string }> = ({
  severity,
}) => (
  <span
    className={`px-2 py-0.5 rounded text-white text-xs font-medium ${colors[severity] || "bg-gray-500"}`}
  >
    {severity.toUpperCase()}
  </span>
);
