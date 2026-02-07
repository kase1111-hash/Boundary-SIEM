import React from "react";
import type { AlertStatus } from "../types/api";

const colors: Record<string, string> = {
  new: "bg-red-500",
  acknowledged: "bg-yellow-500",
  in_progress: "bg-blue-500",
  resolved: "bg-green-500",
  suppressed: "bg-gray-500",
};

export const StatusBadge: React.FC<{ status: AlertStatus | string }> = ({
  status,
}) => (
  <span
    className={`px-2 py-0.5 rounded text-white text-xs font-medium ${colors[status] || "bg-gray-500"}`}
  >
    {status.replace("_", " ")}
  </span>
);
