import React from "react";
import type { WSStatus } from "../hooks/useWebSocket";

const statusConfig: Record<WSStatus, { color: string; label: string }> = {
  connected: { color: "bg-green-500", label: "Live" },
  connecting: { color: "bg-yellow-500", label: "Connecting" },
  disconnected: { color: "bg-red-500", label: "Offline" },
};

export const ConnectionStatus: React.FC<{ status: WSStatus }> = ({
  status,
}) => {
  const { color, label } = statusConfig[status];
  return (
    <div className="flex items-center gap-1.5 text-xs text-gray-400">
      <span className={`w-2 h-2 rounded-full ${color}`} />
      {label}
    </div>
  );
};
