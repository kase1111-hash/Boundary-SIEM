import React, { useCallback, useEffect, useRef } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { ConnectionStatus } from "./ConnectionStatus";
import { ApiKeyControl } from "./ApiKeyDialog";
import { useWebSocket } from "../hooks/useWebSocket";
import type { EventStats, WSServerMessage } from "../types/api";

const navItems = [
  { to: "/", label: "Dashboard" },
  { to: "/alerts", label: "Alerts" },
  { to: "/events", label: "Events" },
  { to: "/rules", label: "Rules" },
];

// Coalesce bursts of alert notifications into one refetch.
const ALERT_REFRESH_DELAY_MS = 1000;

export const Layout: React.FC = () => {
  const queryClient = useQueryClient();
  const alertRefreshRef = useRef<ReturnType<typeof setTimeout>>();

  useEffect(
    () => () => {
      if (alertRefreshRef.current) clearTimeout(alertRefreshRef.current);
    },
    [],
  );

  const handleMessage = useCallback(
    (raw: unknown) => {
      const msg = raw as WSServerMessage;
      switch (msg?.type) {
        case "alert":
          if (!alertRefreshRef.current) {
            alertRefreshRef.current = setTimeout(() => {
              alertRefreshRef.current = undefined;
              queryClient.invalidateQueries({ queryKey: ["alerts"] });
              queryClient.invalidateQueries({ queryKey: ["alert"] });
              queryClient.invalidateQueries({ queryKey: ["recent-alerts"] });
              queryClient.invalidateQueries({ queryKey: ["alert-stats"] });
            }, ALERT_REFRESH_DELAY_MS);
          }
          break;
        case "stats":
          queryClient.setQueryData<EventStats>(["event-stats"], msg.data);
          break;
        default:
          // "event" frames are accepted but not rendered yet
          break;
      }
    },
    [queryClient],
  );

  const { status } = useWebSocket({ enabled: true, onMessage: handleMessage });

  return (
    <div className="min-h-screen bg-gray-900 flex flex-col">
      <header className="bg-gray-900 border-b border-gray-800 px-6 py-3">
        <div className="flex justify-between items-center">
          <div className="flex items-center gap-6">
            <h1 className="text-lg font-bold text-white">Boundary SIEM</h1>
            <nav className="flex gap-1">
              {navItems.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === "/"}
                  className={({ isActive }) =>
                    `px-3 py-1.5 rounded text-sm transition ${
                      isActive
                        ? "bg-blue-600 text-white"
                        : "text-gray-400 hover:bg-gray-800 hover:text-white"
                    }`
                  }
                >
                  {item.label}
                </NavLink>
              ))}
            </nav>
          </div>
          <div className="flex items-center gap-4">
            <ApiKeyControl />
            <ConnectionStatus status={status} />
          </div>
        </div>
      </header>
      <main className="flex-1 p-6 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
};
