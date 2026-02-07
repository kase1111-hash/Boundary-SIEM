import React from "react";
import { NavLink, Outlet } from "react-router-dom";
import { ConnectionStatus } from "./ConnectionStatus";
import { useWebSocket } from "../hooks/useWebSocket";

const navItems = [
  { to: "/", label: "Dashboard" },
  { to: "/alerts", label: "Alerts" },
  { to: "/events", label: "Events" },
  { to: "/rules", label: "Rules" },
];

export const Layout: React.FC = () => {
  const { status } = useWebSocket({ enabled: true });

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
          <ConnectionStatus status={status} />
        </div>
      </header>
      <main className="flex-1 p-6 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
};
