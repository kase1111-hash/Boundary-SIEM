import React from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { getEventStats, getAlertStats, listAlerts } from "../services/api";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

const MetricCard: React.FC<{
  title: string;
  value: string | number;
  subtitle?: string;
  color?: string;
}> = ({ title, value, subtitle, color = "text-white" }) => (
  <div className="bg-gray-800 rounded-lg p-4">
    <h3 className="text-gray-400 text-sm font-medium">{title}</h3>
    <p className={`text-3xl font-bold ${color} mt-1`}>{value}</p>
    {subtitle && <p className="text-gray-500 text-xs mt-1">{subtitle}</p>}
  </div>
);

export const DashboardPage: React.FC = () => {
  const {
    data: stats,
    isError: statsError,
    refetch: refetchStats,
  } = useQuery({
    queryKey: ["event-stats"],
    queryFn: () => getEventStats(),
    refetchInterval: 30_000,
  });

  const { data: alertStats } = useQuery({
    queryKey: ["alert-stats"],
    queryFn: () => getAlertStats(),
    refetchInterval: 30_000,
  });

  const { data: recentAlerts } = useQuery({
    queryKey: ["recent-alerts"],
    queryFn: () => listAlerts({ limit: 5 }),
    refetchInterval: 30_000,
  });

  const totalAlerts =
    typeof alertStats?.total_alerts === "number" ? alertStats.total_alerts : 0;
  const openAlerts =
    typeof alertStats?.open === "number" ? alertStats.open : 0;

  const histogramData = (stats?.time_histogram || []).map((b) => ({
    time:
      typeof b.key === "string"
        ? new Date(b.key).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
          })
        : String(b.key),
    count: b.count,
  }));

  const severityData = (stats?.by_severity || []).map((b) => ({
    name: String(b.key),
    value: b.count,
  }));

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-white">Dashboard</h2>

      {statsError && (
        <div className="bg-gray-800 border border-red-800 rounded-lg px-4 py-3 flex items-center justify-between">
          <span className="text-red-400 text-sm">
            Failed to load dashboard data
          </span>
          <button
            onClick={() => refetchStats()}
            className="px-3 py-1 bg-blue-600 text-white text-sm rounded hover:bg-blue-500"
          >
            Retry
          </button>
        </div>
      )}

      {/* Top metrics */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard
          title="Total Events (24h)"
          value={stats?.total_events?.toLocaleString() ?? "—"}
        />
        <MetricCard
          title="Total Alerts"
          value={totalAlerts}
          color={openAlerts > 0 ? "text-red-400" : "text-white"}
        />
        <MetricCard
          title="Open Alerts"
          value={openAlerts}
          color={openAlerts > 0 ? "text-yellow-400" : "text-green-400"}
        />
        <MetricCard
          title="Top Action"
          value={
            stats?.by_action?.[0]
              ? `${stats.by_action[0].key}`
              : "—"
          }
          subtitle={
            stats?.by_action?.[0]
              ? `${stats.by_action[0].count.toLocaleString()} events`
              : undefined
          }
        />
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* Event histogram */}
        <div className="col-span-8 bg-gray-800 rounded-lg p-4">
          <h3 className="text-white text-sm font-semibold mb-3">
            Events Over Time (24h)
          </h3>
          {histogramData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={histogramData}>
                <XAxis
                  dataKey="time"
                  tick={{ fill: "#9ca3af", fontSize: 11 }}
                  axisLine={{ stroke: "#374151" }}
                />
                <YAxis
                  tick={{ fill: "#9ca3af", fontSize: 11 }}
                  axisLine={{ stroke: "#374151" }}
                />
                <Tooltip
                  contentStyle={{
                    background: "#1f2937",
                    border: "1px solid #374151",
                    borderRadius: 6,
                  }}
                  labelStyle={{ color: "#d1d5db" }}
                />
                <Bar dataKey="count" fill="#3b82f6" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[220px] flex items-center justify-center text-gray-500">
              No data available
            </div>
          )}
        </div>

        {/* Severity breakdown */}
        <div className="col-span-4 bg-gray-800 rounded-lg p-4">
          <h3 className="text-white text-sm font-semibold mb-3">
            By Severity
          </h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={severityData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={2}
                >
                  {severityData.map((entry) => (
                    <Cell
                      key={entry.name}
                      fill={SEVERITY_COLORS[entry.name] || "#6b7280"}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#1f2937",
                    border: "1px solid #374151",
                    borderRadius: 6,
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[220px] flex items-center justify-center text-gray-500">
              No data
            </div>
          )}
        </div>
      </div>

      {/* Recent alerts */}
      <div className="bg-gray-800 rounded-lg p-4">
        <div className="flex justify-between items-center mb-3">
          <h3 className="text-white text-sm font-semibold">Recent Alerts</h3>
          <Link
            to="/alerts"
            className="text-blue-400 text-xs hover:text-blue-300"
          >
            View all
          </Link>
        </div>
        {recentAlerts?.alerts && recentAlerts.alerts.length > 0 ? (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 text-left text-xs border-b border-gray-700">
                <th className="pb-2">Severity</th>
                <th className="pb-2">Title</th>
                <th className="pb-2">Rule</th>
                <th className="pb-2">Status</th>
                <th className="pb-2">Time</th>
              </tr>
            </thead>
            <tbody>
              {recentAlerts.alerts.map((alert) => (
                <tr
                  key={alert.id}
                  className="border-b border-gray-700/50 hover:bg-gray-700/30"
                >
                  <td className="py-2">
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td className="py-2 text-gray-300">
                    <Link
                      to={`/alerts/${alert.id}`}
                      className="hover:text-white"
                    >
                      {alert.title}
                    </Link>
                  </td>
                  <td className="py-2 text-gray-400">{alert.rule_name}</td>
                  <td className="py-2">
                    <StatusBadge status={alert.status} />
                  </td>
                  <td className="py-2 text-gray-500 text-xs">
                    {new Date(alert.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-gray-500 text-sm">No recent alerts</p>
        )}
      </div>
    </div>
  );
};
