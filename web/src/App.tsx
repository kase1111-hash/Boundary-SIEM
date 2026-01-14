// React SOC Dashboard for Boundary SIEM
import React, { useState, useEffect, useCallback } from "react";

// Types
interface DashboardStats {
  total_events: number;
  events_per_second: number;
  active_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  medium_alerts: number;
  low_alerts: number;
  validators_online: number;
  validators_offline: number;
  nodes_healthy: number;
  nodes_unhealthy: number;
  compliance_score: number;
  threat_level: string;
  top_sources: SourceStats[];
  top_alert_types: AlertTypeStats[];
  recent_incidents: IncidentBrief[];
  last_updated: string;
}

interface SourceStats {
  source: string;
  count: number;
}

interface AlertTypeStats {
  type: string;
  count: number;
}

interface IncidentBrief {
  id: string;
  title: string;
  severity: string;
  status: string;
  created_at: string;
}

interface User {
  id: string;
  username: string;
  email: string;
  display_name: string;
  roles: string[];
  tenant_id: string;
}

interface Widget {
  id: string;
  type: string;
  title: string;
  description?: string;
  data_source: string;
  refresh_rate: number;
  position: { x: number; y: number };
  size: { width: number; height: number };
}

interface Layout {
  id: string;
  name: string;
  description?: string;
  widgets: string[];
  is_default: boolean;
}

// API client
const API_BASE = "/api";

async function fetchStats(): Promise<DashboardStats> {
  const response = await fetch(`${API_BASE}/dashboard/stats`);
  if (!response.ok) throw new Error("Failed to fetch stats");
  return response.json();
}

async function fetchWidgets(): Promise<Widget[]> {
  const response = await fetch(`${API_BASE}/dashboard/widgets`);
  if (!response.ok) throw new Error("Failed to fetch widgets");
  return response.json();
}

async function fetchLayouts(): Promise<Layout[]> {
  const response = await fetch(`${API_BASE}/dashboard/layouts`);
  if (!response.ok) throw new Error("Failed to fetch layouts");
  return response.json();
}

async function login(
  username: string,
  password: string,
): Promise<{ token: string; user: User }> {
  const response = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!response.ok) throw new Error("Authentication failed");
  return response.json();
}

// Components
const SeverityBadge: React.FC<{ severity: string }> = ({ severity }) => {
  const colors: Record<string, string> = {
    critical: "bg-red-600",
    high: "bg-orange-500",
    medium: "bg-yellow-500",
    low: "bg-blue-500",
  };
  return (
    <span
      className={`px-2 py-1 rounded text-white text-xs font-medium ${colors[severity] || "bg-gray-500"}`}
    >
      {severity.toUpperCase()}
    </span>
  );
};

const StatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const colors: Record<string, string> = {
    investigating: "bg-yellow-500",
    mitigated: "bg-blue-500",
    resolved: "bg-green-500",
    open: "bg-red-500",
  };
  return (
    <span
      className={`px-2 py-1 rounded text-white text-xs font-medium ${colors[status] || "bg-gray-500"}`}
    >
      {status}
    </span>
  );
};

const MetricCard: React.FC<{
  title: string;
  value: string | number;
  subtitle?: string;
  color?: string;
}> = ({ title, value, subtitle, color = "text-white" }) => (
  <div className="bg-gray-800 rounded-lg p-4 shadow-lg">
    <h3 className="text-gray-400 text-sm font-medium">{title}</h3>
    <p className={`text-3xl font-bold ${color} mt-2`}>{value}</p>
    {subtitle && <p className="text-gray-500 text-xs mt-1">{subtitle}</p>}
  </div>
);

const AlertSummary: React.FC<{ stats: DashboardStats }> = ({ stats }) => (
  <div className="bg-gray-800 rounded-lg p-4 shadow-lg">
    <h3 className="text-white text-lg font-semibold mb-4">Active Alerts</h3>
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <span className="text-red-400">Critical</span>
        <span className="text-2xl font-bold text-red-400">
          {stats.critical_alerts}
        </span>
      </div>
      <div className="flex justify-between items-center">
        <span className="text-orange-400">High</span>
        <span className="text-2xl font-bold text-orange-400">
          {stats.high_alerts}
        </span>
      </div>
      <div className="flex justify-between items-center">
        <span className="text-yellow-400">Medium</span>
        <span className="text-2xl font-bold text-yellow-400">
          {stats.medium_alerts}
        </span>
      </div>
      <div className="flex justify-between items-center">
        <span className="text-blue-400">Low</span>
        <span className="text-2xl font-bold text-blue-400">
          {stats.low_alerts}
        </span>
      </div>
    </div>
  </div>
);

const ValidatorHealth: React.FC<{ online: number; offline: number }> = ({
  online,
  offline,
}) => {
  const total = online + offline;
  const healthPercent = total > 0 ? (online / total) * 100 : 0;
  return (
    <div className="bg-gray-800 rounded-lg p-4 shadow-lg">
      <h3 className="text-white text-lg font-semibold mb-4">
        Validator Health
      </h3>
      <div className="relative pt-1">
        <div className="flex justify-between mb-2">
          <span className="text-green-400">{online} Online</span>
          <span className="text-red-400">{offline} Offline</span>
        </div>
        <div className="overflow-hidden h-2 mb-4 text-xs flex rounded bg-gray-700">
          <div
            style={{ width: `${healthPercent}%` }}
            className="shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center bg-green-500"
          />
        </div>
        <p className="text-gray-400 text-sm">
          {healthPercent.toFixed(1)}% Healthy
        </p>
      </div>
    </div>
  );
};

const ThreatGauge: React.FC<{ level: string }> = ({ level }) => {
  const levels: Record<string, { color: string; percent: number }> = {
    low: { color: "text-green-400", percent: 25 },
    medium: { color: "text-yellow-400", percent: 50 },
    high: { color: "text-orange-400", percent: 75 },
    critical: { color: "text-red-400", percent: 100 },
  };
  const { color, percent } = levels[level] || levels.low;
  return (
    <div className="bg-gray-800 rounded-lg p-4 shadow-lg">
      <h3 className="text-white text-lg font-semibold mb-4">Threat Level</h3>
      <div className="flex items-center justify-center">
        <div className="relative w-32 h-32">
          <svg className="w-full h-full" viewBox="0 0 36 36">
            <path
              className="text-gray-700"
              strokeWidth="3"
              stroke="currentColor"
              fill="none"
              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            />
            <path
              className={color}
              strokeWidth="3"
              strokeDasharray={`${percent}, 100`}
              strokeLinecap="round"
              stroke="currentColor"
              fill="none"
              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className={`text-xl font-bold ${color} uppercase`}>
              {level}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

const ComplianceScore: React.FC<{ score: number }> = ({ score }) => {
  const getColor = (s: number) => {
    if (s >= 90) return "text-green-400";
    if (s >= 70) return "text-yellow-400";
    if (s >= 50) return "text-orange-400";
    return "text-red-400";
  };
  return (
    <div className="bg-gray-800 rounded-lg p-4 shadow-lg">
      <h3 className="text-white text-lg font-semibold mb-4">
        Compliance Score
      </h3>
      <div className="flex items-center justify-center">
        <div className={`text-5xl font-bold ${getColor(score)}`}>
          {score.toFixed(1)}%
        </div>
      </div>
      <p className="text-gray-400 text-sm text-center mt-2">
        SOC 2 / ISO 27001
      </p>
    </div>
  );
};

const TopSources: React.FC<{ sources: SourceStats[] }> = ({ sources }) => (
  <div className="bg-gray-800 rounded-lg p-4 shadow-lg">
    <h3 className="text-white text-lg font-semibold mb-4">Top Event Sources</h3>
    <div className="space-y-2">
      {sources.slice(0, 5).map((source) => (
        <div key={source.source} className="flex justify-between items-center">
          <span className="text-gray-300 text-sm truncate flex-1">
            {source.source}
          </span>
          <span className="text-blue-400 font-medium ml-2">
            {source.count.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  </div>
);

const RecentIncidents: React.FC<{ incidents: IncidentBrief[] }> = ({
  incidents,
}) => (
  <div className="bg-gray-800 rounded-lg p-4 shadow-lg">
    <h3 className="text-white text-lg font-semibold mb-4">Recent Incidents</h3>
    <div className="space-y-3">
      {incidents.map((incident) => (
        <div key={incident.id} className="border-l-4 border-gray-600 pl-3 py-1">
          <div className="flex justify-between items-start">
            <span className="text-gray-300 text-sm font-medium">
              {incident.title}
            </span>
            <SeverityBadge severity={incident.severity} />
          </div>
          <div className="flex justify-between items-center mt-1">
            <span className="text-gray-500 text-xs">{incident.id}</span>
            <StatusBadge status={incident.status} />
          </div>
        </div>
      ))}
    </div>
  </div>
);

const Header: React.FC<{ user?: User; onLogout: () => void }> = ({
  user,
  onLogout,
}) => (
  <header className="bg-gray-900 border-b border-gray-800 px-6 py-4">
    <div className="flex justify-between items-center">
      <div className="flex items-center space-x-4">
        <h1 className="text-xl font-bold text-white">Boundary SIEM</h1>
        <span className="text-gray-500">|</span>
        <span className="text-gray-400">SOC Dashboard</span>
      </div>
      <div className="flex items-center space-x-4">
        {user && (
          <>
            <span className="text-gray-400">
              {user.display_name || user.username}
            </span>
            <button
              onClick={onLogout}
              className="px-3 py-1 bg-gray-700 text-gray-300 rounded hover:bg-gray-600 transition"
            >
              Logout
            </button>
          </>
        )}
      </div>
    </div>
  </header>
);

const Sidebar: React.FC<{
  activeLayout: string;
  layouts: Layout[];
  onLayoutChange: (id: string) => void;
}> = ({ activeLayout, layouts, onLayoutChange }) => (
  <aside className="w-64 bg-gray-900 border-r border-gray-800 p-4">
    <nav className="space-y-2">
      <h2 className="text-gray-400 text-xs uppercase tracking-wider mb-4">
        Dashboards
      </h2>
      {layouts.map((layout) => (
        <button
          key={layout.id}
          onClick={() => onLayoutChange(layout.id)}
          className={`w-full text-left px-3 py-2 rounded transition ${
            activeLayout === layout.id
              ? "bg-blue-600 text-white"
              : "text-gray-400 hover:bg-gray-800 hover:text-white"
          }`}
        >
          {layout.name}
        </button>
      ))}
    </nav>
    <div className="mt-8 space-y-2">
      <h2 className="text-gray-400 text-xs uppercase tracking-wider mb-4">
        Navigation
      </h2>
      {[
        "Alerts",
        "Events",
        "Validators",
        "Compliance",
        "Reports",
        "Settings",
      ].map((item) => (
        <button
          key={item}
          className="w-full text-left px-3 py-2 rounded text-gray-400 hover:bg-gray-800 hover:text-white transition"
        >
          {item}
        </button>
      ))}
    </div>
  </aside>
);

const LoginForm: React.FC<{
  onLogin: (username: string, password: string) => void;
  error?: string;
}> = ({ onLogin, error }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onLogin(username, password);
  };

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center">
      <div className="bg-gray-800 p-8 rounded-lg shadow-xl w-96">
        <h1 className="text-2xl font-bold text-white text-center mb-6">
          Boundary SIEM
        </h1>
        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <div className="bg-red-500/20 border border-red-500 text-red-400 px-4 py-2 rounded text-sm">
              {error}
            </div>
          )}
          <div>
            <label className="block text-gray-400 text-sm mb-2">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-gray-700 text-white px-4 py-2 rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
              placeholder="Enter username"
            />
          </div>
          <div>
            <label className="block text-gray-400 text-sm mb-2">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-gray-700 text-white px-4 py-2 rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
              placeholder="Enter password"
            />
          </div>
          <button
            type="submit"
            className="w-full bg-blue-600 text-white py-2 rounded font-medium hover:bg-blue-700 transition"
          >
            Sign In
          </button>
        </form>
        <p className="text-gray-500 text-xs text-center mt-4">
          Supports OAuth, SAML, and LDAP
        </p>
      </div>
    </div>
  );
};

// Main Dashboard Component
const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [layouts, setLayouts] = useState<Layout[]>([]);
  const [activeLayout, setActiveLayout] = useState("soc-main");
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(
    localStorage.getItem("token"),
  );
  const [loginError, setLoginError] = useState<string>();
  const [loading, setLoading] = useState(true);

  const loadData = useCallback(async () => {
    try {
      const [statsData, layoutsData] = await Promise.all([
        fetchStats(),
        fetchLayouts(),
      ]);
      setStats(statsData);
      setLayouts(layoutsData);
    } catch (error) {
      console.error("Failed to load dashboard data:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (token) {
      loadData();
      const interval = setInterval(loadData, 30000); // Refresh every 30 seconds
      return () => clearInterval(interval);
    } else {
      setLoading(false);
    }
  }, [token, loadData]);

  const handleLogin = async (username: string, password: string) => {
    try {
      setLoginError(undefined);
      const result = await login(username, password);
      setToken(result.token);
      setUser(result.user);
      localStorage.setItem("token", result.token);
    } catch (error) {
      setLoginError("Invalid username or password");
    }
  };

  const handleLogout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem("token");
  };

  if (!token) {
    return <LoginForm onLogin={handleLogin} error={loginError} />;
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-white text-xl">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 flex flex-col">
      <Header user={user || undefined} onLogout={handleLogout} />
      <div className="flex flex-1">
        <Sidebar
          activeLayout={activeLayout}
          layouts={layouts}
          onLayoutChange={setActiveLayout}
        />
        <main className="flex-1 p-6">
          {stats && (
            <div className="grid grid-cols-12 gap-4">
              {/* Top Row - Key Metrics */}
              <div className="col-span-3">
                <MetricCard
                  title="Total Events"
                  value={stats.total_events.toLocaleString()}
                  subtitle={`${stats.events_per_second.toFixed(1)} EPS`}
                />
              </div>
              <div className="col-span-3">
                <MetricCard
                  title="Active Alerts"
                  value={stats.active_alerts}
                  subtitle={`${stats.critical_alerts} Critical`}
                  color={
                    stats.critical_alerts > 0 ? "text-red-400" : "text-white"
                  }
                />
              </div>
              <div className="col-span-3">
                <MetricCard
                  title="Nodes"
                  value={`${stats.nodes_healthy} / ${stats.nodes_healthy + stats.nodes_unhealthy}`}
                  subtitle="Healthy"
                  color={
                    stats.nodes_unhealthy > 0
                      ? "text-yellow-400"
                      : "text-green-400"
                  }
                />
              </div>
              <div className="col-span-3">
                <MetricCard
                  title="Compliance"
                  value={`${stats.compliance_score}%`}
                  color="text-green-400"
                />
              </div>

              {/* Second Row - Charts and Status */}
              <div className="col-span-3">
                <AlertSummary stats={stats} />
              </div>
              <div className="col-span-3">
                <ValidatorHealth
                  online={stats.validators_online}
                  offline={stats.validators_offline}
                />
              </div>
              <div className="col-span-3">
                <ThreatGauge level={stats.threat_level} />
              </div>
              <div className="col-span-3">
                <ComplianceScore score={stats.compliance_score} />
              </div>

              {/* Third Row - Lists */}
              <div className="col-span-4">
                <TopSources sources={stats.top_sources} />
              </div>
              <div className="col-span-8">
                <RecentIncidents incidents={stats.recent_incidents} />
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

export default Dashboard;
