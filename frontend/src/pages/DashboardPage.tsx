import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertOctagon,
  Database,
  FolderKanban,
  RefreshCw,
  Siren,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { apiRequest } from "../services/api";
import { DashboardOverview } from "../types";
import { PageHeader, SeverityBadge, VerdictBadge } from "../components/ui/Badges";

const PIE_COLORS = ["#06B6D4", "#10B981", "#F59E0B", "#EF4444", "#8B5CF6"];

export const DashboardPage: React.FC = () => {
  const [data, setData] = useState<DashboardOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDashboard = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiRequest<DashboardOverview>("/api/dashboard/overview");
      setData(res);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadDashboard();
  }, []);

  if (loading && !data) {
    return (
      <div className="p-12 text-center font-mono text-sm text-slate-400">
        Synchronizing SOC Threat Telemetry...
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-6 rounded-xl bg-red-950/60 border border-red-500/40 text-sm text-red-200">
        Failed to load SOC dashboard: {error}
      </div>
    );
  }

  const kpiCards = [
    {
      label: "Total Indicator Scans",
      value: data.kpis.totalScans,
      icon: Activity,
      accent: "text-cyan-400",
    },
    {
      label: "Critical / High Detections",
      value: data.kpis.criticalThreats,
      icon: AlertOctagon,
      accent: "text-red-400",
    },
    {
      label: "Open Investigations",
      value: data.kpis.openInvestigations,
      icon: FolderKanban,
      accent: "text-amber-400",
    },
    {
      label: "Active SOC Incidents",
      value: data.kpis.activeIncidents,
      icon: Siren,
      accent: "text-orange-400",
    },
    {
      label: "Unique Tracked IOCs",
      value: data.kpis.totalIndicators,
      icon: Database,
      accent: "text-emerald-400",
    },
  ];

  const providers = Object.entries(data.engineHealth?.providers || {});

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Operations Dashboard"
        subtitle="Real-time threat intelligence telemetry, risk distribution, and active incident posture."
        badge="LIVE + DEMO BASELINE"
        actions={
          <button
            onClick={loadDashboard}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold bg-soc-panel hover:bg-slate-800 border border-slate-700 text-slate-200 transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh Telemetry
          </button>
        }
      />

      {/* KPI Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {kpiCards.map((card) => {
          const Icon = card.icon;
          return (
            <div
              key={card.label}
              className="p-5 rounded-xl bg-soc-panel/90 border border-slate-800 flex items-center justify-between"
            >
              <div>
                <p className="text-xs font-mono text-slate-400">{card.label}</p>
                <p className="text-3xl font-bold font-mono text-white mt-1">
                  {card.value}
                </p>
              </div>
              <div className="w-10 h-10 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center">
                <Icon className={`w-5 h-5 ${card.accent}`} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-soc-panel/90 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
              7-Day Threat Detection Velocity
            </h2>
            <span className="text-xs font-mono text-slate-400">
              Critical/High vs Medium/Low
            </span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.trendData}>
                <defs>
                  <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.45} />
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="lowGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06B6D4" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                <XAxis dataKey="date" stroke="#64748B" fontSize={12} />
                <YAxis stroke="#64748B" fontSize={12} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0B1120",
                    borderColor: "#1E293B",
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="criticalHigh"
                  name="Critical / High"
                  stroke="#EF4444"
                  fillOpacity={1}
                  fill="url(#critGrad)"
                />
                <Area
                  type="monotone"
                  dataKey="mediumLow"
                  name="Medium / Low"
                  stroke="#06B6D4"
                  fillOpacity={1}
                  fill="url(#lowGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Indicator Type Donut + Severity Bar */}
        <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-5 space-y-5">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
            IOC Modality & Severity Split
          </h2>
          <div className="h-36">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data.indicatorDistribution}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={32}
                  outerRadius={56}
                  paddingAngle={3}
                >
                  {data.indicatorDistribution.map((_, idx) => (
                    <Cell key={idx} fill={PIE_COLORS[idx % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0B1120",
                    borderColor: "#1E293B",
                    fontSize: "12px",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="h-28">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.severityDistribution}>
                <XAxis dataKey="severity" stroke="#64748B" fontSize={11} />
                <YAxis stroke="#64748B" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0B1120",
                    borderColor: "#1E293B",
                    fontSize: "12px",
                  }}
                />
                <Bar dataKey="count" fill="#06B6D4" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Engine Provider Health Strip */}
      <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
        <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
          Intelligence Provider Adapter Matrix:
        </span>
        <div className="flex flex-wrap gap-2">
          {providers.map(([provider, mode]) => (
            <span
              key={provider}
              className="px-2.5 py-1 rounded text-[11px] font-mono bg-slate-900 border border-slate-800 text-slate-300"
            >
              {provider}:{" "}
              <strong
                className={
                  mode.includes("LIVE") ? "text-emerald-400" : "text-purple-300"
                }
              >
                {mode}
              </strong>
            </span>
          ))}
        </div>
      </div>

      {/* Recent Scans & Active Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-soc-panel/90 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
              Recent Threat Intelligence Scans
            </h2>
            <Link
              to="/scanner/url"
              className="text-xs font-mono text-cyan-400 hover:underline"
            >
              Launch New Scan →
            </Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono">
                  <th className="py-2.5 pr-3">TYPE</th>
                  <th className="py-2.5 pr-3">INDICATOR</th>
                  <th className="py-2.5 pr-3">RISK</th>
                  <th className="py-2.5 pr-3">SEVERITY</th>
                  <th className="py-2.5 pr-3">VERDICT</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {data.recentScans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-900/50">
                    <td className="py-3 pr-3 font-mono text-cyan-300">
                      {scan.scanType}
                    </td>
                    <td className="py-3 pr-3 font-mono text-slate-200 max-w-xs truncate">
                      {scan.isDemoData && (
                        <span className="mr-1.5 text-[10px] px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-300">
                          DEMO
                        </span>
                      )}
                      {scan.normalizedValue}
                    </td>
                    <td className="py-3 pr-3 font-mono font-bold text-white">
                      {scan.riskScore}/100
                    </td>
                    <td className="py-3 pr-3">
                      <SeverityBadge severity={scan.severity} />
                    </td>
                    <td className="py-3 pr-3">
                      <VerdictBadge verdict={scan.verdict} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Active SOC Incidents */}
        <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
              Active Incidents
            </h2>
            <Link
              to="/incidents"
              className="text-xs font-mono text-cyan-400 hover:underline"
            >
              Manage All →
            </Link>
          </div>

          <div className="space-y-3">
            {data.activeIncidentsList.map((inc) => (
              <div
                key={inc.id}
                className="p-3.5 rounded-lg bg-soc-card border border-slate-800 space-y-1.5"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-mono text-cyan-400">{inc.code}</span>
                  <SeverityBadge severity={inc.severity} />
                </div>
                <p className="text-sm font-medium text-white">{inc.title}</p>
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                  <span>Status: {inc.status}</span>
                  <span>{inc.assignedTo?.name?.split(" ")[0] || "Unassigned"}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
