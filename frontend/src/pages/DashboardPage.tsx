import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  Check,
  FolderKanban,
  Lock,
  RefreshCw,
  ScanSearch,
  ShieldCheck,
  Siren,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import { apiRequest } from "../services/api";
import { DashboardOverview, Severity } from "../types";
import { SeverityBadge } from "../components/ui/Badges";

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#f59e0b",
  LOW: "#22c55e",
};

const VERDICT_COLORS: Record<string, string> = {
  MALICIOUS: "#ef4444",
  SUSPICIOUS: "#f59e0b",
  CLEAN: "#22c55e",
  INFO: "#38bdf8",
};

const VECTOR_COLORS = ["#ef4444", "#f97316", "#f59e0b", "#22c55e", "#38bdf8"];

const VECTOR_LABELS: Record<string, string> = {
  URL: "Malicious URLs",
  EMAIL: "Phishing / Email",
  IP: "Hostile IPs",
  DOMAIN: "Suspicious Domains",
  CVE: "Vulnerabilities (CVE)",
};

const fmt = (n: number) => n.toLocaleString("en-US");

const Panel: React.FC<{
  title: string;
  subtitle?: string;
  right?: React.ReactNode;
  className?: string;
  children: React.ReactNode;
}> = ({ title, subtitle, right, className = "", children }) => (
  <section className={`tl-panel p-4 ${className}`}>
    <header className="flex items-start justify-between gap-2 mb-3">
      <div>
        <h2 className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-100">
          {title}
        </h2>
        {subtitle && <p className="text-[10px] text-slate-500 mt-0.5">{subtitle}</p>}
      </div>
      {right}
    </header>
    {children}
  </section>
);

const LiveTick: React.FC<{ ok?: boolean }> = ({ ok = true }) => (
  <span
    className={`w-4 h-4 rounded-full flex items-center justify-center ${
      ok ? "bg-emerald-500/20 text-emerald-400" : "bg-amber-500/20 text-amber-400"
    }`}
  >
    <Check className="w-2.5 h-2.5" strokeWidth={3} />
  </span>
);

/** Circular progress ring used for the verdict split. */
const Ring: React.FC<{ pct: number; color: string; label: string; sub: string }> = ({
  pct,
  color,
  label,
  sub,
}) => {
  const r = 20;
  const c = 2 * Math.PI * r;
  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative w-14 h-14">
        <svg viewBox="0 0 52 52" className="w-full h-full -rotate-90">
          <circle cx="26" cy="26" r={r} fill="none" stroke="rgba(148,163,184,0.15)" strokeWidth="4" />
          <circle
            cx="26"
            cy="26"
            r={r}
            fill="none"
            stroke={color}
            strokeWidth="4"
            strokeLinecap="round"
            strokeDasharray={`${(pct / 100) * c} ${c}`}
            style={{ filter: `drop-shadow(0 0 4px ${color})` }}
          />
        </svg>
        <span className="absolute inset-0 flex items-center justify-center text-[11px] font-bold font-mono text-white">
          {pct}%
        </span>
      </div>
      <span className="text-[10px] font-semibold text-slate-200">{label}</span>
      <span className="text-[9px] font-mono text-slate-500">{sub}</span>
    </div>
  );
};

/** Animated shield "reactor" for the centre of the console. */
const ShieldHero: React.FC<{ tone: "ok" | "warn" | "down"; headline: string; sub: string }> = ({
  tone,
  headline,
  sub,
}) => {
  const color = tone === "ok" ? "#22d3ee" : tone === "warn" ? "#f97316" : "#94a3b8";
  const text = tone === "ok" ? "text-emerald-400" : tone === "warn" ? "text-orange-400" : "text-slate-400";
  const blips = [
    [78, 62, "0s"],
    [236, 78, "0.9s"],
    [262, 190, "1.7s"],
    [58, 212, "2.4s"],
    [150, 20, "1.2s"],
    [150, 282, "2s"],
  ] as const;
  return (
    <div className="relative flex flex-col items-center justify-center py-2">
      <div className="absolute inset-0 tl-radar-grid opacity-70" />
      <div className="relative w-[300px] h-[300px] max-w-full">
        <svg viewBox="0 0 300 300" className="w-full h-full overflow-visible">
          <defs>
            <radialGradient id="coreGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor={color} stopOpacity="0.38" />
              <stop offset="100%" stopColor={color} stopOpacity="0" />
            </radialGradient>
            <linearGradient id="sweepGrad" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor={color} stopOpacity="0" />
              <stop offset="100%" stopColor={color} stopOpacity="0.45" />
            </linearGradient>
          </defs>
          <circle cx="150" cy="150" r="145" fill="url(#coreGlow)" className="tl-pulse-glow" />
          <g className="tl-spin-slow">
            <circle cx="150" cy="150" r="138" fill="none" stroke={color} strokeOpacity="0.35" strokeWidth="1" strokeDasharray="2 7" />
            <circle cx="150" cy="12" r="3.5" fill={color} />
            <circle cx="288" cy="150" r="2.5" fill={color} fillOpacity="0.6" />
          </g>
          <g className="tl-spin-mid">
            <circle cx="150" cy="150" r="112" fill="none" stroke={color} strokeOpacity="0.55" strokeWidth="2" strokeDasharray="38 14 6 14" />
          </g>
          <g className="tl-spin-fast">
            <path d="M150 150 L150 52 A98 98 0 0 1 248 150 Z" fill="url(#sweepGrad)" opacity="0.5" />
          </g>
          <circle cx="150" cy="150" r="86" fill="rgba(4,12,30,0.85)" stroke={color} strokeOpacity="0.8" strokeWidth="2.5" style={{ filter: `drop-shadow(0 0 10px ${color})` }} />
          <circle cx="150" cy="150" r="70" fill="none" stroke={color} strokeOpacity="0.25" strokeWidth="1" />
          {blips.map(([x, y, delay], i) => (
            <circle
              key={i}
              cx={x}
              cy={y}
              r="4"
              fill={tone === "warn" ? "#ef4444" : color}
              className="tl-blip"
              style={{ animationDelay: delay }}
            />
          ))}
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="relative">
            <ShieldCheck
              className="w-24 h-24"
              style={{ color, filter: `drop-shadow(0 0 12px ${color})` }}
              strokeWidth={1.4}
            />
            <Lock
              className="absolute left-1/2 top-[44%] -translate-x-1/2 -translate-y-1/2 w-7 h-7 text-white"
              strokeWidth={2.2}
            />
          </div>
        </div>
      </div>
      <div className="relative mt-1 px-8 py-2.5 rounded-lg border border-emerald-400/30 bg-slate-950/70 text-center">
        <div className={`text-sm font-extrabold tracking-[0.22em] ${text}`}>{headline}</div>
        <div className="text-[10px] font-mono tracking-widest text-slate-400 mt-0.5">{sub}</div>
      </div>
    </div>
  );
};

export const DashboardPage: React.FC = () => {
  const [data, setData] = useState<DashboardOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(() => new Date());

  const loadDashboard = async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await apiRequest<DashboardOverview>("/api/dashboard/overview"));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadDashboard();
    const tick = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(tick);
  }, []);

  const derived = useMemo(() => {
    if (!data) return null;
    const sev = (s: Severity) => data.severityDistribution.find((x) => x.severity === s)?.count ?? 0;
    const totalSev = data.severityDistribution.reduce((a, b) => a + b.count, 0);
    const totalScans = data.indicatorDistribution.reduce((a, b) => a + b.value, 0);
    const verdictTotal = data.verdictDistribution.reduce((a, b) => a + b.count, 0);
    const providers = Object.entries(data.engineHealth?.providers || {});
    const engineUp = data.engineHealth?.status === "ok" || providers.length > 0;
    const hotIncidents = data.activeIncidentsList.filter(
      (i) => i.severity === "CRITICAL" || i.severity === "HIGH"
    ).length;
    return { sev, totalSev, totalScans, verdictTotal, providers, engineUp, hotIncidents };
  }, [data]);

  if (loading && !data) {
    return (
      <div className="p-12 text-center font-mono text-sm text-cyan-400 animate-pulse">
        Synchronizing SOC threat telemetry...
      </div>
    );
  }

  if (error || !data || !derived) {
    return (
      <div className="p-6 rounded-xl bg-red-950/60 border border-red-500/40 text-sm text-red-200">
        Failed to load SOC dashboard: {error}
      </div>
    );
  }

  const { sev, totalSev, totalScans, verdictTotal, providers, engineUp, hotIncidents } = derived;
  const tone = !engineUp ? "down" : hotIncidents > 0 ? "warn" : "ok";
  const headline =
    tone === "down" ? "ENGINE OFFLINE" : tone === "warn" ? "THREATS ACTIVE" : "SYSTEM PROTECTED";
  const heroSub =
    tone === "down"
      ? "ANALYSIS ENGINE UNREACHABLE"
      : tone === "warn"
      ? `${hotIncidents} HIGH-SEVERITY INCIDENT${hotIncidents > 1 ? "S" : ""} OPEN`
      : "AI THREAT DETECTION ACTIVE";

  const severityRows: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const donutData = totalSev
    ? severityRows.map((s) => ({ name: s, value: sev(s) }))
    : [{ name: "NONE", value: 1 }];

  const vectors = [...data.indicatorDistribution].sort((a, b) => b.value - a.value);
  const liveProviders = providers.filter(([, m]) => m.includes("LIVE")).length;

  const statusCards = [
    {
      title: "Indicator Scans",
      sub: "Threat-intel lookups",
      icon: ScanSearch,
      big: data.kpis.totalScans,
      a: { label: "Unique IOCs", value: data.kpis.totalIndicators, cls: "text-cyan-400" },
      b: { label: "Crit / High", value: data.kpis.criticalThreats, cls: "text-red-400" },
    },
    {
      title: "Investigations",
      sub: "Case management",
      icon: FolderKanban,
      big: data.kpis.openInvestigations,
      a: { label: "Open", value: data.kpis.openInvestigations, cls: "text-amber-400" },
      b: { label: "Incidents", value: data.kpis.activeIncidents, cls: "text-orange-400" },
    },
    {
      title: "SOC Incidents",
      sub: "Response status",
      icon: Siren,
      big: data.kpis.activeIncidents,
      a: { label: "Active", value: data.kpis.activeIncidents, cls: "text-orange-400" },
      b: { label: "High severity", value: hotIncidents, cls: "text-red-400" },
    },
  ];

  return (
    <div className="space-y-4">
      {/* Console header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-extrabold tracking-wide text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            Security Operations Command Center
          </h1>
          <p className="text-[11px] text-slate-400">
            Real-time threat intelligence for your workspace
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right font-mono leading-tight">
            <div className="text-sm font-bold text-cyan-300">
              {now.toLocaleTimeString("en-GB")}
            </div>
            <div className="text-[10px] text-slate-500">
              {now.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
            </div>
          </div>
          <button
            onClick={loadDashboard}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-200 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[300px_minmax(0,1fr)_310px] gap-4">
        {/* ---------------- LEFT ---------------- */}
        <div className="space-y-4">
          <Panel title="Threat Overview" subtitle="7-day detection summary">
            <div className="h-20 -mx-1">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.trendData} margin={{ top: 4, right: 0, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="ovGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#ef4444" stopOpacity={0.55} />
                      <stop offset="100%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <Tooltip
                    contentStyle={{ backgroundColor: "#050b1a", borderColor: "#164e63", fontSize: "11px", borderRadius: 8 }}
                    labelStyle={{ color: "#94a3b8" }}
                  />
                  <Area type="monotone" dataKey="total" name="Scans" stroke="#ef4444" strokeWidth={2} fill="url(#ovGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <div className="grid grid-cols-4 gap-2 mt-3">
              {severityRows.map((s) => (
                <div key={s}>
                  <div className="text-[9px] font-bold tracking-widest" style={{ color: SEVERITY_COLORS[s] }}>
                    {s}
                  </div>
                  <div className="text-lg font-extrabold font-mono text-white leading-tight">{fmt(sev(s))}</div>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Active Threats" subtitle="By severity" right={<LiveTick />}>
            <div className="flex items-center gap-3">
              <div className="relative w-32 h-32 shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={donutData}
                      dataKey="value"
                      innerRadius={42}
                      outerRadius={60}
                      paddingAngle={totalSev ? 3 : 0}
                      stroke="none"
                      startAngle={90}
                      endAngle={-270}
                    >
                      {donutData.map((d) => (
                        <Cell key={d.name} fill={SEVERITY_COLORS[d.name as Severity] ?? "#1e293b"} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-xl font-extrabold font-mono text-white">{fmt(totalSev)}</span>
                  <span className="text-[9px] tracking-widest text-slate-400">TOTAL</span>
                </div>
              </div>
              <ul className="flex-1 space-y-1.5 text-[11px]">
                {severityRows.map((s) => (
                  <li key={s} className="flex items-center justify-between">
                    <span className="flex items-center gap-1.5 text-slate-300">
                      <span className="w-2 h-2 rounded-full" style={{ background: SEVERITY_COLORS[s] }} />
                      {s.charAt(0) + s.slice(1).toLowerCase()}
                    </span>
                    <span className="font-mono font-bold text-white">{fmt(sev(s))}</span>
                  </li>
                ))}
              </ul>
            </div>
          </Panel>

          <Panel
            title="Threat Activity Feed"
            subtitle="Latest scans"
            right={
              <Link to="/scanner/url" className="text-[10px] font-mono text-cyan-400 hover:underline">
                New scan →
              </Link>
            }
          >
            {data.recentScans.length === 0 ? (
              <p className="text-[11px] text-slate-500 py-4 text-center">
                No activity yet. Run your first scan to start building your threat picture.
              </p>
            ) : (
              <ul className="space-y-2">
                {data.recentScans.slice(0, 6).map((scan) => (
                  <li
                    key={scan.id}
                    className="flex items-start gap-2.5 p-2 rounded-lg bg-slate-950/50 border border-slate-800/80"
                  >
                    <span
                      className="mt-0.5 shrink-0 px-1.5 py-0.5 rounded text-[8px] font-extrabold tracking-wider"
                      style={{
                        color: SEVERITY_COLORS[scan.severity],
                        background: `${SEVERITY_COLORS[scan.severity]}22`,
                      }}
                    >
                      {scan.severity.slice(0, 4)}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="text-[11px] font-semibold text-slate-100 truncate">
                        {scan.verdict === "MALICIOUS"
                          ? "Malicious"
                          : scan.verdict === "SUSPICIOUS"
                          ? "Suspicious"
                          : scan.verdict === "CLEAN"
                          ? "Clean"
                          : "Info"}{" "}
                        {scan.scanType.toLowerCase()} · {scan.riskScore}/100
                      </div>
                      <div className="text-[10px] font-mono text-slate-500 truncate">{scan.normalizedValue}</div>
                    </div>
                    <span className="text-[9px] font-mono text-slate-500 shrink-0">
                      {new Date(scan.createdAt).toLocaleTimeString("en-GB")}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>

        {/* ---------------- CENTER ---------------- */}
        <div className="space-y-4 min-w-0">
          <section className="tl-panel p-4 relative overflow-hidden">
            <div className="flex items-center justify-between mb-1">
              <div>
                <h2 className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-100">
                  Global Threat Posture
                </h2>
                <p className="text-[10px] text-slate-500">Live analysis-engine status</p>
              </div>
              <span className="text-[10px] font-mono px-2 py-1 rounded border border-cyan-500/30 text-cyan-300 bg-cyan-500/10">
                {liveProviders}/{providers.length || 0} PROVIDERS LIVE
              </span>
            </div>
            <ShieldHero tone={tone} headline={headline} sub={heroSub} />
          </section>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {statusCards.map((card) => {
              const Icon = card.icon;
              return (
                <div key={card.title} className="tl-panel p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-[11px] font-bold uppercase tracking-[0.14em] text-slate-100">
                        {card.title}
                      </div>
                      <div className="text-[10px] text-slate-500">{card.sub}</div>
                    </div>
                    <LiveTick />
                  </div>
                  <div className="flex items-center gap-3 mt-3">
                    <Icon className="w-9 h-9 text-cyan-400 shrink-0" strokeWidth={1.4} />
                    <div>
                      <div className="text-3xl font-extrabold font-mono text-white leading-none">{fmt(card.big)}</div>
                      <div className="text-[10px] text-slate-500 mt-1">current</div>
                    </div>
                  </div>
                  <div className="flex items-center justify-between mt-3 pt-2 border-t border-slate-800 text-[10px]">
                    <span className="text-slate-400">
                      {card.a.label} <b className={`font-mono ${card.a.cls}`}>{fmt(card.a.value)}</b>
                    </span>
                    <span className="text-slate-400">
                      {card.b.label} <b className={`font-mono ${card.b.cls}`}>{fmt(card.b.value)}</b>
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          <Panel
            title="Active Incidents"
            subtitle="Unresolved response cases"
            right={
              <Link to="/incidents" className="text-[10px] font-mono text-cyan-400 hover:underline">
                Manage all →
              </Link>
            }
          >
            {data.activeIncidentsList.length === 0 ? (
              <p className="text-[11px] text-slate-500 py-3 text-center">No active incidents. All clear.</p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {data.activeIncidentsList.map((inc) => (
                  <div key={inc.id} className="p-3 rounded-lg bg-slate-950/50 border border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[11px] font-mono text-cyan-400">{inc.code}</span>
                      <SeverityBadge severity={inc.severity} />
                    </div>
                    <p className="text-xs font-medium text-white">{inc.title}</p>
                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
                      <span>{inc.status}</span>
                      <span>{inc.assignedTo?.name?.split(" ")[0] || "Unassigned"}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>

        {/* ---------------- RIGHT ---------------- */}
        <div className="space-y-4">
          <Panel
            title="Threat Detection Engine"
            subtitle="AI-powered analysis"
            right={<BrainCircuit className="w-5 h-5 text-cyan-400" strokeWidth={1.5} />}
          >
            {providers.length === 0 ? (
              <p className="text-[11px] text-amber-300 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" /> Analysis engine is not reporting.
              </p>
            ) : (
              <ul className="space-y-2">
                {providers.map(([name, mode]) => {
                  const live = mode.includes("LIVE");
                  return (
                    <li key={name} className="flex items-center justify-between text-[11px]">
                      <span className="flex items-center gap-2 text-slate-300">
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${live ? "bg-emerald-400 animate-pulse" : "bg-purple-400"}`}
                        />
                        {name}
                      </span>
                      <span className={`font-mono text-[10px] ${live ? "text-emerald-400" : "text-purple-300"}`}>
                        {live ? "Live" : mode.replace(/_/g, " ").toLowerCase()}
                      </span>
                    </li>
                  );
                })}
              </ul>
            )}
            <div className="mt-3 pt-3 border-t border-slate-800">
              <div className="flex justify-between text-[10px] font-mono text-slate-400 mb-1">
                <span>Live coverage</span>
                <span className="text-cyan-300">
                  {providers.length ? Math.round((liveProviders / providers.length) * 100) : 0}%
                </span>
              </div>
              <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-emerald-400"
                  style={{ width: `${providers.length ? (liveProviders / providers.length) * 100 : 0}%` }}
                />
              </div>
            </div>
          </Panel>

          <Panel title="Top Attack Vectors" subtitle="By indicator type">
            {vectors.length === 0 ? (
              <p className="text-[11px] text-slate-500 py-3 text-center">No scans analysed yet.</p>
            ) : (
              <ul className="space-y-3">
                {vectors.map((v, i) => {
                  const pct = totalScans ? Math.round((v.value / totalScans) * 1000) / 10 : 0;
                  return (
                    <li key={v.name}>
                      <div className="flex justify-between text-[11px] mb-1">
                        <span className="text-slate-300">{VECTOR_LABELS[v.name] ?? v.name}</span>
                        <span className="font-mono font-bold text-white">{pct}%</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${pct}%`,
                            background: VECTOR_COLORS[i % VECTOR_COLORS.length],
                            boxShadow: `0 0 8px ${VECTOR_COLORS[i % VECTOR_COLORS.length]}`,
                          }}
                        />
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </Panel>

          <Panel title="Verdict Breakdown" subtitle="Outcome of all your scans">
            <div className="grid grid-cols-4 gap-1">
              {data.verdictDistribution.map((v) => (
                <Ring
                  key={v.verdict}
                  pct={verdictTotal ? Math.round((v.count / verdictTotal) * 100) : 0}
                  color={VERDICT_COLORS[v.verdict]}
                  label={v.verdict.charAt(0) + v.verdict.slice(1).toLowerCase()}
                  sub={fmt(v.count)}
                />
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
};
