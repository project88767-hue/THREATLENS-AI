import React from "react";
import { Severity, Verdict } from "../../types";

export const SeverityBadge: React.FC<{ severity: Severity | string }> = ({
  severity,
}) => {
  const styles: Record<string, string> = {
    CRITICAL:
      "bg-red-500/15 text-red-300 border-red-500/40 shadow-[0_0_12px_rgba(239,68,68,0.2)]",
    HIGH: "bg-orange-500/15 text-orange-300 border-orange-500/40",
    MEDIUM: "bg-amber-500/15 text-amber-300 border-amber-500/40",
    LOW: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  };
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold border ${
        styles[severity] || "bg-slate-800 text-slate-300 border-slate-700"
      }`}
    >
      {severity}
    </span>
  );
};

export const VerdictBadge: React.FC<{ verdict: Verdict | string }> = ({
  verdict,
}) => {
  const styles: Record<string, string> = {
    MALICIOUS: "bg-red-950/70 text-red-300 border-red-500/40",
    SUSPICIOUS: "bg-amber-950/70 text-amber-300 border-amber-500/40",
    CLEAN: "bg-emerald-950/70 text-emerald-300 border-emerald-500/40",
    INFO: "bg-cyan-950/70 text-cyan-300 border-cyan-500/40",
  };
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-mono font-medium border ${
        styles[verdict] || "bg-slate-800 text-slate-300 border-slate-700"
      }`}
    >
      {verdict}
    </span>
  );
};

export const TelemetrySourceBadge: React.FC<{ isSimulated: boolean }> = ({
  isSimulated,
}) => {
  return isSimulated ? (
    <span
      title="Clearly labelled Demo/Fallback Intelligence (configure API key in server .env for live vendor queries)"
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-purple-500/15 text-purple-300 border border-purple-500/30"
    >
      DEMO TELEMETRY
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
      LIVE INTEL
    </span>
  );
};

export const RiskScoreGauge: React.FC<{
  score: number;
  severity: Severity;
  size?: number;
}> = ({ score, severity, size = 132 }) => {
  const radius = (size - 16) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.min(100, Math.max(0, score));
  const strokeDashoffset = circumference - (clamped / 100) * circumference;

  const strokeColor =
    severity === "CRITICAL"
      ? "#EF4444"
      : severity === "HIGH"
      ? "#F97316"
      : severity === "MEDIUM"
      ? "#F59E0B"
      : "#10B981";

  return (
    <div
      className="relative inline-flex items-center justify-center"
      style={{ width: size, height: size }}
    >
      <svg className="-rotate-90" width={size} height={size}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke="#1E293B"
          strokeWidth="10"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke={strokeColor}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          style={{ transition: "stroke-dashoffset 0.6s ease-out" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold font-mono text-white">{clamped}</span>
        <span className="text-[11px] uppercase tracking-wider text-slate-400">
          / 100 RISK
        </span>
      </div>
    </div>
  );
};

export const PageHeader: React.FC<{
  title: string;
  subtitle: string;
  badge?: string;
  actions?: React.ReactNode;
}> = ({ title, subtitle, badge, actions }) => (
  <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-6 border-b border-slate-800/80 mb-6">
    <div>
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-bold tracking-tight text-white">{title}</h1>
        {badge && (
          <span className="px-2.5 py-0.5 text-xs font-mono rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
            {badge}
          </span>
        )}
      </div>
      <p className="text-sm text-slate-400 mt-1">{subtitle}</p>
    </div>
    {actions && <div className="flex items-center gap-3">{actions}</div>}
  </div>
);
