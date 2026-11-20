import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  FolderPlus,
  Layers,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import { ScanResult } from "../../types";
import {
  RiskScoreGauge,
  SeverityBadge,
  TelemetrySourceBadge,
  VerdictBadge,
} from "../ui/Badges";
import { apiRequest } from "../../services/api";
import { useAuth } from "../../context/AuthContext";

export const ScanResultPanel: React.FC<{ scan: ScanResult }> = ({ scan }) => {
  const { canMutate } = useAuth();
  const navigate = useNavigate();
  const [creatingCase, setCreatingCase] = useState(false);
  const [caseCreatedMsg, setCaseCreatedMsg] = useState<string | null>(null);

  const breakdown = Array.isArray(scan.scoreBreakdown) ? scan.scoreBreakdown : [];
  const ai = scan.aiExplanation || {
    overview: scan.summary,
    why_flagged: [],
    mitre_techniques: [],
    recommended_actions: [],
  };
  const providerEntries = Object.entries(scan.providerStatus || {});

  const handleEscalateCase = async () => {
    setCreatingCase(true);
    setCaseCreatedMsg(null);
    try {
      const res = await apiRequest<{ investigation: { id: string; code: string } }>(
        "/api/investigations",
        {
          method: "POST",
          body: JSON.stringify({
            title: `${scan.scanType} Triage — ${scan.normalizedValue.slice(0, 60)}`,
            description: scan.summary,
            priority: scan.severity,
            tags: [scan.scanType.toLowerCase(), scan.verdict.toLowerCase()],
            scanId: scan.id,
          }),
        }
      );
      setCaseCreatedMsg(
        `Linked to new case ${res.investigation.code}. Open Investigations to collaborate.`
      );
    } catch (err) {
      setCaseCreatedMsg((err as Error).message);
    } finally {
      setCreatingCase(false);
    }
  };

  return (
    <div className="space-y-6 mt-6">
      {/* Top Summary & Risk Gauge Card */}
      <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          <div className="flex flex-col sm:flex-row items-center gap-6">
            <RiskScoreGauge score={scan.riskScore} severity={scan.severity} />
            <div className="space-y-2 text-center sm:text-left">
              <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2">
                <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                  {scan.scanType}
                </span>
                <SeverityBadge severity={scan.severity} />
                <VerdictBadge verdict={scan.verdict} />
                <span className="text-xs font-mono text-slate-400">
                  Confidence: <strong className="text-slate-200">{scan.confidence}%</strong>
                </span>
              </div>
              <h2 className="text-lg font-mono font-semibold text-white break-all">
                {scan.normalizedValue}
              </h2>
              <p className="text-sm text-slate-300 max-w-2xl">{scan.summary}</p>
            </div>
          </div>

          {canMutate && (
            <div className="flex flex-wrap gap-2 w-full lg:w-auto justify-end">
              <button
                onClick={handleEscalateCase}
                disabled={creatingCase}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/40 transition"
              >
                <FolderPlus className="w-4 h-4" />
                {creatingCase ? "Creating Case..." : "Open Investigation Case"}
              </button>
              <button
                onClick={() => navigate(`/assistant?scanId=${scan.id}`)}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/40 transition"
              >
                <Bot className="w-4 h-4" />
                Ask AI Copilot
              </button>
            </div>
          )}
        </div>

        {caseCreatedMsg && (
          <div className="mt-4 px-4 py-2.5 rounded-lg bg-cyan-950/60 border border-cyan-500/40 text-xs text-cyan-200 flex items-center justify-between">
            <span>{caseCreatedMsg}</span>
            <button
              onClick={() => navigate("/investigations")}
              className="underline font-semibold ml-3"
            >
              View Investigations
            </button>
          </div>
        )}
      </div>

      {/* Explainable Score Breakdown + AI Explanation Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Explainable Risk Factor Breakdown
            </h3>
            <span className="text-xs font-mono text-slate-400">Weighted 0–100 Scale</span>
          </div>

          <div className="space-y-4">
            {breakdown.map((item, idx) => {
              const pct =
                item.max_points > 0
                  ? Math.min(100, Math.round((item.points / item.max_points) * 100))
                  : 0;
              return (
                <div
                  key={idx}
                  className="p-3.5 rounded-lg bg-soc-card/80 border border-slate-800/90 space-y-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium text-slate-100">
                      {item.factor}
                    </span>
                    <div className="flex items-center gap-2">
                      <TelemetrySourceBadge isSimulated={Boolean(item.is_simulated)} />
                      <span className="text-xs font-mono font-bold text-cyan-300">
                        +{item.points} / {item.max_points} pts
                      </span>
                    </div>
                  </div>
                  <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${
                        pct >= 65
                          ? "bg-red-500"
                          : pct >= 30
                          ? "bg-amber-500"
                          : "bg-emerald-500"
                      }`}
                      style={{ width: `${Math.max(4, pct)}%` }}
                    />
                  </div>
                  <p className="text-xs text-slate-400">{item.reason}</p>
                </div>
              );
            })}
          </div>
        </div>

        {/* AI Threat Explanation & MITRE ATT&CK */}
        <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6 space-y-5">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-emerald-400" />
              AI Analyst Explanation & Playbook
            </h3>
            {ai.is_simulated_ai ? (
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                SOC Reasoning Engine
              </span>
            ) : (
              <span className="text-[11px] font-mono px-2.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/40">
                LIVE LLM AI
              </span>
            )}
          </div>

          <p className="text-sm text-slate-300 leading-relaxed">{ai.overview}</p>

          {ai.why_flagged?.length > 0 && (
            <div>
              <h4 className="text-xs font-mono uppercase text-slate-400 mb-2">
                Key Evidence Signals
              </h4>
              <ul className="space-y-1.5">
                {ai.why_flagged.map((reason, i) => (
                  <li key={i} className="text-xs text-slate-300 flex items-start gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {ai.mitre_techniques?.length > 0 && (
            <div>
              <h4 className="text-xs font-mono uppercase text-slate-400 mb-2">
                MITRE ATT&CK Mapping
              </h4>
              <div className="flex flex-wrap gap-2">
                {ai.mitre_techniques.map((t) => (
                  <span
                    key={t.id}
                    className="px-2.5 py-1 rounded-md text-xs font-mono bg-red-500/10 text-red-300 border border-red-500/30"
                  >
                    {t.id} · {t.name} ({t.tactic})
                  </span>
                ))}
              </div>
            </div>
          )}

          {ai.recommended_actions?.length > 0 && (
            <div>
              <h4 className="text-xs font-mono uppercase text-slate-400 mb-2">
                Recommended Defensive Actions
              </h4>
              <ul className="space-y-1.5">
                {ai.recommended_actions.map((act, i) => (
                  <li key={i} className="text-xs text-emerald-200/90 flex items-start gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                    <span>{act}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>

      {/* Provider Telemetry Status + Raw Normalized Evidence Cards */}
      <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6 space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            Normalized Intelligence Provider Evidence ({scan.evidence?.length || 0})
          </h3>
          <div className="flex flex-wrap gap-2">
            {providerEntries.map(([name, st]) => (
              <span
                key={name}
                title={st.message}
                className="text-[11px] font-mono px-2.5 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300"
              >
                {name}: <strong className="text-cyan-300">{st.mode}</strong> ({st.latency_ms}ms)
              </span>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {scan.evidence?.map((ev) => (
            <div
              key={ev.id}
              className="p-4 rounded-lg bg-soc-card border border-slate-800 space-y-2.5"
            >
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <span className="text-xs font-mono font-bold text-cyan-400">
                  {ev.provider}
                </span>
                <div className="flex items-center gap-2">
                  <TelemetrySourceBadge isSimulated={ev.isSimulated} />
                  <VerdictBadge verdict={ev.verdict} />
                </div>
              </div>
              <p className="text-sm font-medium text-white">{ev.title}</p>
              <p className="text-xs text-slate-400">{ev.category}</p>
              <pre className="text-[11px] font-mono text-slate-300 bg-slate-950/80 border border-slate-800/80 rounded p-2.5 overflow-x-auto max-h-36">
                {JSON.stringify(ev.details, null, 2)}
              </pre>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
