import React, { useEffect, useState } from "react";
import { CheckSquare, Plus, Siren, Square } from "lucide-react";
import { apiRequest } from "../services/api";
import { Incident, IncidentStatus, PlaybookStep, Severity } from "../types";
import { PageHeader, SeverityBadge } from "../components/ui/Badges";
import { useAuth } from "../context/AuthContext";

const STATUS_FLOW: IncidentStatus[] = [
  "DETECTED",
  "TRIAGING",
  "CONTAINED",
  "ERADICATED",
  "RESOLVED",
];

export const IncidentsPage: React.FC = () => {
  const { canMutate } = useAuth();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const [title, setTitle] = useState("");
  const [summary, setSummary] = useState("");
  const [severity, setSeverity] = useState<Severity>("CRITICAL");
  const [assetsInput, setAssetsInput] = useState("sso-gateway.corp.demo, m365-mail");
  const [mitreInput, setMitreInput] = useState("T1566.002, T1078");

  const loadIncidents = async (focusId?: string) => {
    const res = await apiRequest<{ incidents: Incident[] }>("/api/incidents");
    setIncidents(res.incidents);
    const target =
      res.incidents.find((i) => i.id === (focusId || selected?.id)) ||
      res.incidents[0] ||
      null;
    setSelected(target);
  };

  useEffect(() => {
    void loadIncidents();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await apiRequest<{ incident: Incident }>("/api/incidents", {
      method: "POST",
      body: JSON.stringify({
        title,
        summary,
        severity,
        affectedAssets: assetsInput
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        mitreTechniques: mitreInput
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      }),
    });
    setTitle("");
    setSummary("");
    setShowCreate(false);
    void loadIncidents(res.incident.id);
  };

  const handleStatusUpdate = async (status: IncidentStatus) => {
    if (!selected || !canMutate) return;
    await apiRequest(`/api/incidents/${selected.id}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    });
    void loadIncidents(selected.id);
  };

  const togglePlaybookStep = async (stepId: string) => {
    if (!selected || !canMutate) return;
    const steps: PlaybookStep[] = (selected.playbookSteps || []).map((step) =>
      step.id === stepId ? { ...step, completed: !step.completed } : step
    );
    await apiRequest(`/api/incidents/${selected.id}`, {
      method: "PATCH",
      body: JSON.stringify({ playbookSteps: steps }),
    });
    void loadIncidents(selected.id);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="SOC Incident Management"
        subtitle="Coordinate incident response lifecycles (NIST SP 800-61), containment playbooks, and affected asset tracking."
        badge={`${incidents.length} INCIDENTS`}
        actions={
          canMutate ? (
            <button
              onClick={() => setShowCreate(!showCreate)}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-red-500 hover:bg-red-400 text-slate-950 transition"
            >
              <Plus className="w-4 h-4" />
              Declare Incident
            </button>
          ) : undefined
        }
      />

      {showCreate && (
        <form
          onSubmit={handleCreate}
          className="bg-soc-panel border border-red-500/40 rounded-xl p-6 space-y-4"
        >
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Siren className="w-4 h-4 text-red-400" /> Declare New Security Incident
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2">
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Incident Title
              </label>
              <input
                required
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g. Compromised VPN Session & C2 Callback Alert"
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Severity SLA
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as Severity)}
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
              >
                <option value="CRITICAL">CRITICAL (15m SLA)</option>
                <option value="HIGH">HIGH (1h SLA)</option>
                <option value="MEDIUM">MEDIUM (4h SLA)</option>
                <option value="LOW">LOW (24h SLA)</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Incident Summary & Impact
            </label>
            <textarea
              required
              rows={3}
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Affected Assets (comma-separated)
              </label>
              <input
                value={assetsInput}
                onChange={(e) => setAssetsInput(e.target.value)}
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-white"
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                MITRE ATT&CK IDs
              </label>
              <input
                value={mitreInput}
                onChange={(e) => setMitreInput(e.target.value)}
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-white"
              />
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setShowCreate(false)}
              className="px-4 py-2 rounded-lg text-xs bg-slate-800 text-slate-300"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-5 py-2 rounded-lg text-xs font-bold bg-red-500 text-slate-950"
            >
              Create Incident
            </button>
          </div>
        </form>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="space-y-3">
          {incidents.map((inc) => (
            <button
              key={inc.id}
              onClick={() => setSelected(inc)}
              className={`w-full text-left p-4 rounded-xl border transition space-y-2 ${
                selected?.id === inc.id
                  ? "bg-soc-panel border-cyan-500/50"
                  : "bg-soc-panel/60 border-slate-800 hover:border-slate-700"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-cyan-400">
                  {inc.code}
                </span>
                <SeverityBadge severity={inc.severity} />
              </div>
              <p className="text-sm font-semibold text-white">{inc.title}</p>
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>Stage: {inc.status}</span>
                <span>Assets: {inc.affectedAssets?.length || 0}</span>
              </div>
            </button>
          ))}
        </div>

        <div className="lg:col-span-2">
          {selected ? (
            <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6 space-y-6">
              <div className="space-y-2 border-b border-slate-800 pb-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-cyan-400">
                      {selected.code}
                    </span>
                    <SeverityBadge severity={selected.severity} />
                    {selected.isDemoData && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30">
                        DEMO INCIDENT
                      </span>
                    )}
                  </div>
                  <span className="text-xs font-mono text-slate-400">
                    Commander: {selected.assignedTo?.name || "SOC Duty"}
                  </span>
                </div>
                <h2 className="text-lg font-bold text-white">{selected.title}</h2>
                <p className="text-sm text-slate-300">{selected.summary}</p>
              </div>

              {/* Lifecycle Pipeline Bar */}
              <div>
                <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-2.5">
                  Incident Response Stage Progression
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                  {STATUS_FLOW.map((st) => {
                    const active = selected.status === st;
                    return (
                      <button
                        key={st}
                        disabled={!canMutate}
                        onClick={() => void handleStatusUpdate(st)}
                        className={`py-2 px-2 rounded-lg text-xs font-mono font-semibold border transition ${
                          active
                            ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/50"
                            : "bg-slate-900 text-slate-400 border-slate-800 hover:border-slate-700"
                        }`}
                      >
                        {st}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Affected Assets & MITRE */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-lg bg-soc-card border border-slate-800 space-y-2">
                  <span className="text-xs font-mono text-slate-400">
                    Affected Assets
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {selected.affectedAssets?.map((a) => (
                      <span
                        key={a}
                        className="px-2 py-1 rounded text-xs font-mono bg-slate-900 text-slate-200 border border-slate-700"
                      >
                        {a}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="p-4 rounded-lg bg-soc-card border border-slate-800 space-y-2">
                  <span className="text-xs font-mono text-slate-400">
                    MITRE ATT&CK Techniques
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {selected.mitreTechniques?.map((m) => (
                      <span
                        key={m}
                        className="px-2 py-1 rounded text-xs font-mono bg-red-500/10 text-red-300 border border-red-500/30"
                      >
                        {m}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Interactive NIST Containment Playbook */}
              <div className="space-y-3">
                <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                  Interactive NIST SP 800-61 Response Playbook
                </h3>
                <div className="space-y-2">
                  {(selected.playbookSteps || []).map((step) => (
                    <button
                      key={step.id}
                      disabled={!canMutate}
                      onClick={() => void togglePlaybookStep(step.id)}
                      className={`w-full p-3.5 rounded-lg border text-left flex items-start gap-3 transition ${
                        step.completed
                          ? "bg-emerald-950/25 border-emerald-500/30 text-emerald-200"
                          : "bg-soc-card border-slate-800 hover:border-slate-700 text-slate-200"
                      }`}
                    >
                      {step.completed ? (
                        <CheckSquare className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                      ) : (
                        <Square className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
                      )}
                      <div className="space-y-0.5">
                        <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-900 text-cyan-300">
                          {step.phase}
                        </span>
                        <p
                          className={`text-xs mt-1 ${
                            step.completed ? "line-through opacity-80" : ""
                          }`}
                        >
                          {step.task}
                        </p>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
};
