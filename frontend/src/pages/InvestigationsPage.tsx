import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Bot,
  FolderPlus,
  MessageSquarePlus,
  Siren,
} from "lucide-react";
import { apiRequest } from "../services/api";
import { Investigation, InvestigationStatus, Severity } from "../types";
import { PageHeader, SeverityBadge, VerdictBadge } from "../components/ui/Badges";
import { useAuth } from "../context/AuthContext";

export const InvestigationsPage: React.FC = () => {
  const { canMutate } = useAuth();
  const navigate = useNavigate();
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [selected, setSelected] = useState<Investigation | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  // Create form state
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState<Severity>("HIGH");
  const [tagsInput, setTagsInput] = useState("phishing, soc-triage");

  // Note state
  const [noteText, setNoteText] = useState("");

  const loadList = async (selectId?: string) => {
    const res = await apiRequest<{ investigations: Investigation[] }>(
      "/api/investigations"
    );
    setInvestigations(res.investigations);
    const targetId = selectId || selected?.id || res.investigations[0]?.id;
    if (targetId) {
      void loadDetail(targetId);
    }
  };

  const loadDetail = async (id: string) => {
    const res = await apiRequest<{ investigation: Investigation }>(
      `/api/investigations/${id}`
    );
    setSelected(res.investigation);
  };

  useEffect(() => {
    void loadList();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await apiRequest<{ investigation: Investigation }>(
      "/api/investigations",
      {
        method: "POST",
        body: JSON.stringify({
          title,
          description,
          priority,
          tags: tagsInput
            .split(",")
            .map((t) => t.trim())
            .filter(Boolean),
        }),
      }
    );
    setTitle("");
    setDescription("");
    setShowCreate(false);
    void loadList(res.investigation.id);
  };

  const handleStatusChange = async (status: InvestigationStatus) => {
    if (!selected) return;
    await apiRequest(`/api/investigations/${selected.id}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    });
    void loadList(selected.id);
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selected || !noteText.trim()) return;
    await apiRequest(`/api/investigations/${selected.id}/notes`, {
      method: "POST",
      body: JSON.stringify({ content: noteText }),
    });
    setNoteText("");
    void loadDetail(selected.id);
  };

  const handleEscalateIncident = async () => {
    if (!selected) return;
    await apiRequest("/api/incidents", {
      method: "POST",
      body: JSON.stringify({
        title: `Escalated Case ${selected.code}: ${selected.title.slice(0, 90)}`,
        summary: selected.description,
        severity: selected.priority,
        investigationId: selected.id,
        affectedAssets: ["enterprise-perimeter"],
      }),
    });
    navigate("/incidents");
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="SOC Investigations"
        subtitle="Manage structured threat investigation cases, linked IOC scans, analyst notes, and incident escalations."
        badge={`${investigations.length} CASES`}
        actions={
          canMutate ? (
            <button
              onClick={() => setShowCreate(!showCreate)}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition"
            >
              <FolderPlus className="w-4 h-4" />
              New Investigation
            </button>
          ) : undefined
        }
      />

      {showCreate && (
        <form
          onSubmit={handleCreate}
          className="bg-soc-panel border border-cyan-500/40 rounded-xl p-6 space-y-4"
        >
          <h3 className="text-sm font-bold text-white">Create New Investigation Case</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2">
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Investigation Title
              </label>
              <input
                required
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g. Suspicious OAuth Token Phishing Campaign"
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Priority
              </label>
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value as Severity)}
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Hypothesis & Scope Description
            </label>
            <textarea
              required
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Document observed alerts, affected business units, and authorized triage boundaries..."
              className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            />
          </div>
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Tags (comma-separated)
            </label>
            <input
              value={tagsInput}
              onChange={(e) => setTagsInput(e.target.value)}
              className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-white"
            />
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
              className="px-5 py-2 rounded-lg text-xs font-bold bg-cyan-500 text-slate-950"
            >
              Create Case
            </button>
          </div>
        </form>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Case List */}
        <div className="space-y-3">
          {investigations.map((inv) => (
            <button
              key={inv.id}
              onClick={() => void loadDetail(inv.id)}
              className={`w-full text-left p-4 rounded-xl border transition space-y-2 ${
                selected?.id === inv.id
                  ? "bg-soc-panel border-cyan-500/50 shadow-lg"
                  : "bg-soc-panel/60 border-slate-800 hover:border-slate-700"
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-mono font-bold text-cyan-400">
                  {inv.code}
                </span>
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    {inv.status}
                  </span>
                  <SeverityBadge severity={inv.priority} />
                </div>
              </div>
              <p className="text-sm font-semibold text-white line-clamp-2">
                {inv.title}
              </p>
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>Scans: {inv._count?.scans ?? 0}</span>
                <span>Notes: {inv._count?.notes ?? 0}</span>
              </div>
            </button>
          ))}
        </div>

        {/* Right Case Workspace */}
        <div className="lg:col-span-2">
          {selected ? (
            <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6 space-y-6">
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-cyan-400">
                      {selected.code}
                    </span>
                    <SeverityBadge severity={selected.priority} />
                    {selected.isDemoData && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30">
                        DEMO CASE
                      </span>
                    )}
                  </div>
                  <h2 className="text-lg font-bold text-white">{selected.title}</h2>
                  <p className="text-sm text-slate-300">{selected.description}</p>
                </div>

                {canMutate && (
                  <div className="flex flex-wrap items-center gap-2">
                    <select
                      value={selected.status}
                      onChange={(e) =>
                        void handleStatusChange(
                          e.target.value as InvestigationStatus
                        )
                      }
                      className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-white"
                    >
                      <option value="OPEN">OPEN</option>
                      <option value="IN_PROGRESS">IN_PROGRESS</option>
                      <option value="ESCALATED">ESCALATED</option>
                      <option value="CLOSED">CLOSED</option>
                    </select>

                    <button
                      onClick={() =>
                        navigate(`/assistant?investigationId=${selected.id}`)
                      }
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
                    >
                      <Bot className="w-3.5 h-3.5" /> AI Copilot
                    </button>

                    <button
                      onClick={handleEscalateIncident}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-500/15 text-red-300 border border-red-500/30"
                    >
                      <Siren className="w-3.5 h-3.5" /> Escalate Incident
                    </button>
                  </div>
                )}
              </div>

              {selected.aiSummary && (
                <div className="p-4 rounded-lg bg-cyan-950/30 border border-cyan-500/30 text-xs text-cyan-100">
                  <strong className="font-mono text-cyan-300 block mb-1">
                    AI CASE SUMMARY
                  </strong>
                  {selected.aiSummary}
                </div>
              )}

              {/* Attached Scans */}
              <div>
                <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3">
                  Linked Indicator Scans ({selected.scans?.length || 0})
                </h3>
                <div className="space-y-2">
                  {selected.scans?.map((s) => (
                    <div
                      key={s.id}
                      className="p-3 rounded-lg bg-soc-card border border-slate-800 flex flex-wrap items-center justify-between gap-2"
                    >
                      <div className="min-w-0">
                        <span className="text-xs font-mono text-cyan-400 mr-2">
                          [{s.scanType}]
                        </span>
                        <span className="text-xs font-mono text-white break-all">
                          {s.normalizedValue}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-white">
                          {s.riskScore}/100
                        </span>
                        <VerdictBadge verdict={s.verdict} />
                      </div>
                    </div>
                  ))}
                  {(!selected.scans || selected.scans.length === 0) && (
                    <p className="text-xs text-slate-500">
                      No scans attached yet. Run a scan and click "Open Investigation Case" or attach from any scanner.
                    </p>
                  )}
                </div>
              </div>

              {/* Analyst & AI Case Notes */}
              <div className="space-y-3">
                <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                  Investigation Timeline & Notes ({selected.notes?.length || 0})
                </h3>

                {canMutate && (
                  <form onSubmit={handleAddNote} className="flex gap-2">
                    <input
                      value={noteText}
                      onChange={(e) => setNoteText(e.target.value)}
                      placeholder="Log forensic observation, SIEM query result, or containment note..."
                      className="flex-1 px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white"
                    />
                    <button
                      type="submit"
                      className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold bg-cyan-500 text-slate-950"
                    >
                      <MessageSquarePlus className="w-3.5 h-3.5" /> Add Note
                    </button>
                  </form>
                )}

                <div className="space-y-2.5 max-h-64 overflow-y-auto">
                  {selected.notes?.map((n) => (
                    <div
                      key={n.id}
                      className="p-3.5 rounded-lg bg-soc-card border border-slate-800 space-y-1"
                    >
                      <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                        <span>
                          {n.author?.name}{" "}
                          {n.isAiGenerated && (
                            <span className="ml-1 px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300">
                              AI COPILOT
                            </span>
                          )}
                        </span>
                        <span>{new Date(n.createdAt).toLocaleString()}</span>
                      </div>
                      <p className="text-xs text-slate-200 whitespace-pre-wrap">
                        {n.content}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="p-12 rounded-xl bg-soc-panel border border-slate-800 text-center text-sm text-slate-400">
              Select an investigation case to view evidence and notes.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
