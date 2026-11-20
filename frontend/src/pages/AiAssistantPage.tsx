import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Bot, CheckCircle2, Send, Shield, Sparkles } from "lucide-react";
import { apiRequest } from "../services/api";
import { Investigation, MitreTechnique } from "../types";
import { PageHeader } from "../components/ui/Badges";
import { useAuth } from "../context/AuthContext";

interface ChatTurn {
  role: "user" | "assistant";
  content: string;
}

export const AiAssistantPage: React.FC = () => {
  const { canMutate } = useAuth();
  const [searchParams] = useSearchParams();
  const initialScanId = searchParams.get("scanId") || "";
  const initialInvId = searchParams.get("investigationId") || "";

  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [selectedInvId, setSelectedInvId] = useState(initialInvId);
  const [saveNote, setSaveNote] = useState(false);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [messages, setMessages] = useState<ChatTurn[]>([
    {
      role: "assistant",
      content:
        "### THREATLENS AI SOC Copilot Ready\nSelect an active **Investigation** above (or ask directly) to analyze indicators, explain SPF/DKIM/DMARC or CVSS evidence, map threats to **MITRE ATT&CK**, or draft an **Executive Incident Summary**.",
    },
  ]);
  const [suggested, setSuggested] = useState<string[]>([
    "How do we triage phishing SPF, DKIM, and DMARC failures?",
    "Prioritize CISA KEV vulnerabilities like CVE-2024-3094",
    "Draft an executive summary for our active investigation",
    "What NIST containment steps should run first for a C2 IP?",
  ]);
  const [mitre, setMitre] = useState<MitreTechnique[]>([]);
  const [steps, setSteps] = useState<string[]>([]);

  useEffect(() => {
    apiRequest<{ investigations: Investigation[] }>("/api/investigations")
      .then((res) => setInvestigations(res.investigations))
      .catch(() => {});
  }, []);

  const sendMessage = async (promptText: string) => {
    const trimmed = promptText.trim();
    if (!trimmed || sending) return;

    const nextHistory: ChatTurn[] = [...messages, { role: "user", content: trimmed }];
    setMessages(nextHistory);
    setInput("");
    setSending(true);

    try {
      const res = await apiRequest<{
        reply: string;
        suggested_questions: string[];
        mitre_mappings: MitreTechnique[];
        recommended_steps: string[];
      }>("/api/assistant/chat", {
        method: "POST",
        body: JSON.stringify({
          message: trimmed,
          investigationId: selectedInvId || undefined,
          scanId: !selectedInvId && initialScanId ? initialScanId : undefined,
          saveNoteToInvestigation: saveNote && Boolean(selectedInvId),
          history: messages.slice(-8),
        }),
      });

      setMessages([...nextHistory, { role: "assistant", content: res.reply }]);
      if (res.suggested_questions?.length) setSuggested(res.suggested_questions);
      setMitre(res.mitre_mappings || []);
      setSteps(res.recommended_steps || []);
    } catch (err) {
      setMessages([
        ...nextHistory,
        { role: "assistant", content: `Error: ${(err as Error).message}` },
      ]);
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI Investigation Assistant"
        subtitle="Context-aware defensive SOC Copilot for evidence interpretation, MITRE ATT&CK correlation, and incident containment guidance."
        badge="DEFENSIVE GUARDRAILS ACTIVE"
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Chat Column */}
        <div className="lg:col-span-2 bg-soc-panel/90 border border-slate-800 rounded-xl flex flex-col h-[640px]">
          {/* Context Toolbar */}
          <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2 flex-1 min-w-[220px]">
              <span className="text-xs font-mono text-slate-400 shrink-0">
                Case Context:
              </span>
              <select
                value={selectedInvId}
                onChange={(e) => setSelectedInvId(e.target.value)}
                className="flex-1 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:border-cyan-500 focus:outline-none"
              >
                <option value="">General SOC Knowledge Base</option>
                {investigations.map((inv) => (
                  <option key={inv.id} value={inv.id}>
                    {inv.code} — {inv.title.slice(0, 48)}
                  </option>
                ))}
              </select>
            </div>

            {canMutate && selectedInvId && (
              <label className="inline-flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={saveNote}
                  onChange={(e) => setSaveNote(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-900 text-cyan-500"
                />
                Save reply as Case Note
              </label>
            )}
          </div>

          {/* Messages Stream */}
          <div className="flex-1 overflow-y-auto p-5 space-y-4">
            {messages.map((m, idx) => (
              <div
                key={idx}
                className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}
              >
                <div
                  className={`max-w-[85%] rounded-xl p-4 text-sm whitespace-pre-wrap leading-relaxed ${
                    m.role === "user"
                      ? "bg-cyan-500/20 text-cyan-100 border border-cyan-500/30"
                      : "bg-soc-card text-slate-200 border border-slate-800"
                  }`}
                >
                  {m.role === "assistant" && (
                    <div className="flex items-center gap-1.5 text-[11px] font-mono text-cyan-400 mb-1.5">
                      <Bot className="w-3.5 h-3.5" /> THREATLENS COPILOT
                    </div>
                  )}
                  {m.content}
                </div>
              </div>
            ))}
            {sending && (
              <div className="text-xs font-mono text-cyan-400 animate-pulse">
                Correlating threat intelligence & MITRE ATT&CK techniques...
              </div>
            )}
          </div>

          {/* Input Box */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void sendMessage(input);
            }}
            className="p-4 border-t border-slate-800 flex gap-2"
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask about an indicator, SPF/DMARC anomaly, CVE remediation, or containment step..."
              className="flex-1 px-4 py-2.5 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyan-500 focus:outline-none text-sm text-white"
            />
            <button
              type="submit"
              disabled={sending || !input.trim()}
              className="px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-sm inline-flex items-center gap-2 transition"
            >
              <Send className="w-4 h-4" />
              Send
            </button>
          </form>
        </div>

        {/* Side Intelligence Drawer */}
        <div className="space-y-6">
          <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-5 space-y-3">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              Suggested SOC Prompts
            </h3>
            <div className="space-y-2">
              {suggested.map((q) => (
                <button
                  key={q}
                  onClick={() => void sendMessage(q)}
                  className="w-full p-2.5 rounded-lg bg-soc-card hover:bg-slate-800 border border-slate-800 text-left text-xs text-slate-300 transition"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>

          {mitre.length > 0 && (
            <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-5 space-y-3">
              <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <Shield className="w-4 h-4 text-red-400" />
                Referenced MITRE ATT&CK
              </h3>
              <div className="space-y-2">
                {mitre.map((t) => (
                  <div
                    key={t.id}
                    className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-xs font-mono text-red-200"
                  >
                    <strong>{t.id}</strong> · {t.name}
                    <div className="text-[10px] text-red-300/80 mt-0.5">
                      Tactic: {t.tactic}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {steps.length > 0 && (
            <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-5 space-y-3">
              <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Recommended Triage Checklist
              </h3>
              <ul className="space-y-2">
                {steps.map((s, idx) => (
                  <li key={idx} className="text-xs text-slate-300 flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span>{s}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
