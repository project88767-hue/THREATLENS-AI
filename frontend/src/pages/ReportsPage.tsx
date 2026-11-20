import React, { useEffect, useState } from "react";
import { Download, FilePlus2, Printer } from "lucide-react";
import { apiRequest } from "../services/api";
import { Incident, Investigation, Report, ReportFormat } from "../types";
import { PageHeader } from "../components/ui/Badges";
import { useAuth } from "../context/AuthContext";

export const ReportsPage: React.FC = () => {
  const { canMutate } = useAuth();
  const [reports, setReports] = useState<Report[]>([]);
  const [selected, setSelected] = useState<Report | null>(null);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [showGenerate, setShowGenerate] = useState(false);

  const [title, setTitle] = useState("Q4 Threat Investigation & Incident Summary");
  const [format, setFormat] = useState<ReportFormat>("EXECUTIVE");
  const [invId, setInvId] = useState("");
  const [incId, setIncId] = useState("");
  const [generating, setGenerating] = useState(false);

  const loadReports = async (focusId?: string) => {
    const res = await apiRequest<{ reports: Report[] }>("/api/reports");
    setReports(res.reports);
    const found =
      res.reports.find((r) => r.id === (focusId || selected?.id)) ||
      res.reports[0] ||
      null;
    setSelected(found);
  };

  useEffect(() => {
    void loadReports();
    apiRequest<{ investigations: Investigation[] }>("/api/investigations")
      .then((r) => {
        setInvestigations(r.investigations);
        if (r.investigations[0]) setInvId(r.investigations[0].id);
      })
      .catch(() => {});
    apiRequest<{ incidents: Incident[] }>("/api/incidents")
      .then((r) => {
        setIncidents(r.incidents);
        if (r.incidents[0]) setIncId(r.incidents[0].id);
      })
      .catch(() => {});
  }, []);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    setGenerating(true);
    try {
      const res = await apiRequest<{ report: Report }>("/api/reports/generate", {
        method: "POST",
        body: JSON.stringify({
          title,
          format,
          investigationId: invId || undefined,
          incidentId: incId || undefined,
        }),
      });
      setShowGenerate(false);
      void loadReports(res.report.id);
    } finally {
      setGenerating(false);
    }
  };

  const handleDownloadMarkdown = () => {
    if (!selected) return;
    const blob = new Blob([selected.findingsMarkdown], {
      type: "text/markdown;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${selected.code}-${selected.format.toLowerCase()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Investigation & Compliance Reports"
        subtitle="Generate formal Executive, Technical SOC, and Compliance threat reports with exportable Markdown and print-ready formatting."
        badge={`${reports.length} PUBLISHED`}
        actions={
          canMutate ? (
            <button
              onClick={() => setShowGenerate(!showGenerate)}
              className="no-print inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition"
            >
              <FilePlus2 className="w-4 h-4" />
              Generate Report
            </button>
          ) : undefined
        }
      />

      {showGenerate && (
        <form
          onSubmit={handleGenerate}
          className="no-print bg-soc-panel border border-cyan-500/40 rounded-xl p-6 space-y-4"
        >
          <h3 className="text-sm font-bold text-white">
            Compile Formal Security Report
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Report Title
              </label>
              <input
                required
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Audience / Format
              </label>
              <select
                value={format}
                onChange={(e) => setFormat(e.target.value as ReportFormat)}
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
              >
                <option value="EXECUTIVE">EXECUTIVE (Board / CISO)</option>
                <option value="TECHNICAL">TECHNICAL (SOC / DFIR)</option>
                <option value="COMPLIANCE">COMPLIANCE (ISO 27001 / SOC 2)</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Link Investigation
              </label>
              <select
                value={invId}
                onChange={(e) => setInvId(e.target.value)}
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-white"
              >
                <option value="">None (Use Recent Scans)</option>
                {investigations.map((i) => (
                  <option key={i.id} value={i.id}>
                    {i.code} — {i.title.slice(0, 45)}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Link Incident
              </label>
              <select
                value={incId}
                onChange={(e) => setIncId(e.target.value)}
                className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-white"
              >
                <option value="">None</option>
                {incidents.map((inc) => (
                  <option key={inc.id} value={inc.id}>
                    {inc.code} — {inc.title.slice(0, 45)}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setShowGenerate(false)}
              className="px-4 py-2 rounded-lg text-xs bg-slate-800 text-slate-300"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={generating}
              className="px-5 py-2 rounded-lg text-xs font-bold bg-cyan-500 text-slate-950"
            >
              {generating ? "Compiling..." : "Publish Report"}
            </button>
          </div>
        </form>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="no-print space-y-3">
          {reports.map((r) => (
            <button
              key={r.id}
              onClick={() => setSelected(r)}
              className={`w-full text-left p-4 rounded-xl border transition space-y-1.5 ${
                selected?.id === r.id
                  ? "bg-soc-panel border-cyan-500/50"
                  : "bg-soc-panel/60 border-slate-800 hover:border-slate-700"
              }`}
            >
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-cyan-400 font-bold">{r.code}</span>
                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                  {r.format}
                </span>
              </div>
              <p className="text-sm font-semibold text-white">{r.title}</p>
              <p className="text-[11px] font-mono text-slate-400">
                Peak Risk: {r.riskOverview?.peakRiskScore ?? 0}/100 ·{" "}
                {new Date(r.createdAt).toLocaleDateString()}
              </p>
            </button>
          ))}
        </div>

        <div className="lg:col-span-2">
          {selected && (
            <div className="bg-soc-panel/95 border border-slate-800 rounded-xl p-6 sm:p-8 space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <span className="text-xs font-mono text-cyan-400">
                    {selected.code} · {selected.format} REPORT
                  </span>
                  <h2 className="text-xl font-bold text-white mt-1">
                    {selected.title}
                  </h2>
                </div>
                <div className="no-print flex items-center gap-2">
                  <button
                    onClick={handleDownloadMarkdown}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700"
                  >
                    <Download className="w-3.5 h-3.5" /> Export .MD
                  </button>
                  <button
                    onClick={() => window.print()}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30"
                  >
                    <Printer className="w-3.5 h-3.5" /> Print / PDF
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div className="p-3.5 rounded-lg bg-soc-card border border-slate-800">
                  <div className="text-[11px] font-mono text-slate-400">
                    Analyzed IOCs
                  </div>
                  <div className="text-2xl font-bold font-mono text-white">
                    {selected.riskOverview?.analyzedCount ?? 0}
                  </div>
                </div>
                <div className="p-3.5 rounded-lg bg-soc-card border border-slate-800">
                  <div className="text-[11px] font-mono text-slate-400">
                    Mean Risk Score
                  </div>
                  <div className="text-2xl font-bold font-mono text-amber-300">
                    {selected.riskOverview?.averageRiskScore ?? 0}/100
                  </div>
                </div>
                <div className="p-3.5 rounded-lg bg-soc-card border border-slate-800">
                  <div className="text-[11px] font-mono text-slate-400">
                    Peak Risk Score
                  </div>
                  <div className="text-2xl font-bold font-mono text-red-400">
                    {selected.riskOverview?.peakRiskScore ?? 0}/100
                  </div>
                </div>
              </div>

              <div className="p-5 rounded-xl bg-slate-950/90 border border-slate-800 font-sans text-sm text-slate-200 whitespace-pre-wrap leading-relaxed">
                {selected.findingsMarkdown}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
