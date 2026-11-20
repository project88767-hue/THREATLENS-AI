import React, { useEffect, useState } from "react";
import { AlertCircle, Bug, Search, ShieldAlert } from "lucide-react";
import { apiRequest } from "../services/api";
import { ScanResult } from "../types";
import { PageHeader, SeverityBadge } from "../components/ui/Badges";
import { ScanResultPanel } from "../components/scan/ScanResultPanel";
import { useAuth } from "../context/AuthContext";

const CVE_PRESETS = [
  { label: "CVE-2024-3094 (XZ Backdoor)", value: "CVE-2024-3094" },
  { label: "CVE-2021-44228 (Log4Shell)", value: "CVE-2021-44228" },
  { label: "CVE-2024-21762 (FortiOS RCE)", value: "CVE-2024-21762" },
  { label: "CVE-2024-6387 (OpenSSH regreSSHion)", value: "CVE-2024-6387" },
];

export const VulnIntelPage: React.FC = () => {
  const { canMutate } = useAuth();
  const [cveInput, setCveInput] = useState(CVE_PRESETS[0].value);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);

  const loadHistory = async () => {
    try {
      const res = await apiRequest<{ scans: ScanResult[] }>("/api/scans?type=CVE&limit=6");
      setHistory(res.scans);
      if (!currentScan && res.scans.length > 0) setCurrentScan(res.scans[0]);
    } catch {
      // Ignore
    }
  };

  useEffect(() => {
    void loadHistory();
  }, []);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setScanning(true);
    try {
      const res = await apiRequest<{ scan: ScanResult }>("/api/scans/cve", {
        method: "POST",
        body: JSON.stringify({ cveId: cveInput }),
      });
      setCurrentScan(res.scan);
      void loadHistory();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setScanning(false);
    }
  };

  const meta = (currentScan?.metadata || {}) as Record<string, unknown>;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Vulnerability & CVE Intelligence"
        subtitle="Query NIST NVD v2.0 advisories, parse CVSS v3.1 vectors, detect CISA Known Exploited Vulnerabilities (KEV), and generate remediation playbooks."
        badge="NIST NVD + KEV"
      />

      <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6 space-y-4">
        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Bug className="w-4 h-4 text-slate-400 absolute left-3.5 top-3.5" />
            <input
              type="text"
              required
              value={cveInput}
              onChange={(e) => setCveInput(e.target.value)}
              placeholder="e.g. CVE-2024-3094 or keyword (openssh, log4j)"
              className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyan-500 focus:outline-none font-mono text-sm text-white"
            />
          </div>
          <button
            type="submit"
            disabled={scanning || !canMutate}
            className="inline-flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg text-sm font-bold bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 transition"
          >
            <Search className="w-4 h-4" />
            {scanning ? "Fetching NVD Intel..." : "Analyze CVE"}
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-mono text-slate-400">High-Profile Advisories:</span>
          {CVE_PRESETS.map((p) => (
            <button
              key={p.value}
              type="button"
              onClick={() => setCveInput(p.value)}
              className="px-2.5 py-1 rounded text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition"
            >
              {p.label}
            </button>
          ))}
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-red-950/70 border border-red-500/40 text-xs text-red-200 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* CVE Metadata Banner */}
      {meta.cvss_score !== undefined && (
        <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <span className="text-base font-mono font-bold text-cyan-300">
                {String(meta.cve_id || currentScan?.normalizedValue)}
              </span>
              {Boolean(meta.kev_listed) && (
                <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-red-500/20 text-red-300 border border-red-500/40">
                  <ShieldAlert className="w-3.5 h-3.5" /> CISA KEV ACTIVE EXPLOITATION
                </span>
              )}
            </div>
            <span className="text-xs font-mono text-slate-300 bg-slate-900 px-3 py-1 rounded border border-slate-800">
              CVSS: <strong>{String(meta.cvss_score)}/10</strong> ·{" "}
              {String(meta.cvss_vector || "")}
            </span>
          </div>
          {Boolean(meta.description) && (
            <p className="text-sm text-slate-300 leading-relaxed">
              {String(meta.description)}
            </p>
          )}
          {Boolean(meta.remediation) && (
            <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-xs text-emerald-200">
              <strong>Patch Guidance:</strong> {String(meta.remediation)}
            </div>
          )}
        </div>
      )}

      {currentScan && <ScanResultPanel scan={currentScan} />}

      {history.length > 0 && (
        <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-5">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3">
            Recent CVE Lookups
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
            {history.map((item) => (
              <button
                key={item.id}
                onClick={() => setCurrentScan(item)}
                className="p-3 rounded-lg bg-soc-card border border-slate-800 hover:border-cyan-500/40 flex items-center justify-between transition"
              >
                <span className="text-xs font-mono text-white">
                  {item.normalizedValue}
                </span>
                <SeverityBadge severity={item.severity} />
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
