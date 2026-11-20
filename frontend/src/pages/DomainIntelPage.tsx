import React, { useEffect, useState } from "react";
import { AlertCircle, Globe, Search } from "lucide-react";
import { apiRequest } from "../services/api";
import { ScanResult } from "../types";
import { PageHeader, SeverityBadge } from "../components/ui/Badges";
import { ScanResultPanel } from "../components/scan/ScanResultPanel";
import { useAuth } from "../context/AuthContext";

const DOMAIN_PRESETS = [
  { label: "[DEMO] Microsoft Typosquat (.xyz)", value: "microsoft-verify-sso.xyz" },
  { label: "[DEMO] High-Entropy DGA Sample", value: "xk9q7m4z8w2p1v6n.top" },
  { label: "Established Domain (github.com)", value: "github.com" },
];

export const DomainIntelPage: React.FC = () => {
  const { canMutate } = useAuth();
  const [domainInput, setDomainInput] = useState(DOMAIN_PRESETS[0].value);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);

  const loadHistory = async () => {
    try {
      const res = await apiRequest<{ scans: ScanResult[] }>(
        "/api/scans?type=DOMAIN&limit=6"
      );
      setHistory(res.scans);
      if (!currentScan && res.scans.length > 0) setCurrentScan(res.scans[0]);
    } catch {
      // Ignore
    }
  };

  useEffect(() => {
    void loadHistory();
  }, []);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setScanning(true);
    try {
      const res = await apiRequest<{ scan: ScanResult }>("/api/scans/domain", {
        method: "POST",
        body: JSON.stringify({ domain: domainInput }),
      });
      setCurrentScan(res.scan);
      void loadHistory();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Domain Intelligence & WHOIS/RDAP"
        subtitle="Detect Newly Registered Domains (NRD), Shannon entropy DGA labels, brand typosquatting, passive DNS resolution, and OTX/VT reputation."
        badge="RDAP + DGA DETECTOR"
      />

      <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6 space-y-4">
        <form onSubmit={handleScan} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Globe className="w-4 h-4 text-slate-400 absolute left-3.5 top-3.5" />
            <input
              type="text"
              required
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              placeholder="e.g. suspicious-login-portal.xyz"
              className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyan-500 focus:outline-none font-mono text-sm text-white"
            />
          </div>
          <button
            type="submit"
            disabled={scanning || !canMutate}
            className="inline-flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg text-sm font-bold bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 transition"
          >
            <Search className="w-4 h-4" />
            {scanning ? "Inspecting Domain..." : "Analyze Domain"}
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-mono text-slate-400">Sample Domains:</span>
          {DOMAIN_PRESETS.map((p) => (
            <button
              key={p.value}
              type="button"
              onClick={() => setDomainInput(p.value)}
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

      {currentScan && <ScanResultPanel scan={currentScan} />}

      {history.length > 0 && (
        <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-5">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3">
            Recent Domain Investigations
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
            {history.map((item) => (
              <button
                key={item.id}
                onClick={() => setCurrentScan(item)}
                className="p-3 rounded-lg bg-soc-card border border-slate-800 hover:border-cyan-500/40 flex items-center justify-between transition"
              >
                <span className="text-xs font-mono text-white truncate">
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
