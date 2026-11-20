import React, { useEffect, useState } from "react";
import { AlertCircle, Link2, Search, Shield } from "lucide-react";
import { apiRequest } from "../services/api";
import { ScanResult } from "../types";
import { PageHeader, SeverityBadge } from "../components/ui/Badges";
import { ScanResultPanel } from "../components/scan/ScanResultPanel";
import { useAuth } from "../context/AuthContext";

const URL_PRESETS = [
  {
    label: "[DEMO] Phishing SSO Lookalike",
    value: "http://microsoft-verify-login.account-update.xyz/secure/credential",
  },
  {
    label: "[DEMO] Punycode Wallet Lure",
    value: "https://xn--pypal-4ve.top/wallet/confirm-session",
  },
  {
    label: "Clean Reference URL",
    value: "https://www.cloudflare.com/learning/security/what-is-phishing/",
  },
];

export const UrlScannerPage: React.FC = () => {
  const { canMutate } = useAuth();
  const [urlInput, setUrlInput] = useState(URL_PRESETS[0].value);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);

  const loadHistory = async () => {
    try {
      const res = await apiRequest<{ scans: ScanResult[] }>("/api/scans?type=URL&limit=6");
      setHistory(res.scans);
      if (!currentScan && res.scans.length > 0) {
        setCurrentScan(res.scans[0]);
      }
    } catch {
      // Ignore initial history errors
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
      const res = await apiRequest<{ scan: ScanResult }>("/api/scans/url", {
        method: "POST",
        body: JSON.stringify({ url: urlInput }),
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
        title="URL Threat Intelligence Scanner"
        subtitle="Passive lexical phishing inspection, VirusTotal v3, Google Safe Browsing, AlienVault OTX, and RDAP domain age correlation."
        badge="SSRF PROTECTED"
      />

      <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6 space-y-4">
        <form onSubmit={handleScan} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Link2 className="w-4 h-4 text-slate-400 absolute left-3.5 top-3.5" />
            <input
              type="text"
              required
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="https://suspicious-domain.example/login"
              className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyan-500 focus:outline-none font-mono text-sm text-white"
            />
          </div>
          <button
            type="submit"
            disabled={scanning || !canMutate}
            className="inline-flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg text-sm font-bold bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 transition"
          >
            <Search className="w-4 h-4" />
            {scanning ? "Analyzing URL..." : "Analyze URL"}
          </button>
        </form>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-mono text-slate-400">Quick Samples:</span>
            {URL_PRESETS.map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => setUrlInput(preset.value)}
                className="px-2.5 py-1 rounded text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition"
              >
                {preset.label}
              </button>
            ))}
          </div>
          <span className="inline-flex items-center gap-1.5 text-[11px] font-mono text-emerald-400">
            <Shield className="w-3.5 h-3.5" /> Loopback & RFC1918 private URLs blocked
          </span>
        </div>

        {!canMutate && (
          <p className="text-xs font-mono text-amber-300">
            VIEWER role active: You can inspect historical URL scans below; Analyst/Admin role is required to submit new scans.
          </p>
        )}

        {error && (
          <div className="p-3.5 rounded-lg bg-red-950/70 border border-red-500/40 text-xs text-red-200 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {currentScan && <ScanResultPanel scan={currentScan} />}

      {history.length > 0 && (
        <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-5">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3">
            Recent URL Scans (Click to Inspect)
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
            {history.map((item) => (
              <button
                key={item.id}
                onClick={() => setCurrentScan(item)}
                className={`p-3 rounded-lg border text-left flex items-center justify-between gap-3 transition ${
                  currentScan?.id === item.id
                    ? "bg-cyan-500/10 border-cyan-500/40"
                    : "bg-soc-card border-slate-800 hover:border-slate-700"
                }`}
              >
                <span className="text-xs font-mono text-slate-200 truncate">
                  {item.normalizedValue}
                </span>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-xs font-mono font-bold text-white">
                    {item.riskScore}
                  </span>
                  <SeverityBadge severity={item.severity} />
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
