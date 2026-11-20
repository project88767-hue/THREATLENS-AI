import React, { useEffect, useState } from "react";
import { AlertCircle, MailWarning, Search } from "lucide-react";
import { apiRequest } from "../services/api";
import { ScanResult } from "../types";
import { PageHeader } from "../components/ui/Badges";
import { ScanResultPanel } from "../components/scan/ScanResultPanel";
import { useAuth } from "../context/AuthContext";

const EMAIL_PRESETS = [
  {
    label: "[DEMO] Executive BEC Wire Transfer",
    headers: [
      "From: CEO Office Urgent <ceo-executive@gmail.com>",
      "Reply-To: treasury-wire@offshore-pay-portal.xyz",
      "Return-Path: <bounce@mailer-spoof.tk>",
      "Authentication-Results: mx.enterprise.demo; spf=fail dkim=fail dmarc=fail",
      "Subject: Urgent Action Required - Immediate Wire Transfer & Invoice",
    ].join("\n"),
    body: "Team,\n\nUrgent action required within 24 hours. Complete the confidential vendor wire transfer immediately and verify your password at http://microsoft-verify.offshore-pay-portal.xyz/login or review attached invoice_wire_q4.xlsm.",
  },
  {
    label: "[DEMO] IT MFA Reset Lure",
    headers: [
      "From: IT Security Team <security-alert@m365-reset-help.top>",
      "Authentication-Results: mx.enterprise.demo; spf=softfail dkim=none dmarc=fail",
      "Subject: Unusual Sign-in Detected — MFA Reset Required",
    ].join("\n"),
    body: "We detected an unusual sign-in on your corporate mailbox. Confirm your identity now at https://auth-session-verify.m365-reset-help.top/login or your account will be suspended.",
  },
  {
    label: "Clean Authenticated Corporate Email",
    headers: [
      "From: Engineering Digest <digest@corp-internal-news.org>",
      "Reply-To: digest@corp-internal-news.org",
      "Return-Path: <digest@corp-internal-news.org>",
      "Authentication-Results: mx.enterprise.demo; spf=pass dkim=pass dmarc=pass",
      "Subject: Weekly Architecture Release Notes",
    ].join("\n"),
    body: "Hello Engineering Team,\n\nHere is our weekly summary of service deployments and maintenance windows. Have a great week!",
  },
];

export const EmailAnalyzerPage: React.FC = () => {
  const { canMutate } = useAuth();
  const [rawHeaders, setRawHeaders] = useState(EMAIL_PRESETS[0].headers);
  const [body, setBody] = useState(EMAIL_PRESETS[0].body);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);

  useEffect(() => {
    apiRequest<{ scans: ScanResult[] }>("/api/scans?type=EMAIL&limit=1")
      .then((res) => {
        if (res.scans.length > 0) setCurrentScan(res.scans[0]);
      })
      .catch(() => {});
  }, []);

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setScanning(true);
    try {
      const res = await apiRequest<{ scan: ScanResult }>("/api/scans/email", {
        method: "POST",
        body: JSON.stringify({ rawHeaders, body }),
      });
      setCurrentScan(res.scan);
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
        title="Email Threat & Authentication Analyzer"
        subtitle="Inspect SPF, DKIM, and DMARC alignment, Reply-To spoofing, Business Email Compromise (BEC) cues, embedded phishing links, and risky attachments."
        badge="RFC AUTH PARSER"
      />

      <form
        onSubmit={handleAnalyze}
        className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6 space-y-4"
      >
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-mono text-slate-400">Load Sample (.eml):</span>
          {EMAIL_PRESETS.map((preset) => (
            <button
              key={preset.label}
              type="button"
              onClick={() => {
                setRawHeaders(preset.headers);
                setBody(preset.body);
              }}
              className="px-2.5 py-1 rounded text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition"
            >
              {preset.label}
            </button>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1.5">
              Raw Email Headers (SPF / DKIM / DMARC / From / Reply-To)
            </label>
            <textarea
              rows={7}
              value={rawHeaders}
              onChange={(e) => setRawHeaders(e.target.value)}
              className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyan-500 focus:outline-none font-mono text-xs text-slate-200"
            />
          </div>
          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1.5">
              Email Message Body
            </label>
            <textarea
              rows={7}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyan-500 focus:outline-none font-mono text-xs text-slate-200"
            />
          </div>
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-red-950/70 border border-red-500/40 text-xs text-red-200 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={scanning || !canMutate}
            className="inline-flex items-center gap-2 px-6 py-2.5 rounded-lg text-sm font-bold bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 transition"
          >
            <MailWarning className="w-4 h-4" />
            {scanning ? "Inspecting Headers & Payload..." : "Analyze Email Threat"}
            <Search className="w-4 h-4" />
          </button>
        </div>
      </form>

      {/* Authentication Protocol Matrix if available */}
      {meta.spf !== undefined && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {[
            { proto: "SPF Alignment", val: String(meta.spf) },
            { proto: "DKIM Signature", val: String(meta.dkim) },
            { proto: "DMARC Policy", val: String(meta.dmarc) },
          ].map((item) => {
            const passed = item.val.toLowerCase() === "pass";
            return (
              <div
                key={item.proto}
                className="p-4 rounded-xl bg-soc-panel border border-slate-800 flex items-center justify-between"
              >
                <span className="text-xs font-mono text-slate-400">{item.proto}</span>
                <span
                  className={`px-2.5 py-1 rounded text-xs font-mono font-bold uppercase ${
                    passed
                      ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
                      : "bg-red-500/15 text-red-300 border border-red-500/30"
                  }`}
                >
                  {item.val}
                </span>
              </div>
            );
          })}
        </div>
      )}

      {currentScan && <ScanResultPanel scan={currentScan} />}
    </div>
  );
};
