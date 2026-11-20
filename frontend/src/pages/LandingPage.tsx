import React from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  ArrowRight,
  Bot,
  Bug,
  CheckCircle2,
  FileText,
  Globe,
  Lock,
  MailWarning,
  Network,
  ShieldCheck,
  Siren,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

const CAPABILITIES = [
  {
    icon: Globe,
    title: "URL, Domain & IP Forensics",
    desc: "Correlate VirusTotal, Google Safe Browsing, AbuseIPDB, AlienVault OTX, and live RDAP telemetry with DGA entropy and typosquatting heuristics.",
  },
  {
    icon: MailWarning,
    title: "Email Authentication & BEC Defense",
    desc: "Inspect SPF, DKIM, and DMARC alignment, Reply-To spoofing, executive impersonation, embedded phishing links, and dangerous attachment markers.",
  },
  {
    icon: Bug,
    title: "CVE & Vulnerability Intelligence",
    desc: "Query NIST NVD v2.0 advisories, parse CVSS v3.1 attack vectors, flag CISA Known Exploited Vulnerabilities (KEV), and prioritize patching.",
  },
  {
    icon: Bot,
    title: "Explainable AI SOC Copilot",
    desc: "Transparent 0–100 weighted risk scores backed by plain-language reasoning, MITRE ATT&CK technique mappings, and NIST containment checklists.",
  },
  {
    icon: Network,
    title: "Threat Relationship Graph",
    desc: "Pivot visually across connected campaigns, phishing senders, URLs, domains, offshore C2 IPs, and targeted CVEs.",
  },
  {
    icon: Siren,
    title: "Incidents, Reports & RBAC Audit",
    desc: "Track investigations from detection to containment, generate executive/compliance reports, and enforce OWASP Top 10 controls with immutable audit logs.",
  },
];

export const LandingPage: React.FC = () => {
  const { user } = useAuth();

  return (
    <div className="min-h-screen text-slate-100 flex flex-col">
      {/* Top Navbar */}
      <header className="border-b border-slate-800/80 bg-soc-bg/80 backdrop-blur-md sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
            </div>
            <span className="font-bold tracking-wider text-white">
              THREATLENS <span className="text-cyan-400">AI</span>
            </span>
          </div>

          <div className="flex items-center gap-3">
            {user ? (
              <Link
                to="/dashboard"
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition"
              >
                Open SOC Console <ArrowRight className="w-4 h-4" />
              </Link>
            ) : (
              <>
                <Link
                  to="/login"
                  className="px-4 py-2 rounded-lg text-sm font-medium text-slate-300 hover:text-white transition"
                >
                  Sign In
                </Link>
                <Link
                  to="/register"
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition"
                >
                  Launch Platform <ArrowRight className="w-4 h-4" />
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="max-w-7xl mx-auto px-6 pt-20 pb-16 text-center">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-xs font-mono text-cyan-300 mb-6">
          <Activity className="w-3.5 h-3.5" />
          AI-POWERED CYBERSECURITY INVESTIGATION & THREAT INTELLIGENCE PLATFORM
        </div>

        <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white max-w-4xl mx-auto leading-tight">
          Detect threats. Investigate evidence.{" "}
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-emerald-400">
            Understand risks. Protect systems.
          </span>
        </h1>

        <p className="mt-6 text-base sm:text-lg text-slate-400 max-w-2xl mx-auto leading-relaxed">
          Unify multi-provider threat intelligence, explainable 0–100 risk scoring,
          AI-assisted SOC triage, interactive threat relationship graphs, and NIST
          incident response playbooks inside one defensive command platform.
        </p>

        <div className="mt-9 flex flex-wrap items-center justify-center gap-4">
          <Link
            to={user ? "/dashboard" : "/login"}
            className="inline-flex items-center gap-2 px-6 py-3 rounded-xl text-sm font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-lg shadow-cyan-500/20 transition"
          >
            {user ? "Enter Security Dashboard" : "Try Interactive SOC Demo"}
            <ArrowRight className="w-4 h-4" />
          </Link>
          <Link
            to="/register"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-xl text-sm font-semibold bg-soc-panel hover:bg-slate-800 text-slate-200 border border-slate-700 transition"
          >
            Create Analyst Account
          </Link>
        </div>

        {/* Provider & Security Strip */}
        <div className="mt-12 flex flex-wrap items-center justify-center gap-3 text-xs font-mono text-slate-400">
          {[
            "VirusTotal v3",
            "Google Safe Browsing",
            "AbuseIPDB",
            "AlienVault OTX",
            "NIST NVD v2",
            "IANA RDAP",
            "OWASP Top 10 Hardened",
          ].map((tag) => (
            <span
              key={tag}
              className="px-3 py-1.5 rounded-lg bg-soc-panel/90 border border-slate-800"
            >
              {tag}
            </span>
          ))}
        </div>
      </section>

      {/* Capability Grid */}
      <section className="max-w-7xl mx-auto px-6 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {CAPABILITIES.map((cap) => {
            const Icon = cap.icon;
            return (
              <div
                key={cap.title}
                className="p-6 rounded-xl bg-soc-panel/90 border border-slate-800/90 hover:border-cyan-500/40 transition space-y-3"
              >
                <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
                  <Icon className="w-5 h-5 text-cyan-400" />
                </div>
                <h3 className="text-base font-bold text-white">{cap.title}</h3>
                <p className="text-sm text-slate-400 leading-relaxed">{cap.desc}</p>
              </div>
            );
          })}
        </div>
      </section>

      {/* Defensive Security & Ethics Banner */}
      <section className="max-w-7xl mx-auto px-6 py-10">
        <div className="rounded-2xl bg-gradient-to-r from-soc-panel via-slate-900 to-soc-panel border border-slate-800 p-8 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="inline-flex items-center gap-2 text-xs font-mono text-emerald-400">
              <Lock className="w-4 h-4" />
              DEFENSIVE SECURITY & AUTHORIZED LAB SCOPE
            </div>
            <h2 className="text-xl font-bold text-white">
              Engineered with Zero-Trust & OWASP Top 10 Protections
            </h2>
            <p className="text-sm text-slate-400">
              Server-side API key isolation, strict SSRF private-IP blocking, Zod schema
              validation, bcrypt cost-12 password hashing, CSRF headers, rate limiting,
              and role-based access control (`ADMIN`, `ANALYST`, `VIEWER`).
            </p>
          </div>
          <div className="space-y-2 text-xs font-mono text-slate-300">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" /> No client-side secret exposure
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Passive OSINT & lexical forensics only
            </div>
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" /> Clearly labelled Demo Telemetry fallbacks
            </div>
          </div>
        </div>
      </section>

      <footer className="mt-auto border-t border-slate-800/80 py-6 text-center text-xs text-slate-500 font-mono">
        THREATLENS AI · Defensive Cybersecurity Investigation & Threat Intelligence Portfolio Platform
      </footer>
    </div>
  );
};
