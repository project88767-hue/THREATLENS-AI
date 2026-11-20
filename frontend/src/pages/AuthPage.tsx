import React, { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { AlertCircle, KeyRound, ShieldCheck, Sparkles } from "lucide-react";
import { useAuth } from "../context/AuthContext";

const DEMO_ACCOUNTS = [
  {
    label: "SOC Director (ADMIN)",
    email: "admin@threatlens.demo",
    password: "Admin@12345",
    role: "Full RBAC + Audit",
  },
  {
    label: "Threat Hunter (ANALYST)",
    email: "analyst@threatlens.demo",
    password: "Analyst@12345",
    role: "Scans + Cases + IR",
  },
  {
    label: "Auditor (VIEWER)",
    email: "viewer@threatlens.demo",
    password: "Viewer@12345",
    role: "Read-Only GRC",
  },
];

export const AuthPage: React.FC = () => {
  const location = useLocation();
  const isRegister = location.pathname === "/register";
  const navigate = useNavigate();
  const { login, register } = useAuth();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [department, setDepartment] = useState("SOC Operations");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      if (isRegister) {
        await register({ name, email, password, department });
      } else {
        await login(email, password);
      }
      navigate("/dashboard");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDemoQuickLogin = async (demoEmail: string, demoPassword: string) => {
    setError(null);
    setEmail(demoEmail);
    setPassword(demoPassword);
    setSubmitting(true);
    try {
      await login(demoEmail, demoPassword);
      navigate("/dashboard");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="w-full max-w-md space-y-6">
        <div className="text-center space-y-2">
          <Link to="/" className="inline-flex items-center gap-2.5">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center">
              <ShieldCheck className="w-6 h-6 text-cyan-400" />
            </div>
            <span className="text-xl font-bold tracking-wider text-white">
              THREATLENS <span className="text-cyan-400">AI</span>
            </span>
          </Link>
          <p className="text-xs font-mono text-slate-400">
            {isRegister
              ? "PROVISION NEW DEFENSIVE SOC ANALYST CREDENTIALS"
              : "AUTHENTICATE TO ENTER SECURITY OPERATIONS CONSOLE"}
          </p>
        </div>

        <div className="bg-soc-panel/95 border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl space-y-5">
          {/* Mode Tabs */}
          <div className="grid grid-cols-2 p-1 rounded-lg bg-slate-900 border border-slate-800 text-xs font-semibold">
            <Link
              to="/login"
              className={`py-2 text-center rounded-md transition ${
                !isRegister
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              Sign In
            </Link>
            <Link
              to="/register"
              className={`py-2 text-center rounded-md transition ${
                isRegister
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              Register Account
            </Link>
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-red-950/70 border border-red-500/40 text-xs text-red-200 flex items-start gap-2">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {isRegister && (
              <>
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1.5">
                    Full Analyst Name
                  </label>
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. Aashutosh Sharma"
                    className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyan-500 focus:outline-none text-sm text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1.5">
                    SOC Team / Department
                  </label>
                  <input
                    type="text"
                    value={department}
                    onChange={(e) => setDepartment(e.target.value)}
                    className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyan-500 focus:outline-none text-sm text-white"
                  />
                </div>
              </>
            )}

            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1.5">
                Work Email
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@threatlens.demo"
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyan-500 focus:outline-none text-sm text-white"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1.5">
                Password
              </label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyan-500 focus:outline-none text-sm text-white"
              />
              {isRegister && (
                <p className="text-[11px] text-slate-400 mt-1">
                  Minimum 8 chars with uppercase, lowercase, and numeric character.
                </p>
              )}
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full py-2.5 rounded-lg text-sm font-bold bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 flex items-center justify-center gap-2 transition"
            >
              <KeyRound className="w-4 h-4" />
              {submitting
                ? "Verifying Credentials..."
                : isRegister
                ? "Create SOC Account"
                : "Sign In to SOC Console"}
            </button>
          </form>

          {!isRegister && (
            <div className="pt-4 border-t border-slate-800 space-y-2.5">
              <div className="flex items-center gap-1.5 text-[11px] font-mono text-purple-300">
                <Sparkles className="w-3.5 h-3.5" />
                PORTFOLIO DEMO ACCOUNTS (1-CLICK LOGIN)
              </div>
              <div className="space-y-2">
                {DEMO_ACCOUNTS.map((acct) => (
                  <button
                    key={acct.email}
                    type="button"
                    disabled={submitting}
                    onClick={() => handleDemoQuickLogin(acct.email, acct.password)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 flex items-center justify-between text-left transition"
                  >
                    <div>
                      <div className="text-xs font-semibold text-white">
                        {acct.label}
                      </div>
                      <div className="text-[11px] font-mono text-slate-400">
                        {acct.email}
                      </div>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                      {acct.role}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
