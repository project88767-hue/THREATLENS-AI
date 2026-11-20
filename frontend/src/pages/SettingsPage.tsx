import React, { useEffect, useState } from "react";
import { CheckCircle2, KeyRound, Lock, Save } from "lucide-react";
import { apiRequest } from "../services/api";
import { useAuth } from "../context/AuthContext";
import { PageHeader } from "../components/ui/Badges";

export const SettingsPage: React.FC = () => {
  const { user, refreshUser } = useAuth();
  const [name, setName] = useState(user?.name || "");
  const [department, setDepartment] = useState(user?.department || "");
  const [profileMsg, setProfileMsg] = useState<string | null>(null);

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [passwordMsg, setPasswordMsg] = useState<string | null>(null);

  const [providers, setProviders] = useState<Record<string, string>>({});

  useEffect(() => {
    setName(user?.name || "");
    setDepartment(user?.department || "");
  }, [user]);

  useEffect(() => {
    apiRequest<{ engine?: { providers?: Record<string, string> } }>("/api/health")
      .then((res) => setProviders(res.engine?.providers || {}))
      .catch(() => {});
  }, []);

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setProfileMsg(null);
    try {
      await apiRequest("/api/auth/profile", {
        method: "PATCH",
        body: JSON.stringify({ name, department }),
      });
      await refreshUser();
      setProfileMsg("Profile updated successfully.");
    } catch (err) {
      setProfileMsg((err as Error).message);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordMsg(null);
    try {
      const res = await apiRequest<{ message: string }>(
        "/api/auth/change-password",
        {
          method: "POST",
          body: JSON.stringify({ currentPassword, newPassword }),
        }
      );
      setCurrentPassword("");
      setNewPassword("");
      setPasswordMsg(res.message);
    } catch (err) {
      setPasswordMsg((err as Error).message);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Platform & Analyst Settings"
        subtitle="Manage your SOC profile, rotate credentials, and inspect server-side threat intelligence adapter status."
        badge="ZERO CLIENT SECRET EXPOSURE"
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Profile Form */}
        <form
          onSubmit={handleSaveProfile}
          className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6 space-y-4"
        >
          <h2 className="text-sm font-bold uppercase tracking-wider text-white">
            Analyst Profile
          </h2>
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Email (Immutable Identity)
            </label>
            <input
              disabled
              value={user?.email || ""}
              className="w-full px-3.5 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-400"
            />
          </div>
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Display Name
            </label>
            <input
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            />
          </div>
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Department / Squad
            </label>
            <input
              required
              value={department}
              onChange={(e) => setDepartment(e.target.value)}
              className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            />
          </div>
          {profileMsg && (
            <p className="text-xs font-mono text-cyan-300">{profileMsg}</p>
          )}
          <button
            type="submit"
            className="inline-flex items-center gap-2 px-5 py-2 rounded-lg text-xs font-bold bg-cyan-500 text-slate-950"
          >
            <Save className="w-4 h-4" /> Save Profile
          </button>
        </form>

        {/* Password Rotation */}
        <form
          onSubmit={handleChangePassword}
          className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6 space-y-4"
        >
          <h2 className="text-sm font-bold uppercase tracking-wider text-white flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-cyan-400" /> Rotate Account Password
          </h2>
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              Current Password
            </label>
            <input
              type="password"
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            />
          </div>
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">
              New Password (min 8 chars, upper + lower + digit)
            </label>
            <input
              type="password"
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full px-3.5 py-2 rounded-lg bg-slate-950 border border-slate-800 text-sm text-white"
            />
          </div>
          {passwordMsg && (
            <p className="text-xs font-mono text-cyan-300">{passwordMsg}</p>
          )}
          <button
            type="submit"
            className="inline-flex items-center gap-2 px-5 py-2 rounded-lg text-xs font-bold bg-slate-800 hover:bg-slate-700 text-white border border-slate-700"
          >
            <Lock className="w-4 h-4" /> Update Password
          </button>
        </form>
      </div>

      {/* Server-Side Threat Feed Status */}
      <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6 space-y-4">
        <div>
          <h2 className="text-sm font-bold uppercase tracking-wider text-white">
            Server-Side Intelligence Provider Status
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            API keys are stored exclusively inside{" "}
            <code className="text-cyan-300">analysis-engine/.env</code> and never
            transmitted to the browser. Unconfigured optional keys automatically
            use clearly-labelled Demo Telemetry adapters.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {Object.entries(providers).map(([provider, status]) => (
            <div
              key={provider}
              className="p-3.5 rounded-lg bg-soc-card border border-slate-800 space-y-1"
            >
              <div className="text-xs font-mono font-bold text-slate-200 uppercase">
                {provider}
              </div>
              <div className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-300">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                {status}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
