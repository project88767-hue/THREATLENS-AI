import React, { useEffect, useState } from "react";
import { ShieldCheck, Users } from "lucide-react";
import { apiRequest } from "../services/api";
import { AuditLog, Role, User, UserStatus } from "../types";
import { PageHeader } from "../components/ui/Badges";
import { useAuth } from "../context/AuthContext";

export const AdminPage: React.FC = () => {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [controls, setControls] = useState<Record<string, boolean | number>>({});
  const [error, setError] = useState<string | null>(null);

  const loadAdminData = async () => {
    try {
      const [uRes, lRes, hRes] = await Promise.all([
        apiRequest<{ users: User[] }>("/api/admin/users"),
        apiRequest<{ logs: AuditLog[] }>("/api/admin/audit-logs?limit=50"),
        apiRequest<{ securityControls: Record<string, boolean | number> }>(
          "/api/admin/system-health"
        ),
      ]);
      setUsers(uRes.users);
      setLogs(lRes.logs);
      setControls(hRes.securityControls);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  useEffect(() => {
    void loadAdminData();
  }, []);

  const handleUpdateUser = async (
    id: string,
    payload: { role?: Role; status?: UserStatus }
  ) => {
    setError(null);
    try {
      await apiRequest(`/api/admin/users/${id}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      });
      void loadAdminData();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Admin Governance & Security Audit"
        subtitle="Role-Based Access Control (RBAC) directory, OWASP Top 10 posture verification, and immutable audit logs."
        badge="ADMIN RESTRICTED"
      />

      {error && (
        <div className="p-3.5 rounded-lg bg-red-950/70 border border-red-500/40 text-xs text-red-200">
          {error}
        </div>
      )}

      {/* OWASP Security Posture Matrix */}
      <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-5 space-y-3">
        <h2 className="text-xs font-mono uppercase tracking-wider text-slate-300 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          Active Defensive Security Controls
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {Object.entries(controls).map(([key, val]) => (
            <div
              key={key}
              className="p-3 rounded-lg bg-soc-card border border-slate-800 flex items-center justify-between text-xs font-mono"
            >
              <span className="text-slate-300">{key}</span>
              <span className="text-emerald-400 font-bold">{String(val)}</span>
            </div>
          ))}
        </div>
      </div>

      {/* RBAC User Management */}
      <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6 space-y-4">
        <h2 className="text-sm font-bold uppercase tracking-wider text-white flex items-center gap-2">
          <Users className="w-4 h-4 text-cyan-400" /> SOC Operators & RBAC Roles
        </h2>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono">
                <th className="py-2.5 pr-3">NAME</th>
                <th className="py-2.5 pr-3">EMAIL</th>
                <th className="py-2.5 pr-3">DEPARTMENT</th>
                <th className="py-2.5 pr-3">SCANS</th>
                <th className="py-2.5 pr-3">ROLE</th>
                <th className="py-2.5 pr-3">STATUS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {users.map((u) => (
                <tr key={u.id}>
                  <td className="py-3 pr-3 font-medium text-white">{u.name}</td>
                  <td className="py-3 pr-3 font-mono text-slate-300">{u.email}</td>
                  <td className="py-3 pr-3 text-slate-400">{u.department}</td>
                  <td className="py-3 pr-3 font-mono text-cyan-300">
                    {u._count?.scans ?? 0}
                  </td>
                  <td className="py-3 pr-3">
                    <select
                      value={u.role}
                      onChange={(e) =>
                        void handleUpdateUser(u.id, {
                          role: e.target.value as Role,
                        })
                      }
                      className="px-2 py-1 rounded bg-slate-950 border border-slate-700 font-mono text-white"
                    >
                      <option value="ADMIN">ADMIN</option>
                      <option value="ANALYST">ANALYST</option>
                      <option value="VIEWER">VIEWER</option>
                    </select>
                  </td>
                  <td className="py-3 pr-3">
                    <select
                      disabled={u.id === currentUser?.id}
                      value={u.status || "ACTIVE"}
                      onChange={(e) =>
                        void handleUpdateUser(u.id, {
                          status: e.target.value as UserStatus,
                        })
                      }
                      className="px-2 py-1 rounded bg-slate-950 border border-slate-700 font-mono text-white disabled:opacity-50"
                    >
                      <option value="ACTIVE">ACTIVE</option>
                      <option value="SUSPENDED">SUSPENDED</option>
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Immutable Audit Log Stream */}
      <div className="bg-soc-panel/90 border border-slate-800 rounded-xl p-6 space-y-4">
        <h2 className="text-sm font-bold uppercase tracking-wider text-white">
          Immutable Security Audit Trail (Latest 50 Events)
        </h2>

        <div className="overflow-x-auto max-h-96 overflow-y-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2 pr-3">TIMESTAMP</th>
                <th className="py-2 pr-3">ACTOR</th>
                <th className="py-2 pr-3">ACTION</th>
                <th className="py-2 pr-3">RESOURCE</th>
                <th className="py-2 pr-3">IP</th>
                <th className="py-2 pr-3">STATUS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-900/50">
                  <td className="py-2 pr-3 text-slate-400">
                    {new Date(log.createdAt).toLocaleString()}
                  </td>
                  <td className="py-2 pr-3 text-slate-200">{log.actorEmail}</td>
                  <td className="py-2 pr-3 text-cyan-300">{log.action}</td>
                  <td className="py-2 pr-3 text-slate-400">
                    {log.resourceType}
                  </td>
                  <td className="py-2 pr-3 text-slate-400">
                    {log.ipAddress || "127.0.0.1"}
                  </td>
                  <td className="py-2 pr-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] ${
                        log.status === "SUCCESS"
                          ? "bg-emerald-500/15 text-emerald-300"
                          : "bg-red-500/15 text-red-300"
                      }`}
                    >
                      {log.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
