import React, { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Activity,
  Bot,
  Bug,
  FileText,
  FolderKanban,
  Globe,
  Link2,
  LogOut,
  MailWarning,
  Menu,
  Network,
  Server,
  Settings,
  ShieldCheck,
  Siren,
  UserCheck,
  X,
} from "lucide-react";
import { useAuth } from "../../context/AuthContext";

const NAV_SECTIONS = [
  {
    label: "Command Center",
    items: [
      { to: "/dashboard", label: "Security Dashboard", icon: Activity },
      { to: "/assistant", label: "AI Investigation Copilot", icon: Bot },
    ],
  },
  {
    label: "Threat Intelligence & Scanners",
    items: [
      { to: "/scanner/url", label: "URL Scanner", icon: Link2 },
      { to: "/scanner/email", label: "Email Threat Analyzer", icon: MailWarning },
      { to: "/intel/ip", label: "IP Intelligence", icon: Server },
      { to: "/intel/domain", label: "Domain Intelligence", icon: Globe },
      { to: "/intel/cve", label: "Vulnerability Intel (CVE)", icon: Bug },
    ],
  },
  {
    label: "SOC Operations",
    items: [
      { to: "/investigations", label: "Investigations", icon: FolderKanban },
      { to: "/incidents", label: "Incident Management", icon: Siren },
      { to: "/graph", label: "Threat Relationship Graph", icon: Network },
      { to: "/reports", label: "Reports & Compliance", icon: FileText },
    ],
  },
  {
    label: "Platform & Governance",
    items: [{ to: "/settings", label: "Settings", icon: Settings }],
  },
];

export const SocLayout: React.FC = () => {
  const { user, isAdmin, logout } = useAuth();
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  const renderSidebarContent = () => (
    <div className="flex flex-col h-full bg-soc-panel border-r border-slate-800/90">
      <div className="px-5 py-4 border-b border-slate-800/90 flex items-center justify-between">
        <NavLink to="/" className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-lg bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <div className="text-sm font-bold tracking-wider text-white">
              THREATLENS <span className="text-cyan-400">AI</span>
            </div>
            <div className="text-[10px] font-mono text-slate-400">
              DEFENSIVE SOC v1.0
            </div>
          </div>
        </NavLink>
        <button
          onClick={() => setMobileOpen(false)}
          className="lg:hidden text-slate-400 hover:text-white"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
        {NAV_SECTIONS.map((section) => (
          <div key={section.label}>
            <div className="px-3 mb-2 text-[10px] font-mono uppercase tracking-widest text-slate-500">
              {section.label}
            </div>
            <div className="space-y-1">
              {section.items.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    onClick={() => setMobileOpen(false)}
                    className={({ isActive }) =>
                      `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition ${
                        isActive
                          ? "bg-cyan-500/15 text-cyan-300 border border-cyan-500/30"
                          : "text-slate-400 hover:text-slate-100 hover:bg-slate-800/60"
                      }`
                    }
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{item.label}</span>
                  </NavLink>
                );
              })}
              {section.label === "Platform & Governance" && isAdmin && (
                <NavLink
                  to="/admin"
                  onClick={() => setMobileOpen(false)}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition ${
                      isActive
                        ? "bg-amber-500/15 text-amber-300 border border-amber-500/30"
                        : "text-amber-300/80 hover:text-amber-200 hover:bg-amber-500/10"
                    }`
                  }
                >
                  <UserCheck className="w-4 h-4 shrink-0" />
                  <span>Admin Governance</span>
                </NavLink>
              )}
            </div>
          </div>
        ))}
      </nav>

      <div className="p-4 border-t border-slate-800/90 space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0">
            <div className="text-xs font-semibold text-white truncate">
              {user?.name}
            </div>
            <div className="text-[11px] font-mono text-slate-400 truncate">
              {user?.email}
            </div>
          </div>
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
            {user?.role}
          </span>
        </div>
        <button
          onClick={handleLogout}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-medium bg-slate-900 hover:bg-red-950/60 text-slate-300 hover:text-red-300 border border-slate-800 hover:border-red-500/30 transition"
        >
          <LogOut className="w-3.5 h-3.5" />
          Sign Out
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen flex text-slate-100">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:block w-64 shrink-0 sticky top-0 h-screen">
        {renderSidebarContent()}
      </aside>

      {/* Mobile Drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div className="w-72 h-full">{renderSidebarContent()}</div>
          <div
            className="flex-1 bg-black/70 backdrop-blur-sm"
            onClick={() => setMobileOpen(false)}
          />
        </div>
      )}

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="sticky top-0 z-30 h-14 px-4 lg:px-8 bg-soc-bg/85 backdrop-blur-md border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileOpen(true)}
              className="lg:hidden p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-slate-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>AUTHORIZED DEFENSIVE OPERATIONS ONLY</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <span className="hidden md:inline-block text-xs font-mono text-slate-400">
              Dept: <strong className="text-slate-200">{user?.department}</strong>
            </span>
            <NavLink
              to="/scanner/url"
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition"
            >
              + Quick Threat Scan
            </NavLink>
          </div>
        </header>

        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
