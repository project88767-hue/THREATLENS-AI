import React from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { SocLayout } from "./components/layout/SocLayout";
import { LandingPage } from "./pages/LandingPage";
import { AuthPage } from "./pages/AuthPage";
import { DashboardPage } from "./pages/DashboardPage";
import { UrlScannerPage } from "./pages/UrlScannerPage";
import { EmailAnalyzerPage } from "./pages/EmailAnalyzerPage";
import { IpIntelPage } from "./pages/IpIntelPage";
import { DomainIntelPage } from "./pages/DomainIntelPage";
import { VulnIntelPage } from "./pages/VulnIntelPage";
import { AiAssistantPage } from "./pages/AiAssistantPage";
import { InvestigationsPage } from "./pages/InvestigationsPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { ThreatGraphPage } from "./pages/ThreatGraphPage";
import { ReportsPage } from "./pages/ReportsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { AdminPage } from "./pages/AdminPage";

const ProtectedRoute: React.FC<{
  children: React.ReactNode;
  adminOnly?: boolean;
}> = ({ children, adminOnly = false }) => {
  const { user, loading, isAdmin } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center font-mono text-sm text-cyan-400">
        Initializing THREATLENS AI Security Context...
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (adminOnly && !isAdmin) {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
};

export const AppRoutes: React.FC = () => (
  <Routes>
    <Route path="/" element={<LandingPage />} />
    <Route path="/login" element={<AuthPage />} />
    <Route path="/register" element={<AuthPage />} />

    <Route
      element={
        <ProtectedRoute>
          <SocLayout />
        </ProtectedRoute>
      }
    >
      <Route path="/dashboard" element={<DashboardPage />} />
      <Route path="/scanner/url" element={<UrlScannerPage />} />
      <Route path="/scanner/email" element={<EmailAnalyzerPage />} />
      <Route path="/intel/ip" element={<IpIntelPage />} />
      <Route path="/intel/domain" element={<DomainIntelPage />} />
      <Route path="/intel/cve" element={<VulnIntelPage />} />
      <Route path="/assistant" element={<AiAssistantPage />} />
      <Route path="/investigations" element={<InvestigationsPage />} />
      <Route path="/incidents" element={<IncidentsPage />} />
      <Route path="/graph" element={<ThreatGraphPage />} />
      <Route path="/reports" element={<ReportsPage />} />
      <Route path="/settings" element={<SettingsPage />} />
      <Route
        path="/admin"
        element={
          <ProtectedRoute adminOnly>
            <AdminPage />
          </ProtectedRoute>
        }
      />
    </Route>

    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>
);

export const App: React.FC = () => (
  <AuthProvider>
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  </AuthProvider>
);

export default App;
