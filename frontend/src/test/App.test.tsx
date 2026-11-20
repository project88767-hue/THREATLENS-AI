import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "../context/AuthContext";
import { AppRoutes } from "../App";
import { RiskScoreGauge, SeverityBadge, TelemetrySourceBadge } from "../components/ui/Badges";

describe("THREATLENS AI Frontend Suite", () => {
  it("renders Landing Page with official tagline and defensive security messaging", () => {
    render(
      <AuthProvider>
        <MemoryRouter initialEntries={["/"]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    );

    expect(screen.getByText(/Detect threats\. Investigate evidence\./i)).toBeInTheDocument();
    expect(screen.getByText(/Understand risks\. Protect systems\./i)).toBeInTheDocument();
    expect(screen.getByText(/VirusTotal v3/i)).toBeInTheDocument();
  });

  it("renders Login Page with 1-click Demo RBAC role buttons", () => {
    render(
      <AuthProvider>
        <MemoryRouter initialEntries={["/login"]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    );

    expect(screen.getByText(/SOC Director \(ADMIN\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Threat Hunter \(ANALYST\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Auditor \(VIEWER\)/i)).toBeInTheDocument();
  });

  it("renders RiskScoreGauge, SeverityBadge, and TelemetrySourceBadge accurately", () => {
    render(
      <div>
        <RiskScoreGauge score={92} severity="CRITICAL" />
        <SeverityBadge severity="CRITICAL" />
        <TelemetrySourceBadge isSimulated={true} />
      </div>
    );

    expect(screen.getByText("92")).toBeInTheDocument();
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
    expect(screen.getByText("DEMO TELEMETRY")).toBeInTheDocument();
  });
});
