export type Role = "ADMIN" | "ANALYST" | "VIEWER";
export type UserStatus = "ACTIVE" | "SUSPENDED";
export type IndicatorType = "URL" | "DOMAIN" | "IP" | "EMAIL" | "CVE";
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Verdict = "CLEAN" | "SUSPICIOUS" | "MALICIOUS" | "INFO";
export type InvestigationStatus = "OPEN" | "IN_PROGRESS" | "ESCALATED" | "CLOSED";
export type IncidentStatus =
  | "DETECTED"
  | "TRIAGING"
  | "CONTAINED"
  | "ERADICATED"
  | "RESOLVED";
export type ReportFormat = "EXECUTIVE" | "TECHNICAL" | "COMPLIANCE";

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  status?: UserStatus;
  department: string;
  preferences?: Record<string, unknown> | null;
  lastLoginAt?: string | null;
  createdAt?: string;
  _count?: { scans: number; ownedInvestigations: number };
}

export interface ScoreFactor {
  factor: string;
  points: number;
  max_points: number;
  reason: string;
  source: string;
  is_simulated: boolean;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
}

export interface AiExplanation {
  overview: string;
  why_flagged: string[];
  mitre_techniques: MitreTechnique[];
  recommended_actions: string[];
  is_simulated_ai?: boolean;
}

export interface Evidence {
  id: string;
  provider: string;
  category: string;
  title: string;
  verdict: Verdict;
  weight: number;
  details: Record<string, unknown>;
  isSimulated: boolean;
  createdAt: string;
}

export interface ScanResult {
  id: string;
  scanType: IndicatorType;
  targetValue: string;
  normalizedValue: string;
  riskScore: number;
  severity: Severity;
  confidence: number;
  verdict: Verdict;
  summary: string;
  aiExplanation: AiExplanation;
  scoreBreakdown: ScoreFactor[];
  providerStatus: Record<
    string,
    { mode: string; latency_ms: number; message: string }
  >;
  metadata?: Record<string, unknown>;
  isDemoData: boolean;
  evidence: Evidence[];
  investigationId?: string | null;
  investigation?: { id: string; code: string; title: string } | null;
  user?: { id?: string; name: string; email?: string };
  createdAt: string;
}

export interface InvestigationNote {
  id: string;
  content: string;
  isAiGenerated: boolean;
  author: { id: string; name: string; role: Role };
  createdAt: string;
}

export interface Investigation {
  id: string;
  code: string;
  title: string;
  description: string;
  status: InvestigationStatus;
  priority: Severity;
  tags: string[];
  aiSummary?: string | null;
  isDemoData: boolean;
  owner: { id: string; name: string; email: string };
  scans?: ScanResult[];
  notes?: InvestigationNote[];
  incidents?: Incident[];
  _count?: {
    scans: number;
    evidence: number;
    notes: number;
    incidents: number;
  };
  createdAt: string;
  updatedAt: string;
}

export interface PlaybookStep {
  id: string;
  phase: string;
  task: string;
  completed: boolean;
}

export interface Incident {
  id: string;
  code: string;
  title: string;
  summary: string;
  severity: Severity;
  status: IncidentStatus;
  affectedAssets: string[];
  mitreTechniques: string[];
  playbookSteps: PlaybookStep[];
  isDemoData: boolean;
  assignedTo?: { id: string; name: string; email: string } | null;
  investigation?: { id: string; code: string; title: string } | null;
  resolvedAt?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface GraphNode {
  id: string;
  type: string;
  value: string;
  label: string;
  severity: Severity;
  riskScore: number;
  isDemoData: boolean;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
  confidence: number;
  severity: Severity;
  isDemoData: boolean;
}

export interface Report {
  id: string;
  code: string;
  title: string;
  format: ReportFormat;
  summary: string;
  findingsMarkdown: string;
  riskOverview: {
    analyzedCount: number;
    averageRiskScore: number;
    peakRiskScore: number;
    generatedAt: string;
  };
  recommendations: string[];
  isDemoData: boolean;
  generatedBy: { id: string; name: string; email: string };
  investigation?: { id: string; code: string; title: string } | null;
  incident?: { id: string; code: string; title: string; severity: Severity } | null;
  createdAt: string;
}

export interface AuditLog {
  id: string;
  actorEmail: string;
  action: string;
  resourceType: string;
  resourceId?: string | null;
  ipAddress?: string | null;
  status: string;
  metadata?: Record<string, unknown>;
  createdAt: string;
}

export interface DashboardOverview {
  kpis: {
    totalScans: number;
    criticalThreats: number;
    openInvestigations: number;
    activeIncidents: number;
    totalIndicators: number;
  };
  trendData: Array<{
    date: string;
    total: number;
    criticalHigh: number;
    mediumLow: number;
  }>;
  indicatorDistribution: Array<{ name: string; value: number }>;
  severityDistribution: Array<{ severity: Severity; count: number }>;
  verdictDistribution: Array<{ verdict: Verdict; count: number }>;
  recentScans: ScanResult[];
  activeIncidentsList: Incident[];
  engineHealth: {
    status: string;
    providers?: Record<string, string>;
  };
}
