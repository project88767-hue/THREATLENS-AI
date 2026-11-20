import { env } from "../config/env";

export class EngineClientError extends Error {
  constructor(
    public statusCode: number,
    message: string
  ) {
    super(message);
    this.name = "EngineClientError";
  }
}

export interface EngineAnalysisResult {
  indicator_type: "URL" | "IP" | "DOMAIN" | "EMAIL" | "CVE";
  target: string;
  normalized_target: string;
  risk_score: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence: number;
  verdict: "CLEAN" | "SUSPICIOUS" | "MALICIOUS";
  summary: string;
  ai_explanation: Record<string, unknown>;
  score_breakdown: Array<Record<string, unknown>>;
  evidence: Array<{
    provider: string;
    category: string;
    title: string;
    verdict: "CLEAN" | "SUSPICIOUS" | "MALICIOUS" | "INFO";
    weight: number;
    details: Record<string, unknown>;
    is_simulated: boolean;
  }>;
  provider_status: Record<string, unknown>;
  extracted_relations: Array<{
    source_type: string;
    source_value: string;
    source_label: string;
    target_type: string;
    target_value: string;
    target_label: string;
    relation: string;
    confidence: number;
  }>;
  metadata: Record<string, unknown>;
}

const PRIVATE_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^0\./,
  /^::1$/,
  /\.local$/i,
  /\.internal$/i,
];

export function enforceBackendSsrfGuard(target: string, kind: "URL" | "IP" | "DOMAIN"): void {
  const trimmed = target.trim();
  if (kind === "URL") {
    let parsed: URL;
    try {
      parsed = new URL(/^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
    } catch {
      if (/^[a-zA-Z]+:\/\//.test(trimmed)) {
        throw new EngineClientError(403, "SSRF Protection: Only http:// and https:// URLs are permitted.");
      }
      throw new EngineClientError(400, "Invalid URL format.");
    }
    if (!["http:", "https:"].includes(parsed.protocol)) {
      throw new EngineClientError(403, `SSRF Protection: Restricted protocol '${parsed.protocol}'.`);
    }
    const host = parsed.hostname.toLowerCase();
    if (PRIVATE_HOST_PATTERNS.some((rx) => rx.test(host))) {
      throw new EngineClientError(
        403,
        `SSRF Protection: Internal, loopback, or metadata host '${host}' is blocked.`
      );
    }
  } else if (kind === "IP" || kind === "DOMAIN") {
    if (PRIVATE_HOST_PATTERNS.some((rx) => rx.test(trimmed.toLowerCase()))) {
      throw new EngineClientError(
        403,
        `SSRF Protection: Restricted private or internal indicator '${trimmed}' cannot be scanned.`
      );
    }
  }
}

export async function callAnalysisEngine(
  endpoint: string,
  payload: Record<string, unknown>
): Promise<EngineAnalysisResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);

  try {
    const res = await fetch(`${env.ANALYSIS_ENGINE_URL}${endpoint}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Engine-Key": env.INTERNAL_ENGINE_KEY,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) {
      const errBody = (await res.json().catch(() => ({}))) as { detail?: string };
      throw new EngineClientError(
        res.status,
        errBody.detail || `Analysis engine returned HTTP ${res.status}`
      );
    }
    return (await res.json()) as EngineAnalysisResult;
  } catch (err) {
    clearTimeout(timeout);
    if (err instanceof EngineClientError) {
      throw err;
    }
    // Graceful degraded fallback if Python FastAPI microservice is unreachable
    return buildEmergencyFallback(endpoint, payload);
  }
}

export async function fetchEngineHealth(): Promise<Record<string, unknown>> {
  try {
    const res = await fetch(`${env.ANALYSIS_ENGINE_URL}/health`, {
      headers: { "X-Engine-Key": env.INTERNAL_ENGINE_KEY },
    });
    if (res.ok) {
      return (await res.json()) as Record<string, unknown>;
    }
  } catch {
    // Fallback status
  }
  return {
    status: "degraded_fallback",
    service: "threatlens-analysis-engine",
    authorized_defensive_mode: true,
    providers: {
      virustotal: "DEMO_FALLBACK",
      google_safe_browsing: "DEMO_FALLBACK",
      abuseipdb: "DEMO_FALLBACK",
      alienvault_otx: "DEMO_FALLBACK",
      nvd: "DEMO_FALLBACK",
      rdap: "DEMO_FALLBACK",
      ai_assistant: "SOC_COPILOT_ENGINE",
    },
  };
}

export async function callAssistantEngine(payload: Record<string, unknown>): Promise<{
  reply: string;
  suggested_questions: string[];
  mitre_mappings: Array<{ id: string; name: string; tactic: string }>;
  recommended_steps: string[];
  is_simulated_ai: boolean;
}> {
  try {
    const res = await fetch(`${env.ANALYSIS_ENGINE_URL}/api/v1/assistant/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Engine-Key": env.INTERNAL_ENGINE_KEY,
      },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // Fallback below
  }

  return {
    reply:
      "### SOC Investigation Copilot (Fallback Mode)\n" +
      "1. **Verify Indicator Reputation**: Cross-check multi-engine hits against structural lexical/header evidence.\n" +
      "2. **Contain Exposure**: Block confirmed malicious hosts at DNS/SWG/Firewall and audit 30-day SIEM logs.\n" +
      "3. **Document & Escalate**: Attach scan findings to an Investigation and open an Incident if internal endpoints are affected.",
    suggested_questions: [
      "How do we triage phishing SPF/DMARC failures?",
      "Draft an executive summary for this investigation",
      "Prioritize CVE patching for internet-facing systems",
    ],
    mitre_mappings: [
      { id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "Initial Access" },
    ],
    recommended_steps: [
      "Review score breakdown factors",
      "Check Threat Relationship Graph",
      "Initiate Incident containment checklist if high risk",
    ],
    is_simulated_ai: true,
  };
}

function buildEmergencyFallback(
  endpoint: string,
  payload: Record<string, unknown>
): EngineAnalysisResult {
  const indicatorMap: Record<string, EngineAnalysisResult["indicator_type"]> = {
    "/api/v1/analyze/url": "URL",
    "/api/v1/analyze/ip": "IP",
    "/api/v1/analyze/domain": "DOMAIN",
    "/api/v1/analyze/email": "EMAIL",
    "/api/v1/analyze/cve": "CVE",
  };
  const indicator_type = indicatorMap[endpoint] || "URL";
  const rawTarget = String(
    payload.url || payload.ip || payload.domain || payload.cve_id || payload.sender || "email-sample"
  );
  const blob = JSON.stringify(payload).toLowerCase();
  const isRisky =
    /verify|login|phish|\.xyz|\.tk|fail|urgent|wire|45\.95\.|185\.220\.|cve-2024-3094|cve-2021-44228/.test(
      blob
    );
  const risk_score = isRisky ? 82 : 14;
  const severity = isRisky ? "HIGH" : "LOW";
  const verdict = isRisky ? "MALICIOUS" : "CLEAN";

  return {
    indicator_type,
    target: rawTarget,
    normalized_target: rawTarget.trim().toLowerCase(),
    risk_score,
    severity,
    confidence: 70,
    verdict,
    summary: `[Resilient Fallback] ${indicator_type} '${rawTarget}' evaluated as ${verdict} (${risk_score}/100).`,
    ai_explanation: {
      overview:
        "Evaluated via resilient backend fallback heuristics while Python analysis microservice reconnected.",
      why_flagged: isRisky
        ? ["Matched high-risk phishing, C2, authentication failure, or critical CVE pattern (+82 pts)"]
        : ["No high-risk heuristic patterns detected"],
      mitre_techniques: isRisky
        ? [{ id: "T1566", name: "Phishing / Initial Access", tactic: "Initial Access" }]
        : [],
      recommended_actions: isRisky
        ? ["Block indicator on perimeter controls and escalate to SOC Investigation."]
        : ["Continue baseline monitoring."],
      is_simulated_ai: true,
    },
    score_breakdown: [
      {
        factor: "Resilient Heuristic Engine",
        points: risk_score,
        max_points: 100,
        reason: isRisky ? "High-risk threat signature detected." : "Clean baseline signature.",
        source: "Backend Resilient Analyzer",
        is_simulated: true,
      },
    ],
    evidence: [
      {
        provider: "HEURISTIC_ENGINE",
        category: "Resilient Fallback Forensics (Demo Telemetry)",
        title: isRisky ? "[DEMO] High-risk indicator traits matched" : "[DEMO] Clean baseline indicator",
        verdict,
        weight: risk_score,
        details: { fallback: true, target: rawTarget },
        is_simulated: true,
      },
    ],
    provider_status: {
      heuristic_engine: {
        mode: "DEMO_FALLBACK",
        latency_ms: 2,
        message: "Resilient fallback active",
      },
    },
    extracted_relations: [],
    metadata: { target: rawTarget, fallback: true },
  };
}
