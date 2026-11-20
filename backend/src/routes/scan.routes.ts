import { Router } from "express";
import { IndicatorType, Prisma, Severity, Verdict } from "@prisma/client";
import { z } from "zod";
import { prisma } from "../lib/prisma";
import { recordAudit } from "../lib/audit";
import {
  callAnalysisEngine,
  enforceBackendSsrfGuard,
  EngineAnalysisResult,
} from "../lib/engineClient";
import { requireAuth, requireRole } from "../middleware/auth";
import { scanLimiter } from "../middleware/rateLimiters";

export const scanRouter = Router();

scanRouter.use(requireAuth);

const urlScanSchema = z.object({
  url: z.string().min(4).max(2048),
  investigationId: z.string().uuid().optional(),
});

const ipScanSchema = z.object({
  ip: z.string().min(3).max(128),
  investigationId: z.string().uuid().optional(),
});

const domainScanSchema = z.object({
  domain: z.string().min(3).max(253),
  investigationId: z.string().uuid().optional(),
});

const emailScanSchema = z.object({
  rawHeaders: z.string().max(50000).default(""),
  body: z.string().max(100000).default(""),
  subject: z.string().max(500).optional(),
  sender: z.string().max(320).optional(),
  investigationId: z.string().uuid().optional(),
});

const cveScanSchema = z.object({
  cveId: z.string().min(2).max(120),
  investigationId: z.string().uuid().optional(),
});

async function persistAnalysisResult(
  userId: string,
  analysis: EngineAnalysisResult,
  investigationId?: string
) {
  const scanType = analysis.indicator_type as IndicatorType;
  const severity = analysis.severity as Severity;
  const verdict = analysis.verdict as Verdict;

  const indicator = await prisma.indicator.upsert({
    where: {
      type_normalizedValue: {
        type: scanType,
        normalizedValue: analysis.normalized_target,
      },
    },
    update: {
      riskScore: analysis.risk_score,
      severity,
      confidence: analysis.confidence,
      verdict,
      lastSeenAt: new Date(),
      scanCount: { increment: 1 },
    },
    create: {
      type: scanType,
      value: analysis.target,
      normalizedValue: analysis.normalized_target,
      riskScore: analysis.risk_score,
      severity,
      confidence: analysis.confidence,
      verdict,
      tags: [scanType.toLowerCase(), severity.toLowerCase()],
    },
  });

  const scan = await prisma.scanResult.create({
    data: {
      indicatorId: indicator.id,
      userId,
      investigationId: investigationId ?? null,
      scanType,
      targetValue: analysis.target,
      normalizedValue: analysis.normalized_target,
      riskScore: analysis.risk_score,
      severity,
      confidence: analysis.confidence,
      verdict,
      summary: analysis.summary,
      aiExplanation: analysis.ai_explanation as Prisma.InputJsonValue,
      scoreBreakdown: analysis.score_breakdown as Prisma.InputJsonValue,
      providerStatus: analysis.provider_status as Prisma.InputJsonValue,
      metadata: (analysis.metadata ?? {}) as Prisma.InputJsonValue,
      evidence: {
        create: analysis.evidence.map((ev) => ({
          investigationId: investigationId ?? null,
          provider: ev.provider,
          category: ev.category,
          title: ev.title,
          verdict: ev.verdict as Verdict,
          weight: ev.weight,
          details: ev.details as Prisma.InputJsonValue,
          isSimulated: ev.is_simulated,
        })),
      },
    },
    include: {
      evidence: true,
      indicator: true,
      user: { select: { id: true, name: true, email: true } },
    },
  });

  // Persist extracted threat relationships for the Threat Relationship Graph
  for (const rel of analysis.extracted_relations ?? []) {
    const exists = await prisma.threatRelation.findFirst({
      where: {
        sourceValue: rel.source_value,
        targetValue: rel.target_value,
        relation: rel.relation,
      },
    });
    if (!exists) {
      await prisma.threatRelation.create({
        data: {
          sourceType: rel.source_type,
          sourceValue: rel.source_value,
          sourceLabel: rel.source_label,
          targetType: rel.target_type,
          targetValue: rel.target_value,
          targetLabel: rel.target_label,
          relation: rel.relation,
          confidence: rel.confidence,
          severity,
          investigationId: investigationId ?? null,
        },
      });
    }
  }

  return scan;
}

scanRouter.get("/", async (req, res, next) => {
  try {
    const typeFilter = req.query.type as IndicatorType | undefined;
    const severityFilter = req.query.severity as Severity | undefined;
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 25));

    const scans = await prisma.scanResult.findMany({
      where: {
        ...(typeFilter ? { scanType: typeFilter } : {}),
        ...(severityFilter ? { severity: severityFilter } : {}),
      },
      include: {
        evidence: true,
        user: { select: { id: true, name: true, role: true } },
        investigation: { select: { id: true, code: true, title: true } },
      },
      orderBy: { createdAt: "desc" },
      take: limit,
    });

    res.json({ scans });
  } catch (err) {
    next(err);
  }
});

scanRouter.get("/:id", async (req, res, next) => {
  try {
    const scan = await prisma.scanResult.findUnique({
      where: { id: req.params.id },
      include: {
        evidence: true,
        indicator: true,
        user: { select: { id: true, name: true, email: true } },
        investigation: { select: { id: true, code: true, title: true } },
      },
    });
    if (!scan) {
      res.status(404).json({ error: "Scan result not found." });
      return;
    }
    res.json({ scan });
  } catch (err) {
    next(err);
  }
});

scanRouter.post(
  "/url",
  requireRole("ADMIN", "ANALYST"),
  scanLimiter,
  async (req, res, next) => {
    try {
      const body = urlScanSchema.parse(req.body);
      enforceBackendSsrfGuard(body.url, "URL");
      const analysis = await callAnalysisEngine("/api/v1/analyze/url", { url: body.url });
      const scan = await persistAnalysisResult(req.user!.id, analysis, body.investigationId);

      await recordAudit({
        req,
        userId: req.user!.id,
        actorEmail: req.user!.email,
        action: "SCAN_URL",
        resourceType: "ScanResult",
        resourceId: scan.id,
        metadata: { target: scan.normalizedValue, riskScore: scan.riskScore, severity: scan.severity },
      });

      res.status(201).json({ scan });
    } catch (err) {
      next(err);
    }
  }
);

scanRouter.post(
  "/ip",
  requireRole("ADMIN", "ANALYST"),
  scanLimiter,
  async (req, res, next) => {
    try {
      const body = ipScanSchema.parse(req.body);
      enforceBackendSsrfGuard(body.ip, "IP");
      const analysis = await callAnalysisEngine("/api/v1/analyze/ip", { ip: body.ip });
      const scan = await persistAnalysisResult(req.user!.id, analysis, body.investigationId);

      await recordAudit({
        req,
        userId: req.user!.id,
        actorEmail: req.user!.email,
        action: "SCAN_IP",
        resourceType: "ScanResult",
        resourceId: scan.id,
        metadata: { target: scan.normalizedValue, riskScore: scan.riskScore, severity: scan.severity },
      });

      res.status(201).json({ scan });
    } catch (err) {
      next(err);
    }
  }
);

scanRouter.post(
  "/domain",
  requireRole("ADMIN", "ANALYST"),
  scanLimiter,
  async (req, res, next) => {
    try {
      const body = domainScanSchema.parse(req.body);
      enforceBackendSsrfGuard(body.domain, "DOMAIN");
      const analysis = await callAnalysisEngine("/api/v1/analyze/domain", {
        domain: body.domain,
      });
      const scan = await persistAnalysisResult(req.user!.id, analysis, body.investigationId);

      await recordAudit({
        req,
        userId: req.user!.id,
        actorEmail: req.user!.email,
        action: "SCAN_DOMAIN",
        resourceType: "ScanResult",
        resourceId: scan.id,
        metadata: { target: scan.normalizedValue, riskScore: scan.riskScore, severity: scan.severity },
      });

      res.status(201).json({ scan });
    } catch (err) {
      next(err);
    }
  }
);

scanRouter.post(
  "/email",
  requireRole("ADMIN", "ANALYST"),
  scanLimiter,
  async (req, res, next) => {
    try {
      const body = emailScanSchema.parse(req.body);
      if (!body.rawHeaders.trim() && !body.body.trim()) {
        res.status(400).json({ error: "Provide email headers or body to analyze." });
        return;
      }
      const analysis = await callAnalysisEngine("/api/v1/analyze/email", {
        raw_headers: body.rawHeaders,
        body: body.body,
        subject: body.subject,
        sender: body.sender,
      });
      const scan = await persistAnalysisResult(req.user!.id, analysis, body.investigationId);

      await recordAudit({
        req,
        userId: req.user!.id,
        actorEmail: req.user!.email,
        action: "SCAN_EMAIL",
        resourceType: "ScanResult",
        resourceId: scan.id,
        metadata: { target: scan.normalizedValue, riskScore: scan.riskScore, severity: scan.severity },
      });

      res.status(201).json({ scan });
    } catch (err) {
      next(err);
    }
  }
);

scanRouter.post(
  "/cve",
  requireRole("ADMIN", "ANALYST"),
  scanLimiter,
  async (req, res, next) => {
    try {
      const body = cveScanSchema.parse(req.body);
      const analysis = await callAnalysisEngine("/api/v1/analyze/cve", { cve_id: body.cveId });
      const scan = await persistAnalysisResult(req.user!.id, analysis, body.investigationId);

      await recordAudit({
        req,
        userId: req.user!.id,
        actorEmail: req.user!.email,
        action: "SCAN_CVE",
        resourceType: "ScanResult",
        resourceId: scan.id,
        metadata: { target: scan.normalizedValue, riskScore: scan.riskScore, severity: scan.severity },
      });

      res.status(201).json({ scan });
    } catch (err) {
      next(err);
    }
  }
);
