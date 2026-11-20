import { Router } from "express";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { prisma } from "../lib/prisma";
import { recordAudit } from "../lib/audit";
import { requireAuth, requireRole } from "../middleware/auth";
import { sanitizeText } from "../middleware/errorHandler";

export const reportsRouter = Router();

reportsRouter.use(requireAuth);

const generateReportSchema = z.object({
  title: z.string().min(3).max(160),
  format: z.enum(["EXECUTIVE", "TECHNICAL", "COMPLIANCE"]).default("TECHNICAL"),
  investigationId: z.string().uuid().optional(),
  incidentId: z.string().uuid().optional(),
});

reportsRouter.get("/", async (_req, res, next) => {
  try {
    const reports = await prisma.report.findMany({
      include: {
        generatedBy: { select: { id: true, name: true, email: true } },
        investigation: { select: { id: true, code: true, title: true } },
        incident: { select: { id: true, code: true, title: true, severity: true } },
      },
      orderBy: { createdAt: "desc" },
    });
    res.json({ reports });
  } catch (err) {
    next(err);
  }
});

reportsRouter.get("/:id", async (req, res, next) => {
  try {
    const report = await prisma.report.findUnique({
      where: { id: req.params.id },
      include: {
        generatedBy: { select: { id: true, name: true, email: true } },
        investigation: {
          include: { scans: { include: { evidence: true } }, notes: true },
        },
        incident: true,
      },
    });
    if (!report) {
      res.status(404).json({ error: "Report not found." });
      return;
    }
    res.json({ report });
  } catch (err) {
    next(err);
  }
});

reportsRouter.post(
  "/generate",
  requireRole("ADMIN", "ANALYST"),
  async (req, res, next) => {
    try {
      const body = generateReportSchema.parse(req.body);
      const count = await prisma.report.count();
      const code = `RPT-2026-${String(count + 301).padStart(3, "0")}`;

      const investigation = body.investigationId
        ? await prisma.investigation.findUnique({
            where: { id: body.investigationId },
            include: { scans: true, incidents: true },
          })
        : null;

      const incident = body.incidentId
        ? await prisma.incident.findUnique({ where: { id: body.incidentId } })
        : null;

      const scans =
        investigation?.scans ??
        (await prisma.scanResult.findMany({ orderBy: { createdAt: "desc" }, take: 5 }));

      const avgRisk = scans.length
        ? Math.round(scans.reduce((acc, s) => acc + s.riskScore, 0) / scans.length)
        : 50;
      const maxRisk = scans.length ? Math.max(...scans.map((s) => s.riskScore)) : 50;

      const summary =
        `${body.format} cybersecurity assessment compiled by ${req.user!.name}. ` +
        `Analyzed ${scans.length} indicator scans (peak risk score ${maxRisk}/100, mean ${avgRisk}/100).` +
        (incident ? ` Linked Incident ${incident.code} status: ${incident.status}.` : "");

      const scanLines = scans
        .map(
          (s) =>
            `- **[${s.severity}] ${s.scanType}** \`${s.normalizedValue}\` — Risk Score **${s.riskScore}/100** (${s.verdict}): ${s.summary}`
        )
        .join("\n");

      const findingsMarkdown = [
        `# ${sanitizeText(body.title)}`,
        `**Report ID:** \`${code}\` | **Format:** \`${body.format}\` | **Author:** ${req.user!.name}`,
        "",
        "## 1. Executive Assessment",
        summary,
        "",
        investigation
          ? `## 2. Linked Investigation (${investigation.code})\n**${investigation.title}** — Status: \`${investigation.status}\` | Priority: \`${investigation.priority}\`\n\n${investigation.description}`
          : "## 2. Scope of Analysis\nConsolidated multi-provider SOC indicator review under authorized defensive operations.",
        "",
        "## 3. Analyzed Indicators & Explainable Risk Scores",
        scanLines || "- No scan artifacts attached.",
        "",
        "## 4. Defensive Remediation & Hardening Controls",
        "1. Enforce DNS RPZ, Secure Web Gateway, and Perimeter Firewall blocks on all `MALICIOUS` indicators.",
        "2. Enforce strict DMARC (`p=reject`), DKIM signing, and phishing-resistant MFA across privileged accounts.",
        "3. Patch CISA KEV / high-CVSS vulnerabilities within emergency SLA windows and verify via continuous vulnerability scanning.",
        "4. Retain immutable audit logs and evidence artifacts for compliance verification (ISO 27001 / SOC 2 / NIST CSF).",
      ].join("\n");

      const recommendations = [
        "Block high-severity indicators across DNS, SWG, and Firewall policies.",
        "Complete endpoint EDR and 30-day SIEM retro-hunt for correlated IOCs.",
        "Validate MFA session revocation and patch compliance on exposed assets.",
      ];

      const report = await prisma.report.create({
        data: {
          code,
          title: sanitizeText(body.title),
          format: body.format,
          summary,
          findingsMarkdown,
          riskOverview: {
            analyzedCount: scans.length,
            averageRiskScore: avgRisk,
            peakRiskScore: maxRisk,
            generatedAt: new Date().toISOString(),
          } as Prisma.InputJsonValue,
          recommendations: recommendations as Prisma.InputJsonValue,
          investigationId: body.investigationId ?? null,
          incidentId: body.incidentId ?? null,
          generatedById: req.user!.id,
        },
        include: {
          generatedBy: { select: { id: true, name: true, email: true } },
          investigation: { select: { id: true, code: true, title: true } },
          incident: { select: { id: true, code: true, title: true, severity: true } },
        },
      });

      await recordAudit({
        req,
        userId: req.user!.id,
        actorEmail: req.user!.email,
        action: "REPORT_GENERATED",
        resourceType: "Report",
        resourceId: report.id,
        metadata: { code: report.code, format: report.format },
      });

      res.status(201).json({ report });
    } catch (err) {
      next(err);
    }
  }
);
