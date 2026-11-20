import { Router } from "express";
import { IncidentStatus, Prisma, Severity } from "@prisma/client";
import { z } from "zod";
import { prisma } from "../lib/prisma";
import { recordAudit } from "../lib/audit";
import { requireAuth, requireRole } from "../middleware/auth";
import { sanitizeText } from "../middleware/errorHandler";

export const incidentsRouter = Router();

incidentsRouter.use(requireAuth);

const playbookStepSchema = z.object({
  id: z.string(),
  phase: z.string(),
  task: z.string(),
  completed: z.boolean(),
});

const createIncidentSchema = z.object({
  title: z.string().min(3).max(160),
  summary: z.string().min(5).max(4000),
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).default("HIGH"),
  affectedAssets: z.array(z.string().max(120)).max(20).default([]),
  mitreTechniques: z.array(z.string().max(60)).max(15).default([]),
  investigationId: z.string().uuid().optional(),
  playbookSteps: z.array(playbookStepSchema).optional(),
});

const updateIncidentSchema = z.object({
  title: z.string().min(3).max(160).optional(),
  summary: z.string().min(5).max(4000).optional(),
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional(),
  status: z.enum(["DETECTED", "TRIAGING", "CONTAINED", "ERADICATED", "RESOLVED"]).optional(),
  affectedAssets: z.array(z.string().max(120)).max(20).optional(),
  playbookSteps: z.array(playbookStepSchema).optional(),
  assignedToId: z.string().uuid().nullable().optional(),
});

const DEFAULT_NIST_PLAYBOOK = [
  {
    id: "pb-1",
    phase: "Identification",
    task: "Validate indicator telemetry & confirm affected users/hosts in SIEM",
    completed: true,
  },
  {
    id: "pb-2",
    phase: "Containment",
    task: "Block malicious domains, URLs, or IPs on Firewall / SWG / DNS RPZ",
    completed: false,
  },
  {
    id: "pb-3",
    phase: "Containment",
    task: "Isolate impacted endpoints or revoke compromised user session tokens",
    completed: false,
  },
  {
    id: "pb-4",
    phase: "Eradication",
    task: "Purge phishing payloads, apply CVE patches, and rotate credentials",
    completed: false,
  },
  {
    id: "pb-5",
    phase: "Recovery & Lessons",
    task: "Verify clean telemetry for 24h and publish formal Incident Report",
    completed: false,
  },
];

incidentsRouter.get("/", async (req, res, next) => {
  try {
    const status = req.query.status as IncidentStatus | undefined;
    const severity = req.query.severity as Severity | undefined;

    const incidents = await prisma.incident.findMany({
      where: {
        ...(status ? { status } : {}),
        ...(severity ? { severity } : {}),
      },
      include: {
        assignedTo: { select: { id: true, name: true, email: true } },
        investigation: { select: { id: true, code: true, title: true } },
      },
      orderBy: { updatedAt: "desc" },
    });

    res.json({ incidents });
  } catch (err) {
    next(err);
  }
});

incidentsRouter.get("/:id", async (req, res, next) => {
  try {
    const incident = await prisma.incident.findUnique({
      where: { id: req.params.id },
      include: {
        assignedTo: { select: { id: true, name: true, email: true } },
        investigation: {
          include: { scans: { take: 5, orderBy: { createdAt: "desc" } } },
        },
        reports: true,
      },
    });
    if (!incident) {
      res.status(404).json({ error: "Incident not found." });
      return;
    }
    res.json({ incident });
  } catch (err) {
    next(err);
  }
});

incidentsRouter.post(
  "/",
  requireRole("ADMIN", "ANALYST"),
  async (req, res, next) => {
    try {
      const body = createIncidentSchema.parse(req.body);
      const count = await prisma.incident.count();
      const code = `INC-2026-${String(count + 201).padStart(3, "0")}`;

      const incident = await prisma.incident.create({
        data: {
          code,
          title: sanitizeText(body.title),
          summary: sanitizeText(body.summary),
          severity: body.severity,
          status: "DETECTED",
          affectedAssets: body.affectedAssets.map(sanitizeText),
          mitreTechniques: body.mitreTechniques.map(sanitizeText),
          playbookSteps: (body.playbookSteps ?? DEFAULT_NIST_PLAYBOOK) as Prisma.InputJsonValue,
          assignedToId: req.user!.id,
          investigationId: body.investigationId ?? null,
        },
        include: {
          assignedTo: { select: { id: true, name: true, email: true } },
          investigation: { select: { id: true, code: true, title: true } },
        },
      });

      if (body.investigationId) {
        await prisma.investigation.update({
          where: { id: body.investigationId },
          data: { status: "ESCALATED" },
        });
      }

      await recordAudit({
        req,
        userId: req.user!.id,
        actorEmail: req.user!.email,
        action: "INCIDENT_CREATED",
        resourceType: "Incident",
        resourceId: incident.id,
        metadata: { code: incident.code, severity: incident.severity },
      });

      res.status(201).json({ incident });
    } catch (err) {
      next(err);
    }
  }
);

incidentsRouter.patch(
  "/:id",
  requireRole("ADMIN", "ANALYST"),
  async (req, res, next) => {
    try {
      const body = updateIncidentSchema.parse(req.body);
      const resolvedAt =
        body.status === "RESOLVED"
          ? new Date()
          : body.status
          ? null
          : undefined;

      const incident = await prisma.incident.update({
        where: { id: req.params.id },
        data: {
          ...(body.title ? { title: sanitizeText(body.title) } : {}),
          ...(body.summary ? { summary: sanitizeText(body.summary) } : {}),
          ...(body.severity ? { severity: body.severity } : {}),
          ...(body.status ? { status: body.status } : {}),
          ...(body.affectedAssets
            ? { affectedAssets: body.affectedAssets.map(sanitizeText) }
            : {}),
          ...(body.playbookSteps
            ? { playbookSteps: body.playbookSteps as Prisma.InputJsonValue }
            : {}),
          ...(body.assignedToId !== undefined ? { assignedToId: body.assignedToId } : {}),
          ...(resolvedAt !== undefined ? { resolvedAt } : {}),
        },
        include: {
          assignedTo: { select: { id: true, name: true, email: true } },
          investigation: { select: { id: true, code: true, title: true } },
        },
      });

      await recordAudit({
        req,
        userId: req.user!.id,
        actorEmail: req.user!.email,
        action: "INCIDENT_UPDATED",
        resourceType: "Incident",
        resourceId: incident.id,
        metadata: { status: incident.status, severity: incident.severity },
      });

      res.json({ incident });
    } catch (err) {
      next(err);
    }
  }
);
