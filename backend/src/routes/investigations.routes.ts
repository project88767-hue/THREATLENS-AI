import { Router } from "express";
import { InvestigationStatus, Severity } from "@prisma/client";
import { z } from "zod";
import { prisma } from "../lib/prisma";
import { recordAudit } from "../lib/audit";
import { requireAuth, requireRole } from "../middleware/auth";
import { sanitizeText } from "../middleware/errorHandler";

export const investigationsRouter = Router();

investigationsRouter.use(requireAuth);

const createInvestigationSchema = z.object({
  title: z.string().min(3).max(160),
  description: z.string().min(5).max(4000),
  priority: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).default("MEDIUM"),
  tags: z.array(z.string().max(40)).max(12).default([]),
  scanId: z.string().uuid().optional(),
});

const updateInvestigationSchema = z.object({
  title: z.string().min(3).max(160).optional(),
  description: z.string().min(5).max(4000).optional(),
  status: z.enum(["OPEN", "IN_PROGRESS", "ESCALATED", "CLOSED"]).optional(),
  priority: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional(),
  aiSummary: z.string().max(6000).optional(),
  tags: z.array(z.string().max(40)).max(12).optional(),
});

const noteSchema = z.object({
  content: z.string().min(2).max(5000),
});

const attachScanSchema = z.object({
  scanId: z.string().uuid(),
});

investigationsRouter.get("/", async (req, res, next) => {
  try {
    const status = req.query.status as InvestigationStatus | undefined;
    const priority = req.query.priority as Severity | undefined;

    const investigations = await prisma.investigation.findMany({
      where: {
        ...(status ? { status } : {}),
        ...(priority ? { priority } : {}),
      },
      include: {
        owner: { select: { id: true, name: true, email: true, role: true } },
        _count: {
          select: { scans: true, evidence: true, notes: true, incidents: true },
        },
      },
      orderBy: { updatedAt: "desc" },
    });

    res.json({ investigations });
  } catch (err) {
    next(err);
  }
});

investigationsRouter.get("/:id", async (req, res, next) => {
  try {
    const investigation = await prisma.investigation.findUnique({
      where: { id: req.params.id },
      include: {
        owner: { select: { id: true, name: true, email: true } },
        scans: {
          include: { evidence: true },
          orderBy: { createdAt: "desc" },
        },
        notes: {
          include: { author: { select: { id: true, name: true, role: true } } },
          orderBy: { createdAt: "desc" },
        },
        incidents: true,
        reports: true,
      },
    });
    if (!investigation) {
      res.status(404).json({ error: "Investigation not found." });
      return;
    }
    res.json({ investigation });
  } catch (err) {
    next(err);
  }
});

investigationsRouter.post(
  "/",
  requireRole("ADMIN", "ANALYST"),
  async (req, res, next) => {
    try {
      const body = createInvestigationSchema.parse(req.body);
      const count = await prisma.investigation.count();
      const code = `INV-2026-${String(count + 101).padStart(3, "0")}`;

      const investigation = await prisma.investigation.create({
        data: {
          code,
          title: sanitizeText(body.title),
          description: sanitizeText(body.description),
          priority: body.priority,
          tags: body.tags.map(sanitizeText),
          ownerId: req.user!.id,
        },
        include: {
          owner: { select: { id: true, name: true, email: true } },
        },
      });

      if (body.scanId) {
        await prisma.scanResult.updateMany({
          where: { id: body.scanId },
          data: { investigationId: investigation.id },
        });
        await prisma.evidence.updateMany({
          where: { scanResultId: body.scanId },
          data: { investigationId: investigation.id },
        });
      }

      await recordAudit({
        req,
        userId: req.user!.id,
        actorEmail: req.user!.email,
        action: "INVESTIGATION_CREATED",
        resourceType: "Investigation",
        resourceId: investigation.id,
        metadata: { code: investigation.code, priority: investigation.priority },
      });

      res.status(201).json({ investigation });
    } catch (err) {
      next(err);
    }
  }
);

investigationsRouter.patch(
  "/:id",
  requireRole("ADMIN", "ANALYST"),
  async (req, res, next) => {
    try {
      const body = updateInvestigationSchema.parse(req.body);
      const updated = await prisma.investigation.update({
        where: { id: req.params.id },
        data: {
          ...(body.title ? { title: sanitizeText(body.title) } : {}),
          ...(body.description ? { description: sanitizeText(body.description) } : {}),
          ...(body.status ? { status: body.status } : {}),
          ...(body.priority ? { priority: body.priority } : {}),
          ...(body.aiSummary !== undefined ? { aiSummary: sanitizeText(body.aiSummary) } : {}),
          ...(body.tags ? { tags: body.tags.map(sanitizeText) } : {}),
        },
        include: {
          owner: { select: { id: true, name: true, email: true } },
        },
      });

      await recordAudit({
        req,
        userId: req.user!.id,
        actorEmail: req.user!.email,
        action: "INVESTIGATION_UPDATED",
        resourceType: "Investigation",
        resourceId: updated.id,
        metadata: { status: updated.status, priority: updated.priority },
      });

      res.json({ investigation: updated });
    } catch (err) {
      next(err);
    }
  }
);

investigationsRouter.post(
  "/:id/notes",
  requireRole("ADMIN", "ANALYST"),
  async (req, res, next) => {
    try {
      const body = noteSchema.parse(req.body);
      const note = await prisma.investigationNote.create({
        data: {
          investigationId: req.params.id,
          authorId: req.user!.id,
          content: sanitizeText(body.content),
        },
        include: {
          author: { select: { id: true, name: true, role: true } },
        },
      });

      res.status(201).json({ note });
    } catch (err) {
      next(err);
    }
  }
);

investigationsRouter.post(
  "/:id/attach-scan",
  requireRole("ADMIN", "ANALYST"),
  async (req, res, next) => {
    try {
      const body = attachScanSchema.parse(req.body);
      await prisma.scanResult.update({
        where: { id: body.scanId },
        data: { investigationId: req.params.id },
      });
      await prisma.evidence.updateMany({
        where: { scanResultId: body.scanId },
        data: { investigationId: req.params.id },
      });
      res.json({ message: "Scan attached to investigation." });
    } catch (err) {
      next(err);
    }
  }
);
