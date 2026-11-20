import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma";
import { recordAudit } from "../lib/audit";
import { callAssistantEngine } from "../lib/engineClient";
import { requireAuth } from "../middleware/auth";
import { scanLimiter } from "../middleware/rateLimiters";

export const assistantRouter = Router();

assistantRouter.use(requireAuth);

const chatSchema = z.object({
  message: z.string().min(1).max(4000),
  investigationId: z.string().uuid().optional(),
  scanId: z.string().uuid().optional(),
  saveNoteToInvestigation: z.boolean().optional(),
  history: z
    .array(
      z.object({
        role: z.enum(["user", "assistant"]),
        content: z.string().max(8000),
      })
    )
    .max(12)
    .default([]),
});

assistantRouter.post("/chat", scanLimiter, async (req, res, next) => {
  try {
    const body = chatSchema.parse(req.body);
    let context: Record<string, unknown> = {};

    if (body.investigationId) {
      const inv = await prisma.investigation.findUnique({
        where: { id: body.investigationId },
        include: {
          scans: { take: 5, orderBy: { createdAt: "desc" } },
          incidents: { take: 3 },
        },
      });
      if (inv) {
        context = {
          investigationCode: inv.code,
          investigationTitle: inv.title,
          priority: inv.priority,
          status: inv.status,
          recentScans: inv.scans.map((s) => ({
            type: s.scanType,
            target: s.targetValue,
            riskScore: s.riskScore,
            severity: s.severity,
            summary: s.summary,
          })),
        };
      }
    } else if (body.scanId) {
      const scan = await prisma.scanResult.findUnique({
        where: { id: body.scanId },
        include: { evidence: true },
      });
      if (scan) {
        context = {
          scanType: scan.scanType,
          targetValue: scan.targetValue,
          riskScore: scan.riskScore,
          severity: scan.severity,
          summary: scan.summary,
          scoreBreakdown: scan.scoreBreakdown,
        };
      }
    }

    const aiResponse = await callAssistantEngine({
      message: body.message,
      context,
      history: body.history,
    });

    if (
      body.saveNoteToInvestigation &&
      body.investigationId &&
      req.user!.role !== "VIEWER"
    ) {
      await prisma.investigationNote.create({
        data: {
          investigationId: body.investigationId,
          authorId: req.user!.id,
          content: aiResponse.reply,
          isAiGenerated: true,
        },
      });
    }

    await recordAudit({
      req,
      userId: req.user!.id,
      actorEmail: req.user!.email,
      action: "AI_ASSISTANT_QUERY",
      resourceType: "Assistant",
      resourceId: body.investigationId ?? body.scanId ?? null,
    });

    res.json(aiResponse);
  } catch (err) {
    next(err);
  }
});
