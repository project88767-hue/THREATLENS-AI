import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma";
import { recordAudit } from "../lib/audit";
import { requireAuth, requireRole } from "../middleware/auth";
import { sanitizeText } from "../middleware/errorHandler";
import { relationScope, requireOwnedInvestigation, scanScope } from "../lib/access";

export const graphRouter = Router();

graphRouter.use(requireAuth);

const createRelationSchema = z.object({
  sourceType: z.enum(["CAMPAIGN", "EMAIL", "URL", "DOMAIN", "IP", "CVE", "ASSET"]),
  sourceValue: z.string().min(2).max(255),
  sourceLabel: z.string().min(2).max(80).optional(),
  targetType: z.enum(["CAMPAIGN", "EMAIL", "URL", "DOMAIN", "IP", "CVE", "ASSET"]),
  targetValue: z.string().min(2).max(255),
  targetLabel: z.string().min(2).max(80).optional(),
  relation: z.string().min(2).max(60),
  confidence: z.number().int().min(10).max(100).default(85),
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).default("HIGH"),
  investigationId: z.string().uuid().optional(),
});

graphRouter.get("/", async (req, res, next) => {
  try {
    const investigationId =
      typeof req.query.investigationId === "string" ? req.query.investigationId : undefined;
    const relations = await prisma.threatRelation.findMany({
      where: { ...relationScope(req.user!), ...(investigationId ? { investigationId } : {}) },
      orderBy: { createdAt: "desc" },
      take: 120,
    });

    // Risk/severity come from THIS user's own latest scans, never from the shared indicator cache.
    const ownScans = await prisma.scanResult.findMany({
      where: scanScope(req.user!),
      select: { normalizedValue: true, riskScore: true, severity: true, scanType: true },
      orderBy: { createdAt: "desc" },
    });
    const indicatorLookup = new Map<string, (typeof ownScans)[number]>();
    for (const scan of ownScans) {
      const key = scan.normalizedValue.toLowerCase();
      if (!indicatorLookup.has(key)) indicatorLookup.set(key, scan);
    }

    const nodesMap = new Map<
      string,
      {
        id: string;
        type: string;
        value: string;
        label: string;
        severity: string;
        riskScore: number;
        isDemoData: boolean;
      }
    >();

    for (const rel of relations) {
      const srcKey = `${rel.sourceType}:${rel.sourceValue.toLowerCase()}`;
      const dstKey = `${rel.targetType}:${rel.targetValue.toLowerCase()}`;
      const srcInd = indicatorLookup.get(rel.sourceValue.toLowerCase());
      const dstInd = indicatorLookup.get(rel.targetValue.toLowerCase());

      if (!nodesMap.has(srcKey)) {
        nodesMap.set(srcKey, {
          id: srcKey,
          type: rel.sourceType,
          value: rel.sourceValue,
          label: rel.sourceLabel,
          severity: srcInd?.severity ?? rel.severity,
          riskScore: srcInd?.riskScore ?? (rel.severity === "CRITICAL" ? 90 : 72),
          isDemoData: rel.isDemoData,
        });
      }
      if (!nodesMap.has(dstKey)) {
        nodesMap.set(dstKey, {
          id: dstKey,
          type: rel.targetType,
          value: rel.targetValue,
          label: rel.targetLabel,
          severity: dstInd?.severity ?? rel.severity,
          riskScore: dstInd?.riskScore ?? (rel.severity === "CRITICAL" ? 88 : 65),
          isDemoData: rel.isDemoData,
        });
      }
    }

    const edges = relations.map((rel) => ({
      id: rel.id,
      source: `${rel.sourceType}:${rel.sourceValue.toLowerCase()}`,
      target: `${rel.targetType}:${rel.targetValue.toLowerCase()}`,
      relation: rel.relation,
      confidence: rel.confidence,
      severity: rel.severity,
      isDemoData: rel.isDemoData,
    }));

    res.json({
      nodes: Array.from(nodesMap.values()),
      edges,
    });
  } catch (err) {
    next(err);
  }
});

graphRouter.post(
  "/relations",
  requireRole("ADMIN", "ANALYST"),
  async (req, res, next) => {
    try {
      const body = createRelationSchema.parse(req.body);
      if (body.investigationId) {
        await requireOwnedInvestigation(req.user!, body.investigationId);
      }
      const relation = await prisma.threatRelation.create({
        data: {
          sourceType: body.sourceType,
          sourceValue: sanitizeText(body.sourceValue),
          sourceLabel: sanitizeText(body.sourceLabel ?? body.sourceValue.slice(0, 40)),
          targetType: body.targetType,
          targetValue: sanitizeText(body.targetValue),
          targetLabel: sanitizeText(body.targetLabel ?? body.targetValue.slice(0, 40)),
          relation: sanitizeText(body.relation.toUpperCase().replace(/\s+/g, "_")),
          confidence: body.confidence,
          severity: body.severity,
          investigationId: body.investigationId ?? null,
          createdById: req.user!.id,
        },
      });

      await recordAudit({
        req,
        userId: req.user!.id,
        actorEmail: req.user!.email,
        action: "GRAPH_RELATION_CREATED",
        resourceType: "ThreatRelation",
        resourceId: relation.id,
      });

      res.status(201).json({ relation });
    } catch (err) {
      next(err);
    }
  }
);
