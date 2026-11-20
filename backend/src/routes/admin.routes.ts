import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma";
import { recordAudit } from "../lib/audit";
import { fetchEngineHealth } from "../lib/engineClient";
import { requireAuth, requireRole } from "../middleware/auth";

export const adminRouter = Router();

adminRouter.use(requireAuth, requireRole("ADMIN"));

const updateUserSchema = z.object({
  role: z.enum(["ADMIN", "ANALYST", "VIEWER"]).optional(),
  status: z.enum(["ACTIVE", "SUSPENDED"]).optional(),
  department: z.string().min(2).max(80).optional(),
});

adminRouter.get("/users", async (_req, res, next) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        status: true,
        department: true,
        lastLoginAt: true,
        createdAt: true,
        _count: {
          select: { scans: true, ownedInvestigations: true },
        },
      },
      orderBy: { createdAt: "asc" },
    });
    res.json({ users });
  } catch (err) {
    next(err);
  }
});

adminRouter.patch("/users/:id", async (req, res, next) => {
  try {
    const body = updateUserSchema.parse(req.body);
    if (req.params.id === req.user!.id && body.status === "SUSPENDED") {
      res.status(400).json({ error: "Administrators cannot suspend their own active session." });
      return;
    }

    const updated = await prisma.user.update({
      where: { id: req.params.id },
      data: {
        ...(body.role ? { role: body.role } : {}),
        ...(body.status ? { status: body.status } : {}),
        ...(body.department ? { department: body.department } : {}),
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        status: true,
        department: true,
      },
    });

    await recordAudit({
      req,
      userId: req.user!.id,
      actorEmail: req.user!.email,
      action: "ADMIN_USER_UPDATED",
      resourceType: "User",
      resourceId: updated.id,
      metadata: { targetEmail: updated.email, role: updated.role, status: updated.status },
    });

    res.json({ user: updated });
  } catch (err) {
    next(err);
  }
});

adminRouter.get("/audit-logs", async (req, res, next) => {
  try {
    const limit = Math.min(200, Math.max(10, Number(req.query.limit) || 60));
    const status = req.query.status as string | undefined;

    const logs = await prisma.auditLog.findMany({
      where: status ? { status } : {},
      orderBy: { createdAt: "desc" },
      take: limit,
    });
    res.json({ logs });
  } catch (err) {
    next(err);
  }
});

adminRouter.get("/system-health", async (_req, res, next) => {
  try {
    const [userCount, scanCount, incidentCount, auditCount, engineHealth] = await Promise.all([
      prisma.user.count(),
      prisma.scanResult.count(),
      prisma.incident.count(),
      prisma.auditLog.count(),
      fetchEngineHealth(),
    ]);

    res.json({
      database: "CONNECTED",
      securityControls: {
        helmetHeaders: true,
        corsStrictOrigin: true,
        csrfCustomHeaderGuard: true,
        rateLimiting: true,
        ssrfGuard: true,
        rbacEnforcement: true,
        bcryptCostFactor: 12,
        auditLogging: true,
      },
      metrics: {
        userCount,
        scanCount,
        incidentCount,
        auditCount,
      },
      engineHealth,
    });
  } catch (err) {
    next(err);
  }
});

adminRouter.delete("/demo-data", async (req, res, next) => {
  try {
    const demoScans = await prisma.scanResult.findMany({
      where: { isDemoData: true },
      select: { id: true, indicatorId: true },
    });
    const demoInvs = await prisma.investigation.findMany({
      where: { isDemoData: true },
      select: { id: true },
    });
    const demoIncs = await prisma.incident.findMany({
      where: { isDemoData: true },
      select: { id: true },
    });

    const invIds = demoInvs.map((i) => i.id);
    const incIds = demoIncs.map((i) => i.id);
    const scanIds = demoScans.map((s) => s.id);
    const demoIndicatorIds = Array.from(
      new Set(demoScans.map((s) => s.indicatorId).filter((id): id is string => Boolean(id)))
    );

    const deletedReports = await prisma.report.deleteMany({
      where: {
        OR: [
          ...(invIds.length ? [{ investigationId: { in: invIds } }] : []),
          ...(incIds.length ? [{ incidentId: { in: incIds } }] : []),
          { title: { contains: "Seed" } },
        ],
      },
    });
    const deletedIncidents = await prisma.incident.deleteMany({
      where: { isDemoData: true },
    });
    const deletedInvestigations = await prisma.investigation.deleteMany({
      where: { isDemoData: true },
    });
    const deletedScans = await prisma.scanResult.deleteMany({
      where: { id: { in: scanIds } },
    });

    let deletedIndicatorsCount = 0;
    if (demoIndicatorIds.length > 0) {
      const deletedIndicators = await prisma.indicator.deleteMany({
        where: {
          id: { in: demoIndicatorIds },
          scans: { none: {} },
        },
      });
      deletedIndicatorsCount = deletedIndicators.count;
    }

    await recordAudit({
      req,
      userId: req.user!.id,
      actorEmail: req.user!.email,
      action: "ADMIN_PURGED_DEMO_DATA",
      resourceType: "System",
      metadata: {
        deletedScans: deletedScans.count,
        deletedInvestigations: deletedInvestigations.count,
        deletedIncidents: deletedIncidents.count,
        deletedReports: deletedReports.count,
        deletedIndicators: deletedIndicatorsCount,
      },
    });

    res.json({
      purged: {
        scans: deletedScans.count,
        investigations: deletedInvestigations.count,
        incidents: deletedIncidents.count,
        reports: deletedReports.count,
        indicators: deletedIndicatorsCount,
      },
    });
  } catch (err) {
    next(err);
  }
});
