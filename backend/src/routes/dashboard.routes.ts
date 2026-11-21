import { Router } from "express";
import { prisma } from "../lib/prisma";
import { fetchEngineHealth } from "../lib/engineClient";
import { requireAuth } from "../middleware/auth";
import { incidentScope, investigationScope, scanScope } from "../lib/access";

export const dashboardRouter = Router();

dashboardRouter.use(requireAuth);

dashboardRouter.get("/overview", async (req, res, next) => {
  try {
    const scans = scanScope(req.user!);
    const incidents = incidentScope(req.user!);
    const [
      totalScans,
      criticalThreats,
      openInvestigations,
      activeIncidents,
      totalIndicators,
      recentScans,
      incidentsList,
      allScansLast7Days,
      typeGroups,
      severityGroups,
      verdictGroups,
      engineHealth,
    ] = await Promise.all([
      prisma.scanResult.count({ where: scans }),
      prisma.scanResult.count({ where: { ...scans, severity: { in: ["CRITICAL", "HIGH"] } } }),
      prisma.investigation.count({
        where: { ...investigationScope(req.user!), status: { not: "CLOSED" } },
      }),
      prisma.incident.count({ where: { ...incidents, status: { not: "RESOLVED" } } }),
      prisma.scanResult
        .groupBy({ by: ["indicatorId"], where: scans })
        .then((groups) => groups.length),
      prisma.scanResult.findMany({
        where: scans,
        orderBy: { createdAt: "desc" },
        take: 8,
        include: { user: { select: { name: true } } },
      }),
      prisma.incident.findMany({
        where: { ...incidents, status: { not: "RESOLVED" } },
        orderBy: { createdAt: "desc" },
        take: 5,
        include: { assignedTo: { select: { name: true } } },
      }),
      prisma.scanResult.findMany({
        where: {
          ...scans,
          createdAt: {
            gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
          },
        },
        select: { createdAt: true, severity: true, riskScore: true },
      }),
      prisma.scanResult.groupBy({
        by: ["scanType"],
        where: scans,
        _count: { _all: true },
      }),
      prisma.scanResult.groupBy({
        by: ["severity"],
        where: scans,
        _count: { _all: true },
      }),
      prisma.scanResult.groupBy({
        by: ["verdict"],
        where: scans,
        _count: { _all: true },
      }),
      fetchEngineHealth(),
    ]);

    // Build 7-day timeline buckets for Recharts AreaChart
    const dayMap = new Map<
      string,
      { date: string; total: number; criticalHigh: number; mediumLow: number }
    >();
    for (let i = 6; i >= 0; i--) {
      const d = new Date(Date.now() - i * 24 * 60 * 60 * 1000);
      const key = d.toISOString().slice(0, 10);
      const label = d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
      dayMap.set(key, { date: label, total: 0, criticalHigh: 0, mediumLow: 0 });
    }

    for (const s of allScansLast7Days) {
      const key = s.createdAt.toISOString().slice(0, 10);
      const bucket = dayMap.get(key);
      if (bucket) {
        bucket.total += 1;
        if (s.severity === "CRITICAL" || s.severity === "HIGH") {
          bucket.criticalHigh += 1;
        } else {
          bucket.mediumLow += 1;
        }
      }
    }

    const indicatorDistribution = typeGroups.map((g) => ({
      name: g.scanType,
      value: g._count._all,
    }));

    const severityDistribution = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => ({
      severity: sev,
      count: severityGroups.find((g) => g.severity === sev)?._count._all ?? 0,
    }));

    const verdictDistribution = ["MALICIOUS", "SUSPICIOUS", "CLEAN", "INFO"].map((verdict) => ({
      verdict,
      count: verdictGroups.find((g) => g.verdict === verdict)?._count._all ?? 0,
    }));

    res.json({
      kpis: {
        totalScans,
        criticalThreats,
        openInvestigations,
        activeIncidents,
        totalIndicators,
      },
      trendData: Array.from(dayMap.values()),
      indicatorDistribution,
      severityDistribution,
      verdictDistribution,
      recentScans,
      activeIncidentsList: incidentsList,
      engineHealth,
    });
  } catch (err) {
    next(err);
  }
});
