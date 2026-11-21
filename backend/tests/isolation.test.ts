import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { app } from "../src/app";
import { prisma } from "../src/lib/prisma";

const STAMP = Date.now();
const PASSWORD = "Isolation1234";

async function register(label: string) {
  const email = `isolation-${label}-${STAMP}@example.test`;
  const res = await request(app)
    .post("/api/auth/register")
    .send({ name: `Isolation ${label}`, email, password: PASSWORD });
  expect(res.status).toBe(201);
  return { id: res.body.user.id as string, email, token: res.body.token as string };
}

const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

describe("Per-account data isolation", () => {
  let a: Awaited<ReturnType<typeof register>>;
  let b: Awaited<ReturnType<typeof register>>;
  let scanId = "";
  let invId = "";
  let incId = "";
  let reportId = "";

  beforeAll(async () => {
    a = await register("a");
    b = await register("b");

    const indicator = await prisma.indicator.create({
      data: {
        type: "DOMAIN",
        value: `a-${STAMP}.example.test`,
        normalizedValue: `a-${STAMP}.example.test`,
        riskScore: 90,
        severity: "HIGH",
        verdict: "MALICIOUS",
      },
    });
    const scan = await prisma.scanResult.create({
      data: {
        indicatorId: indicator.id,
        userId: a.id,
        scanType: "DOMAIN",
        targetValue: indicator.value,
        normalizedValue: indicator.normalizedValue,
        riskScore: 90,
        severity: "HIGH",
        confidence: 80,
        verdict: "MALICIOUS",
        summary: "A's private scan",
        aiExplanation: {},
        scoreBreakdown: [],
        providerStatus: {},
      },
    });
    scanId = scan.id;

    const inv = await request(app)
      .post("/api/investigations")
      .set(auth(a.token))
      .send({ title: "A private case", description: "only A may see this", scanId });
    expect(inv.status).toBe(201);
    invId = inv.body.investigation.id;

    const inc = await request(app)
      .post("/api/incidents")
      .set(auth(a.token))
      .send({ title: "A private incident", summary: "only A may see this", investigationId: invId });
    expect(inc.status).toBe(201);
    incId = inc.body.incident.id;

    const rpt = await request(app)
      .post("/api/reports/generate")
      .set(auth(a.token))
      .send({ title: "A private report", investigationId: invId });
    expect(rpt.status).toBe(201);
    reportId = rpt.body.report.id;

    await prisma.threatRelation.create({
      data: {
        sourceType: "DOMAIN",
        sourceValue: indicator.value,
        sourceLabel: "a",
        targetType: "IP",
        targetValue: "203.0.113.9",
        targetLabel: "ip",
        relation: "RESOLVES_TO",
        createdById: a.id,
      },
    });
  });

  afterAll(async () => {
    const ids = [a?.id, b?.id].filter(Boolean) as string[];
    await prisma.report.deleteMany({ where: { generatedById: { in: ids } } });
    await prisma.incident.deleteMany({ where: { createdById: { in: ids } } });
    await prisma.threatRelation.deleteMany({ where: { createdById: { in: ids } } });
    await prisma.investigation.deleteMany({ where: { ownerId: { in: ids } } });
    await prisma.scanResult.deleteMany({ where: { userId: { in: ids } } });
    await prisma.indicator.deleteMany({ where: { value: { contains: `a-${STAMP}` } } });
    await prisma.auditLog.deleteMany({ where: { actorEmail: { contains: `-${STAMP}@` } } });
    await prisma.user.deleteMany({ where: { id: { in: ids } } });
  });

  it("owner sees their own data", async () => {
    const dash = await request(app).get("/api/dashboard/overview").set(auth(a.token));
    expect(dash.body.kpis).toMatchObject({
      totalScans: 1,
      openInvestigations: 1,
      activeIncidents: 1,
      totalIndicators: 1,
    });
    expect((await request(app).get("/api/graph").set(auth(a.token))).body.edges).toHaveLength(1);
  });

  it("a brand-new account starts completely empty", async () => {
    const dash = await request(app).get("/api/dashboard/overview").set(auth(b.token));
    expect(dash.body.kpis).toEqual({
      totalScans: 0,
      criticalThreats: 0,
      openInvestigations: 0,
      activeIncidents: 0,
      totalIndicators: 0,
    });
    expect(dash.body.recentScans).toEqual([]);

    for (const [path, key] of [
      ["/api/scans", "scans"],
      ["/api/investigations", "investigations"],
      ["/api/incidents", "incidents"],
      ["/api/reports", "reports"],
    ] as const) {
      const res = await request(app).get(path).set(auth(b.token));
      expect(res.status).toBe(200);
      expect(res.body[key]).toEqual([]);
    }
    const graph = await request(app).get("/api/graph").set(auth(b.token));
    expect(graph.body).toEqual({ nodes: [], edges: [] });
  });

  it("other accounts get 404 for direct-ID access, never the data", async () => {
    for (const path of [
      `/api/scans/${scanId}`,
      `/api/investigations/${invId}`,
      `/api/incidents/${incId}`,
      `/api/reports/${reportId}`,
    ]) {
      expect((await request(app).get(path).set(auth(b.token))).status).toBe(404);
    }
  });

  it("other accounts cannot mutate or attach to someone else's records", async () => {
    const patch = await request(app)
      .patch(`/api/investigations/${invId}`)
      .set(auth(b.token))
      .send({ status: "CLOSED" });
    expect(patch.status).toBe(404);

    const note = await request(app)
      .post(`/api/investigations/${invId}/notes`)
      .set(auth(b.token))
      .send({ content: "intrusion" });
    expect(note.status).toBe(404);

    const incPatch = await request(app)
      .patch(`/api/incidents/${incId}`)
      .set(auth(b.token))
      .send({ status: "RESOLVED" });
    expect(incPatch.status).toBe(404);

    const ownInv = await request(app)
      .post("/api/investigations")
      .set(auth(b.token))
      .send({ title: "B steals scan", description: "attach A's scan", scanId });
    expect(ownInv.status).toBe(404);

    const assistant = await request(app)
      .post("/api/assistant/chat")
      .set(auth(b.token))
      .send({ message: "summarise", investigationId: invId });
    expect(assistant.status).toBe(404);

    const report = await request(app)
      .post("/api/reports/generate")
      .set(auth(b.token))
      .send({ title: "B report", investigationId: invId });
    expect(report.status).toBe(404);

    // A's data is untouched
    const still = await request(app).get(`/api/investigations/${invId}`).set(auth(a.token));
    expect(still.body.investigation.status).not.toBe("CLOSED");
    expect(still.body.investigation.notes).toEqual([]);
  });

  it("report generation without a target only uses the caller's own scans", async () => {
    const res = await request(app)
      .post("/api/reports/generate")
      .set(auth(b.token))
      .send({ title: "B fallback report" });
    expect(res.status).toBe(201);
    expect(res.body.report.riskOverview.analyzedCount).toBe(0);
    expect(res.body.report.findingsMarkdown).not.toContain("a-" + STAMP);
  });

  it("logout clears the session cookie even with an expired/invalid token", async () => {
    const res = await request(app)
      .post("/api/auth/logout")
      .set("Authorization", "Bearer not-a-real-token")
      .set("X-ThreatLens-Client", "test");
    expect(res.status).toBe(200);
    expect(String(res.headers["set-cookie"])).toContain("tl_token=;");
  });
});
