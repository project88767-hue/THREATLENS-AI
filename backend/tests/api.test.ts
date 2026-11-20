import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import { app } from "../src/app";

describe("THREATLENS AI Backend Security & REST API Suite", () => {
  let adminToken = "";
  let analystToken = "";
  let viewerToken = "";

  beforeAll(async () => {
    const adminLogin = await request(app)
      .post("/api/auth/login")
      .send({ email: "admin@threatlens.demo", password: "Admin@12345" });
    expect(adminLogin.status).toBe(200);
    adminToken = adminLogin.body.token;

    const analystLogin = await request(app)
      .post("/api/auth/login")
      .send({ email: "analyst@threatlens.demo", password: "Analyst@12345" });
    expect(analystLogin.status).toBe(200);
    analystToken = analystLogin.body.token;

    const viewerLogin = await request(app)
      .post("/api/auth/login")
      .send({ email: "viewer@threatlens.demo", password: "Viewer@12345" });
    expect(viewerLogin.status).toBe(200);
    viewerToken = viewerLogin.body.token;
  });

  it("exposes health endpoint with security headers", async () => {
    const res = await request(app).get("/api/health");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
  });

  it("blocks unauthenticated dashboard access", async () => {
    const res = await request(app).get("/api/dashboard/overview");
    expect(res.status).toBe(401);
  });

  it("blocks CSRF when cookie auth is sent without X-ThreatLens-Client header", async () => {
    const res = await request(app)
      .post("/api/scans/url")
      .set("Cookie", [`tl_token=${analystToken}`])
      .send({ url: "https://example.com" });
    expect(res.status).toBe(403);
    expect(res.body.error).toContain("CSRF");
  });

  it("enforces RBAC: VIEWER cannot initiate scans or access admin endpoints", async () => {
    const scanAttempt = await request(app)
      .post("/api/scans/url")
      .set("Authorization", `Bearer ${viewerToken}`)
      .send({ url: "https://example.com" });
    expect(scanAttempt.status).toBe(403);

    const adminAttempt = await request(app)
      .get("/api/admin/users")
      .set("Authorization", `Bearer ${viewerToken}`);
    expect(adminAttempt.status).toBe(403);
  });

  it("enforces SSRF protection blocking localhost and metadata IPs", async () => {
    const localUrl = await request(app)
      .post("/api/scans/url")
      .set("Authorization", `Bearer ${analystToken}`)
      .send({ url: "http://169.254.169.254/latest/meta-data" });
    expect(localUrl.status).toBe(403);
    expect(localUrl.body.error).toContain("SSRF");

    const privateIp = await request(app)
      .post("/api/scans/ip")
      .set("Authorization", `Bearer ${analystToken}`)
      .send({ ip: "192.168.1.50" });
    expect(privateIp.status).toBe(403);
  });

  it("performs URL scan and persists ScanResult + Evidence", async () => {
    const res = await request(app)
      .post("/api/scans/url")
      .set("Authorization", `Bearer ${analystToken}`)
      .send({ url: "http://secure-login-verify-microsoft.xyz/auth" });
    expect(res.status).toBe(201);
    expect(res.body.scan.riskScore).toBeGreaterThanOrEqual(50);
    expect(Array.isArray(res.body.scan.evidence)).toBe(true);
  });

  it("returns dashboard KPIs, threat graph, investigations, incidents, reports, and admin audit logs", async () => {
    const [dash, graph, invs, incs, rpts, adminHealth] = await Promise.all([
      request(app).get("/api/dashboard/overview").set("Authorization", `Bearer ${analystToken}`),
      request(app).get("/api/graph").set("Authorization", `Bearer ${analystToken}`),
      request(app).get("/api/investigations").set("Authorization", `Bearer ${analystToken}`),
      request(app).get("/api/incidents").set("Authorization", `Bearer ${analystToken}`),
      request(app).get("/api/reports").set("Authorization", `Bearer ${analystToken}`),
      request(app).get("/api/admin/system-health").set("Authorization", `Bearer ${adminToken}`),
    ]);

    expect(dash.status).toBe(200);
    expect(dash.body.kpis.totalScans).toBeGreaterThan(0);
    expect(graph.status).toBe(200);
    expect(graph.body.nodes.length).toBeGreaterThan(0);
    expect(invs.status).toBe(200);
    expect(incs.status).toBe(200);
    expect(rpts.status).toBe(200);
    expect(adminHealth.status).toBe(200);
    expect(adminHealth.body.securityControls.ssrfGuard).toBe(true);
  });
});
