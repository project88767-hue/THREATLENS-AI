import path from "path";
import fs from "fs";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import { env } from "./config/env";
import { csrfProtection } from "./middleware/csrf";
import { errorHandler } from "./middleware/errorHandler";
import { globalApiLimiter } from "./middleware/rateLimiters";
import { fetchEngineHealth } from "./lib/engineClient";
import { authRouter } from "./routes/auth.routes";
import { dashboardRouter } from "./routes/dashboard.routes";
import { scanRouter } from "./routes/scan.routes";
import { assistantRouter } from "./routes/assistant.routes";
import { investigationsRouter } from "./routes/investigations.routes";
import { incidentsRouter } from "./routes/incidents.routes";
import { graphRouter } from "./routes/graph.routes";
import { reportsRouter } from "./routes/reports.routes";
import { adminRouter } from "./routes/admin.routes";

export const app = express();

app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", "https:"],
        upgradeInsecureRequests: null,
      },
    },
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

const allowedOrigins = new Set(
  [
    ...env.FRONTEND_ORIGIN.split(",").map((s) => s.trim()),
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4000",
    "http://127.0.0.1:4000",
    "http://localhost:8081",
  ].filter(Boolean)
);

app.use((req, res, next) => {
  const reqHost = (
    (req.headers["x-forwarded-host"] as string) ||
    req.headers.host ||
    ""
  )
    .split(",")[0]
    .trim()
    .toLowerCase();

  return cors({
    origin: (origin, callback) => {
      if (!origin) {
        callback(null, true);
        return;
      }
      try {
        const parsedOrigin = new URL(origin);
        const isSameHost = reqHost && parsedOrigin.host.toLowerCase() === reqHost;
        const isCloudflareTunnel = parsedOrigin.hostname
          .toLowerCase()
          .endsWith(".trycloudflare.com");
        if (allowedOrigins.has(origin) || isSameHost || isCloudflareTunnel) {
          callback(null, true);
          return;
        }
      } catch {
        // Invalid Origin header
      }
      callback(new Error("CORS origin denied"));
    },
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization", "X-ThreatLens-Client"],
  })(req, res, next);
});

app.use(cookieParser());
app.use(express.json({ limit: "256kb" }));
app.use("/api", globalApiLimiter);
app.use("/api", csrfProtection);

app.get("/api/health", async (_req, res) => {
  const engine = await fetchEngineHealth();
  res.json({
    status: "ok",
    service: "threatlens-backend-api",
    version: "1.0.0",
    engine,
  });
});

app.use("/api/auth", authRouter);
app.use("/api/dashboard", dashboardRouter);
app.use("/api/scans", scanRouter);
app.use("/api/assistant", assistantRouter);
app.use("/api/investigations", investigationsRouter);
app.use("/api/incidents", incidentsRouter);
app.use("/api/graph", graphRouter);
app.use("/api/reports", reportsRouter);
app.use("/api/admin", adminRouter);

app.use("/api/*", (_req, res) => {
  res.status(404).json({ error: "API route not found." });
});

// Serve built React SPA (frontend/dist) from unified production server when available
const frontendDistPath = path.resolve(__dirname, "../../frontend/dist");
const frontendIndexHtml = path.join(frontendDistPath, "index.html");

if (fs.existsSync(frontendIndexHtml)) {
  app.use(express.static(frontendDistPath, { maxAge: "1h" }));
  app.get("*", (_req, res) => {
    res.sendFile(frontendIndexHtml);
  });
} else {
  app.use((_req, res) => {
    res.status(404).json({ error: "Route not found." });
  });
}

app.use(errorHandler);
