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
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
      },
    },
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

const allowedOrigins = new Set([
  env.FRONTEND_ORIGIN,
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "http://localhost:8081",
]);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.has(origin)) {
        callback(null, true);
      } else {
        callback(new Error("CORS origin denied"));
      }
    },
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization", "X-ThreatLens-Client"],
  })
);

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

app.use((_req, res) => {
  res.status(404).json({ error: "API route not found." });
});

app.use(errorHandler);
