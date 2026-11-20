import dotenv from "dotenv";
import { z } from "zod";

dotenv.config();

const envSchema = z.object({
  PORT: z.coerce.number().default(4000),
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  DATABASE_URL: z.string().min(10),
  JWT_SECRET: z.string().min(24),
  JWT_EXPIRES_IN: z.string().default("12h"),
  FRONTEND_ORIGIN: z.string().default("http://localhost:5173"),
  ANALYSIS_ENGINE_URL: z.string().url().default("http://127.0.0.1:8088"),
  INTERNAL_ENGINE_KEY: z.string().min(8).default("threatlens-internal-dev-key-change-in-prod"),
});

export const env = envSchema.parse(process.env);
