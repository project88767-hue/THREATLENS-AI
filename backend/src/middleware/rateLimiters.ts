import rateLimit from "express-rate-limit";
import { env } from "../config/env";

const isTest = env.NODE_ENV === "test";

export const globalApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isTest ? 10000 : 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many API requests. Please wait before retrying." },
});

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isTest ? 1000 : 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many authentication attempts from this IP. Please try again in 15 minutes.",
  },
});

export const scanLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: isTest ? 1000 : 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Scan rate limit exceeded. Please wait before submitting additional indicators.",
  },
});
