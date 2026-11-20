import { NextFunction, Request, Response } from "express";
import { ZodError } from "zod";
import { EngineClientError } from "../lib/engineClient";
import { env } from "../config/env";

export function sanitizeText(input: string): string {
  return input
    .replace(/<\s*\/?\s*script\b[^>]*>/gi, "")
    .replace(/javascript\s*:/gi, "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "")
    .trim();
}

export function errorHandler(
  err: unknown,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  if (err instanceof ZodError) {
    res.status(400).json({
      error: "Validation failed",
      details: err.errors.map((issue) => ({
        path: issue.path.join("."),
        message: issue.message,
      })),
    });
    return;
  }

  if (err instanceof EngineClientError) {
    res.status(err.statusCode).json({ error: err.message });
    return;
  }

  if (env.NODE_ENV !== "production") {
    console.error("[API_ERROR]", err);
  }

  res.status(500).json({
    error: "An unexpected internal server error occurred.",
  });
}
