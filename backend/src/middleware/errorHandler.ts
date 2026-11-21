import { NextFunction, Request, Response } from "express";
import { Prisma } from "@prisma/client";
import { ZodError } from "zod";
import { NotFoundError } from "../lib/access";
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

  if (err instanceof NotFoundError) {
    res.status(404).json({ error: err.message });
    return;
  }

  if (err instanceof Prisma.PrismaClientKnownRequestError) {
    if (err.code === "P2025") {
      res.status(404).json({ error: "Record not found." });
      return;
    }
    if (err.code === "P2002") {
      res.status(409).json({ error: "A record with these unique values already exists." });
      return;
    }
    if (err.code === "P2003") {
      res.status(400).json({ error: "Referenced record does not exist." });
      return;
    }
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
