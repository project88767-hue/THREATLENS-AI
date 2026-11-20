import { Request } from "express";
import { Prisma } from "@prisma/client";
import { prisma } from "./prisma";

interface AuditParams {
  req?: Request;
  userId?: string | null;
  actorEmail: string;
  action: string;
  resourceType: string;
  resourceId?: string | null;
  status?: "SUCCESS" | "FAILURE" | "BLOCKED";
  metadata?: Record<string, unknown>;
}

export async function recordAudit(params: AuditParams): Promise<void> {
  try {
    const ipAddress =
      (params.req?.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ||
      params.req?.socket?.remoteAddress ||
      "127.0.0.1";
    const userAgent = params.req?.headers["user-agent"]?.slice(0, 250) || "unknown";

    await prisma.auditLog.create({
      data: {
        userId: params.userId ?? null,
        actorEmail: params.actorEmail,
        action: params.action,
        resourceType: params.resourceType,
        resourceId: params.resourceId ?? null,
        ipAddress,
        userAgent,
        status: params.status ?? "SUCCESS",
        metadata: (params.metadata ?? {}) as Prisma.InputJsonValue,
      },
    });
  } catch (err) {
    console.error("[AUDIT_LOG_ERROR]", err);
  }
}
