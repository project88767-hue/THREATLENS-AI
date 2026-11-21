import { Prisma } from "@prisma/client";
import { AuthUser } from "../middleware/auth";
import { prisma } from "./prisma";

/**
 * Per-user data isolation.
 *
 * Every tenant-visible resource is owned by exactly one account. These helpers are the
 * single place that defines "what may this user see", so route handlers can never forget
 * a filter. Indicators are a shared reputation cache and are never returned wholesale.
 */
type Actor = Pick<AuthUser, "id">;

export const scanScope = (u: Actor): Prisma.ScanResultWhereInput => ({ userId: u.id });

export const investigationScope = (u: Actor): Prisma.InvestigationWhereInput => ({
  ownerId: u.id,
});

export const incidentScope = (u: Actor): Prisma.IncidentWhereInput => ({
  OR: [{ createdById: u.id }, { assignedToId: u.id }],
});

export const reportScope = (u: Actor): Prisma.ReportWhereInput => ({ generatedById: u.id });

export const relationScope = (u: Actor): Prisma.ThreatRelationWhereInput => ({
  createdById: u.id,
});

/** Thrown when a referenced resource does not exist OR belongs to someone else (never reveal which). */
export class NotFoundError extends Error {
  constructor(public readonly resource: string) {
    super(`${resource} not found.`);
  }
}

export async function requireOwnedInvestigation(u: Actor, id: string) {
  const inv = await prisma.investigation.findFirst({
    where: { id, ...investigationScope(u) },
    select: { id: true },
  });
  if (!inv) throw new NotFoundError("Investigation");
  return inv;
}

export async function requireOwnedScan(u: Actor, id: string) {
  const scan = await prisma.scanResult.findFirst({
    where: { id, ...scanScope(u) },
    select: { id: true },
  });
  if (!scan) throw new NotFoundError("Scan result");
  return scan;
}

export async function requireAccessibleIncident(u: Actor, id: string) {
  const inc = await prisma.incident.findFirst({
    where: { id, ...incidentScope(u) },
    select: { id: true },
  });
  if (!inc) throw new NotFoundError("Incident");
  return inc;
}

/**
 * Sequential human-friendly codes (INV-2026-101) that survive deletions and concurrent
 * creates: retry on unique-constraint collisions instead of trusting row counts.
 */
export async function createWithUniqueCode<T>(
  prefix: string,
  base: number,
  countFn: () => Promise<number>,
  create: (code: string) => Promise<T>
): Promise<T> {
  const start = (await countFn()) + base;
  for (let attempt = 0; attempt < 25; attempt++) {
    const code = `${prefix}-${String(start + attempt).padStart(3, "0")}`;
    try {
      return await create(code);
    } catch (err) {
      const isCodeCollision =
        err instanceof Prisma.PrismaClientKnownRequestError &&
        err.code === "P2002" &&
        JSON.stringify(err.meta?.target ?? "").includes("code");
      if (!isCodeCollision) throw err;
    }
  }
  throw new Error("Unable to allocate a unique record code.");
}
