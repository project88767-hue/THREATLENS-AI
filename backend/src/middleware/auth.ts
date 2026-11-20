import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { Role } from "@prisma/client";
import { env } from "../config/env";
import { prisma } from "../lib/prisma";
import { recordAudit } from "../lib/audit";

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: Role;
  department: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

interface JwtPayload {
  sub: string;
  email: string;
  role: Role;
}

export function signAccessToken(user: { id: string; email: string; role: Role }): string {
  return jwt.sign(
    { sub: user.id, email: user.email, role: user.role },
    env.JWT_SECRET,
    { expiresIn: env.JWT_EXPIRES_IN as jwt.SignOptions["expiresIn"] }
  );
}

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    const bearerToken =
      authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;
    const cookieToken = req.cookies?.tl_token as string | undefined;
    const token = bearerToken || cookieToken;

    if (!token) {
      res.status(401).json({ error: "Authentication required. Please sign in." });
      return;
    }

    const decoded = jwt.verify(token, env.JWT_SECRET) as JwtPayload;
    const user = await prisma.user.findUnique({
      where: { id: decoded.sub },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        status: true,
        department: true,
      },
    });

    if (!user || user.status !== "ACTIVE") {
      res.status(403).json({ error: "Account is suspended or no longer active." });
      return;
    }

    req.user = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      department: user.department,
    };
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired session token." });
  }
}

export function requireRole(...allowedRoles: Role[]) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user) {
      res.status(401).json({ error: "Authentication required." });
      return;
    }
    if (!allowedRoles.includes(req.user.role)) {
      await recordAudit({
        req,
        userId: req.user.id,
        actorEmail: req.user.email,
        action: "RBAC_ACCESS_DENIED",
        resourceType: req.originalUrl,
        status: "BLOCKED",
        metadata: { requiredRoles: allowedRoles, actualRole: req.user.role },
      });
      res.status(403).json({
        error: `Insufficient permissions. Required role: ${allowedRoles.join(" or ")}.`,
      });
      return;
    }
    next();
  };
}
