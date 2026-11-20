import { Router } from "express";
import bcrypt from "bcryptjs";
import { Prisma } from "@prisma/client";
import { z } from "zod";
import { prisma } from "../lib/prisma";
import { recordAudit } from "../lib/audit";
import { requireAuth, signAccessToken } from "../middleware/auth";
import { authLimiter } from "../middleware/rateLimiters";
import { sanitizeText } from "../middleware/errorHandler";
import { env } from "../config/env";

export const authRouter = Router();

const registerSchema = z.object({
  name: z.string().min(2).max(80),
  email: z.string().email().max(160),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(100)
    .regex(/[A-Z]/, "Must include an uppercase letter")
    .regex(/[a-z]/, "Must include a lowercase letter")
    .regex(/[0-9]/, "Must include a number"),
  department: z.string().min(2).max(80).optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1).max(128),
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z
    .string()
    .min(8)
    .max(100)
    .regex(/[A-Z]/, "Must include an uppercase letter")
    .regex(/[a-z]/, "Must include a lowercase letter")
    .regex(/[0-9]/, "Must include a number"),
});

const updateProfileSchema = z.object({
  name: z.string().min(2).max(80).optional(),
  department: z.string().min(2).max(80).optional(),
  preferences: z.record(z.unknown()).optional(),
});

function setAuthCookie(res: import("express").Response, token: string): void {
  res.cookie("tl_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: env.NODE_ENV === "production",
    maxAge: 12 * 60 * 60 * 1000,
  });
}

authRouter.post("/register", authLimiter, async (req, res, next) => {
  try {
    const body = registerSchema.parse(req.body);
    const normalizedEmail = body.email.toLowerCase().trim();

    const existing = await prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (existing) {
      res.status(409).json({ error: "An account with this email already exists." });
      return;
    }

    const passwordHash = await bcrypt.hash(body.password, 12);
    const user = await prisma.user.create({
      data: {
        name: sanitizeText(body.name),
        email: normalizedEmail,
        passwordHash,
        role: "ANALYST",
        department: body.department ? sanitizeText(body.department) : "SOC Operations",
        lastLoginAt: new Date(),
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        department: true,
        status: true,
        createdAt: true,
      },
    });

    const token = signAccessToken(user);
    setAuthCookie(res, token);

    await recordAudit({
      req,
      userId: user.id,
      actorEmail: user.email,
      action: "AUTH_REGISTER",
      resourceType: "User",
      resourceId: user.id,
      status: "SUCCESS",
    });

    res.status(201).json({ user, token });
  } catch (err) {
    next(err);
  }
});

authRouter.post("/login", authLimiter, async (req, res, next) => {
  try {
    const body = loginSchema.parse(req.body);
    const normalizedEmail = body.email.toLowerCase().trim();

    const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (!user) {
      await recordAudit({
        req,
        actorEmail: normalizedEmail,
        action: "AUTH_LOGIN_FAILED",
        resourceType: "Auth",
        status: "FAILURE",
        metadata: { reason: "unknown_email" },
      });
      res.status(401).json({ error: "Invalid email or password." });
      return;
    }

    if (user.status !== "ACTIVE") {
      await recordAudit({
        req,
        userId: user.id,
        actorEmail: user.email,
        action: "AUTH_LOGIN_SUSPENDED",
        resourceType: "Auth",
        status: "BLOCKED",
      });
      res.status(403).json({ error: "This account has been suspended by an administrator." });
      return;
    }

    const validPassword = await bcrypt.compare(body.password, user.passwordHash);
    if (!validPassword) {
      await recordAudit({
        req,
        userId: user.id,
        actorEmail: user.email,
        action: "AUTH_LOGIN_FAILED",
        resourceType: "Auth",
        status: "FAILURE",
        metadata: { reason: "bad_password" },
      });
      res.status(401).json({ error: "Invalid email or password." });
      return;
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    const token = signAccessToken(user);
    setAuthCookie(res, token);

    await recordAudit({
      req,
      userId: user.id,
      actorEmail: user.email,
      action: "AUTH_LOGIN_SUCCESS",
      resourceType: "Auth",
      resourceId: user.id,
      status: "SUCCESS",
    });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        department: user.department,
        preferences: user.preferences,
      },
    });
  } catch (err) {
    next(err);
  }
});

authRouter.post("/logout", requireAuth, async (req, res) => {
  res.clearCookie("tl_token");
  if (req.user) {
    await recordAudit({
      req,
      userId: req.user.id,
      actorEmail: req.user.email,
      action: "AUTH_LOGOUT",
      resourceType: "Auth",
      status: "SUCCESS",
    });
  }
  res.json({ message: "Signed out successfully." });
});

authRouter.get("/me", requireAuth, async (req, res, next) => {
  try {
    const profile = await prisma.user.findUnique({
      where: { id: req.user!.id },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        status: true,
        department: true,
        preferences: true,
        lastLoginAt: true,
        createdAt: true,
      },
    });
    res.json({ user: profile });
  } catch (err) {
    next(err);
  }
});

authRouter.patch("/profile", requireAuth, async (req, res, next) => {
  try {
    const body = updateProfileSchema.parse(req.body);
    const updated = await prisma.user.update({
      where: { id: req.user!.id },
      data: {
        ...(body.name ? { name: sanitizeText(body.name) } : {}),
        ...(body.department ? { department: sanitizeText(body.department) } : {}),
        ...(body.preferences
          ? { preferences: body.preferences as Prisma.InputJsonValue }
          : {}),
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        department: true,
        preferences: true,
      },
    });

    await recordAudit({
      req,
      userId: req.user!.id,
      actorEmail: req.user!.email,
      action: "USER_PROFILE_UPDATED",
      resourceType: "User",
      resourceId: req.user!.id,
      status: "SUCCESS",
    });

    res.json({ user: updated });
  } catch (err) {
    next(err);
  }
});

authRouter.post("/change-password", requireAuth, async (req, res, next) => {
  try {
    const body = changePasswordSchema.parse(req.body);
    const user = await prisma.user.findUnique({ where: { id: req.user!.id } });
    if (!user) {
      res.status(404).json({ error: "User not found." });
      return;
    }

    const matches = await bcrypt.compare(body.currentPassword, user.passwordHash);
    if (!matches) {
      res.status(400).json({ error: "Current password is incorrect." });
      return;
    }

    const passwordHash = await bcrypt.hash(body.newPassword, 12);
    await prisma.user.update({
      where: { id: user.id },
      data: { passwordHash },
    });

    await recordAudit({
      req,
      userId: user.id,
      actorEmail: user.email,
      action: "USER_PASSWORD_CHANGED",
      resourceType: "User",
      resourceId: user.id,
      status: "SUCCESS",
    });

    res.json({ message: "Password updated successfully." });
  } catch (err) {
    next(err);
  }
});
