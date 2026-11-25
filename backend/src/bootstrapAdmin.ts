import bcrypt from "bcryptjs";
import { prisma } from "./lib/prisma";

/**
 * Fresh deployments start with an empty database and the public sign-up only creates
 * ANALYST accounts. If BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD are set, make
 * sure that one ADMIN account exists. It never overwrites an existing account's password.
 */
export async function bootstrapAdmin(): Promise<void> {
  const email = process.env.BOOTSTRAP_ADMIN_EMAIL?.toLowerCase().trim();
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (!email || !password) return;
  if (password.length < 8) {
    console.warn("[BOOTSTRAP] BOOTSTRAP_ADMIN_PASSWORD is too short; skipping admin creation.");
    return;
  }
  try {
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      if (existing.role !== "ADMIN") {
        await prisma.user.update({ where: { id: existing.id }, data: { role: "ADMIN" } });
        console.log(`[BOOTSTRAP] Promoted ${email} to ADMIN.`);
      }
      return;
    }
    await prisma.user.create({
      data: {
        email,
        name: "ThreatLens Administrator",
        passwordHash: await bcrypt.hash(password, 12),
        role: "ADMIN",
        department: "Security Administration",
      },
    });
    console.log(`[BOOTSTRAP] Created admin account ${email}.`);
  } catch (err) {
    console.error("[BOOTSTRAP] Admin bootstrap failed:", err);
  }
}
