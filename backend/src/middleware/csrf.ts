import { NextFunction, Request, Response } from "express";

const STATE_CHANGING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * OWASP CSRF Mitigation:
 * When cookie-based auth is used without an explicit Authorization Bearer header,
 * require custom X-ThreatLens-Client header (which browsers block cross-origin without CORS preflight).
 */
export function csrfProtection(req: Request, res: Response, next: NextFunction): void {
  if (!STATE_CHANGING_METHODS.has(req.method.toUpperCase())) {
    next();
    return;
  }

  const hasBearer = Boolean(req.headers.authorization?.startsWith("Bearer "));
  const hasCookie = Boolean(req.cookies?.tl_token);
  const customHeader = req.headers["x-threatlens-client"];

  if (hasCookie && !hasBearer && !customHeader) {
    res.status(403).json({
      error: "CSRF validation failed: Missing X-ThreatLens-Client security header.",
    });
    return;
  }
  next();
}
