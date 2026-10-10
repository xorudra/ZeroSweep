import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

export function requestIdMiddleware(req: Request & { requestId?: string }, res: Response, next: NextFunction): void {
  req.requestId = (req.headers["x-request-id"] as string) || randomUUID();
  res.setHeader("x-request-id", req.requestId);
  next();
}

/**
 * Client IP for rate-limit keying (Launch Safety Standard A10).
 *
 * Behind the platform proxy the LAST X-Forwarded-For entry is the hop
 * the edge actually observed; the first entries are client-supplied and
 * spoofable, so they are never used as a key. This mirrors the AI
 * service's `_client_ip` (apps/ai/app/main.py). When no XFF header is
 * present (direct/local traffic) the socket address is the identity.
 * Keys derived this way are unspoofable AND per-client: keying on the
 * raw socket address instead would collapse every hosted caller into
 * the one shared edge IP, making per-IP caps effectively global.
 */
export function clientIp(req: { headers: Record<string, unknown>; ip?: string; socket?: { remoteAddress?: string } }): string {
  const xff = req.headers["x-forwarded-for"];
  const raw = Array.isArray(xff) ? xff.join(",") : typeof xff === "string" ? xff : "";
  if (raw) {
    const parts = raw.split(",").map((s) => s.trim()).filter(Boolean);
    if (parts.length > 0) return parts[parts.length - 1]!;
  }
  return req.ip ?? req.socket?.remoteAddress ?? "unknown";
}

/** Minimal fixed-window rate limiter (per IP). Redis-backed limiting is a
 *  later hardening step; this keeps the foundation dependency-light. */
const buckets = new Map<string, { count: number; resetAt: number }>();
export function rateLimitMiddleware(limit = 300, windowMs = 60_000) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const key = clientIp(req);
    const now = Date.now();
    const bucket = buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      buckets.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    bucket.count += 1;
    if (bucket.count > limit) {
      res.status(429).json({ statusCode: 429, message: "Too many requests", timestamp: new Date().toISOString() });
      return;
    }
    next();
  };
}
