import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

export function requestIdMiddleware(req: Request & { requestId?: string }, res: Response, next: NextFunction): void {
  req.requestId = (req.headers["x-request-id"] as string) || randomUUID();
  res.setHeader("x-request-id", req.requestId);
  next();
}

/** Minimal fixed-window rate limiter (per IP). Redis-backed limiting is a
 *  later hardening step; this keeps the foundation dependency-light. */
const buckets = new Map<string, { count: number; resetAt: number }>();
export function rateLimitMiddleware(limit = 300, windowMs = 60_000) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const key = req.ip ?? "unknown";
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
