import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

export function requestIdMiddleware(req: Request & { requestId?: string }, res: Response, next: NextFunction): void {
  req.requestId = (req.headers["x-request-id"] as string) || randomUUID();
  res.setHeader("x-request-id", req.requestId);
  next();
}

/**
 * Trusted-proxy state for clientIp (Launch Safety Standard A10).
 *
 * The last X-Forwarded-For entry is the address the platform edge
 * observed ONLY when the request demonstrably arrived through the
 * configured proxy hop. main.ts enables trust exactly where it sets
 * Express `trust proxy` for the deployment's single platform hop;
 * everywhere else (direct exposure, local dev, tests) XFF is fully
 * client-controlled and must never key a limiter. Default: untrusted.
 */
let trustProxyEnabled = false;
export function setTrustProxyEnabled(enabled: boolean): void {
  trustProxyEnabled = enabled;
}
export function isTrustProxyEnabled(): boolean {
  return trustProxyEnabled;
}

/**
 * Client IP for rate-limit keying (Launch Safety Standard A10).
 *
 * When the trusted proxy hop is configured, the LAST X-Forwarded-For
 * entry is the hop the edge actually observed; the first entries are
 * client-supplied and spoofable, so they are never used as a key.
 * When no trusted proxy is configured, XFF is ignored entirely and
 * the identity is the socket / Express peer address (req.ip — which,
 * with `trust proxy` set, Express itself derives from the trusted
 * hop), so a directly exposed deployment keys on the real peer and
 * an attacker cannot rotate limiter buckets by forging a header.
 */
export function clientIp(req: { headers: Record<string, unknown>; ip?: string; socket?: { remoteAddress?: string } }): string {
  if (trustProxyEnabled) {
    const xff = req.headers["x-forwarded-for"];
    const raw = Array.isArray(xff) ? xff.join(",") : typeof xff === "string" ? xff : "";
    if (raw) {
      const parts = raw.split(",").map((s) => s.trim()).filter(Boolean);
      if (parts.length > 0) return parts[parts.length - 1]!;
    }
  }
  return req.ip ?? req.socket?.remoteAddress ?? "unknown";
}

/** Minimal fixed-window rate limiter (per IP). Redis-backed limiting is a
 *  later hardening step; this keeps the foundation dependency-light.
 *  State is BOUNDED: expired buckets are swept periodically and the map
 *  is hard-capped (oldest entry evicted) so client-address churn cannot
 *  grow memory without limit. NOTE: state is still per-process — under
 *  a multi-replica deployment the effective aggregate cap is
 *  limit × replicas until the limiter moves to the shared Redis. */
const buckets = new Map<string, { count: number; resetAt: number }>();
export const MAX_RATE_LIMIT_BUCKETS = 100_000;
const sweep = setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of buckets) if (bucket.resetAt <= now) buckets.delete(key);
}, 60_000);
sweep.unref?.();
export function rateLimitMiddleware(limit = 300, windowMs = 60_000) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const key = clientIp(req);
    const now = Date.now();
    const bucket = buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      if (!bucket && buckets.size >= MAX_RATE_LIMIT_BUCKETS) {
        // Hard cap: evict the oldest bucket rather than growing forever.
        const oldest = buckets.keys().next().value as string | undefined;
        if (oldest !== undefined) buckets.delete(oldest);
      }
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
