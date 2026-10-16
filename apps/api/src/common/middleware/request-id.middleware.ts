import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { rateLimitCheck, rateLimitRecord } from "../rate-limit-store";

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

/** Fixed-window rate limiter (per IP) over the shared rate-limit store
 *  (security audit 2026-10-16 run-2): counters live in Redis when it is
 *  configured, so replicas share one budget; the bounded in-process
 *  fallback inside the store keeps single-process deployments and
 *  Redis outages safe. */
export function rateLimitMiddleware(limit = 300, windowMs = 60_000) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const key = clientIp(req);
    void (async () => {
      const decision = await rateLimitCheck(key, limit, windowMs);
      if (!decision.allowed) {
        res.status(429).json({ statusCode: 429, message: "Too many requests", timestamp: new Date().toISOString() });
        return;
      }
      await rateLimitRecord(key, windowMs);
      next();
    })().catch(() => next());
  };
}
