import { loadEnv } from "@zerosweep/config";
import type { Request, Response } from "express";

/**
 * Launch Safety A7 — the refresh cookie.
 *
 * Login-shaped responses carry the opaque server-side session credential
 * (the same token whose SHA-256 hash is stored on the UserSession row);
 * it is mirrored into an HttpOnly cookie so the web client never has to
 * persist anything: the access JWT lives in memory only, and when it
 * expires the browser presents this cookie to POST /auth/refresh, which
 * rotates the credential and mints a fresh JWT. Cookie parsing is done
 * by hand — the API has no cookie-parser dependency and needs exactly
 * one cookie.
 */
export const SESSION_COOKIE = "zerosweep_session";

/** Transport lifetime only — the server enforces the real (org-policy)
 *  session windows on every validation; 12h mirrors the default absolute
 *  session lifetime (§42). */
const SESSION_COOKIE_MAX_AGE_SECONDS = 12 * 60 * 60;

export function readSessionCookie(req: Request): string | null {
  const header = req.headers?.cookie;
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== SESSION_COOKIE) continue;
    const value = part.slice(eq + 1).trim();
    if (!value) return null;
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }
  return null;
}

function cookieValue(token: string, maxAgeSeconds: number): string {
  const secure = loadEnv().NODE_ENV === "production" ? "; Secure" : "";
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax${secure}; Max-Age=${maxAgeSeconds}`;
}

export function setSessionCookie(res: Response, token: string): void {
  res.setHeader("Set-Cookie", cookieValue(token, SESSION_COOKIE_MAX_AGE_SECONDS));
}

export function clearSessionCookie(res: Response): void {
  res.setHeader("Set-Cookie", cookieValue("", 0));
}

/** Sets the refresh cookie when a handler's response body is a login
 *  result (carries `sessionToken`); a no-op for every other response, so
 *  it can be applied unconditionally on the auth surface. */
export function applySessionCookie(res: Response, body: unknown): void {
  const token = (body as { sessionToken?: unknown } | null | undefined)?.sessionToken;
  if (typeof token === "string" && token) setSessionCookie(res, token);
}

/** The session credential travels ONLY in the HttpOnly cookie (set via
 *  applySessionCookie from the full service result). Login-shaped
 *  response bodies must never serialize it — controllers return this
 *  stripped copy ({accessToken, sessionId, ...} — the same shape the
 *  refresh handler already returns). */
export function withoutSessionToken<T extends Record<string, unknown>>(body: T): Omit<T, "sessionToken"> {
  if (!body || typeof body !== "object") return body as Omit<T, "sessionToken">;
  const { sessionToken: _redacted, ...safe } = body as Record<string, unknown>;
  void _redacted;
  return safe as Omit<T, "sessionToken">;
}
