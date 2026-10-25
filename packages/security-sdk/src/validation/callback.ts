import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Controlled callback service (Prompt 16 §47–§50). OAST-style safe
 * validation uses callbacks ONLY on infrastructure owned/configured for
 * ZeroSweep validation. Tokens are unique, random, short-lived, and
 * bound to one tenant + one validation session.
 *
 * §48 is explicit: a callback token is NOT authorization. Presenting a
 * token proves only "something reached the callback endpoint with this
 * correlation id" — it grants no access, exposes no tenant metadata,
 * and ingestion is rate-limited with minimal metadata stored (§50).
 * DNS callbacks (§49) share the same token discipline: the token is
 * the leftmost DNS label on a ZeroSweep-owned validation domain.
 */

export interface IssuedCallbackToken {
  /** Shown once to the validation session that embeds it. */
  token: string;
  /** Only the hash is ever stored. */
  tokenHash: string;
  expiresAt: string;
}

export function issueCallbackToken(ttlSeconds = 600, now: Date = new Date()): IssuedCallbackToken {
  const token = randomBytes(32).toString("base64url");
  return {
    token,
    tokenHash: hashCallbackToken(token),
    expiresAt: new Date(now.getTime() + ttlSeconds * 1000).toISOString(),
  };
}

export function hashCallbackToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export interface StoredCallbackToken {
  tokenHash: string;
  workspaceId: string;
  sessionId?: string | null;
  expiresAt: string;
  consumedAt?: string | null;
}

export type CallbackVerification =
  | { ok: true }
  | { ok: false; reasonCode: "TOKEN_MISMATCH" | "TENANT_MISMATCH" | "SESSION_MISMATCH" | "EXPIRED" | "ALREADY_CONSUMED"; message: string };

/** Verify a presented callback against its stored record: constant-time
 *  hash comparison, tenant binding, session binding, expiry (§87). */
export function verifyCallbackToken(input: {
  presentedToken: string;
  stored: StoredCallbackToken;
  workspaceId: string;
  sessionId?: string;
  now: Date;
}): CallbackVerification {
  const presentedHash = Buffer.from(hashCallbackToken(input.presentedToken), "hex");
  const storedHash = Buffer.from(input.stored.tokenHash, "hex");
  if (presentedHash.length !== storedHash.length || !timingSafeEqual(presentedHash, storedHash)) {
    return { ok: false, reasonCode: "TOKEN_MISMATCH", message: "callback token does not match" };
  }
  if (input.stored.workspaceId !== input.workspaceId) {
    return { ok: false, reasonCode: "TENANT_MISMATCH", message: "callback token belongs to a different tenant (§87)" };
  }
  if (input.stored.sessionId && input.sessionId && input.stored.sessionId !== input.sessionId) {
    return { ok: false, reasonCode: "SESSION_MISMATCH", message: "callback token is bound to a different validation session (§87)" };
  }
  if (new Date(input.stored.expiresAt).getTime() <= input.now.getTime()) {
    return { ok: false, reasonCode: "EXPIRED", message: "callback token has expired (§87)" };
  }
  if (input.stored.consumedAt) {
    return { ok: false, reasonCode: "ALREADY_CONSUMED", message: "callback token was already consumed" };
  }
  return { ok: true };
}
