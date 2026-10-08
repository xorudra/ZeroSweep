import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * OAuth 2.0 connection safety (Prompt 24 §101, §102): unguessable
 * state values validated in constant time, redirect URIs matched
 * EXACTLY against the registered list (no prefix/wildcard matching),
 * and PKCE S256 for authorization-code flows.
 */

export function generateOAuthState(): string {
  return randomBytes(32).toString("base64url");
}

export function validateOAuthState(presented: string, expected: string): boolean {
  if (!presented || !expected) return false;
  const a = Buffer.from(presented, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** PKCE pair generation lives in the identity module
 *  (generatePkcePair, Prompt 23); this module adds the challenge
 *  verifier used when a provider connection flow completes. */
export function verifyPkceChallenge(verifier: string, challenge: string): boolean {
  const computed = createHash("sha256").update(verifier).digest("base64url");
  const a = Buffer.from(computed, "utf8");
  const b = Buffer.from(challenge, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** §101: redirect URIs must match a registered URI byte-for-byte. */
export function validateRedirectUri(presented: string, registered: string[]): boolean {
  return registered.includes(presented);
}
