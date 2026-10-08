import { randomBytes } from "node:crypto";
import { sha256Hex, verifyTokenHash } from "./crypto";

/** API keys (§76–83): high-entropy secrets shown exactly once, stored only
 *  as hashes, identified by a safe prefix, scoped by a CLOSED typed-scope
 *  catalog. There is deliberately no shell/execute or wildcard scope —
 *  such scopes are unrepresentable (§79, §143). */

export const API_SCOPES = [
  "findings:read",
  "assets:read",
  "scans:read",
  "scans:create-safe",
  "reports:read",
  "reports:create",
  "targets:read",
  "vulnerabilities:read",
  "notifications:read",
] as const;
export type ApiScope = (typeof API_SCOPES)[number];

export function isValidApiScope(scope: string): scope is ApiScope {
  return (API_SCOPES as readonly string[]).includes(scope);
}

export function validateApiScopes(scopes: string[]): { ok: boolean; invalid: string[] } {
  const invalid = scopes.filter((s) => !isValidApiScope(s));
  return { ok: invalid.length === 0 && scopes.length > 0, invalid };
}

export function scopeAllows(granted: string[], required: string): boolean {
  return granted.includes(required);
}

export interface GeneratedApiKey { plaintext: string; prefix: string; secretHash: string }

export function generateApiKey(): GeneratedApiKey {
  const secret = randomBytes(32).toString("base64url");
  const plaintext = `dsr_live_${secret}`;
  return { plaintext, prefix: plaintext.slice(0, 16), secretHash: sha256Hex(plaintext) };
}

export function verifyApiKey(plaintext: string, secretHash: string): boolean {
  if (!plaintext.startsWith("dsr_live_")) return false;
  return verifyTokenHash(plaintext, secretHash);
}

export function apiKeyUsable(key: { secretHash: string; revokedAtMs: number | null; expiresAtMs: number | null }, plaintext: string, nowMs: number): string | null {
  if (key.revokedAtMs) return "REVOKED";
  if (key.expiresAtMs && nowMs > key.expiresAtMs) return "EXPIRED";
  if (!verifyApiKey(plaintext, key.secretHash)) return "MISMATCH";
  return null;
}
