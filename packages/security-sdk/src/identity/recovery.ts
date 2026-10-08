import { randomBytes } from "node:crypto";
import { sha256Hex, verifyTokenHash } from "./crypto";

/** One-time recovery codes (§29–30): generated in human-friendly groups,
 *  shown exactly once, stored ONLY as SHA-256 hashes, invalidated on use. */

export function generateRecoveryCodes(count = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const raw = randomBytes(5).toString("hex").toUpperCase(); // 10 hex chars
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return codes;
}

export function hashRecoveryCode(code: string): string {
  return sha256Hex(code.replace(/[\s-]/g, "").toUpperCase());
}

export function verifyRecoveryCode(code: string, storedHash: string): boolean {
  // Compare hashes of the normalized form — plaintext is never stored.
  return verifyTokenHash(code.replace(/[\s-]/g, "").toUpperCase(), storedHash);
}
