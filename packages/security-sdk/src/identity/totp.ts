import { createHmac, randomBytes } from "node:crypto";

/** Standards-compatible TOTP (RFC 4226/6238, §26) with replay protection:
 *  verification reports the matched time-step so the caller can persist it
 *  and reject any later code from the same or an earlier step (§28). */

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/=+$/, "").replace(/\s/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error("Invalid base32 character");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function generateTotpSecret(): { secretBase32: string; secret: Buffer } {
  const secret = randomBytes(20);
  return { secretBase32: base32Encode(secret), secret };
}

export function hotp(secret: Buffer, counter: bigint, digits = 6): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(counter);
  const digest = createHmac("sha1", secret).update(msg).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) | ((digest[offset + 1] & 0xff) << 16) | ((digest[offset + 2] & 0xff) << 8) | (digest[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, "0");
}

export function totp(secret: Buffer, atMs: number, stepSeconds = 30, digits = 6): { code: string; step: bigint } {
  const step = BigInt(Math.floor(atMs / 1000 / stepSeconds));
  return { code: hotp(secret, step, digits), step };
}

export interface TotpVerifyResult {
  ok: boolean;
  matchedStep: bigint | null;
  reason?: "MISMATCH" | "REPLAY";
}

/** Verify with a ±1 step window. `lastUsedStep` enforces replay protection:
 *  a code whose step is <= lastUsedStep is REJECTED even if valid (§28). */
export function verifyTotp(secret: Buffer, code: string, atMs: number, lastUsedStep: bigint | null, stepSeconds = 30): TotpVerifyResult {
  const clean = code.replace(/\s/g, "");
  if (!/^\d{6,8}$/.test(clean)) return { ok: false, matchedStep: null, reason: "MISMATCH" };
  const current = BigInt(Math.floor(atMs / 1000 / stepSeconds));
  for (const delta of [0n, -1n, 1n]) {
    const step = current + delta;
    if (step < 0n) continue;
    if (hotp(secret, step, clean.length) === clean) {
      if (lastUsedStep !== null && step <= lastUsedStep) return { ok: false, matchedStep: step, reason: "REPLAY" };
      return { ok: true, matchedStep: step };
    }
  }
  return { ok: false, matchedStep: null, reason: "MISMATCH" };
}

export function totpSetupUri(secretBase32: string, account: string, issuer = "ZeroSweep"): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${secretBase32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
