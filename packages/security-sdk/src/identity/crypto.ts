import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** Shared cryptographic primitives for the identity engine (Prompt 23).
 *  Secrets are only ever handled as hashes, AES-256-GCM ciphertext under a
 *  platform key supplied by the caller, or opaque random tokens whose hash
 *  is what gets stored. Plaintext secrets never persist. */

export function sha256Hex(value: string | Uint8Array): string {
  const hash = createHash("sha256");
  if (typeof value === "string") hash.update(value, "utf8"); else hash.update(value);
  return hash.digest("hex");
}

export function hmacSha256Hex(key: string, value: string): string {
  return createHmac("sha256", key).update(value, "utf8").digest("hex");
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/** Hash-then-compare for stored token/code hashes. */
export function verifyTokenHash(token: string, storedHash: string): boolean {
  return safeEqual(sha256Hex(token), storedHash);
}

const GCM_PREFIX = "gcm1.";

export function encryptSecret(plaintext: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const body = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return GCM_PREFIX + Buffer.concat([iv, tag, body]).toString("base64url");
}

export function decryptSecret(ciphertext: string, key: Buffer): string {
  if (!ciphertext.startsWith(GCM_PREFIX)) throw new Error("Unsupported secret format");
  const raw = Buffer.from(ciphertext.slice(GCM_PREFIX.length), "base64url");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const body = raw.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
}

export function platformKeyFromMaterial(material: string): Buffer {
  // The platform key is derived from admin-supplied secret material held
  // outside the database (env/secret manager); only its hash-derived key
  // ever touches process memory.
  return createHash("sha256").update(material, "utf8").digest();
}
