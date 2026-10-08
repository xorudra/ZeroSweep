import { createHash, randomBytes } from "node:crypto";

/**
 * Prompt 37 §106/§107: secure report share links.
 *
 * Reports are private by default (§107). A share link is an explicit,
 * expiring, revocable exception: the raw token is generated here and
 * shown to its creator exactly once; the platform stores only its
 * SHA-256 hash, so a database read never yields a usable link.
 */
export function generateShareToken(): string {
  return randomBytes(32).toString("base64url");
}

export function hashShareToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export interface ShareLinkState {
  expiresAt: Date | string;
  revokedAt?: Date | string | null;
  maxDownloads?: number | null;
  downloadCount: number;
}

export type ShareLinkVerdict =
  | { usable: true }
  | { usable: false; reason: "REVOKED" | "EXPIRED" | "DOWNLOAD_LIMIT" };

export function evaluateShareLink(link: ShareLinkState, now: Date): ShareLinkVerdict {
  if (link.revokedAt) return { usable: false, reason: "REVOKED" };
  if (new Date(link.expiresAt).getTime() <= now.getTime()) return { usable: false, reason: "EXPIRED" };
  if (typeof link.maxDownloads === "number" && (link.downloadCount ?? 0) >= link.maxDownloads) {
    return { usable: false, reason: "DOWNLOAD_LIMIT" };
  }
  return { usable: true };
}
