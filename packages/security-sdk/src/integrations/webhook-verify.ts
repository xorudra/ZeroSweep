import { createHmac, timingSafeEqual } from "node:crypto";
import type { WebhookVerification } from "./types";

/**
 * Inbound webhook verification (Prompt 24 §15, §25, §82, §100, §108).
 * Verification ALWAYS runs before the payload is parsed for trust:
 * signature/token first, semantics second. Comparisons are
 * constant-time, timestamps tolerate only a bounded skew (§100), and
 * payload size is capped before any parsing (§82).
 */

/** §82: hard cap for inbound webhook bodies. */
export const MAX_WEBHOOK_PAYLOAD_BYTES = 1_000_000;

/** §100: bounded legitimate clock skew for signed requests. */
export const MAX_CLOCK_SKEW_SECONDS = 300;

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

function hmac(secret: string, data: string | Buffer): string {
  return createHmac("sha256", secret).update(data).digest("hex");
}

export function checkPayloadSize(rawBody: string | Buffer): WebhookVerification | null {
  const size = typeof rawBody === "string" ? Buffer.byteLength(rawBody, "utf8") : rawBody.length;
  if (size > MAX_WEBHOOK_PAYLOAD_BYTES) {
    return { ok: false, reasonCode: "PAYLOAD_TOO_LARGE", detail: `webhook payload of ${size} bytes exceeds the ${MAX_WEBHOOK_PAYLOAD_BYTES}-byte limit (§82)` };
  }
  return null;
}

/** §15: GitHub `X-Hub-Signature-256` (sha256 HMAC over the RAW body). */
export function verifyGitHubSignature(input: {
  rawBody: string | Buffer; signatureHeader?: string; secret: string;
}): WebhookVerification {
  const header = input.signatureHeader?.trim();
  if (!header) return { ok: false, reasonCode: "SIGNATURE_MISSING", detail: "missing X-Hub-Signature-256 header" };
  if (!header.startsWith("sha256=")) {
    return { ok: false, reasonCode: "SIGNATURE_INVALID", detail: "X-Hub-Signature-256 must use the sha256= scheme" };
  }
  const expected = `sha256=${hmac(input.secret, input.rawBody)}`;
  if (!safeEqual(expected, header.toLowerCase())) {
    return { ok: false, reasonCode: "SIGNATURE_INVALID", detail: "GitHub webhook signature does not match (§15)" };
  }
  return { ok: true, detail: "GitHub signature verified" };
}

/** §25: GitLab `X-Gitlab-Token` — the configured secret token itself,
 *  compared in constant time. */
export function verifyGitLabToken(input: { tokenHeader?: string; secret: string }): WebhookVerification {
  const presented = input.tokenHeader?.trim();
  if (!presented) return { ok: false, reasonCode: "SIGNATURE_MISSING", detail: "missing X-Gitlab-Token header" };
  if (!safeEqual(presented, input.secret)) {
    return { ok: false, reasonCode: "TOKEN_INVALID", detail: "GitLab webhook token does not match (§25/§113)" };
  }
  return { ok: true, detail: "GitLab webhook token verified" };
}

/** Bitbucket Cloud signs with `X-Hub-Signature` (same sha256 scheme
 *  as GitHub) when a webhook secret is configured. */
export function verifyBitbucketSignature(input: {
  rawBody: string | Buffer; signatureHeader?: string; secret: string;
}): WebhookVerification {
  const result = verifyGitHubSignature(input);
  return result.ok ? { ok: true, detail: "Bitbucket signature verified" } : result;
}

/** §57: Slack signed requests — `v0=<hmac>` over
 *  `v0:<timestamp>:<body>` with a bounded timestamp skew (§100). */
export function verifySlackSignature(input: {
  rawBody: string; signatureHeader?: string; timestampHeader?: string; secret: string; nowSeconds?: number;
}): WebhookVerification {
  const signature = input.signatureHeader?.trim();
  const timestamp = input.timestampHeader?.trim();
  if (!signature || !timestamp) {
    return { ok: false, reasonCode: "SIGNATURE_MISSING", detail: "missing Slack signature or timestamp header" };
  }
  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) return { ok: false, reasonCode: "SIGNATURE_INVALID", detail: "Slack timestamp is not numeric" };
  const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > MAX_CLOCK_SKEW_SECONDS) {
    return { ok: false, reasonCode: "TIMESTAMP_SKEW", detail: `Slack request timestamp skew exceeds ${MAX_CLOCK_SKEW_SECONDS}s (§100)` };
  }
  const expected = `v0=${hmac(input.secret, `v0:${timestamp}:${input.rawBody}`)}`;
  if (!safeEqual(expected, signature.toLowerCase())) {
    return { ok: false, reasonCode: "SIGNATURE_INVALID", detail: "Slack signature does not match (§57)" };
  }
  return { ok: true, detail: "Slack signature verified" };
}

/**
 * Outbound webhook signing (§71): the receiver gets
 * `X-ZeroSweep-Signature: sha256=<hmac>` computed with the secret the
 * REFERENCE resolves to at delivery time. The secret itself never
 * appears in the payload, the delivery record, or any log.
 */
export function signOutboundPayload(secret: string, rawBody: string): string {
  return `sha256=${hmac(secret, rawBody)}`;
}
