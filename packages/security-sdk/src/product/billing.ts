/**
 * Billing provider abstraction helpers (Prompt 40 §19–§27).
 *
 * Product logic never hardcodes one payment processor (§19). Providers:
 * a Stripe-compatible SaaS provider, manual invoice, enterprise
 * contract, or self-hosted license (§20). When NO provider is
 * configured the platform reports billing NOT_CONFIGURED and never
 * simulates a successful payment (§21/§268).
 *
 * ZeroSweep never stores raw card numbers, CVVs or full payment
 * credentials (§26) — payment data stays with the provider's hosted /
 * tokenized flow.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

export const BILLING_PROVIDER_KINDS = ["STRIPE_COMPATIBLE", "MANUAL_INVOICE", "ENTERPRISE_CONTRACT", "SELF_HOSTED_LICENSE", "TEST"] as const;
export type BillingProviderKind = (typeof BILLING_PROVIDER_KINDS)[number];

export type BillingConfigurationStatus = "CONFIGURED" | "NOT_CONFIGURED" | "TEST_ONLY";

/**
 * Decide the honest billing status from deployment configuration.
 * The TEST provider is refused in production (§21).
 */
export function billingConfigurationStatus(config: {
  provider: string | null | undefined;
  nodeEnv: string;
}): { status: BillingConfigurationStatus; provider: BillingProviderKind | null; reason: string } {
  if (!config.provider) {
    return { status: "NOT_CONFIGURED", provider: null, reason: "No billing provider is configured; payments are not processed and never simulated." };
  }
  if (config.provider === "test") {
    if (config.nodeEnv === "production") {
      return { status: "NOT_CONFIGURED", provider: null, reason: "The test billing provider is refused in production (§21)." };
    }
    return { status: "TEST_ONLY", provider: "TEST", reason: "Development/test billing provider explicitly configured; no real payment occurs." };
  }
  if (config.provider === "manual") {
    return { status: "CONFIGURED", provider: "MANUAL_INVOICE", reason: "Manual-invoice billing: subscriptions change only via recorded invoice/contract events." };
  }
  return { status: "NOT_CONFIGURED", provider: null, reason: `Unknown billing provider '${config.provider}'.` };
}

// ---------------------------------------------------------------------------
// Webhook verification (§23/§24/§219/§220)
// ---------------------------------------------------------------------------

export interface BillingWebhookVerification {
  ok: boolean;
  reason?: string;
}

/**
 * Verify an HMAC-SHA256 billing webhook: signature over
 * `${timestamp}.${rawBody}`, constant-time comparison, and a replay
 * window on the timestamp (§23). The caller additionally enforces
 * event-ID idempotency against BillingEvent (§24).
 */
export function verifyBillingWebhookSignature(input: {
  rawBody: string;
  signatureHeader: string | null;
  timestampHeader: string | null;
  secret: string;
  now: Date;
  replayWindowSeconds?: number;
}): BillingWebhookVerification {
  if (!input.signatureHeader || !input.timestampHeader) {
    return { ok: false, reason: "Missing signature or timestamp header." };
  }
  const ts = Number(input.timestampHeader);
  if (!Number.isFinite(ts)) return { ok: false, reason: "Malformed webhook timestamp." };
  const windowSeconds = input.replayWindowSeconds ?? 300;
  const skew = Math.abs(Math.floor(input.now.getTime() / 1000) - ts);
  if (skew > windowSeconds) {
    return { ok: false, reason: `Webhook timestamp outside the ${windowSeconds}s replay window.` };
  }
  const expected = createHmac("sha256", input.secret).update(`${ts}.${input.rawBody}`).digest("hex");
  const provided = input.signatureHeader.startsWith("sha256=") ? input.signatureHeader.slice(7) : input.signatureHeader;
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(provided, "utf8");
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return { ok: false, reason: "Webhook signature mismatch." };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Payment-data guard (§26)
// ---------------------------------------------------------------------------

const FORBIDDEN_PAYMENT_KEYS = ["card_number", "cardnumber", "pan", "cvv", "cvc", "card_cvv", "card_cvc", "full_card", "payment_credentials"];

/** Luhn check used only to DETECT card numbers so they can be refused. */
export function looksLikeCardNumber(value: string): boolean {
  const digits = value.replace(/[\s-]/g, "");
  if (!/^\d{13,19}$/.test(digits)) return false;
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = Number(digits[i]);
    if (dbl) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

/**
 * Refuse to persist any billing payload that carries raw payment data
 * (§26/§298). Returns the offending paths; empty array = safe metadata.
 */
export function findPaymentDataViolations(value: unknown, path = "$"): string[] {
  const violations: string[] = [];
  if (typeof value === "string") {
    if (looksLikeCardNumber(value)) violations.push(`${path} (card-number-like value)`);
    return violations;
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => violations.push(...findPaymentDataViolations(v, `${path}[${i}]`)));
    return violations;
  }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (FORBIDDEN_PAYMENT_KEYS.includes(k.toLowerCase())) violations.push(`${path}.${k} (forbidden payment field)`);
      violations.push(...findPaymentDataViolations(v, `${path}.${k}`));
    }
  }
  return violations;
}
