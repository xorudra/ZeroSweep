import { blockedTargetReason } from "../scope/scope.matcher";
import type { HostResolver } from "../validation/scope-revalidation";

/**
 * Workflow webhook destination security (Prompt 22 §73/§74, §115).
 *
 * HTTPS only, destination allowlist, and SSRF protection that reuses
 * the platform's protected-destination policy: localhost, link-local
 * (incl. the cloud metadata range), loopback and private management
 * networks are refused. DNS is re-validated at check time — a name
 * that resolves to a protected address is refused even if the name
 * itself looks public (rebinding defense). The ONLY exception is an
 * explicitly administrator-approved infrastructure policy, which is
 * off by default and never implied.
 */

export interface WebhookValidationInput {
  url: string;
  /** Hostnames (exact or *.suffix) an administrator allowlisted. When
   *  non-empty, the destination host MUST match it. */
  allowlist: string[];
  resolver: HostResolver;
  /** Administrator-approved infrastructure exception (§74) — permits
   *  private destinations ONLY for hosts on the allowlist. */
  adminApprovedInfrastructure?: boolean;
}

export type WebhookValidationResult =
  | { ok: true; host: string; resolvedIps: string[] }
  | { ok: false; reasonCode: "INVALID_URL" | "NOT_HTTPS" | "CREDENTIALS_IN_URL" | "NOT_ALLOWLISTED" | "SSRF_PROTECTED_DESTINATION" | "RESOLUTION_FAILED"; message: string };

function hostMatchesAllowlist(host: string, allowlist: string[]): boolean {
  return allowlist.some((entry) => {
    const e = entry.toLowerCase();
    if (e.startsWith("*.")) return host.endsWith(e.slice(1)) && host.length > e.length - 1;
    return host === e;
  });
}

const IPV4_RE = /^[0-9.]+$/;

export async function validateWebhookDestination(input: WebhookValidationInput): Promise<WebhookValidationResult> {
  let u: URL;
  try {
    u = new URL(input.url);
  } catch {
    return { ok: false, reasonCode: "INVALID_URL", message: "webhook URL does not parse" };
  }
  if (u.protocol !== "https:") {
    return { ok: false, reasonCode: "NOT_HTTPS", message: "webhook destinations must use HTTPS (§73)" };
  }
  if (u.username || u.password) {
    return { ok: false, reasonCode: "CREDENTIALS_IN_URL", message: "webhook URLs must not embed credentials" };
  }
  const host = u.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) {
    return { ok: false, reasonCode: "SSRF_PROTECTED_DESTINATION", message: "localhost webhook destinations are blocked (§74)" };
  }
  if (input.allowlist.length > 0 && !hostMatchesAllowlist(host, input.allowlist)) {
    return { ok: false, reasonCode: "NOT_ALLOWLISTED", message: `host ${host} is not on the webhook destination allowlist (§73)` };
  }
  let resolvedIps: string[];
  if (IPV4_RE.test(host) || host.includes(":")) {
    resolvedIps = [host];
  } else {
    try {
      resolvedIps = await input.resolver(host);
    } catch {
      return { ok: false, reasonCode: "RESOLUTION_FAILED", message: `host ${host} could not be resolved for SSRF validation` };
    }
    if (resolvedIps.length === 0) {
      return { ok: false, reasonCode: "RESOLUTION_FAILED", message: `host ${host} resolved to no addresses` };
    }
  }
  const exceptionApplies = input.adminApprovedInfrastructure === true
    && input.allowlist.length > 0 && hostMatchesAllowlist(host, input.allowlist);
  for (const ip of resolvedIps) {
    const blocked = blockedTargetReason(ip);
    if (blocked && !exceptionApplies) {
      return {
        ok: false, reasonCode: "SSRF_PROTECTED_DESTINATION",
        message: `webhook host ${host} resolves to a protected destination (${blocked}) — blocked (§74/§115)`,
      };
    }
  }
  return { ok: true, host, resolvedIps };
}

/** Signing material handling (§73): the secret itself is a credential
 *  REFERENCE, resolved by the delivery layer; only its presence is
 *  ever recorded in policy rows. */
export interface WebhookDeliveryPolicy {
  timeoutMs: number;
  maxRetries: number;
  signingSecretRef?: string;
}

export const DEFAULT_WEBHOOK_DELIVERY_POLICY: WebhookDeliveryPolicy = {
  timeoutMs: 5000,
  maxRetries: 2,
};
