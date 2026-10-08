/**
 * Prompt 34 — CloudConnectionTestService logic (§12/§13) and cloud
 * assessment authorization (§8).
 *
 * The connection test is a pure evaluation over transport probe
 * facts: it never sees a credential value, and a forbidden provider
 * operation is surfaced as a recorded missing permission — it is
 * never retried in a loop (§13). Authorization is checked BEFORE any
 * assessment: an active authorization record, a provider/account
 * match, a credential reference and an allowed scope must all hold.
 */
import { isValidCredentialReference, looksLikeSecretValue } from "../cloudsec/guards";
import type {
  CloudConnectionEvaluation, CloudConnectionProbeFacts,
} from "./types";

/**
 * Evaluate a connection test (§12). Precedence is deliberate:
 * §145 account mismatch first (the credential belongs to a different
 * estate — nothing else about it may be trusted), then credential
 * presence, expiry, auth failure, transport honesty, reachability,
 * and finally permission limitations (§144: the assessment continues
 * where possible and records the gap — PERMISSION_LIMITED only when a
 * CORE inventory/IAM permission is missing).
 */
export function evaluateCloudConnection(facts: CloudConnectionProbeFacts): CloudConnectionEvaluation {
  const limitations: CloudConnectionEvaluation["limitations"] = [];
  const missing = [...(facts.missingPermissions ?? [])];
  const accountMatch = !facts.identityAccountId || !facts.expectedAccountId
    || facts.identityAccountId === facts.expectedAccountId;

  if (!accountMatch) {
    limitations.push({
      code: "ACCOUNT_MISMATCH",
      detail: "The credential resolves to a different account than the registered account — assessment is blocked until the registration or credential is corrected (§145). No secret material was exposed.",
    });
    return { result: "AUTH_FAILED", accountMatch: false, limitations, missingPermissions: missing };
  }
  if (!facts.credentialReferencePresent) {
    limitations.push({
      code: "SECRET_UNAVAILABLE",
      detail: "No credential reference is registered for this account — there is nothing to test (§10).",
    });
    return { result: "AUTH_FAILED", accountMatch, limitations, missingPermissions: missing };
  }
  if (facts.secretResolvable === false) {
    limitations.push({
      code: "SECRET_UNAVAILABLE",
      detail: "The credential reference does not resolve in Secrets Management (§10).",
    });
    return { result: "AUTH_FAILED", accountMatch, limitations, missingPermissions: missing };
  }
  if (facts.authOutcome === "EXPIRED") {
    limitations.push({
      code: "CREDENTIAL_EXPIRED",
      detail: "The provider rejected the credential as expired (§12). Rotate it in Secrets Management; the value is never handled here.",
    });
    return { result: "EXPIRED", accountMatch, limitations, missingPermissions: missing };
  }
  if (facts.authOutcome === "AUTH_FAILED") {
    limitations.push({
      code: "AUTH_FAILED",
      detail: "The provider rejected the credential (§143). No secret material was exposed in the test or this record.",
    });
    return { result: "AUTH_FAILED", accountMatch, limitations, missingPermissions: missing };
  }
  if (!facts.transportConfigured) {
    limitations.push({
      code: "TRANSPORT_NOT_CONFIGURED",
      detail: "No live provider transport is wired in this deployment (NOT_CONFIGURED), so provider reachability cannot be proven — reported honestly as UNREACHABLE rather than assumed connected.",
    });
    return { result: "UNREACHABLE", accountMatch, limitations, missingPermissions: missing };
  }
  if (facts.reachable === false) {
    limitations.push({
      code: "PROVIDER_UNREACHABLE",
      detail: "The provider endpoint could not be reached from the assessment worker (§12).",
    });
    return { result: "UNREACHABLE", accountMatch, limitations, missingPermissions: missing };
  }
  if ((facts.coreMissingPermissions ?? []).length > 0) {
    limitations.push({
      code: "CORE_PERMISSION_MISSING",
      detail: `Core read permissions are missing (${(facts.coreMissingPermissions ?? []).join(", ")}) — core inventory/IAM collection is blocked; the gap is recorded, never retried in a loop (§13/§144).`,
    });
    return { result: "PERMISSION_LIMITED", accountMatch, limitations, missingPermissions: missing };
  }
  if (missing.length > 0) {
    limitations.push({
      code: "PERMISSION_LIMITED",
      detail: `Connected with limitations: ${missing.length} non-core read permission(s) missing — affected areas become coverage gaps, the rest of the assessment proceeds (§144).`,
    });
    return { result: "CONNECTED_WITH_LIMITATIONS", accountMatch, limitations, missingPermissions: missing };
  }
  return { result: "CONNECTED", accountMatch, limitations, missingPermissions: missing };
}

export interface CloudAuthorizationFacts {
  /** Authorization record id registered on the account (§6/§8). */
  authorizationId?: string | null;
  /** Status of that record where the platform tracks it. */
  authorizationStatus?: string | null;
  /** Expiry of the authorization, when bounded. */
  authorizationExpiresAt?: string | null;
  accountProvider: string;
  authorizationProvider?: string | null;
  externalAccountId: string;
  authorizationAccountId?: string | null;
  credentialReference?: string | null;
  /** Regions/subscriptions/projects the authorization allows (§8). */
  allowedRegions?: string[];
  requestedRegions?: string[];
  now?: Date;
}

/**
 * §8 authorization gate for a V2 assessment. Every condition is
 * checked and every failure is returned — the caller blocks the run
 * and records the reasons; nothing is silently waived.
 */
export function evaluateCloudAuthorization(facts: CloudAuthorizationFacts): { allowed: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (!facts.authorizationId) reasons.push("No authorization record is registered for this account (§8) — assessment requires an active authorization.");
  if (facts.authorizationStatus && facts.authorizationStatus !== "APPROVED" && facts.authorizationStatus !== "ACTIVE") {
    reasons.push(`Authorization status is ${facts.authorizationStatus}, not APPROVED/ACTIVE (§8).`);
  }
  if (facts.authorizationExpiresAt) {
    const now = facts.now ?? new Date();
    if (new Date(facts.authorizationExpiresAt).getTime() <= now.getTime()) {
      reasons.push("The authorization record has expired (§8).");
    }
  }
  if (facts.authorizationProvider && facts.authorizationProvider !== facts.accountProvider) {
    reasons.push(`Authorization provider ${facts.authorizationProvider} does not match account provider ${facts.accountProvider} (§8/§145).`);
  }
  if (facts.authorizationAccountId && facts.authorizationAccountId !== facts.externalAccountId) {
    reasons.push("Authorization account does not match the registered external account id (§8/§145).");
  }
  if (!facts.credentialReference) {
    reasons.push("No credential reference is registered — credentials are secret references only (§10).");
  } else if (!isValidCredentialReference(facts.credentialReference) || looksLikeSecretValue(facts.credentialReference)) {
    reasons.push("The stored credential reference is not a valid secret reference name — a secret-shaped value is refused, never persisted (§10).");
  }
  if ((facts.allowedRegions ?? []).length > 0 && (facts.requestedRegions ?? []).length > 0) {
    const outside = (facts.requestedRegions ?? []).filter((r) => !(facts.allowedRegions ?? []).includes(r));
    if (outside.length > 0) reasons.push(`Requested regions are outside the authorized scope: ${outside.join(", ")} (§8).`);
  }
  return { allowed: reasons.length === 0, reasons };
}
