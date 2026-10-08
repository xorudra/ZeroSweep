import type { PreflightStatus } from "./types";
import { judgeUrlAgainstSnapshot, type ScopeSnapshot } from "./scope-lock";

/**
 * Preflight evaluation (Prompt 32 §6–§9).
 *
 * Preflight is a pure evaluation over (a) authorization facts read
 * from the platform's own records and (b) probe observations supplied
 * by a transport. The probe transport is a deployment seam: when it is
 * NOT_CONFIGURED the reachability checks are UNKNOWN and the verdict
 * is BLOCKED with that exact reason — preflight never guesses a target
 * is reachable, and it never authorizes anything itself (§6).
 */

export interface AuthorizationFacts {
  /** Target has an APPROVED assessment / active authorization (§6). */
  activeAuthorization: boolean;
  /** Authorization expiry, if any — expired means BLOCKED (§174). */
  expiresAt?: Date | null;
  /** Owning target record is VERIFIED. */
  targetVerified: boolean;
}

export interface ProbeObservations {
  transport: "CONFIGURED" | "NOT_CONFIGURED";
  dnsResolves?: boolean;
  httpReachable?: boolean;
  tlsValid?: boolean;
  /** Final URL observed after redirects, if a redirect occurred. */
  redirectFinalUrl?: string;
  authenticationAvailable?: boolean;
  authenticationRequired?: boolean;
  maintenanceWindowActive?: boolean;
  ratePolicyAccepted?: boolean;
}

export interface PreflightCheck {
  name: string;
  status: "PASS" | "WARN" | "FAIL" | "UNKNOWN";
  detail: string;
}

export interface PreflightResult {
  status: PreflightStatus;
  checks: PreflightCheck[];
  /** §9: set when a redirect left the authorized scope. */
  redirectRecorded?: string;
}

export function evaluatePreflight(input: {
  authorization: AuthorizationFacts;
  probes: ProbeObservations;
  snapshot: ScopeSnapshot;
  now?: Date;
}): PreflightResult {
  const now = input.now ?? new Date();
  const checks: PreflightCheck[] = [];
  const { authorization: auth, probes } = input;

  checks.push(auth.targetVerified
    ? { name: "TARGET_VERIFIED", status: "PASS", detail: "target ownership verified" }
    : { name: "TARGET_VERIFIED", status: "FAIL", detail: "target is not VERIFIED — active testing is refused (§6)" });
  checks.push(auth.activeAuthorization
    ? { name: "ACTIVE_AUTHORIZATION", status: "PASS", detail: "active authorization present" }
    : { name: "ACTIVE_AUTHORIZATION", status: "FAIL", detail: "no active authorization for this target (§6/§173)" });
  if (auth.expiresAt) {
    checks.push(auth.expiresAt.getTime() > now.getTime()
      ? { name: "AUTHORIZATION_EXPIRY", status: "PASS", detail: `authorization valid until ${auth.expiresAt.toISOString()}` }
      : { name: "AUTHORIZATION_EXPIRY", status: "FAIL", detail: "authorization has expired (§174)" });
  }

  let redirectRecorded: string | undefined;
  if (probes.redirectFinalUrl) {
    const verdict = judgeUrlAgainstSnapshot(input.snapshot, probes.redirectFinalUrl);
    if (verdict === "IN_SCOPE") {
      checks.push({ name: "REDIRECT_SCOPE", status: "PASS", detail: "redirect stays inside the authorized scope snapshot" });
    } else {
      redirectRecorded = probes.redirectFinalUrl;
      checks.push({ name: "REDIRECT_SCOPE", status: "FAIL", detail: `redirect leaves authorized scope (${verdict}) — recorded, active follow-up stopped (§9/§175)` });
    }
  }

  if (probes.transport === "NOT_CONFIGURED") {
    checks.push({ name: "PROBE_TRANSPORT", status: "UNKNOWN", detail: "probe transport NOT_CONFIGURED in this deployment — reachability cannot be confirmed" });
  } else {
    checks.push(probes.dnsResolves ? { name: "DNS", status: "PASS", detail: "DNS resolves" } : { name: "DNS", status: "FAIL", detail: "DNS does not resolve" });
    checks.push(probes.httpReachable ? { name: "HTTP_REACHABILITY", status: "PASS", detail: "HTTP reachable" } : { name: "HTTP_REACHABILITY", status: "FAIL", detail: "HTTP unreachable" });
    if (probes.tlsValid === false) checks.push({ name: "TLS", status: "WARN", detail: "TLS validation problem observed — testing continues read-only where safe" });
    if (probes.maintenanceWindowActive) checks.push({ name: "MAINTENANCE", status: "FAIL", detail: "target is inside a maintenance restriction window (§7)" });
    if (probes.ratePolicyAccepted === false) checks.push({ name: "RATE_POLICY", status: "FAIL", detail: "target rate policy rejects the planned request budget (§7)" });
  }

  const hardFail = checks.some((c) => c.status === "FAIL");
  let status: PreflightStatus;
  if (probes.transport === "CONFIGURED" && probes.httpReachable === false && auth.targetVerified && auth.activeAuthorization) {
    status = "UNREACHABLE";
  } else if (hardFail) {
    status = "BLOCKED";
  } else if (probes.authenticationRequired && probes.authenticationAvailable === false) {
    status = "AUTH_REQUIRED";
  } else if (checks.some((c) => c.status === "WARN" || c.status === "UNKNOWN")) {
    status = probes.transport === "NOT_CONFIGURED" ? "BLOCKED" : "READY_WITH_WARNINGS";
  } else {
    status = "READY";
  }
  // NOT_CONFIGURED transport can never yield READY: reachability is
  // unproven, so the honest verdict is BLOCKED with the reason above.
  if (probes.transport === "NOT_CONFIGURED" && (status === "READY" || status === "READY_WITH_WARNINGS")) status = "BLOCKED";

  return { status, checks, ...(redirectRecorded ? { redirectRecorded } : {}) };
}
