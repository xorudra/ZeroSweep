/**
 * RetestRouter (Prompt 20 §37–§39).
 *
 * ONE retest entry point for every domain. The router maps a finding to
 * the SAME safe engine that detected it — a retest never escalates
 * intrusiveness (§39) and never bypasses the original engine's
 * authorization/scope/policy gates: the route returned here is a PLAN;
 * execution still flows through the governed scan/validation paths.
 *
 * Outcomes (§37) are RESOLVED / REOPENED / INCONCLUSIVE. INCONCLUSIVE
 * is a first-class result: a retest that produced no comparable
 * evidence (engine unavailable, target not observed) proves nothing —
 * it is never a pass (carried over from the Prompt 11/19 rule).
 */

export type RetestRouteKind =
  | "WEB_VALIDATOR" | "DEPENDENCY_SCANNER" | "CLOUD_READONLY_CHECK" | "CONTAINER_IMAGE_SCAN"
  | "MOBILE_BUILD_SCAN" | "WIRELESS_PASSIVE_OBSERVATION" | "IDENTITY_POSTURE_CHECK"
  | "NETWORK_SAFE_CHECK" | "API_SAFE_CHECK" | "BINARY_STATIC_RESCAN" | "CODE_RESCAN" | "MANUAL_REVIEW";

export interface RetestRoute {
  kind: RetestRouteKind;
  /** The engine family that must perform the retest (original detector). */
  engine: string;
  rationale: string;
  /** §39: the route can never be more intrusive than the original detection. */
  maxIntrusiveness: "PASSIVE" | "SAFE_ACTIVE";
}

export interface RoutableFinding {
  sourceDomain?: string | null;
  sources?: string[];
  lifecycleStatus: string;
}

const ROUTES: Record<string, RetestRoute> = {
  WEB: { kind: "WEB_VALIDATOR", engine: "web-validation", rationale: "web finding → safe web validator/scanner (§38)", maxIntrusiveness: "SAFE_ACTIVE" },
  API: { kind: "API_SAFE_CHECK", engine: "api-safe-check", rationale: "API finding → safe API check set (§38)", maxIntrusiveness: "SAFE_ACTIVE" },
  NETWORK: { kind: "NETWORK_SAFE_CHECK", engine: "network-safe-check", rationale: "network finding → governed safe network check (§38)", maxIntrusiveness: "SAFE_ACTIVE" },
  SCA: { kind: "DEPENDENCY_SCANNER", engine: "dependency-scanner", rationale: "dependency finding → dependency scanner (§38)", maxIntrusiveness: "PASSIVE" },
  SAST: { kind: "CODE_RESCAN", engine: "code-scanner", rationale: "code finding → rescan of the new snapshot (§38)", maxIntrusiveness: "PASSIVE" },
  SECRET: { kind: "CODE_RESCAN", engine: "secret-scanner", rationale: "secret finding → rescan; the secret VALUE is never re-read (§38)", maxIntrusiveness: "PASSIVE" },
  CONTAINER: { kind: "CONTAINER_IMAGE_SCAN", engine: "container-scanner", rationale: "container finding → image rescan by digest (§38)", maxIntrusiveness: "PASSIVE" },
  KUBERNETES: { kind: "CONTAINER_IMAGE_SCAN", engine: "kubernetes-posture", rationale: "kubernetes finding → posture re-evaluation (§38)", maxIntrusiveness: "PASSIVE" },
  CLOUD: { kind: "CLOUD_READONLY_CHECK", engine: "cloud-readonly", rationale: "cloud finding → read-only cloud check (§38)", maxIntrusiveness: "PASSIVE" },
  IDENTITY: { kind: "IDENTITY_POSTURE_CHECK", engine: "identity-posture", rationale: "identity finding → defensive posture check (§38)", maxIntrusiveness: "PASSIVE" },
  MOBILE: { kind: "MOBILE_BUILD_SCAN", engine: "mobile-scanner", rationale: "mobile finding → scan of the NEW build (§38)", maxIntrusiveness: "PASSIVE" },
  BINARY: { kind: "BINARY_STATIC_RESCAN", engine: "binary-scanner", rationale: "binary finding → static rescan of the new artifact (§38)", maxIntrusiveness: "PASSIVE" },
  WIRELESS: { kind: "WIRELESS_PASSIVE_OBSERVATION", engine: "wireless-passive", rationale: "wireless finding → passive observation only (§38)", maxIntrusiveness: "PASSIVE" },
  RECON: { kind: "MANUAL_REVIEW", engine: "manual-review", rationale: "recon observation → analyst review (§38)", maxIntrusiveness: "PASSIVE" },
  MANUAL: { kind: "MANUAL_REVIEW", engine: "manual-review", rationale: "manual finding → analyst re-review (§38)", maxIntrusiveness: "PASSIVE" },
  EXTERNAL_IMPORT: { kind: "MANUAL_REVIEW", engine: "manual-review", rationale: "imported finding → analyst re-review; the external platform is not re-queried as an oracle (§38)", maxIntrusiveness: "PASSIVE" },
};

const RETESTABLE = new Set(["REMEDIATED", "RETEST_PENDING", "CONFIRMED", "IN_PROGRESS", "REOPENED", "MITIGATED"]);

export type RetestRouteResult = { ok: true; route: RetestRoute } | { ok: false; error: string };

export function routeRetest(finding: RoutableFinding): RetestRouteResult {
  if (!RETESTABLE.has(finding.lifecycleStatus)) {
    return { ok: false, error: `finding in lifecycle ${finding.lifecycleStatus} cannot be retested — remediate it first (§37)` };
  }
  const domain = (finding.sourceDomain ?? "").toUpperCase();
  const route = ROUTES[domain];
  if (!route) return { ok: false, error: `no safe retest route for source domain ${domain || "(unset)"} (§38)` };
  return { ok: true, route };
}

export type UnifiedRetestOutcome = "RESOLVED" | "REOPENED" | "INCONCLUSIVE";

/**
 * Judge a routed retest (§37): the original fingerprint present → the
 * remediation failed → REOPENED. Absent with comparable evidence →
 * RESOLVED. No comparable evidence → INCONCLUSIVE, never RESOLVED.
 */
export function judgeUnifiedRetest(input: { originalFingerprint: string; producedFingerprints: string[]; evidenceProduced: boolean }): UnifiedRetestOutcome {
  if (!input.evidenceProduced || input.producedFingerprints.length === 0) return "INCONCLUSIVE";
  return input.producedFingerprints.includes(input.originalFingerprint) ? "REOPENED" : "RESOLVED";
}

export const RetestRouter = { route: routeRetest, judge: judgeUnifiedRetest };
