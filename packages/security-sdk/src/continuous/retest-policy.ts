import { routeRetest, type RetestRoute } from "../unified/retest-router";
import { classifyTechnique } from "../validation/catalog";
import type { ValidationFindingView } from "../validation/types";
import { validatorsForFinding } from "../validation/catalog";
import { classifyAutomationName } from "./safety";

/**
 * Safe automatic retesting (Prompt 22 §51–§55). Eligibility is
 * decided by THREE gates, all of which must pass:
 *  1. The Prompt 20 RetestRouter must route the finding (reuse — no
 *     duplicate retest logic, §55), and the route must not be a
 *     manual-review route.
 *  2. A Prompt 16 governed SAFE catalog validator must support the
 *     finding — scheduled revalidation inherits the closed SAFE-only
 *     catalog forever; anything classified PROHIBITED_AUTOMATION or
 *     REVIEW_REQUIRED is unschedulable.
 *  3. The finding must not fall in a §53 exclusion family (intrusive
 *     validation, credential attacks, exploitation, active wireless,
 *     dynamic instrumentation, binary runtime execution).
 *
 * Allowed families (§52): TLS configuration, security headers,
 * dependency version, container CVE, SAST finding, cloud
 * configuration, Kubernetes configuration, passive wireless posture.
 */

export const RETEST_TRIGGERS = [
  "SCHEDULED", "NEW_DEPLOYMENT_OR_BUILD", "NEW_SCAN_OBSERVATION", "REMEDIATION_MARKER",
] as const;
export type RetestTrigger = (typeof RETEST_TRIGGERS)[number];

const EXCLUSION_MARKERS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /exploit|rce|remote code execution/i, reason: "finding requires exploitation to validate (§53)" },
  { pattern: /credential|password|brute|kerberoast|ntlm|hash dump/i, reason: "finding involves credential attacks (§53)" },
  { pattern: /intrusive/i, reason: "finding requires intrusive validation (§53)" },
  { pattern: /frida|instrumentation|dynamic analysis/i, reason: "finding requires dynamic instrumentation (§53)" },
  { pattern: /debugger|runtime execution/i, reason: "finding requires binary runtime execution (§53)" },
  { pattern: /deauth|evil twin|wifite|active wireless/i, reason: "finding requires active wireless actions (§53)" },
];

export interface AutoRetestFindingView extends ValidationFindingView {
  lifecycleStatus: string;
  sourceDomain?: string | null;
  sources?: string[];
}

export interface AutoRetestEligibility {
  eligible: boolean;
  reason: string;
  route?: RetestRoute;
  validatorSlug?: string;
}

export function evaluateAutoRetestEligibility(
  finding: AutoRetestFindingView,
  trigger: RetestTrigger,
): AutoRetestEligibility {
  const haystack = `${finding.vulnClass ?? ""} ${finding.title}`;
  for (const marker of EXCLUSION_MARKERS) {
    if (marker.pattern.test(haystack)) return { eligible: false, reason: marker.reason };
  }
  if (classifyAutomationName(finding.title) === "PROHIBITED_AUTOMATION") {
    return { eligible: false, reason: "finding names a prohibited automation capability (§11)" };
  }
  const routed = routeRetest({
    sourceDomain: finding.sourceDomain ?? null,
    sources: finding.sources ?? finding.sources,
    lifecycleStatus: finding.lifecycleStatus,
  });
  if (!routed.ok) return { eligible: false, reason: routed.error };
  if (routed.route.kind === "MANUAL_REVIEW") {
    return { eligible: false, reason: "router assigned manual review — no automatic retest (§55)" };
  }
  const validators = validatorsForFinding(finding);
  if (validators.length === 0) {
    return { eligible: false, reason: "no governed SAFE catalog validator supports this finding (§51)" };
  }
  const validator = validators[0]!;
  if (classifyTechnique(validator.slug) !== "SAFE") {
    return { eligible: false, reason: `validator ${validator.slug} is not classified SAFE — unschedulable` };
  }
  return {
    eligible: true,
    reason: `safe deterministic retest via ${routed.route.kind} / validator ${validator.slug} (trigger: ${trigger})`,
    route: routed.route,
    validatorSlug: validator.slug,
  };
}
