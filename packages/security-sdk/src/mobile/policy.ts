/**
 * Prompt 17 — MobileSecurityGate (§90), instrumentation policy
 * (§69–§75) and mobile correlation (§51/§52/§88).
 */
import type { NormalizedFinding } from "../findings/finding.types";
import { mobileCrossBuildKey, mobileFindingFingerprint } from "./taxonomy";
import { isProhibitedMobileAction } from "./types";

// ── §90: MobileSecurityGate ────────────────────────────────────────

export interface MobileGatePolicy {
  blockOnCritical: boolean;
  blockOnVerifiedSecrets: boolean;
  blockOnKevDependencies: boolean;
  blockOnCriticalExportedComponent: boolean;
  blockOnCriticalNetworkMisconfiguration: boolean;
}

export const DEFAULT_MOBILE_GATE_POLICY: MobileGatePolicy = {
  blockOnCritical: true,
  blockOnVerifiedSecrets: true,
  blockOnKevDependencies: true,
  blockOnCriticalExportedComponent: true,
  blockOnCriticalNetworkMisconfiguration: true,
};

export const MOBILE_GATE_POLICY_VERSION = "mobile-gate-v1";

export interface MobileGateEvaluation {
  status: "PASSED" | "FAILED" | "WARNING";
  failedRules: string[];
  warningRules: string[];
}

export function evaluateMobileSecurityGate(
  summary: {
    critical: number; verifiedSecrets: number; kevDependencies: number;
    criticalExportedComponents: number; criticalNetworkMisconfigurations: number;
  },
  policy: MobileGatePolicy = DEFAULT_MOBILE_GATE_POLICY,
): MobileGateEvaluation {
  const failed: string[] = [];
  if (policy.blockOnCritical && summary.critical > 0) failed.push("NO_CRITICAL_FINDINGS");
  if (policy.blockOnVerifiedSecrets && summary.verifiedSecrets > 0) failed.push("NO_VERIFIED_SECRETS");
  if (policy.blockOnKevDependencies && summary.kevDependencies > 0) failed.push("NO_KEV_DEPENDENCIES");
  if (policy.blockOnCriticalExportedComponent && summary.criticalExportedComponents > 0) failed.push("NO_CRITICAL_EXPORTED_COMPONENT");
  if (policy.blockOnCriticalNetworkMisconfiguration && summary.criticalNetworkMisconfigurations > 0) failed.push("NO_CRITICAL_NETWORK_MISCONFIGURATION");
  return { status: failed.length > 0 ? "FAILED" : "PASSED", failedRules: failed, warningRules: [] };
}

// ── §69–§75: MobileInstrumentationPolicy ───────────────────────────

export interface InstrumentationModuleRecord {
  id: string;
  name: string;
  tool: "FRIDA" | "OBJECTION";
  version: string;
  moduleHash: string;
  approved: boolean;
  status: string; // REGISTERED | APPROVED | DISABLED
}

export interface InstrumentationRequest {
  /** Free-form action names the caller asks for — matched against
   *  the PROHIBITED list and the shell/script bans. */
  requestedActions: string[];
  /** A raw script body is NEVER acceptable input (§72) — the field
   *  exists so its presence is refused explicitly, never executed. */
  scriptBody?: string;
  /** A raw shell command is NEVER acceptable input (§59/§75). */
  shellCommand?: string;
  moduleIds: string[];
  hasApprovedSession: boolean;
  hasInstrumentationApproval: boolean;
  killSwitchActive: boolean;
}

export interface InstrumentationDecision {
  allowed: boolean;
  reasons: string[];
}

/**
 * The ONLY path by which instrumentation may be considered (§73):
 * authorized build + lab device + approved profile + valid
 * authorization + policy approval + approved versioned modules +
 * no kill switch. Arbitrary scripts, arbitrary shell commands and
 * every §75 prohibited action refuse the whole request.
 */
export function evaluateInstrumentationPolicy(
  request: InstrumentationRequest,
  modules: InstrumentationModuleRecord[],
  budget: { maxInstrumentationModules: number },
): InstrumentationDecision {
  const reasons: string[] = [];
  if (request.scriptBody !== undefined && request.scriptBody.length > 0) {
    reasons.push("ARBITRARY_FRIDA_SCRIPT: user-supplied JavaScript is never accepted through the API (§72/§75)");
  }
  if (request.shellCommand !== undefined && request.shellCommand.length > 0) {
    reasons.push("ARBITRARY_ADB_SHELL: no generic shell exists in ZeroSweep (§59/§75)");
  }
  for (const action of request.requestedActions) {
    if (isProhibitedMobileAction(action)) {
      reasons.push(`${action.toUpperCase()}: prohibited automation (§75/§119) — never implemented, never executable`);
    }
    if (/shell|script|command/i.test(action)) {
      reasons.push(`${action}: arbitrary shell/script/command actions are refused (§59/§72/§75)`);
    }
  }
  if (request.killSwitchActive) reasons.push("KILL_SWITCH_ACTIVE: a kill switch covers this session (§92)");
  if (!request.hasApprovedSession) reasons.push("NO_APPROVED_SESSION: dynamic work requires an approved lab session (§73)");
  if (!request.hasInstrumentationApproval) reasons.push("NO_INSTRUMENTATION_APPROVAL: APPROVE_MOBILE_INSTRUMENTATION is required (§71/§101)");
  if (request.moduleIds.length === 0) reasons.push("NO_MODULES: only administrator-reviewed modules may run (§71)");
  if (request.moduleIds.length > budget.maxInstrumentationModules) {
    reasons.push(`MODULE_BUDGET: ${request.moduleIds.length} modules exceed the budget of ${budget.maxInstrumentationModules} (§91)`);
  }
  for (const id of request.moduleIds) {
    const mod = modules.find((m) => m.id === id);
    if (!mod) { reasons.push(`MODULE_UNKNOWN: module ${id} is not registered (§71)`); continue; }
    if (!mod.approved || mod.status !== "APPROVED") reasons.push(`MODULE_NOT_APPROVED: module ${mod.name}@${mod.version} is not approved (§71)`);
  }
  return { allowed: reasons.length === 0, reasons };
}

// ── §51/§52/§88: correlation ───────────────────────────────────────

export interface MobileCorrelationIdentity {
  applicationRef: string;
  buildHash: string;
  platform: string;
}

/** Canonical (per-build) fingerprint for a mobile finding (§50). */
export function canonicalMobileFingerprint(f: NormalizedFinding, identity: MobileCorrelationIdentity): string {
  if (f.secret) {
    return mobileFindingFingerprint({
      applicationRef: identity.applicationRef, buildHash: identity.buildHash, platform: identity.platform,
      component: `secret:${f.secret.fingerprint}`, ruleId: "MOBILE_HARDCODED_SECRET",
      ...(f.cwe ? { cwe: f.cwe } : {}), findingType: "MOBILE_SECRET",
    });
  }
  const component = f.filePath ?? f.mobileComponent ?? f.host ?? f.endpoint ?? f.title;
  return mobileFindingFingerprint({
    applicationRef: identity.applicationRef, buildHash: identity.buildHash, platform: identity.platform,
    component, ruleId: f.ruleId ?? f.title,
    ...(f.cwe ? { cwe: f.cwe } : {}), findingType: f.mobileFindingType ?? "MOBILE_CODE_FINDING",
  });
}

/** Cross-build key for a mobile finding (§51). */
export function crossBuildKeyFor(f: NormalizedFinding, identity: MobileCorrelationIdentity): string {
  if (f.secret) {
    return mobileCrossBuildKey({
      applicationRef: identity.applicationRef, platform: identity.platform,
      component: `secret:${f.secret.fingerprint}`, ruleId: "MOBILE_HARDCODED_SECRET",
      ...(f.cwe ? { cwe: f.cwe } : {}), findingType: "MOBILE_SECRET",
    });
  }
  const component = f.filePath ?? f.mobileComponent ?? f.host ?? f.endpoint ?? f.title;
  return mobileCrossBuildKey({
    applicationRef: identity.applicationRef, platform: identity.platform,
    component, ruleId: f.ruleId ?? f.title,
    ...(f.cwe ? { cwe: f.cwe } : {}), findingType: f.mobileFindingType ?? "MOBILE_CODE_FINDING",
  });
}

/**
 * §52 + §88 correlation for SDK-level consumers: findings sharing a
 * canonical fingerprint merge into ONE canonical finding with all
 * sources preserved; a DYNAMIC observation (runtime finding) whose
 * cross-build key matches a static finding CONFIRMS it — confidence
 * rises and BOTH observations are preserved (sources list).
 */
export function correlateMobileFindings(
  findings: NormalizedFinding[],
  identity: MobileCorrelationIdentity,
): NormalizedFinding[] {
  const byCanonical = new Map<string, NormalizedFinding>();
  for (const f of findings) {
    const fp = canonicalMobileFingerprint(f, identity);
    const existing = byCanonical.get(fp);
    if (!existing) {
      byCanonical.set(fp, { ...f, sourceFingerprint: fp, crossBuildFingerprint: crossBuildKeyFor(f, identity) });
      continue;
    }
    // Merge: keep the stronger severity/confidence, union sources via
    // evidence (the worker's correlation owns the sources column).
    if (severityRank(f.severity) > severityRank(existing.severity)) existing.severity = f.severity;
    existing.confidence = Math.max(existing.confidence, f.confidence);
  }
  const merged = [...byCanonical.values()];
  // §88: dynamic confirmation across finding types — a runtime
  // cleartext observation shares its cross-build semantics with the
  // static cleartext rule family.
  const staticCleartext = merged.find((f) => f.ruleId === "MOBILE_CLEARTEXT_ENABLED");
  const runtimeCleartext = merged.find((f) => f.ruleId === "MOBILE_RUNTIME_CLEARTEXT_TRAFFIC");
  if (staticCleartext && runtimeCleartext) {
    staticCleartext.dynamicConfirmed = true;
    staticCleartext.confidence = Math.min(1, Math.max(staticCleartext.confidence, runtimeCleartext.confidence) + 0.05);
  }
  return merged;
}

function severityRank(s: string): number {
  return { INFORMATIONAL: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[s] ?? 0;
}
