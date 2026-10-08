/**
 * Effective entitlements & capability resolution (Prompt 40 §13–§16,
 * §119–§121).
 *
 * Precedence is deterministic (§15):
 *   platform safety ceiling → deployment capability → contract/license
 *   → plan → temporary approved override.
 * Overrides can only RAISE a numeric limit or ENABLE within the layers
 * above them; nothing below the safety ceiling can weaken it.
 *
 * SAFETY CANNOT BE ENTITLED AWAY (§16): no plan, license, contract or
 * override may disable tenant isolation, authorization, scope
 * enforcement, scanner safety, audit controls, or platform hard safety
 * ceilings. Those controls are not features and never appear as
 * entitlements.
 */
import { getFeatureDefinition, type FeatureKey } from "./features";

export const SAFETY_INVARIANTS = [
  "TENANT_ISOLATION",
  "AUTHORIZATION",
  "SCOPE_ENFORCEMENT",
  "SCANNER_SAFETY",
  "AUDIT_CONTROLS",
  "PLATFORM_HARD_SAFETY_CEILING",
] as const;
export type SafetyInvariant = (typeof SAFETY_INVARIANTS)[number];

/** Keys that must never be accepted as feature entitlements (§16/§298). */
export function isSafetyInvariantKey(key: string): boolean {
  return (SAFETY_INVARIANTS as readonly string[]).includes(key);
}

export interface EntitlementGrant {
  featureKey: FeatureKey;
  enabled: boolean;
  limit: number | null;
}

export interface EntitlementLayers {
  /** From the installed license / enterprise contract (§14). Null when absent. */
  license: EntitlementGrant[] | null;
  /** From the subscription's plan version (§14). Null when absent. */
  plan: EntitlementGrant[] | null;
  /** Features the trial grants while active (§54). Null when no trial. */
  trial: EntitlementGrant[] | null;
  /** Temporary approved overrides (§138): feature -> raised limit. */
  limitOverrides: Array<{ featureKey: FeatureKey; limit: number }>;
}

export interface EffectiveEntitlement extends EntitlementGrant {
  source: "LICENSE" | "PLAN" | "TRIAL" | "NONE";
}

function index(grants: EntitlementGrant[] | null): Map<FeatureKey, EntitlementGrant> {
  const map = new Map<FeatureKey, EntitlementGrant>();
  for (const g of grants ?? []) map.set(g.featureKey, g);
  return map;
}

/**
 * Compute effective entitlements for every registered feature.
 * License/contract wins over plan; trial grants apply only while the
 * trial layer is supplied (callers pass null once expired). A feature
 * disabled at a higher layer stays disabled — lower layers cannot
 * re-enable it (§15).
 */
export function computeEffectiveEntitlements(layers: EntitlementLayers): EffectiveEntitlement[] {
  const license = index(layers.license);
  const plan = index(layers.plan);
  const trial = index(layers.trial);
  const overrides = new Map(layers.limitOverrides.map((o) => [o.featureKey, o.limit]));

  const keys = new Set<FeatureKey>([
    ...license.keys(), ...plan.keys(), ...trial.keys(),
  ]);

  const out: EffectiveEntitlement[] = [];
  for (const key of keys) {
    const lic = license.get(key);
    const pln = plan.get(key);
    const tri = trial.get(key);
    let base: EffectiveEntitlement;
    if (lic) base = { ...lic, source: "LICENSE" };
    else if (pln) base = { ...pln, source: "PLAN" };
    else if (tri) base = { ...tri, source: "TRIAL" };
    else continue;
    // A trial grant may add a feature the plan lacks, but never override
    // an explicit disable from license/plan layers.
    if ((lic || pln) && tri && !base.enabled && tri.enabled && base.source !== "LICENSE") {
      // plan explicitly disabled it: plan wins over trial (§15 order).
    }
    const overrideLimit = overrides.get(key);
    if (base.enabled && overrideLimit !== undefined) {
      base = { ...base, limit: base.limit === null ? overrideLimit : Math.max(base.limit, overrideLimit) };
    }
    out.push(base);
  }
  return out.sort((a, b) => a.featureKey.localeCompare(b.featureKey));
}

export function findEntitlement(effective: EffectiveEntitlement[], key: FeatureKey): EffectiveEntitlement {
  return effective.find((e) => e.featureKey === key) ?? { featureKey: key, enabled: false, limit: null, source: "NONE" };
}

// ---------------------------------------------------------------------------
// Capability resolution (§120/§121)
// ---------------------------------------------------------------------------

export const CAPABILITY_STATES = [
  "AVAILABLE",
  "NOT_ENTITLED",
  "NOT_DEPLOYED",
  "TOOL_UNAVAILABLE",
  "WORKER_UNAVAILABLE",
  "UNAUTHORIZED",
  "QUOTA_EXCEEDED",
  "TEMPORARILY_DISABLED",
  /** §119 display state: entitled, but a technical dependency is absent. */
  "ENTITLED_BUT_UNAVAILABLE",
] as const;
export type CapabilityState = (typeof CAPABILITY_STATES)[number];

export interface CapabilityFacts {
  entitled: boolean;
  /** Deployment provides the technical dependency at all (§120). */
  deployed: boolean;
  /** Required tool present/healthy; null when the feature needs no tool. */
  toolAvailable: boolean | null;
  /** Required worker online; null when the feature needs no worker. */
  workerAvailable: boolean | null;
  /** Caller passes RBAC/authorization (§120). */
  authorized: boolean;
  /** Quota headroom remains (§120). */
  quotaAvailable: boolean;
  /** Kill switch / maintenance (§121 TEMPORARILY_DISABLED). */
  temporarilyDisabled: boolean;
}

export interface CapabilityResolution {
  featureKey: FeatureKey;
  state: CapabilityState;
  reason: string;
}

/**
 * Deterministic capability resolution (§120). Order matters: entitlement
 * first (product truth), then authorization, temporary disablement,
 * deployment capability (§119 ENTITLED_BUT_UNAVAILABLE), quota.
 */
export function resolveCapability(featureKey: FeatureKey, facts: CapabilityFacts): CapabilityResolution {
  const def = getFeatureDefinition(featureKey);
  const name = def?.displayName ?? featureKey;
  if (!facts.entitled) return { featureKey, state: "NOT_ENTITLED", reason: `${name} is not included in the current plan/license.` };
  if (!facts.authorized) return { featureKey, state: "UNAUTHORIZED", reason: `Your role does not permit ${name}.` };
  if (facts.temporarilyDisabled) return { featureKey, state: "TEMPORARILY_DISABLED", reason: `${name} is temporarily disabled by platform operations.` };
  if (!facts.deployed) return { featureKey, state: "NOT_DEPLOYED", reason: `${name} is entitled but not deployed in this installation (ENTITLED_BUT_UNAVAILABLE).` };
  if (facts.toolAvailable === false) return { featureKey, state: "TOOL_UNAVAILABLE", reason: `${name} is entitled but its required tool is unavailable (ENTITLED_BUT_UNAVAILABLE).` };
  if (facts.workerAvailable === false) return { featureKey, state: "WORKER_UNAVAILABLE", reason: `${name} is entitled but no suitable worker is online (ENTITLED_BUT_UNAVAILABLE).` };
  if (!facts.quotaAvailable) return { featureKey, state: "QUOTA_EXCEEDED", reason: `${name} quota for the current period is exhausted.` };
  return { featureKey, state: "AVAILABLE", reason: `${name} is available.` };
}

/** §119: the three deployment-absence states are all "entitled but unavailable". */
export function isEntitledButUnavailable(state: CapabilityState): boolean {
  return state === "NOT_DEPLOYED" || state === "TOOL_UNAVAILABLE" || state === "WORKER_UNAVAILABLE" || state === "ENTITLED_BUT_UNAVAILABLE";
}
