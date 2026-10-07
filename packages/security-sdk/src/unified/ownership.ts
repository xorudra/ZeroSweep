/**
 * FindingOwnership + OwnershipRule auto-assignment (Prompt 20 §26/§27).
 *
 * Ownership answers "whose problem is this" for a person, a team, an
 * application, a business unit, or the asset owner. Rules make the
 * common cases automatic (repository → AppSec team, cloud account →
 * Cloud Security, mobile app → Mobile team). The hard rule from §27:
 * auto-assignment NEVER silently overrides a manual assignment.
 */

export type OwnerType = "USER" | "TEAM" | "APPLICATION" | "BUSINESS_UNIT" | "ASSET_OWNER";

export interface OwnershipRuleView {
  id: string;
  matchKind: "SOURCE_DOMAIN" | "REPOSITORY" | "CLOUD_ACCOUNT" | "ASSET_GROUP" | "MOBILE_APP";
  matchValue: string;
  ownerType: OwnerType;
  ownerRef: string;
  priority: number; // lower = evaluated first
  enabled: boolean;
}

export interface OwnershipContext {
  sourceDomain?: string | null;
  repositoryId?: string | null;
  cloudAccountId?: string | null;
  assetGroup?: string | null;
  mobileApplicationId?: string | null;
}

export interface OwnershipDecision {
  ownerType: OwnerType;
  ownerRef: string;
  ruleId: string;
  rationale: string;
}

const MATCH_VALUE: Record<OwnershipRuleView["matchKind"], (ctx: OwnershipContext) => string | null | undefined> = {
  SOURCE_DOMAIN: (c) => c.sourceDomain,
  REPOSITORY: (c) => c.repositoryId,
  CLOUD_ACCOUNT: (c) => c.cloudAccountId,
  ASSET_GROUP: (c) => c.assetGroup,
  MOBILE_APP: (c) => c.mobileApplicationId,
};

/** Evaluate rules in priority order; first enabled match wins. */
export function evaluateOwnershipRules(rules: OwnershipRuleView[], ctx: OwnershipContext): OwnershipDecision | undefined {
  const ordered = [...rules].filter((r) => r.enabled).sort((a, b) => a.priority - b.priority);
  for (const rule of ordered) {
    const actual = MATCH_VALUE[rule.matchKind](ctx);
    if (actual && actual === rule.matchValue) {
      return {
        ownerType: rule.ownerType,
        ownerRef: rule.ownerRef,
        ruleId: rule.id,
        rationale: `rule ${rule.id}: ${rule.matchKind}=${rule.matchValue} → ${rule.ownerType} ${rule.ownerRef} (§27)`,
      };
    }
  }
  return undefined;
}

export type AssignmentSource = "MANUAL" | "RULE";

/**
 * §27 guard: given the existing ownership source, may an auto-rule be
 * applied? Manual assignments are sticky — only an explicit manual
 * reassignment (or clearing ownership) changes them.
 */
export function mayAutoAssign(existingSource: AssignmentSource | undefined): boolean {
  return existingSource !== "MANUAL";
}
