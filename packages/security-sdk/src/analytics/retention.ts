import { sha256Hex } from "../identity/crypto";
import { analyticsClassificationRank } from "./events";

/**
 * Analytics retention + tenant-safe caching (Prompt 27 §113–§114,
 * §122–§124).
 *
 * Retention applies ONLY to lake-owned records (analytics events,
 * search documents, snapshots). Audit logs and compliance evidence
 * are PROTECTED kinds — this module has no code path that returns
 * them as eligible, so analytics retention can never destroy
 * required audit/evidence records (§148).
 */

export interface AnalyticsRetentionPolicyInput {
  eventRetentionDays: number;
  searchDocRetentionDays: number;
  snapshotRetentionDays: number;
  restrictedEventRetentionDays: number;
}

export type LakeRecordKind = "ANALYTICS_EVENT" | "SEARCH_DOCUMENT" | "SNAPSHOT";

export function retentionCutoff(policy: AnalyticsRetentionPolicyInput, kind: LakeRecordKind, classification: string | null, now: Date): Date {
  let days: number;
  if (kind === "ANALYTICS_EVENT") {
    days = classification && analyticsClassificationRank(classification) >= analyticsClassificationRank("RESTRICTED")
      ? policy.restrictedEventRetentionDays
      : policy.eventRetentionDays;
  } else if (kind === "SEARCH_DOCUMENT") days = policy.searchDocRetentionDays;
  else days = policy.snapshotRetentionDays;
  return new Date(now.getTime() - Math.max(1, days) * 86_400_000);
}

export function isExpired(policy: AnalyticsRetentionPolicyInput, kind: LakeRecordKind, classification: string | null, recordTime: Date, now: Date): boolean {
  return recordTime.getTime() < retentionCutoff(policy, kind, classification, now).getTime();
}

/**
 * §122 cache key: organization + workspace + security context
 * (role, permission fingerprint, classification ceiling) + view +
 * filter version. A key without ALL of these would be a tenant
 * isolation bug (§123/§142).
 */
export function analyticsCacheKey(input: {
  organizationId: string;
  workspaceId: string;
  role: string;
  permissions: readonly string[];
  classificationCeiling: string;
  view: string;
  filters: unknown;
  queryVersion?: string;
}): string {
  const permissionFingerprint = sha256Hex([...input.permissions].sort().join(","));
  return sha256Hex([
    input.organizationId, input.workspaceId, input.role, permissionFingerprint,
    input.classificationCeiling, input.view, input.queryVersion ?? "v1",
    JSON.stringify(input.filters ?? {}),
  ].join("|"));
}

/** §124 invalidation scope: keys are namespaced by workspace prefix. */
export function analyticsCachePrefix(organizationId: string, workspaceId: string): string {
  return sha256Hex(`${organizationId}|${workspaceId}`).slice(0, 16);
}
