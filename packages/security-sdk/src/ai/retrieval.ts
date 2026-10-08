import type { AiDataClassification } from "./types";
import { classificationRank } from "./types";

/**
 * Permission-aware retrieval (Prompt 36 §10–§18). Every retrieval
 * candidate is filtered by workspace, tenant, the requesting user's
 * permissions, resource-level ACL and the data-classification ceiling
 * BEFORE it can enter a context (§10). The filter is pure and total —
 * the API layer loads rows per source, and this function is the
 * single choke point that decides what the model may see. Cross-tenant
 * retrieval is impossible by construction: a candidate whose
 * workspaceId differs from the request's is dropped, never re-homed
 * (§12).
 */

/** §11: retrieval sources across the V2 domains. */
export const AI_RETRIEVAL_SOURCE_TYPES = [
  "ASSET", "ASSET_GRAPH", "FINDING", "FINDING_OBSERVATION", "EVIDENCE_METADATA",
  "SCAN", "COVERAGE", "VULNERABILITY_INTEL", "SBOM_COMPONENT", "REMEDIATION",
  "VERIFICATION", "CLOUD_INVENTORY", "CONTAINER_INVENTORY", "KUBERNETES_INVENTORY",
  "MOBILE_FINDING", "BINARY_FINDING", "SOC_ALERT", "SOC_INCIDENT", "GRC_EVIDENCE",
  "REPORT", "DOCUMENTATION",
] as const;
export type AiRetrievalSourceType = (typeof AI_RETRIEVAL_SOURCE_TYPES)[number];

export interface AiRetrievalRequest {
  workspaceId: string;
  userId: string;
  /** Permissions the requesting user actually holds (RBAC resolved by
   *  the API layer BEFORE retrieval, §10). */
  userPermissions: string[];
  /** Permission required per source type; a source the user cannot
   *  read contributes nothing. */
  sourcePermissions: Partial<Record<AiRetrievalSourceType, string>>;
  /** Highest classification the assembled context may contain. */
  classificationCeiling: AiDataClassification;
  sourceTypes?: AiRetrievalSourceType[];
  maxRecords: number;
}

export interface AiRetrievalCandidate {
  sourceType: AiRetrievalSourceType;
  sourceId: string;
  workspaceId: string;
  classification: AiDataClassification;
  /** §13: resource-level ACL — user ids / role names allowed to read
   *  this specific resource. Empty/undefined = workspace-readable. */
  aclPrincipals?: string[];
  /** When the underlying observation was made (§18 staleness). */
  observedAt?: string;
  fields: Record<string, string>;
}

export interface AiRetrievalResult {
  records: AiRetrievalCandidate[];
  dropped: { sourceType: string; sourceId: string; reason: string }[];
  /** Sources skipped wholesale because the user lacks the source
   *  permission — disclosed so answers can state the gap (§21). */
  skippedSources: AiRetrievalSourceType[];
}

export function filterRetrievalCandidates(req: AiRetrievalRequest, candidates: AiRetrievalCandidate[]): AiRetrievalResult {
  const records: AiRetrievalCandidate[] = [];
  const dropped: AiRetrievalResult["dropped"] = [];
  const skippedSources: AiRetrievalSourceType[] = [];
  const wanted = req.sourceTypes && req.sourceTypes.length > 0 ? new Set(req.sourceTypes) : null;

  // Source-level permission gate first (§10): a source the user may
  // not read is skipped as a whole and DISCLOSED, not silently empty.
  const permittedSources = new Set<AiRetrievalSourceType>();
  for (const st of AI_RETRIEVAL_SOURCE_TYPES) {
    if (wanted && !wanted.has(st)) continue;
    const needed = req.sourcePermissions[st];
    if (needed && !req.userPermissions.includes(needed)) { skippedSources.push(st); continue; }
    permittedSources.add(st);
  }

  for (const c of candidates) {
    const drop = (reason: string) => dropped.push({ sourceType: c.sourceType, sourceId: c.sourceId, reason });
    if (wanted && !wanted.has(c.sourceType)) continue;
    if (!permittedSources.has(c.sourceType)) continue; // already disclosed via skippedSources
    if (c.workspaceId !== req.workspaceId) { drop("cross-tenant candidate refused (§12)"); continue; }
    if (classificationRank(c.classification) > classificationRank(req.classificationCeiling)) {
      drop(`classification ${c.classification} exceeds ceiling ${req.classificationCeiling} (§10)`);
      continue;
    }
    // §13 resource ACL: when a resource carries an ACL, the requester
    // must be named (by user id or by a principal in their permission set).
    if (c.aclPrincipals && c.aclPrincipals.length > 0) {
      const allowed = c.aclPrincipals.includes(req.userId) || c.aclPrincipals.some((p) => req.userPermissions.includes(p));
      if (!allowed) { drop("resource ACL does not include the requesting user (§13)"); continue; }
    }
    records.push(c);
    if (records.length >= req.maxRecords) break;
  }
  return { records, dropped, skippedSources };
}

/** §18: staleness labelling. A stale observation is still evidence,
 *  but it must never be presented as current fact — callers attach
 *  this label to the context record and the answer. */
export function assessEvidenceFreshness(observedAt: string | undefined, now: Date, staleAfterHours = 72): {
  state: "CURRENT" | "STALE" | "UNKNOWN";
  ageHours: number | null;
  label: string;
} {
  if (!observedAt) return { state: "UNKNOWN", ageHours: null, label: "observation time unknown — currency cannot be asserted" };
  const t = new Date(observedAt).getTime();
  if (Number.isNaN(t)) return { state: "UNKNOWN", ageHours: null, label: "observation time unparseable — currency cannot be asserted" };
  const ageHours = Math.max(0, (now.getTime() - t) / 3600000);
  if (ageHours > staleAfterHours) {
    return { state: "STALE", ageHours, label: `STALE: observed ${Math.round(ageHours)}h ago (threshold ${staleAfterHours}h) — do not present as current fact (§18)` };
  }
  return { state: "CURRENT", ageHours, label: `observed ${Math.round(ageHours)}h ago` };
}
