/**
 * Prompt 34 — Cloud IAM posture V2 (§28–§33), IAM graph (§31) and
 * defensive attack-path candidates (§32).
 *
 * Posture analysis works over NORMALIZED identity metadata only:
 * secret values are never retrieved for inventory (§30) — there is
 * nothing secret-shaped in the inputs by construction. The graph is
 * built only from relationships evidence supports (§31): identity
 * metadata declaring assumed roles, attached policies, accessible
 * resources or a bound workload. Attack-path candidates are
 * ANALYTICAL (§33): they are modelled, labelled OBSERVED/INFERRED
 * (§132) and never executed.
 */
import type {
  NormalizedCloudIdentity, NormalizedCloudRelationship, NormalizedCloudResource,
} from "../findings/finding.types";
import type { CloudV2AttackPathCandidate } from "./types";

export interface CloudIamRiskSignal {
  kind:
    | "OVERLY_BROAD_PERMISSIONS" | "PUBLIC_ACCESS" | "DANGEROUS_TRUST"
    | "UNUSED_PRIVILEGED_IDENTITY" | "STALE_PRIVILEGED_IDENTITY"
    | "LONG_LIVED_CREDENTIAL" | "MISSING_MFA_EVIDENCE";
  identityRef: string;
  identityName: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  detail: string;
  evidence: string;
}

export interface CloudIamPostureOptions {
  now?: Date;
  /** A privileged identity unused for longer than this is stale (§29). */
  staleDays?: number;
  /** Long-lived credential age threshold in days (§29). */
  longLivedKeyDays?: number;
}

/**
 * CloudIamPostureService core (§28/§29). Every signal cites the exact
 * metadata fact behind it. Absent evidence stays silent: an identity
 * with unknown last-used is NOT declared unused, and unknown MFA is
 * NOT declared missing — only explicit facts produce signals.
 */
export function analyzeCloudIamPosture(
  identities: NormalizedCloudIdentity[],
  opts: CloudIamPostureOptions = {},
): CloudIamRiskSignal[] {
  const now = opts.now ?? new Date();
  const staleDays = opts.staleDays ?? 90;
  const longLived = opts.longLivedKeyDays ?? 365;
  const signals: CloudIamRiskSignal[] = [];
  const push = (s: CloudIamRiskSignal) => signals.push(s);

  for (const idn of identities) {
    const ref = idn.providerIdentityId;
    const evidence = (idn.privilegeEvidence ?? {}) as Record<string, unknown>;
    const meta = (idn.metadata ?? {}) as Record<string, unknown>;

    if (idn.privileged) {
      push({
        kind: "OVERLY_BROAD_PERMISSIONS", identityRef: ref, identityName: idn.name, severity: "HIGH",
        detail: "Identity holds administrative-equivalent permissions (evidence-backed, §29). Flagged for organizational review — privilege alone is context, corroborating exposure raises priority.",
        evidence: typeof evidence.summary === "string" ? evidence.summary : "privileged=true from provider policy analysis",
      });
    }
    if (meta.publicAccess === true || evidence.publicAccess === true) {
      push({
        kind: "PUBLIC_ACCESS", identityRef: ref, identityName: idn.name, severity: "CRITICAL",
        detail: "Identity or its trust policy grants public/anonymous access (§29).",
        evidence: "publicAccess=true in identity metadata",
      });
    }
    if (evidence.broadTrust === true || meta.broadTrust === true) {
      push({
        kind: "DANGEROUS_TRUST", identityRef: ref, identityName: idn.name, severity: "HIGH",
        detail: "Trust relationship accepts principals outside the account/organization boundary (§29).",
        evidence: "broadTrust=true from trust-policy analysis",
      });
    }
    if (idn.mfaEnabled === false && (idn.identityType === "USER")) {
      push({
        kind: "MISSING_MFA_EVIDENCE", identityRef: ref, identityName: idn.name, severity: "MEDIUM",
        detail: "Provider reports MFA not enabled for this human identity (§29). Unknown MFA state is never reported as missing.",
        evidence: "mfaEnabled=false from provider metadata",
      });
    }
    if (typeof idn.keyAgeDays === "number" && idn.keyAgeDays > longLived) {
      push({
        kind: "LONG_LIVED_CREDENTIAL", identityRef: ref, identityName: idn.name, severity: "MEDIUM",
        detail: `Long-lived credential metadata: key age ${idn.keyAgeDays} days exceeds the ${longLived}-day threshold (§29). Only the AGE is stored — never the key (§30).`,
        evidence: `keyAgeDays=${idn.keyAgeDays}`,
      });
    }
    if (idn.privileged) {
      const lastUsed = idn.lastUsedAt ?? idn.lastSignInAt;
      if (lastUsed) {
        const ageDays = Math.floor((now.getTime() - new Date(lastUsed).getTime()) / 86_400_000);
        if (ageDays > staleDays) {
          push({
            kind: "STALE_PRIVILEGED_IDENTITY", identityRef: ref, identityName: idn.name, severity: "HIGH",
            detail: `Privileged identity last used ${ageDays} days ago (threshold ${staleDays}) — stale privilege is standing attack surface (§29).`,
            evidence: `lastUsedAt=${lastUsed}`,
          });
        }
      } else if (meta.neverUsed === true) {
        push({
          kind: "UNUSED_PRIVILEGED_IDENTITY", identityRef: ref, identityName: idn.name, severity: "HIGH",
          detail: "Privileged identity has never been used according to provider metadata (§29).",
          evidence: "neverUsed=true from provider metadata",
        });
      }
    }
  }
  return signals;
}

function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

/**
 * IAM graph edges (§31) in the canonical CloudRelationship shape:
 * IDENTITY → ROLE (ASSUMES / CAN_ASSUME via trust), ROLE → POLICY
 * (GRANTS), IDENTITY → RESOURCE (GRANTS = resource access),
 * SERVICE_IDENTITY → WORKLOAD (RUNS), and TRUSTS edges where a trust
 * relationship is evidenced. Only declared metadata creates edges.
 */
export function buildIamGraphEdges(
  identities: NormalizedCloudIdentity[],
  resources: NormalizedCloudResource[] = [],
): NormalizedCloudRelationship[] {
  const edges: NormalizedCloudRelationship[] = [];
  const seen = new Set<string>();
  const add = (e: NormalizedCloudRelationship) => {
    const key = `${e.fromType}|${e.fromRef}|${e.relationship}|${e.toType}|${e.toRef}`;
    if (seen.has(key)) return;
    seen.add(key);
    edges.push(e);
  };

  for (const idn of identities) {
    const meta = (idn.metadata ?? {}) as Record<string, unknown>;
    const ref = idn.providerIdentityId;
    for (const role of strList(meta.assumesRoles)) {
      add({ fromType: "IDENTITY", fromRef: ref, toType: "ROLE", toRef: role, relationship: "ASSUMES", evidence: "identity metadata: assumesRoles" });
      add({ fromType: "IDENTITY", fromRef: ref, toType: "ROLE", toRef: role, relationship: "CAN_ASSUME", evidence: "trust relationship evidenced in metadata (§31)" });
    }
    for (const trusted of strList(meta.trustsPrincipals)) {
      add({ fromType: "IDENTITY", fromRef: ref, toType: "IDENTITY", toRef: trusted, relationship: "TRUSTS", evidence: "trust policy metadata (§31)" });
    }
    for (const policy of strList(meta.attachedPolicies)) {
      add({ fromType: idn.identityType === "ROLE" ? "ROLE" : "IDENTITY", fromRef: ref, toType: "POLICY", toRef: policy, relationship: "GRANTS", evidence: "attached policy in provider metadata (§31)" });
    }
    for (const resource of strList(meta.accessibleResources)) {
      add({ fromType: "IDENTITY", fromRef: ref, toType: "RESOURCE", toRef: resource, relationship: "GRANTS", evidence: "resource access evidenced in policy analysis (§31)" });
    }
    if (typeof meta.workloadRef === "string") {
      add({ fromType: "IDENTITY", fromRef: ref, toType: "WORKLOAD", toRef: meta.workloadRef, relationship: "RUNS", evidence: "workload-bound service identity (§31)" });
    }
  }
  for (const res of resources) {
    const attached = (res.configuration as Record<string, unknown>)?.attachedIdentityId;
    if (typeof attached === "string") {
      add({ fromType: "RESOURCE", fromRef: res.providerResourceId, toType: "IDENTITY", toRef: attached, relationship: "ATTACHED_TO", evidence: "resource configuration: attachedIdentityId" });
    }
  }
  return edges;
}

const SENSITIVE_RESOURCE_RE = /(storage|bucket|database|db|rds|sql|secret|kms|key)/i;

/**
 * Defensive attack-path candidates (§32): Internet Exposure →
 * Workload → Overprivileged Role → Sensitive Resource. Assembled only
 * from observed inventory + IAM facts; steps the data merely suggests
 * (role assumed by the workload's identity) are labelled INFERRED.
 * The path is a model — it is never executed (§33).
 */
export function buildCloudAttackPathCandidates(input: {
  resources: NormalizedCloudResource[];
  identities: NormalizedCloudIdentity[];
  edges: NormalizedCloudRelationship[];
}): CloudV2AttackPathCandidate[] {
  const candidates: CloudV2AttackPathCandidate[] = [];
  const identityByRef = new Map(input.identities.map((i) => [i.providerIdentityId, i]));
  const assumes = new Map<string, string[]>();
  for (const e of input.edges) {
    if (e.relationship === "ASSUMES") {
      assumes.set(e.fromRef, [...(assumes.get(e.fromRef) ?? []), e.toRef]);
    }
  }
  const accessibleBy = new Map<string, string[]>();
  for (const e of input.edges) {
    if (e.relationship === "GRANTS" && e.toType === "RESOURCE") {
      accessibleBy.set(e.fromRef, [...(accessibleBy.get(e.fromRef) ?? []), e.toRef]);
    }
  }
  const sensitive = input.resources.filter((r) => SENSITIVE_RESOURCE_RE.test(r.resourceType) || SENSITIVE_RESOURCE_RE.test(r.name));

  for (const res of input.resources) {
    if (res.exposure !== "PUBLIC") continue;
    const config = (res.configuration ?? {}) as Record<string, unknown>;
    const identityRef = typeof config.attachedIdentityId === "string" ? config.attachedIdentityId : undefined;
    if (!identityRef) continue;
    const roleRefs = assumes.get(identityRef) ?? [];
    for (const roleRef of roleRefs) {
      const role = identityByRef.get(roleRef);
      if (!role?.privileged) continue;
      const reachable = new Set([...(accessibleBy.get(roleRef) ?? []), ...(accessibleBy.get(identityRef) ?? [])]);
      for (const target of sensitive) {
        if (target.providerResourceId === res.providerResourceId) continue;
        if (reachable.size > 0 && !reachable.has(target.providerResourceId)) continue;
        candidates.push({
          title: `Internet exposure → ${res.name} → overprivileged role ${role.name} → sensitive resource ${target.name}`,
          domain: "CLOUD",
          steps: [
            { kind: "INTERNET_EXPOSURE", ref: res.providerResourceId, label: `Public resource ${res.name}`, evidence: "OBSERVED" },
            { kind: "WORKLOAD", ref: res.providerResourceId, label: res.name, evidence: "OBSERVED" },
            { kind: "ROLE", ref: roleRef, label: `Overprivileged role ${role.name}`, evidence: reachable.size > 0 ? "OBSERVED" : "INFERRED" },
            { kind: "SENSITIVE_RESOURCE", ref: target.providerResourceId, label: target.name, evidence: reachable.has(target.providerResourceId) ? "OBSERVED" : "INFERRED" },
          ],
          confidence: reachable.has(target.providerResourceId) ? "HIGH" : "MEDIUM",
          executed: false,
        });
      }
    }
  }
  return candidates;
}
