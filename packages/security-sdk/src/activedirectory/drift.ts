/**
 * Prompt 15 — DirectoryDriftService (§79/§80).
 *
 * Snapshot-vs-snapshot diffing over normalized directory data: new
 * privileged users, privileged membership changes, new/changed trusts,
 * GPO changes, delegation changes, new risky ACLs and certificate
 * template changes become REVIEW SIGNALS. A change is never labelled
 * malicious automatically (§80) — drift feeds human review and the
 * audit trail, nothing else.
 */
import type { NormalizedDirectoryData } from "./types";
import { isPrivilegedGroup } from "./types";
import { buildIdentityGraph, privilegedPrincipals, resolveNestedGroups } from "./graph";

export type AdDriftKind =
  | "NEW_PRIVILEGED_MEMBER"
  | "PRIVILEGED_MEMBERSHIP_REMOVED"
  | "NEW_PRIVILEGED_USER"
  | "NEW_TRUST"
  | "TRUST_CHANGED"
  | "GPO_CHANGED"
  | "DELEGATION_CHANGED"
  | "NEW_RISKY_ACL"
  | "CERTIFICATE_TEMPLATE_CHANGED";

export interface AdDriftEventDraft {
  kind: AdDriftKind;
  objectRef?: string;
  detail: string;
  /** High-risk kinds (§80) are REVIEW signals with elevated priority —
   *  still never an automatic "malicious" verdict. */
  highRisk: boolean;
}

const HIGH_RISK_KINDS = new Set<AdDriftKind>([
  "NEW_PRIVILEGED_MEMBER", "NEW_PRIVILEGED_USER", "NEW_TRUST", "NEW_RISKY_ACL", "CERTIFICATE_TEMPLATE_CHANGED",
]);

function event(kind: AdDriftKind, objectRef: string | undefined, detail: string): AdDriftEventDraft {
  return { kind, ...(objectRef ? { objectRef } : {}), detail, highRisk: HIGH_RISK_KINDS.has(kind) };
}

function aclKey(e: { fromRef: string; relationship: string; toRef: string }): string {
  return `${e.fromRef}|${e.relationship}|${e.toRef}`;
}

export function diffDirectorySnapshots(
  previous: NormalizedDirectoryData | undefined,
  current: NormalizedDirectoryData,
  domainRef: string,
): AdDriftEventDraft[] {
  if (!previous) return []; // first snapshot is the baseline — no drift against nothing
  const events: AdDriftEventDraft[] = [];

  const prevGraph = buildIdentityGraph(previous, domainRef);
  const curGraph = buildIdentityGraph(current, domainRef);
  const prevPriv = privilegedPrincipals(previous, prevGraph, resolveNestedGroups(prevGraph, previous.groups));
  const curPriv = privilegedPrincipals(current, curGraph, resolveNestedGroups(curGraph, current.groups));

  const prevUsers = new Set(previous.users.map((u) => u.objectId));
  for (const [ref, info] of curPriv) {
    if (!prevPriv.has(ref)) {
      events.push(event(
        prevUsers.has(ref) ? "NEW_PRIVILEGED_MEMBER" : "NEW_PRIVILEGED_USER",
        ref,
        `Principal ${ref} gained privileged access: ${info.via.join("; ")}. Review signal only — not classified malicious (§80).`,
      ));
    }
  }
  for (const ref of prevPriv.keys()) {
    if (!curPriv.has(ref)) {
      events.push(event("PRIVILEGED_MEMBERSHIP_REMOVED", ref, `Principal ${ref} no longer holds privileged access.`));
    }
  }

  const prevTrusts = new Map(previous.trusts.map((t) => [t.targetDomainName, t]));
  for (const trust of current.trusts) {
    const before = prevTrusts.get(trust.targetDomainName);
    if (!before) {
      events.push(event("NEW_TRUST", trust.targetDomainName, `New ${trust.direction} ${trust.trustType} trust to ${trust.targetDomainName} discovered. Review signal only (§80).`));
    } else if (
      before.sidFilteringEnabled !== trust.sidFilteringEnabled
      || before.selectiveAuthentication !== trust.selectiveAuthentication
      || before.direction !== trust.direction
    ) {
      events.push(event("TRUST_CHANGED", trust.targetDomainName, `Trust to ${trust.targetDomainName} changed (sidFiltering ${String(before.sidFilteringEnabled)}→${String(trust.sidFilteringEnabled)}, selectiveAuth ${String(before.selectiveAuthentication)}→${String(trust.selectiveAuthentication)}).`));
    }
  }

  const prevGpos = new Map(previous.groupPolicies.map((g) => [g.objectId, g]));
  for (const gpo of current.groupPolicies) {
    const before = prevGpos.get(gpo.objectId);
    if (before && JSON.stringify(before.securityMetadata) !== JSON.stringify(gpo.securityMetadata)) {
      events.push(event("GPO_CHANGED", gpo.objectId, `GPO ${gpo.name} security metadata changed between snapshots.`));
    }
  }

  const delegationOf = (list: { objectId: string; delegationType?: string }[]) =>
    new Map(list.map((x) => [x.objectId, x.delegationType ?? "NONE"]));
  const prevDel = delegationOf([...previous.users, ...previous.computers]);
  for (const obj of [...current.users, ...current.computers]) {
    const now = obj.delegationType ?? "NONE";
    const before = prevDel.get(obj.objectId);
    if (before !== undefined && before !== now) {
      events.push(event("DELEGATION_CHANGED", obj.objectId, `Delegation on ${obj.objectId} changed ${before} → ${now}.`));
    }
  }

  const risky = (edges: NormalizedDirectoryData["relationships"]) =>
    new Set(edges.filter((e) => ["GENERIC_ALL", "GENERIC_WRITE", "WRITE_DACL", "WRITE_OWNER"].includes(e.relationship)).map(aclKey));
  const prevAcls = risky(previous.relationships);
  const privilegedGroupRefs = new Set(current.groups.filter((g) => isPrivilegedGroup({ objectId: g.objectId })).map((g) => g.objectId));
  for (const key of risky(current.relationships)) {
    if (!prevAcls.has(key)) {
      const [fromRef, relationship, toRef] = key.split("|");
      const targetIsHighValue = privilegedGroupRefs.has(toRef ?? "") || current.computers.some((c) => c.isDomainController && c.objectId === toRef);
      events.push(event("NEW_RISKY_ACL", toRef, `New risky ACL: ${fromRef} gained ${relationship} over ${toRef}${targetIsHighValue ? " (high-value target)" : ""}. Review signal only (§80).`));
    }
  }

  const prevTemplates = new Map(previous.certificateTemplates.map((t) => [t.name, JSON.stringify(t.riskClasses)]));
  for (const template of current.certificateTemplates) {
    const before = prevTemplates.get(template.name);
    const nowClasses = JSON.stringify([...template.riskClasses].sort());
    if (before === undefined || before !== nowClasses) {
      events.push(event("CERTIFICATE_TEMPLATE_CHANGED", template.name, `Certificate template ${template.name} risk classes changed (${before ?? "new"} → ${nowClasses}).`));
    }
  }

  return events;
}
