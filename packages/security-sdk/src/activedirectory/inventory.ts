/**
 * Prompt 15 — directory collection transport + normalization
 * (§10–§18/§30).
 *
 * The transport interface is READ-ONLY BY CONSTRUCTION: it exposes
 * collection methods (inventory, relationships, posture metadata,
 * artifact upload/download) and NO method that can modify a directory
 * object, authenticate as another identity, request a certificate or
 * execute anything (§83/§120). Fixture transports prove the pipeline
 * deterministically (spec §104); the production LDAP/SharpHound
 * transports are wired by a deployment on an approved internal worker
 * — in THIS build the connector deps are deliberately inert, so a
 * registered domain reports NOT_CONFIGURED instead of inventing data
 * (the platform never fabricates directory state).
 *
 * Raw directory datasets are highly sensitive (§30): the artifact
 * upload path returns only a storage REFERENCE + hash; content is
 * never embedded in results, queue payloads or logs.
 */
import { createHash } from "node:crypto";
import type { DirectoryDomainRecord, DirectoryBudget } from "./types";
import { clampDirectoryBudget, DIRECTORY_THROTTLE } from "./types";
import type {
  NormalizedDirectoryData, NormalizedDirectoryRelationship, NormalizedDirectorySnapshot,
} from "./types";
import { sanitizeDirectoryText } from "./guards";

/** What a collection transport can be asked to collect (§13). */
export type DirectoryCollectionKind =
  | "DIRECTORY_INVENTORY"
  | "LDAP_SECURITY_ANALYSIS"
  | "IDENTITY_RELATIONSHIP_DISCOVERY"
  | "SHARPHOUND_COLLECTION"
  | "BLOODHOUND_IMPORT"
  | "ADCS_INVENTORY"
  | "ADCS_POSTURE_ANALYSIS"
  | "SMB_INVENTORY";

export interface DirectoryCollectionRequest {
  domain: DirectoryDomainRecord;
  kind: DirectoryCollectionKind;
  /** SharpHound collection methods — validated through the §29 policy
   *  by the adapter BEFORE the transport is called. */
  collectionMethods?: string[];
  /** True only when an administrator approved the §29 REVIEW_REQUIRED
   *  set — gates session/local-admin edge production (§69). */
  includeReviewRequired?: boolean;
  /** A raw artifact to import (BloodHound/PingCastle/ADExplorer). */
  artifactText?: string;
  artifactFormat?: string;
  budget: DirectoryBudget;
}

export interface DirectoryCollectionResult {
  data: NormalizedDirectoryData;
  collectorVersions: Record<string, string>;
  /** Findings the collector itself emitted (e.g. PingCastle rules). */
  findingsCount: number;
  sessionsDropped: number;
  /** Proof surface for tests: every mutating verb the transport was
   *  (hypothetically) asked to perform. The interface HAS no mutating
   *  methods, so a correct transport's list stays empty forever. */
  mutationCalls: string[];
}

export interface DirectoryCollectionTransport {
  /** Collect directory data read-only. Implementations connect ONLY to
   *  the domain's explicitly approved DCs (§11). */
  collect(req: DirectoryCollectionRequest): Promise<DirectoryCollectionResult>;
  /** Store a raw directory artifact in protected object storage (§30)
   *  and return ONLY its reference + hash. */
  storeArtifact?(input: { domainId: string; kind: string; bytes: Buffer }): Promise<{ storageKey: string; sha256: string }>;
}

export interface DirectoryArtifactAccess {
  fetchArtifact(storageKey: string): Promise<Buffer>;
}

export interface DirectoryConnectorDeps {
  domains: { getDomain(id: string): Promise<DirectoryDomainRecord | undefined> };
  transports: Record<string, DirectoryCollectionTransport>;
  artifacts?: DirectoryArtifactAccess;
}

/** Inert deps for this build: no domain resolves → every connector
 *  reports NOT_CONFIGURED. Mirrors the P14 worker deps pattern. */
export const INERT_DIRECTORY_DEPS: DirectoryConnectorDeps = {
  domains: { getDomain: async () => undefined },
  transports: {},
};

export function hashDirectoryArtifact(bytes: Buffer): { sha256: string; sizeBytes: number } {
  return { sha256: createHash("sha256").update(bytes).digest("hex"), sizeBytes: bytes.length };
}

/** Stable content hash for a normalized collection (§18): the drift
 *  baseline. Order-independent over objects/edges, identity fields only. */
export function directorySnapshotHash(data: NormalizedDirectoryData): string {
  const parts: string[] = [];
  const push = (kind: string, id: string, extra = "") => parts.push(`${kind}:${id}:${extra}`);
  for (const u of data.users) push("user", u.objectId, `${u.enabled}|${u.delegationType ?? ""}`);
  for (const g of data.groups) push("group", g.objectId, g.privilegeClass);
  for (const c of data.computers) push("computer", c.objectId, `${c.enabled}|${c.delegationType ?? ""}`);
  for (const dc of data.domainControllers) push("dc", dc.hostname);
  for (const t of data.trusts) push("trust", t.targetDomainName, `${t.direction}|${t.sidFilteringEnabled ?? ""}|${t.selectiveAuthentication ?? ""}`);
  for (const r of data.relationships) push("edge", `${r.fromType}:${r.fromRef}`, `${r.relationship}:${r.toType}:${r.toRef}`);
  for (const s of data.smbShares) push("share", `${s.host}/${s.shareName}`, s.accessLevel);
  for (const ca of data.certificateAuthorities) push("ca", ca.name);
  for (const t of data.certificateTemplates) push("template", t.name, (t.riskClasses ?? []).join(","));
  parts.sort();
  return createHash("sha256").update(parts.join("\n")).digest("hex");
}

export function buildDirectorySnapshot(
  data: NormalizedDirectoryData,
  input: { collectionProfile: string; collectorVersions: Record<string, string> },
): NormalizedDirectorySnapshot {
  return {
    collectionProfile: input.collectionProfile,
    collectorVersions: input.collectorVersions,
    objectCounts: {
      users: data.users.length, groups: data.groups.length, computers: data.computers.length,
      domainControllers: data.domainControllers.length,
      organizationalUnits: data.organizationalUnits.length, groupPolicies: data.groupPolicies.length,
      trusts: data.trusts.length, smbShares: data.smbShares.length,
      certificateAuthorities: data.certificateAuthorities.length,
      certificateTemplates: data.certificateTemplates.length,
    },
    relationshipCount: data.relationships.length,
    snapshotHash: directorySnapshotHash(data),
  };
}

/**
 * Normalize a collected payload (§13–§17): sanitize every display
 * string, clamp every collection to the scan budget (counts beyond
 * the budget are TRUNCATED and reported, never silently kept), and
 * dedupe relationships by their identity key. Pagination discipline
 * is the transport's (§17); this is the deterministic shaping layer
 * every transport's output passes through.
 */
export function normalizeDirectoryCollection(
  data: NormalizedDirectoryData,
  budgetInput: Partial<DirectoryBudget> = {},
): { data: NormalizedDirectoryData; truncated: Record<string, number> } {
  const budget = clampDirectoryBudget(budgetInput);
  const truncated: Record<string, number> = {};
  const clampList = <T,>(list: T[], cap: number, key: string): T[] => {
    if (list.length > cap) { truncated[key] = list.length - cap; return list.slice(0, cap); }
    return list;
  };
  const clean = (s: string | undefined): string | undefined => (s ? sanitizeDirectoryText(s) : s);

  const users = clampList(data.users.map((u) => ({
    ...u, samAccountName: sanitizeDirectoryText(u.samAccountName), displayName: clean(u.displayName),
  })), budget.maxUsers, "users");
  const groups = clampList(data.groups.map((g) => ({ ...g, name: sanitizeDirectoryText(g.name) })), budget.maxGroups, "groups");
  const computers = clampList(data.computers.map((c) => ({ ...c, hostname: sanitizeDirectoryText(c.hostname) })), budget.maxComputers, "computers");
  const totalObjects = users.length + groups.length + computers.length
    + data.organizationalUnits.length + data.groupPolicies.length;
  if (totalObjects > budget.maxDirectoryObjects) truncated.objects = totalObjects - budget.maxDirectoryObjects;

  const seen = new Set<string>();
  const relationships: NormalizedDirectoryRelationship[] = [];
  for (const r of data.relationships) {
    const key = `${r.fromType}|${r.fromRef}|${r.relationship}|${r.toType}|${r.toRef}`;
    if (seen.has(key)) continue;
    seen.add(key);
    relationships.push(r);
  }
  const boundedRelationships = clampList(relationships, budget.maxRelationships, "relationships");

  return {
    data: {
      ...(data.domain ? { domain: data.domain } : {}),
      domainControllers: data.domainControllers.slice(0, 256),
      users, groups, computers,
      organizationalUnits: data.organizationalUnits,
      groupPolicies: data.groupPolicies,
      trusts: data.trusts.slice(0, budget.maxDomains * 64),
      relationships: boundedRelationships,
      smbShares: clampList(data.smbShares, budget.maxSmbHosts * 64, "smbShares"),
      certificateAuthorities: data.certificateAuthorities,
      certificateTemplates: data.certificateTemplates,
      ...(data.passwordPolicy ? { passwordPolicy: data.passwordPolicy } : {}),
    },
    truncated,
  };
}

/** §11: the only hosts a collection may contact are the domain's
 *  explicitly approved DCs (plus, for SMB posture, in-scope file-server
 *  hosts validated by the network scope engine upstream). */
export function assertApprovedDirectoryHosts(domain: DirectoryDomainRecord, hosts: string[]): void {
  const approved = new Set(domain.dcHosts.map((h) => h.toLowerCase()));
  for (const h of hosts) {
    if (!approved.has(h.toLowerCase())) {
      throw new Error(`host ${h} is not an approved domain controller for ${domain.dnsName} (§11)`);
    }
  }
}

export { DIRECTORY_THROTTLE };
