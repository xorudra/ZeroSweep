/**
 * Prompt 34 — Steampipe approved query packs (§24/§25) and the
 * CloudMapper-style defensive exposure graph (§23).
 *
 * Steampipe is usable ONLY through platform-approved packs: a
 * request names a pack + query id from the catalog below. Raw SQL
 * from any caller is rejected before it can reach an adapter — there
 * is no arbitrary query or host-command path (§25/§107).
 * CloudMapper-style output is a defensive network/exposure
 * VISUALIZATION model over inventory the platform already holds —
 * never an offensive capability (§23).
 */
import type { NormalizedCloudResource } from "../findings/finding.types";

export interface SteampipeApprovedQuery {
  queryId: string;
  title: string;
  domain: "INVENTORY" | "POSTURE" | "COMPLIANCE" | "EXPOSURE";
}

export interface SteampipeApprovedPack {
  packId: string;
  provider: "AWS" | "AZURE" | "GCP" | "ALL";
  title: string;
  queries: SteampipeApprovedQuery[];
}

/** The approved pack catalog (§24). Queries are referenced by id;
 *  their SQL lives inside the governed adapter, never in API input. */
export const APPROVED_STEAMPIPE_PACKS: SteampipeApprovedPack[] = [
  {
    packId: "aws-inventory-core", provider: "AWS", title: "AWS core inventory",
    queries: [
      { queryId: "aws.account.regions", title: "Account regions", domain: "INVENTORY" },
      { queryId: "aws.network.security_groups", title: "Security groups", domain: "INVENTORY" },
      { queryId: "aws.storage.buckets", title: "Storage buckets", domain: "INVENTORY" },
    ],
  },
  {
    packId: "aws-posture-cis", provider: "AWS", title: "AWS CIS posture checks",
    queries: [
      { queryId: "aws.posture.public_storage", title: "Public storage check", domain: "COMPLIANCE" },
      { queryId: "aws.posture.logging_enabled", title: "Audit logging check", domain: "COMPLIANCE" },
      { queryId: "aws.exposure.public_databases", title: "Public database exposure", domain: "EXPOSURE" },
    ],
  },
  {
    packId: "azure-posture-core", provider: "AZURE", title: "Azure core posture",
    queries: [
      { queryId: "azure.posture.public_storage", title: "Public storage check", domain: "COMPLIANCE" },
      { queryId: "azure.exposure.public_services", title: "Public service exposure", domain: "EXPOSURE" },
    ],
  },
  {
    packId: "gcp-posture-core", provider: "GCP", title: "GCP core posture",
    queries: [
      { queryId: "gcp.posture.public_storage", title: "Public storage check", domain: "COMPLIANCE" },
      { queryId: "gcp.posture.audit_logging", title: "Audit logging check", domain: "COMPLIANCE" },
    ],
  },
];

export interface SteampipeQueryDecision {
  allowed: boolean;
  reason?: string;
  pack?: SteampipeApprovedPack;
  query?: SteampipeApprovedQuery;
}

/** §25 gate: only catalog pack + query ids may run. Anything else —
 *  above all raw SQL — is rejected as data, never executed. */
export function evaluateSteampipeQueryRequest(input: {
  packId?: string;
  queryId?: string;
  rawSql?: string;
}): SteampipeQueryDecision {
  if (input.rawSql && input.rawSql.trim().length > 0) {
    return { allowed: false, reason: "Raw SQL is never accepted — Steampipe runs platform-approved query packs only (§25)." };
  }
  const pack = APPROVED_STEAMPIPE_PACKS.find((p) => p.packId === input.packId);
  if (!pack) return { allowed: false, reason: `Unknown Steampipe pack "${input.packId ?? ""}" — only approved packs may run (§24/§25).` };
  const query = pack.queries.find((q) => q.queryId === input.queryId);
  if (!query) return { allowed: false, reason: `Query "${input.queryId ?? ""}" is not in approved pack ${pack.packId} (§24).` };
  return { allowed: true, pack, query };
}

/* ---------------- CloudMapper-style exposure graph (§23) ---------------- */

export interface CloudExposureGraphNode {
  id: string;
  kind: "INTERNET" | "RESOURCE";
  label: string;
  resourceType?: string;
  exposure?: string;
}

export interface CloudExposureGraphEdge {
  from: string;
  to: string;
  relationship: "EXPOSES" | "ROUTES_TO";
  evidence: string;
}

/**
 * Build the defensive exposure graph: an INTERNET node, one node per
 * inventoried resource, EXPOSES edges for publicly exposed resources
 * and ROUTES_TO edges where a network resource (load balancer /
 * firewall / security group) declares routes to a target resource.
 * Pure visualization data over existing inventory — no probing, no
 * exploitation (§23).
 */
export function buildCloudExposureGraph(resources: NormalizedCloudResource[]): {
  nodes: CloudExposureGraphNode[];
  edges: CloudExposureGraphEdge[];
} {
  const nodes: CloudExposureGraphNode[] = [{ id: "internet", kind: "INTERNET", label: "Internet" }];
  const edges: CloudExposureGraphEdge[] = [];
  for (const r of resources) nodes.push({ id: r.providerResourceId, kind: "RESOURCE", label: r.name, resourceType: r.resourceType, exposure: r.exposure });
  const ids = new Set(resources.map((r) => r.providerResourceId));
  for (const r of resources) {
    if (r.exposure === "PUBLIC" || r.exposure === "INTERNET_REACHABLE_POSSIBLE") {
      edges.push({ from: "internet", to: r.providerResourceId, relationship: "EXPOSES", evidence: `inventory exposure=${r.exposure} (§34)` });
    }
    const routes = (r.configuration as Record<string, unknown>)?.routesTo;
    if (Array.isArray(routes)) {
      for (const target of routes) {
        if (typeof target === "string" && ids.has(target)) {
          edges.push({ from: r.providerResourceId, to: target, relationship: "ROUTES_TO", evidence: "network configuration: routesTo (§34)" });
        }
      }
    }
  }
  return { nodes, edges };
}
