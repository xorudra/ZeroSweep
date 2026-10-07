import type { CanonicalFindingView } from "./types";

/**
 * FindingCorrelationEngine (Prompt 20 §14–§18).
 *
 * Correlation LINKS findings; it never destructively merges them. The
 * only merge in the platform is exact fingerprint dedup (§13). Rules:
 *  - same canonical fingerprint (cross-tool) → DUPLICATE relationship
 *    is already represented by the canonical finding itself; here,
 *    distinct findings sharing a fingerprint → POTENTIAL_DUPLICATE for
 *    analyst review, never an automatic collapse.
 *  - shared CWE alone → NO relationship (§17: CWE is taxonomy).
 *  - shared CVE across domains → a FindingCluster + intelligence link
 *    (§16/§101), with per-asset remediation state untouched.
 *  - a cross-domain exposure chain (§15/§100): PUBLIC_EXPOSURE (cloud)
 *    EXPOSES a network service on the same host, which EXPOSES a web
 *    finding, whose code/dependency findings are RELATED by root-cause
 *    evidence — the chain is represented, the root causes stay separate.
 *  - title similarity alone produces NOTHING (§14/§114).
 */

export type CorrelationRelationship =
  | "SAME_ROOT_CAUSE" | "RELATED" | "PARENT_CHILD" | "CAUSES" | "EXPOSES" | "DUPLICATE" | "POTENTIAL_DUPLICATE";

export interface CorrelationLink {
  fromFindingId: string;
  toFindingId: string;
  relationship: CorrelationRelationship;
  rationale: string;
}

export interface FindingClusterView {
  key: string;
  kind: "CVE" | "CWE" | "COMPONENT" | "CLOUD_POLICY" | "CONFIG_CLASS";
  label: string;
  findingIds: string[];
}

interface CorrFinding extends CanonicalFindingView {
  fingerprint?: string | null;
  vulnClass?: string | null;
  componentPurl?: string | null;
  providerResourceId?: string | null;
  cloudResourceId?: string | null;
  ruleId?: string | null;
}

const CLOSED = new Set(["RESOLVED", "FALSE_POSITIVE", "DUPLICATE"]);

function sameHost(a: CorrFinding, b: CorrFinding): boolean {
  return !!a.host && !!b.host && a.host.toLowerCase() === b.host.toLowerCase();
}

/**
 * Derive correlation links between a set of canonical findings.
 * Deterministic, pairwise, and conservative: every emitted link carries
 * the evidence-based rationale that produced it.
 */
export function deriveCorrelationLinks(findings: CorrFinding[]): CorrelationLink[] {
  const links: CorrelationLink[] = [];
  const seen = new Set<string>();
  const add = (from: string, to: string, relationship: CorrelationRelationship, rationale: string) => {
    if (from === to) return;
    const key = `${from}|${to}|${relationship}`;
    if (seen.has(key)) return;
    seen.add(key);
    links.push({ fromFindingId: from, toFindingId: to, relationship, rationale });
  };

  for (let i = 0; i < findings.length; i++) {
    for (let j = i + 1; j < findings.length; j++) {
      const a = findings[i]!, b = findings[j]!;

      // Same canonical fingerprint on two distinct rows → a human
      // reviews; the platform never auto-collapses (§13/§14).
      if (a.fingerprint && b.fingerprint && a.fingerprint === b.fingerprint) {
        add(a.id, b.id, "POTENTIAL_DUPLICATE", "identical canonical fingerprint on two canonical rows — analyst review required, never auto-merged (§13)");
        continue;
      }

      // §15 cross-domain exposure chain: cloud public exposure EXPOSES
      // the network/web finding on the same host.
      const aExposure = a.category === "PUBLIC_EXPOSURE";
      const bExposure = b.category === "PUBLIC_EXPOSURE";
      if ((aExposure || bExposure) && sameHost(a, b)) {
        const [expo, other] = aExposure ? [a, b] : [b, a];
        add(expo.id, other.id, "EXPOSES", `public-exposure finding exposes host ${other.host} where ${other.sourceDomain ?? "another engine"} reported a finding (§15)`);
        continue;
      }

      // Same root cause: same rule/check on the same host across two
      // engines (e.g. TLS policy found by network + web) → SAME_ROOT_CAUSE.
      if (a.ruleId && b.ruleId && a.ruleId === b.ruleId && sameHost(a, b) && a.sourceDomain !== b.sourceDomain) {
        add(a.id, b.id, "SAME_ROOT_CAUSE", `same governed rule ${a.ruleId} on host ${a.host} reported by ${a.sourceDomain} and ${b.sourceDomain} (§14)`);
        continue;
      }

      // Vulnerable code (SAST) on an endpoint + the runtime web finding
      // for the same weakness class → RELATED root-cause evidence (§15).
      // Requires shared CWE AND shared host/endpoint context — CWE
      // alone is explicitly not enough (§17).
      if (a.cwe && b.cwe && a.cwe.toUpperCase() === b.cwe.toUpperCase() && sameHost(a, b)) {
        const domains = new Set([a.sourceDomain, b.sourceDomain]);
        if (domains.has("SAST") && (domains.has("WEB") || domains.has("API"))) {
          add(a.id, b.id, "RELATED", `shared ${a.cwe.toUpperCase()} across source and runtime views of host ${a.host} — related evidence, distinct findings (§15/§17)`);
        }
      }
    }
  }
  return links;
}

/**
 * §18/§101 FindingClusters: group WITHOUT merging. A CVE cluster links
 * every asset-specific finding for one CVE; remediation state stays
 * per-finding. CWE clusters are analysis groupings only (§17).
 */
export function buildFindingClusters(findings: CorrFinding[]): FindingClusterView[] {
  const clusters = new Map<string, FindingClusterView>();
  const push = (key: string, kind: FindingClusterView["kind"], label: string, id: string) => {
    let c = clusters.get(key);
    if (!c) { c = { key, kind, label, findingIds: [] }; clusters.set(key, c); }
    if (!c.findingIds.includes(id)) c.findingIds.push(id);
  };
  for (const f of findings) {
    if (CLOSED.has(f.lifecycleStatus)) continue;
    if (f.cve) push(`cve:${f.cve.toUpperCase()}`, "CVE", `${f.cve.toUpperCase()} — one vulnerability, many affected assets (§101)`, f.id);
    else if (f.componentPurl) push(`component:${f.componentPurl.toLowerCase()}`, "COMPONENT", `${f.componentPurl} — shared vulnerable component`, f.id);
    if (f.sourceDomain === "CLOUD" && f.ruleId) {
      push(`cloud-policy:${f.ruleId.toLowerCase()}`, "CLOUD_POLICY", `${f.ruleId} — same cloud policy violation across accounts`, f.id);
    }
    if (f.vulnClass && (f.category === "MISCONFIGURATION" || f.category === "COMPLIANCE_FAILURE")) {
      push(`config:${f.vulnClass.toLowerCase()}`, "CONFIG_CLASS", `${f.vulnClass} — one configuration fix`, f.id);
    }
  }
  return [...clusters.values()].filter((c) => c.findingIds.length >= 2).sort((a, b) => b.findingIds.length - a.findingIds.length);
}

export const FindingCorrelationEngine = { correlate: deriveCorrelationLinks, buildClusters: buildFindingClusters };
