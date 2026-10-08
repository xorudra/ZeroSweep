import { sha256Hex } from "../identity/crypto";

/**
 * Security graph analytics + attack-path candidates
 * (Prompt 27 §81–§87).
 *
 * Graph queries are BOUNDED (depth / node / edge limits, §82) — an
 * excessive request is rejected, not served partially in silence.
 * Attack paths are ANALYTICAL correlation over known relationships
 * and findings (§83/§84): every edge references observed evidence
 * (§86) and NOTHING here executes or plans exploitation (§148).
 */

export interface AnalyticsGraphNode { id: string; kind: string; label: string }
export interface AnalyticsGraphEdge { from: string; to: string; relation: string; evidenceType: string; evidenceId: string }

export const GRAPH_LIMITS = { maxDepth: 4, maxNodes: 200, maxEdges: 500 } as const;

export interface TraverseResult {
  nodes: AnalyticsGraphNode[];
  edges: AnalyticsGraphEdge[];
  truncated: false;
}
export type TraverseOutcome = TraverseResult | { rejected: string };

export function traverseGraph(
  nodes: readonly AnalyticsGraphNode[], edges: readonly AnalyticsGraphEdge[], startId: string,
  opts: { maxDepth?: number; maxNodes?: number; maxEdges?: number } = {},
): TraverseOutcome {
  const maxDepth = opts.maxDepth ?? GRAPH_LIMITS.maxDepth;
  const maxNodes = opts.maxNodes ?? GRAPH_LIMITS.maxNodes;
  const maxEdges = opts.maxEdges ?? GRAPH_LIMITS.maxEdges;
  if (maxDepth > GRAPH_LIMITS.maxDepth) return { rejected: `depth ${maxDepth} exceeds limit ${GRAPH_LIMITS.maxDepth} (§82/§139)` };
  if (maxNodes > GRAPH_LIMITS.maxNodes) return { rejected: `node limit ${maxNodes} exceeds ${GRAPH_LIMITS.maxNodes} (§82)` };
  if (maxEdges > GRAPH_LIMITS.maxEdges) return { rejected: `edge limit ${maxEdges} exceeds ${GRAPH_LIMITS.maxEdges} (§82)` };
  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  if (!nodeById.has(startId)) return { nodes: [], edges: [], truncated: false };
  const adjacency = new Map<string, AnalyticsGraphEdge[]>();
  for (const e of edges) {
    (adjacency.get(e.from) ?? adjacency.set(e.from, []).get(e.from)!).push(e);
    (adjacency.get(e.to) ?? adjacency.set(e.to, []).get(e.to)!).push(e);
  }
  const visited = new Set<string>([startId]);
  const usedEdges: AnalyticsGraphEdge[] = [];
  let frontier = [startId];
  for (let depth = 0; depth < maxDepth && frontier.length; depth++) {
    const nextFrontier: string[] = [];
    for (const id of frontier) {
      for (const e of adjacency.get(id) ?? []) {
        if (usedEdges.length >= maxEdges) return { rejected: `traversal exceeds edge limit ${maxEdges} (§82/§139)` };
        const other = e.from === id ? e.to : e.from;
        if (!usedEdges.includes(e)) usedEdges.push(e);
        if (!visited.has(other)) {
          if (visited.size >= maxNodes) return { rejected: `traversal exceeds node limit ${maxNodes} (§82/§139)` };
          visited.add(other);
          nextFrontier.push(other);
        }
      }
    }
    frontier = nextFrontier;
  }
  return {
    nodes: [...visited].map((id) => nodeById.get(id)!).filter(Boolean),
    edges: usedEdges.filter((e) => visited.has(e.from) && visited.has(e.to)),
    truncated: false,
  };
}

/* ------------------------- attack paths (§83–§87) ------------------------- */

export interface AttackPathNodeRef { kind: string; id: string; label: string }
export interface AttackPathEdgeRef { from: string; to: string; evidenceType: string; evidenceId: string }

export interface AttackPathInput {
  /** The public entry asset. */
  entry: { assetId: string; label: string; criticality: string; dataSensitivity?: string | null };
  /** The finding that makes the entry exploitable-in-analysis (never executed). */
  finding: { id: string; title: string; severity: string; riskScore: number | null; verificationStatus: string; cve?: string | null };
  /** Optional downstream asset reached via a known relationship edge. */
  downstream?: { assetId: string; label: string; criticality: string; dataSensitivity?: string | null; relationEvidenceId: string } | null;
}

const CRITICALITY_SCORE: Record<string, number> = { CRITICAL: 15, HIGH: 11, MEDIUM: 7, LOW: 3, UNSPECIFIED: 0 };
const SENSITIVITY_SCORE: Record<string, number> = { RESTRICTED: 10, CONFIDENTIAL: 7, INTERNAL: 3, PUBLIC: 0 };

/**
 * §85 scoring (documented, deterministic, 0–100):
 *   finding risk (riskScore, else severity-derived base) × 0.40
 * + internet exposure of the entry point          +20 (by construction of the input)
 * + entry criticality                              +0..15
 * + downstream sensitivity (when a backend exists) +0..10
 * + verified finding                               +10
 * − path-length penalty                            −2 per hop beyond 2 nodes
 * Confidence mirrors evidence completeness: verified finding +
 * relationship evidence = HIGH; verified only = MEDIUM; else LOW.
 */
export function scoreAttackPath(input: AttackPathInput): { score: number; confidence: "LOW" | "MEDIUM" | "HIGH"; nodes: AttackPathNodeRef[]; edges: AttackPathEdgeRef[]; fingerprint: string; title: string } {
  const severityBase = { CRITICAL: 95, HIGH: 80, MEDIUM: 55, LOW: 30, INFO: 10 }[input.finding.severity] ?? 40;
  const risk = input.finding.riskScore ?? severityBase;
  const verified = input.finding.verificationStatus === "CONFIRMED";
  const nodes: AttackPathNodeRef[] = [
    { kind: "INTERNET", id: "internet", label: "Internet" },
    { kind: "ASSET", id: input.entry.assetId, label: input.entry.label },
    { kind: "FINDING", id: input.finding.id, label: input.finding.title },
  ];
  const edges: AttackPathEdgeRef[] = [
    { from: "internet", to: input.entry.assetId, evidenceType: "ASSET_EXPOSURE", evidenceId: input.entry.assetId },
    { from: input.entry.assetId, to: input.finding.id, evidenceType: "FINDING", evidenceId: input.finding.id },
  ];
  if (input.downstream) {
    nodes.push({ kind: "ASSET", id: input.downstream.assetId, label: input.downstream.label });
    edges.push({ from: input.entry.assetId, to: input.downstream.assetId, evidenceType: "ASSET_RELATIONSHIP", evidenceId: input.downstream.relationEvidenceId });
  }
  let score = risk * 0.4 + 20 + (CRITICALITY_SCORE[input.entry.criticality] ?? 0) + (verified ? 10 : 0);
  if (input.downstream) score += SENSITIVITY_SCORE[input.downstream.dataSensitivity ?? ""] ?? 0;
  score -= Math.max(0, nodes.length - 2) * 2;
  score = Math.round(Math.max(0, Math.min(100, score)) * 10) / 10;
  const confidence: "LOW" | "MEDIUM" | "HIGH" = verified && input.downstream ? "HIGH" : verified ? "MEDIUM" : "LOW";
  const fingerprint = sha256Hex([input.entry.assetId, input.finding.id, input.downstream?.assetId ?? ""].join("|"));
  const title = `Internet → ${input.entry.label} → ${input.finding.title}${input.downstream ? ` → ${input.downstream.label}` : ""}`;
  return { score, confidence, nodes, edges, fingerprint, title };
}
