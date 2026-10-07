/**
 * Prompt 15 — IdentityGraphService + AdAttackPathService + blast
 * radius (§27/§32–§37/§65/§75/§76/§108).
 *
 * The graph is built ONLY from collected, evidence-backed
 * relationships (§33): no edge is ever inferred from naming,
 * probability or a tool's raw reachability claim alone. Attack paths
 * are ANALYSIS RESULTS over that graph — computed, explained, and
 * never executed (§34). Traversal is bounded (maxGraphDepth,
 * maxAttackPaths, visited sets): cyclic group nesting (Group A →
 * Group B → Group A, §108) terminates by construction.
 */
import type { DirectoryBudget } from "./types";
import { clampDirectoryBudget, isPrivilegedGroup } from "./types";
import type {
  NormalizedDirectoryComputer, NormalizedDirectoryData, NormalizedDirectoryGroup,
  NormalizedDirectoryRelationship, NormalizedDirectoryUser,
} from "./types";

export interface IdentityGraphNode {
  key: string; // `${type}:${ref}`
  type: string;
  ref: string;
  label: string;
  privileged?: boolean;
  critical?: boolean;
}

export interface IdentityGraph {
  nodes: Map<string, IdentityGraphNode>;
  /** Adjacency: fromKey → edges (direction of privilege flow: the
   *  FROM node gains the TO node's rights for MEMBER_OF/PRIVILEGE
   *  edges; ACL edges point principal → object). */
  edges: NormalizedDirectoryRelationship[];
  out: Map<string, NormalizedDirectoryRelationship[]>;
  into: Map<string, NormalizedDirectoryRelationship[]>;
}

export function nodeKey(type: string, ref: string): string {
  return `${type}:${ref}`;
}

/** Privilege-bearing relationships (§32): edges along which effective
 *  access propagates. TRUST/GPO_LINK/HAS_SESSION are modeled but do
 *  not by themselves propagate privilege. */
export const PRIVILEGE_EDGE_KINDS = new Set([
  "MEMBER_OF", "ADMIN_TO", "CAN_RDP", "CAN_REMOTE_MANAGE", "OWNS",
  "GENERIC_ALL", "GENERIC_WRITE", "WRITE_DACL", "WRITE_OWNER", "DELEGATION",
]);

export function buildIdentityGraph(data: NormalizedDirectoryData, domainRef: string): IdentityGraph {
  const nodes = new Map<string, IdentityGraphNode>();
  const add = (type: string, ref: string, label: string, extra: Partial<IdentityGraphNode> = {}) => {
    const key = nodeKey(type, ref);
    if (!nodes.has(key)) nodes.set(key, { key, type, ref, label, ...extra });
  };
  const privilegedGroups = new Set(
    data.groups.filter((g) => isPrivilegedGroup({ objectId: g.objectId })).map((g) => g.objectId),
  );
  for (const u of data.users) {
    add(u.isServiceAccount ? "SERVICE_ACCOUNT" : "USER", u.objectId, u.displayName ?? u.samAccountName);
  }
  for (const g of data.groups) add("GROUP", g.objectId, g.name, { privileged: privilegedGroups.has(g.objectId) });
  for (const c of data.computers) add("COMPUTER", c.objectId, c.hostname, { critical: c.isDomainController === true });
  for (const dc of data.domainControllers) add("COMPUTER", dc.objectId ?? dc.hostname, dc.hostname, { critical: true });
  for (const ou of data.organizationalUnits) add("OU", ou.objectId, ou.name);
  for (const gpo of data.groupPolicies) add("GPO", gpo.objectId, gpo.name);
  for (const ca of data.certificateAuthorities) add("CERTIFICATE_AUTHORITY", ca.name, ca.name, { critical: true });
  for (const t of data.certificateTemplates) add("CERTIFICATE_TEMPLATE", t.objectId ?? t.name, t.name);
  add("DOMAIN", domainRef, domainRef, { critical: true });

  const out = new Map<string, NormalizedDirectoryRelationship[]>();
  const into = new Map<string, NormalizedDirectoryRelationship[]>();
  const push = (map: Map<string, NormalizedDirectoryRelationship[]>, key: string, e: NormalizedDirectoryRelationship) => {
    const list = map.get(key) ?? [];
    list.push(e);
    map.set(key, list);
  };
  for (const e of data.relationships) {
    // Ensure endpoint nodes exist even when the collection carried an
    // edge to an object outside the object lists (§33 provenance kept).
    add(e.fromType, e.fromRef, e.fromRef);
    add(e.toType, e.toRef, e.toRef);
    push(out, nodeKey(e.fromType, e.fromRef), e);
    push(into, nodeKey(e.toType, e.toRef), e);
  }
  return { nodes, edges: data.relationships, out, into };
}

// ── Nested group resolution (§65) ────────────────────────────────────

export interface GroupResolution {
  /** groupRef → set of principal refs with effective membership. */
  effectiveMembers: Map<string, Set<string>>;
  /** principalRef → set of groupRefs it effectively belongs to. */
  principalGroups: Map<string, Set<string>>;
  cyclesDetected: number;
  truncatedExpansions: number;
}

const MAX_GROUP_EXPANSION = 100000;

/**
 * Resolve nested group membership (§65) with cycle + depth +
 * expansion protection (§108): a Group A → Group B → Group A cycle
 * terminates (visited-set fixpoint), nesting deeper than maxDepth is
 * cut and counted, and pathological expansions are capped. Membership
 * propagates principal → group only along MEMBER_OF edges.
 */
export function resolveNestedGroups(
  graph: IdentityGraph,
  groups: NormalizedDirectoryGroup[],
  opts: { maxDepth?: number } = {},
): GroupResolution {
  const maxDepth = Math.min(Math.max(opts.maxDepth ?? 10, 1), 32);
  const groupRefs = new Set(groups.map((g) => g.objectId));
  // Direct members per group.
  const direct = new Map<string, Set<string>>();
  for (const e of graph.edges) {
    if (e.relationship !== "MEMBER_OF" || e.toType !== "GROUP") continue;
    const set = direct.get(e.toRef) ?? new Set<string>();
    set.add(e.fromRef);
    direct.set(e.toRef, set);
  }
  const effectiveMembers = new Map<string, Set<string>>();
  let cyclesDetected = 0;
  let truncatedExpansions = 0;
  for (const groupRef of groupRefs) {
    const members = new Set<string>();
    // Iterative DFS with per-path depth + global visited groups.
    const stack: { ref: string; depth: number }[] = [{ ref: groupRef, depth: 0 }];
    const visitedGroups = new Set<string>([groupRef]);
    while (stack.length > 0) {
      const { ref, depth } = stack.pop()!;
      for (const member of direct.get(ref) ?? []) {
        if (groupRefs.has(member)) {
          if (visitedGroups.has(member)) { cyclesDetected++; continue; }
          if (depth + 1 > maxDepth) { truncatedExpansions++; continue; }
          visitedGroups.add(member);
          stack.push({ ref: member, depth: depth + 1 });
        } else {
          members.add(member);
          if (members.size > MAX_GROUP_EXPANSION) { truncatedExpansions++; break; }
        }
      }
    }
    effectiveMembers.set(groupRef, members);
  }
  const principalGroups = new Map<string, Set<string>>();
  for (const [groupRef, members] of effectiveMembers) {
    for (const m of members) {
      const set = principalGroups.get(m) ?? new Set<string>();
      set.add(groupRef);
      principalGroups.set(m, set);
    }
  }
  return { effectiveMembers, principalGroups, cyclesDetected, truncatedExpansions };
}

/** Principals with effective privileged access (§64): direct or nested
 *  membership in a privileged/high-impact group, or a high-impact ACL
 *  edge onto a privileged group / domain / DC. Evidence is recorded per
 *  principal so the finding layer never asserts without provenance. */
export function privilegedPrincipals(
  data: NormalizedDirectoryData,
  graph: IdentityGraph,
  resolution: GroupResolution,
): Map<string, { via: string[]; groups: string[] }> {
  const out = new Map<string, { via: string[]; groups: string[] }>();
  const privilegedGroups = data.groups.filter((g) => isPrivilegedGroup({ objectId: g.objectId }));
  for (const g of privilegedGroups) {
    for (const member of resolution.effectiveMembers.get(g.objectId) ?? []) {
      const rec = out.get(member) ?? { via: [], groups: [] };
      rec.via.push(`member of ${g.name} (${g.objectId})`);
      rec.groups.push(g.objectId);
      out.set(member, rec);
    }
  }
  const criticalRefs = new Set<string>([
    ...privilegedGroups.map((g) => g.objectId),
    ...(data.domain?.domainSid ? [data.domain.domainSid] : []),
    ...data.computers.filter((c) => c.isDomainController).map((c) => c.objectId),
  ]);
  for (const e of graph.edges) {
    if (!["GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "OWNS"].includes(e.relationship)) continue;
    if (!criticalRefs.has(e.toRef)) continue;
    if (e.fromType === "GROUP" && isPrivilegedGroup({ objectId: e.fromRef })) continue;
    const rec = out.get(e.fromRef) ?? { via: [], groups: [] };
    rec.via.push(`${e.relationship} over ${e.toType} ${e.toRef} (source ${e.source})`);
    out.set(e.fromRef, rec);
  }
  return out;
}

// ── Attack-path analysis (§34–§37) ───────────────────────────────────

export interface AttackPathStep {
  kind: string; // node type
  ref: string;
  label: string;
  via?: string; // the relationship that led here
}

export interface AdAttackPathResult {
  title: string;
  steps: AttackPathStep[];
  status: "THEORETICAL" | "EVIDENCE_BACKED";
  confidence: "LOW" | "MEDIUM" | "HIGH";
  riskScore: number;
  riskFactors: Record<string, number | string>;
  startRef: string;
  targetRef: string;
}

const HIGH_VALUE_TYPES = new Set(["DOMAIN", "CERTIFICATE_AUTHORITY"]);

/** Whether a graph node is a high-value target (§73): domain
 *  controllers and PKI by default, the domain itself, and privileged
 *  groups (reaching one IS reaching administrative control). */
function isHighValueTarget(node: IdentityGraphNode, data: NormalizedDirectoryData): boolean {
  if (HIGH_VALUE_TYPES.has(node.type)) return true;
  if (node.type === "GROUP") return isPrivilegedGroup({ objectId: node.ref });
  if (node.type === "COMPUTER") return node.critical === true;
  return false;
}

/**
 * Compute defensive attack paths (§34): bounded BFS from every
 * non-privileged principal over PRIVILEGE edges to high-value targets.
 * Every step is an evidence-backed edge from the collection (§33);
 * status is EVIDENCE_BACKED when all edges are HIGH confidence,
 * THEORETICAL otherwise — NEVER COMPROMISED (§35). Risk (§37) weighs
 * target criticality, path privilege, confidence and length (shorter
 * is worse, but never the only factor). Bounded by budget (§87):
 * traversal stops at maxGraphDepth and returns at most maxAttackPaths.
 */
export function findAttackPaths(
  data: NormalizedDirectoryData,
  graph: IdentityGraph,
  resolution: GroupResolution,
  budgetInput: Partial<DirectoryBudget> = {},
  domainRef = "",
): AdAttackPathResult[] {
  const budget = clampDirectoryBudget(budgetInput);
  const privileged = privilegedPrincipals(data, graph, resolution);
  const targets = new Map<string, IdentityGraphNode>();
  for (const node of graph.nodes.values()) {
    if (isHighValueTarget(node, data)) targets.set(node.key, node);
  }
  const userByRef = new Map<string, NormalizedDirectoryUser>(data.users.map((u) => [u.objectId, u]));
  const computerByRef = new Map<string, NormalizedDirectoryComputer>(data.computers.map((c) => [c.objectId, c]));

  // Reverse adjacency over privilege edges: from a target, walk to the
  // principals that can REACH it (edge direction = privilege flow).
  const reversePrivilege = new Map<string, { fromKey: string; via: string; confidence: string }[]>();
  for (const e of graph.edges) {
    if (!PRIVILEGE_EDGE_KINDS.has(e.relationship)) continue;
    const toKey = nodeKey(e.toType, e.toRef);
    const fromKey = nodeKey(e.fromType, e.fromRef);
    const list = reversePrivilege.get(toKey) ?? [];
    list.push({ fromKey, via: e.relationship, confidence: e.confidence });
    reversePrivilege.set(toKey, list);
  }

  const paths: AdAttackPathResult[] = [];
  const seenPathKeys = new Set<string>();
  for (const target of targets.values()) {
    // BFS from the target backwards; each frontier node that is a
    // principal (user/service account/computer not already privileged
    // by definition of the target set) yields one path.
    const visited = new Map<string, { prevKey: string; via: string; confidence: string; depth: number }>();
    const queue: string[] = [target.key];
    visited.set(target.key, { prevKey: "", via: "", confidence: "HIGH", depth: 0 });
    while (queue.length > 0 && paths.length < budget.maxAttackPaths) {
      const current = queue.shift()!;
      const curMeta = visited.get(current)!;
      if (curMeta.depth >= budget.maxGraphDepth) continue;
      for (const step of reversePrivilege.get(current) ?? []) {
        if (visited.has(step.fromKey)) continue;
        visited.set(step.fromKey, { prevKey: current, via: step.via, confidence: step.confidence, depth: curMeta.depth + 1 });
        queue.push(step.fromKey);
        const startNode = graph.nodes.get(step.fromKey);
        if (!startNode) continue;
        // A path start is an identity principal that is not itself a
        // high-value target and not already counted as the target.
        if (targets.has(step.fromKey)) continue;
        if (!["USER", "SERVICE_ACCOUNT", "COMPUTER", "GROUP"].includes(startNode.type)) continue;
        if (startNode.type === "GROUP" && isPrivilegedGroup({ objectId: startNode.ref })) continue;
        // Reconstruct steps start → target.
        const chain: AttackPathStep[] = [];
        let cursor = step.fromKey;
        const confs: string[] = [];
        while (cursor) {
          const meta = visited.get(cursor)!;
          const node = graph.nodes.get(cursor)!;
          chain.push({
            kind: node.type, ref: node.ref, label: node.label,
            ...(meta.via ? { via: meta.via } : {}),
          });
          if (meta.confidence) confs.push(meta.confidence);
          cursor = meta.prevKey;
        }
        const pathKey = chain.map((s) => s.ref).join(">");
        if (seenPathKeys.has(pathKey)) continue;
        seenPathKeys.add(pathKey);
        const allHigh = confs.every((c) => c === "HIGH");
        const confidence: AdAttackPathResult["confidence"] = allHigh ? "HIGH" : confs.includes("LOW") ? "LOW" : "MEDIUM";
        // §37 risk factors — explained, never length alone.
        const startUser = userByRef.get(startNode.ref);
        const factors: Record<string, number | string> = {
          pathLength: chain.length - 1,
          targetCriticality: target.type === "DOMAIN" ? 40 : target.critical ? 35 : 25,
          privilegeGain: target.type === "GROUP" || target.type === "DOMAIN" ? 30 : 20,
          confidenceFactor: confidence === "HIGH" ? 15 : confidence === "MEDIUM" ? 8 : 3,
          lengthFactor: Math.max(0, 12 - (chain.length - 1) * 2),
          startAlreadyPrivileged: privileged.has(startNode.ref) ? "start principal already holds separate privileged access" : "none",
          startEnabled: startUser ? String(startUser.enabled) : (computerByRef.get(startNode.ref) ? String(computerByRef.get(startNode.ref)!.enabled) : "unknown"),
        };
        const riskScore = Math.min(100, Math.round(
          (factors.targetCriticality as number) + (factors.privilegeGain as number)
          + (factors.confidenceFactor as number) + (factors.lengthFactor as number),
        ));
        paths.push({
          title: `${startNode.label} can reach ${target.label} in ${chain.length - 1} step(s) — analysis only, never executed`,
          steps: chain,
          status: allHigh ? "EVIDENCE_BACKED" : "THEORETICAL",
          confidence,
          riskScore,
          riskFactors: { ...factors, domain: domainRef },
          startRef: startNode.ref,
          targetRef: target.ref,
        });
        if (paths.length >= budget.maxAttackPaths) break;
      }
    }
    if (paths.length >= budget.maxAttackPaths) break;
  }
  return paths.sort((a, b) => b.riskScore - a.riskScore);
}

// ── Blast radius (§75/§76) ───────────────────────────────────────────

export interface BlastRadiusResult {
  principalRef: string;
  /** Nodes reachable via privilege edges, with the path evidence. */
  reachable: { ref: string; type: string; label: string; viaPath: string[] }[];
  privilegedGroupsReached: string[];
  computersAdministered: string[];
  highValueTargetsReached: string[];
  /** §76: the mandatory framing — reachability is not compromise. */
  framing: string;
}

export const BLAST_RADIUS_FRAMING = "Blast radius is computed from collected relationship EVIDENCE: it shows what the principal could reach if every recorded relationship were exercised. It does not imply the principal is compromised, and no access was attempted (§76).";

/** IdentityBlastRadiusService (§75): forward reachability over
 *  privilege edges, bounded and cycle-safe. */
export function computeBlastRadius(
  data: NormalizedDirectoryData,
  graph: IdentityGraph,
  principalRef: string,
  budgetInput: Partial<DirectoryBudget> = {},
): BlastRadiusResult {
  const budget = clampDirectoryBudget(budgetInput);
  const startNode = [...graph.nodes.values()].find((n) => n.ref === principalRef);
  const reachable: BlastRadiusResult["reachable"] = [];
  if (!startNode) {
    return { principalRef, reachable, privilegedGroupsReached: [], computersAdministered: [], highValueTargetsReached: [], framing: BLAST_RADIUS_FRAMING };
  }
  const visited = new Map<string, string[]>();
  visited.set(startNode.key, [startNode.label]);
  const queue: { key: string; depth: number }[] = [{ key: startNode.key, depth: 0 }];
  while (queue.length > 0) {
    const { key, depth } = queue.shift()!;
    if (depth >= budget.maxGraphDepth) continue;
    for (const e of graph.out.get(key) ?? []) {
      if (!PRIVILEGE_EDGE_KINDS.has(e.relationship)) continue;
      const toKey = nodeKey(e.toType, e.toRef);
      if (visited.has(toKey)) continue;
      const viaPath = [...(visited.get(key) ?? []), `${e.relationship} → ${graph.nodes.get(toKey)?.label ?? e.toRef}`];
      visited.set(toKey, viaPath);
      queue.push({ key: toKey, depth: depth + 1 });
    }
  }
  const privilegedGroupsReached: string[] = [];
  const computersAdministered: string[] = [];
  const highValueTargetsReached: string[] = [];
  for (const [key, viaPath] of visited) {
    if (key === startNode.key) continue;
    const node = graph.nodes.get(key)!;
    reachable.push({ ref: node.ref, type: node.type, label: node.label, viaPath });
    if (node.type === "GROUP" && isPrivilegedGroup({ objectId: node.ref })) privilegedGroupsReached.push(node.ref);
    if (node.type === "COMPUTER") {
      const inbound = graph.into.get(key) ?? [];
      if (inbound.some((e) => e.relationship === "ADMIN_TO" && visited.has(nodeKey(e.fromType, e.fromRef)))) computersAdministered.push(node.ref);
      if (node.critical) highValueTargetsReached.push(node.ref);
    }
    if (node.type === "DOMAIN" || node.type === "CERTIFICATE_AUTHORITY") highValueTargetsReached.push(node.ref);
  }
  return { principalRef, reachable, privilegedGroupsReached, computersAdministered, highValueTargetsReached, framing: BLAST_RADIUS_FRAMING };
}
