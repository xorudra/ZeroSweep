import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  scoreAttackPath, traverseGraph, type AnalyticsGraphEdge, type AnalyticsGraphNode,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { deriveExposure } from "../../continuous-security/snapshots/snapshot.service";

/**
 * Security graph analytics + attack-path candidates (§81–§87).
 *
 * The graph is assembled from KNOWN relationships only: asset →
 * service, asset → finding, repository → image-bearing finding,
 * asset → same-network asset. Every edge carries an evidence
 * reference (§86). Traversal is bounded by the SDK limits (§82) and
 * attack paths are analytical candidates — read-only output, never
 * an exploitation plan (§83/§148).
 */
@Injectable()
export class GraphService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async buildGraph(workspaceId: string): Promise<{ nodes: AnalyticsGraphNode[]; edges: AnalyticsGraphEdge[] }> {
    const [assets, services, findings] = await Promise.all([
      this.prisma.asset.findMany({ where: { workspaceId }, take: 5000 }),
      this.prisma.service.findMany({ take: 10_000 }),
      this.prisma.finding.findMany({ where: { workspaceId }, take: 10_000 }),
    ]);
    const assetIds = new Set(assets.map((a) => a.id));
    const nodes: AnalyticsGraphNode[] = [{ id: "internet", kind: "INTERNET", label: "Internet" }];
    const edges: AnalyticsGraphEdge[] = [];
    for (const a of assets) {
      nodes.push({ id: a.id, kind: "ASSET", label: a.host });
      if (deriveExposure(a.ip) === "INTERNET_FACING") {
        edges.push({ from: "internet", to: a.id, relation: "EXPOSES", evidenceType: "ASSET_EXPOSURE", evidenceId: a.id });
      }
    }
    for (const s of services) {
      if (!assetIds.has(s.assetId)) continue;
      const id = `svc:${s.id}`;
      nodes.push({ id, kind: "SERVICE", label: `${s.name ?? "service"}:${s.port}/${s.protocol}` });
      edges.push({ from: s.assetId, to: id, relation: "RUNS_SERVICE", evidenceType: "SERVICE", evidenceId: s.id });
    }
    for (const f of findings) {
      if (!f.assetId || !assetIds.has(f.assetId)) continue;
      nodes.push({ id: `fnd:${f.id}`, kind: "FINDING", label: f.title });
      edges.push({ from: f.assetId, to: `fnd:${f.id}`, relation: "HAS_FINDING", evidenceType: "FINDING", evidenceId: f.id });
      if (f.repositoryId) {
        const repoNode = `repo:${f.repositoryId}`;
        if (!nodes.some((n) => n.id === repoNode)) nodes.push({ id: repoNode, kind: "REPOSITORY", label: f.repositoryId });
        edges.push({ from: repoNode, to: `fnd:${f.id}`, relation: "INTRODUCED", evidenceType: "FINDING_REPOSITORY", evidenceId: f.id });
      }
      if (f.imageDigest) {
        const imgNode = `img:${f.imageDigest}`;
        if (!nodes.some((n) => n.id === imgNode)) nodes.push({ id: imgNode, kind: "IMAGE", label: f.imageRef ?? f.imageDigest.slice(0, 19) });
        edges.push({ from: imgNode, to: `fnd:${f.id}`, relation: "HAS_VULNERABILITY", evidenceType: "FINDING_IMAGE", evidenceId: f.id });
        edges.push({ from: f.assetId, to: imgNode, relation: "RUNS_IMAGE", evidenceType: "FINDING_IMAGE", evidenceId: f.id });
      }
    }
    // Same-network asset relationships (observed inventory fact).
    const byNetwork = new Map<string, string[]>();
    for (const a of assets) if (a.network) byNetwork.set(a.network, [...(byNetwork.get(a.network) ?? []), a.id]);
    for (const [network, ids] of byNetwork) {
      for (let i = 0; i < ids.length; i++) {
        for (let j = i + 1; j < ids.length; j++) {
          edges.push({ from: ids[i]!, to: ids[j]!, relation: "SAME_NETWORK", evidenceType: "ASSET_NETWORK", evidenceId: network });
        }
      }
    }
    return { nodes, edges };
  }

  async traverse(workspaceId: string, startId: string, opts: { maxDepth?: number } = {}) {
    const graph = await this.buildGraph(workspaceId);
    const result = traverseGraph(graph.nodes, graph.edges, startId, opts);
    if ("rejected" in result) return { rejected: result.rejected, nodes: [], edges: [] };
    return result;
  }

  /**
   * Generate attack-path candidates: internet-facing entry assets
   * with CRITICAL/HIGH findings, optionally extended to a sensitive
   * same-network backend. Candidates are upserted by fingerprint;
   * previously seen candidates that no longer match become REMOVED
   * so "when did this path first appear / when was it removed" is
   * answerable from history (§87).
   */
  async generateAttackPaths(workspaceId: string): Promise<{ created: number; updated: number; removed: number; total: number }> {
    const [assets, findings] = await Promise.all([
      this.prisma.asset.findMany({ where: { workspaceId }, take: 5000 }),
      this.prisma.finding.findMany({ where: { workspaceId }, take: 10_000 }),
    ]);
    const assetById = new Map(assets.map((a) => [a.id, a]));
    const seen = new Set<string>();
    let created = 0; let updated = 0;
    for (const f of findings) {
      if (!f.assetId) continue;
      if (f.severity !== "CRITICAL" && f.severity !== "HIGH") continue;
      if (["RESOLVED", "REMEDIATED", "CLOSED", "FALSE_POSITIVE"].includes(f.lifecycleStatus)) continue;
      const entry = assetById.get(f.assetId);
      if (!entry || deriveExposure(entry.ip) !== "INTERNET_FACING") continue;
      // Downstream: a same-network asset carrying sensitive findings.
      let downstream: { assetId: string; label: string; criticality: string; dataSensitivity?: string | null; relationEvidenceId: string } | null = null;
      if (entry.network) {
        const candidate = assets.find((a) => a.id !== entry.id && a.network === entry.network
          && findings.some((x) => x.assetId === a.id && (x.dataSensitivity === "CONFIDENTIAL" || x.dataSensitivity === "RESTRICTED")));
        if (candidate) {
          const sensitive = findings.find((x) => x.assetId === candidate.id && (x.dataSensitivity === "CONFIDENTIAL" || x.dataSensitivity === "RESTRICTED"));
          downstream = {
            assetId: candidate.id, label: candidate.host, criticality: candidate.criticality,
            dataSensitivity: sensitive?.dataSensitivity ?? null, relationEvidenceId: entry.network,
          };
        }
      }
      const scored = scoreAttackPath({
        entry: { assetId: entry.id, label: entry.host, criticality: entry.criticality },
        finding: { id: f.id, title: f.title, severity: f.severity, riskScore: f.riskScore, verificationStatus: f.verificationStatus, cve: f.cve },
        downstream,
      });
      seen.add(scored.fingerprint);
      const existing = await this.prisma.attackPathCandidate.findFirst({
        where: { workspaceId, fingerprint: scored.fingerprint },
      });
      const data = {
        title: scored.title, score: scored.score, confidence: scored.confidence, status: "ACTIVE",
        nodes: scored.nodes as never, edges: scored.edges as never,
        assetId: entry.id, findingId: f.id, lastSeenAt: new Date(),
      };
      if (existing) { await this.prisma.attackPathCandidate.update({ where: { id: existing.id }, data }); updated++; }
      else {
        await this.prisma.attackPathCandidate.create({ data: { workspaceId, fingerprint: scored.fingerprint, ...data } });
        created++;
      }
    }
    const active = await this.prisma.attackPathCandidate.findMany({ where: { workspaceId, status: "ACTIVE" }, take: 5000 });
    let removed = 0;
    for (const path of active) {
      if (!seen.has(path.fingerprint)) {
        await this.prisma.attackPathCandidate.update({ where: { id: path.id }, data: { status: "REMOVED" } });
        removed++;
      }
    }
    return { created, updated, removed, total: seen.size };
  }

  async listAttackPaths(workspaceId: string, status?: string) {
    const items = await this.prisma.attackPathCandidate.findMany({
      where: { workspaceId, ...(status ? { status } : {}) } as never,
      orderBy: { score: "desc" }, take: 500,
    });
    return { items, total: items.length };
  }

  async getAttackPath(workspaceId: string, id: string) {
    const path = await this.prisma.attackPathCandidate.findFirst({ where: { id, workspaceId } });
    if (!path) throw new NotFoundException("Attack path candidate not found");
    return path;
  }
}
