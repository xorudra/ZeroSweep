import { Inject, Injectable } from "@nestjs/common";
import {
  filterRetrievalCandidates, type AiRetrievalCandidate, type AiRetrievalSourceType,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { aiPermissionsHeld, requireAiPermission } from "./permissions";

/**
 * SecurityRetrievalService (Prompt 36 §10–§13). Loads candidate
 * records from the governed domain stores — ALWAYS workspace-scoped
 * at the data layer — then passes them through the SDK permission /
 * ACL / classification filter, the single choke point before any
 * context construction (§16). Sources the user may not read are
 * skipped and DISCLOSED (§21), so answers can state their gaps.
 * Vulnerability intelligence is global reference data: it is only
 * ever attached for CVEs present on THIS workspace's findings, and
 * is labelled with the dataset's real sync state (never fabricated).
 */
@Injectable()
export class AiRetrievalService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  /** Which AI permission gates each retrieval source (§10). */
  private static SOURCE_PERMISSIONS: Partial<Record<AiRetrievalSourceType, string>> = {
    FINDING: "AI_EXPLAIN_FINDING",
    FINDING_OBSERVATION: "AI_EXPLAIN_FINDING",
    EVIDENCE_METADATA: "AI_EXPLAIN_FINDING",
    MOBILE_FINDING: "AI_EXPLAIN_FINDING",
    BINARY_FINDING: "AI_EXPLAIN_FINDING",
    VULNERABILITY_INTEL: "USE_AI_COPILOT",
    ASSET: "USE_AI_COPILOT",
    ASSET_GRAPH: "USE_AI_COPILOT",
    SCAN: "USE_AI_COPILOT",
    COVERAGE: "USE_AI_COPILOT",
    SBOM_COMPONENT: "USE_AI_COPILOT",
    REMEDIATION: "USE_AI_COPILOT",
    VERIFICATION: "USE_AI_COPILOT",
    CLOUD_INVENTORY: "USE_AI_COPILOT",
    CONTAINER_INVENTORY: "USE_AI_COPILOT",
    KUBERNETES_INVENTORY: "USE_AI_COPILOT",
    SOC_ALERT: "USE_AI_COPILOT",
    SOC_INCIDENT: "USE_AI_COPILOT",
    GRC_EVIDENCE: "AI_EXPLAIN_FINDING",
    REPORT: "AI_DRAFT_REPORT",
    DOCUMENTATION: "USE_AI_COPILOT",
  };

  async retrieve(user: RequestUser, workspaceId: string, opts: {
    sourceTypes?: AiRetrievalSourceType[];
    maxRecords?: number;
    classificationCeiling?: "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED" | "SECRET";
  } = {}) {
    requireAiPermission(user, "USE_AI_COPILOT");
    const maxRecords = Math.min(opts.maxRecords ?? 25, 100);
    const wanted = new Set(opts.sourceTypes ?? []);
    const want = (t: AiRetrievalSourceType) => wanted.size === 0 || wanted.has(t);
    const candidates: AiRetrievalCandidate[] = [];

    const [findings, assets, scans, incidents, cases] = await Promise.all([
      want("FINDING") || want("MOBILE_FINDING") || want("BINARY_FINDING")
        ? this.prisma.finding.findMany({ where: { workspaceId }, orderBy: { riskScore: "desc" }, take: 50 }) : Promise.resolve([]),
      want("ASSET") ? this.prisma.asset.findMany({ where: { workspaceId }, take: 50 }) : Promise.resolve([]),
      want("SCAN") ? this.prisma.scan.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 20 }) : Promise.resolve([]),
      want("SOC_INCIDENT") ? this.prisma.securityIncident.findMany({ where: { workspaceId }, orderBy: { detectedAt: "desc" }, take: 20 }) : Promise.resolve([]),
      want("REMEDIATION") ? this.prisma.remediationCase.findMany({ where: { workspaceId }, take: 50 }) : Promise.resolve([]),
    ]);

    for (const f of findings as Record<string, unknown>[]) {
      const sourceType: AiRetrievalSourceType = f.sourceDomain === "MOBILE" ? "MOBILE_FINDING" : f.sourceDomain === "BINARY" ? "BINARY_FINDING" : "FINDING";
      if (!want(sourceType) && !want("FINDING")) continue;
      candidates.push({
        sourceType, sourceId: f.id as string, workspaceId, classification: "INTERNAL",
        observedAt: (f.updatedAt as Date | undefined)?.toISOString?.() ?? undefined,
        fields: {
          title: String(f.title ?? ""), severity: String(f.severity ?? ""),
          ...(f.cve ? { cve: String(f.cve) } : {}),
          ...(f.riskScore != null ? { riskScore: String(f.riskScore) } : {}),
          ...(f.lifecycleStatus ? { status: String(f.lifecycleStatus) } : {}),
        },
      });
    }
    for (const a of assets as Record<string, unknown>[]) {
      candidates.push({
        sourceType: "ASSET", sourceId: a.id as string, workspaceId, classification: "INTERNAL",
        fields: { name: String(a.host ?? a.name ?? ""), type: String(a.type ?? ""), criticality: String(a.criticality ?? "") },
      });
    }
    for (const s of scans as Record<string, unknown>[]) {
      candidates.push({
        sourceType: "SCAN", sourceId: s.id as string, workspaceId, classification: "INTERNAL",
        observedAt: (s.createdAt as Date | undefined)?.toISOString?.() ?? undefined,
        fields: { status: String(s.status ?? ""), ...(s.currentStage ? { currentStage: String(s.currentStage) } : {}) },
      });
    }
    for (const i of incidents as Record<string, unknown>[]) {
      candidates.push({
        sourceType: "SOC_INCIDENT", sourceId: i.id as string, workspaceId, classification: "INTERNAL",
        observedAt: (i.detectedAt as Date | undefined)?.toISOString?.() ?? undefined,
        fields: { title: String(i.title ?? ""), severity: String(i.severity ?? ""), status: String(i.status ?? "") },
      });
    }
    for (const c of cases as Record<string, unknown>[]) {
      candidates.push({
        sourceType: "REMEDIATION", sourceId: c.id as string, workspaceId, classification: "INTERNAL",
        fields: { findingId: String(c.findingId ?? ""), status: String(c.status ?? ""), verificationState: String(c.verificationState ?? "") },
      });
    }

    // Vulnerability intelligence (§11): only for CVEs on this
    // workspace's findings; the candidate carries the workspace id of
    // the REQUESTER because the intel is attached through their own
    // finding — the intel rows themselves stay global reference data.
    if (want("VULNERABILITY_INTEL")) {
      const cves = [...new Set((findings as Record<string, unknown>[]).map((f) => f.cve).filter(Boolean))] as string[];
      for (const cveId of cves.slice(0, 25)) {
        const rec = await this.prisma.cveRecord.findFirst({ where: { cveId } });
        if (!rec) continue;
        candidates.push({
          sourceType: "VULNERABILITY_INTEL", sourceId: cveId, workspaceId, classification: "PUBLIC",
          fields: { cve: cveId, cvssScore: rec.cvssScore != null ? String(rec.cvssScore) : "unknown", datasetStatus: "LOCAL_DATASET" },
        });
      }
    }

    const result = filterRetrievalCandidates({
      workspaceId, userId: user.id, userPermissions: aiPermissionsHeld(user),
      sourcePermissions: AiRetrievalService.SOURCE_PERMISSIONS,
      classificationCeiling: opts.classificationCeiling ?? "INTERNAL",
      sourceTypes: opts.sourceTypes, maxRecords,
    }, candidates);

    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "AI_RETRIEVAL_PERFORMED", resourceType: "AiRetrieval",
      metadata: { returned: result.records.length, dropped: result.dropped.length, skippedSources: result.skippedSources },
    });
    return {
      records: result.records.map((r) => ({ sourceType: r.sourceType, sourceId: r.sourceId, classification: r.classification, fields: r.fields })),
      droppedCount: result.dropped.length,
      droppedReasons: result.dropped.map((d) => d.reason),
      skippedSources: result.skippedSources,
    };
  }
}
