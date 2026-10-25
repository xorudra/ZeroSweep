import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import { createHash } from "node:crypto";
import {
  buildFindingContext, estimateTokens,
  type AiBuiltContext, type AiContextRecord, type AiFindingContextInput, type AiTaskType,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";

/**
 * Tenant-filtered AI context loading (Prompt 21 §9–§12/§40/§48). EVERY
 * query here is scoped by workspaceId at the data layer — tenant
 * isolation never depends on prompt instructions (§12). Callers check
 * RBAC permissions BEFORE invoking these loaders (§11): the model
 * only ever receives records the requesting user may access.
 */
@Injectable()
export class AiContextService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  /** Load one finding + relations as builder input; 404 when the
   *  finding is not in THIS workspace (cross-tenant = nonexistent, §94). */
  async loadFindingInput(workspaceId: string, findingId: string): Promise<AiFindingContextInput> {
    const f = await this.prisma.finding.findFirst({ where: { id: findingId, workspaceId } });
    if (!f) throw new NotFoundException("finding not found in this workspace");
    const [observations, evidence, asset, cve, cwe, epss, kev] = await Promise.all([
      this.prisma.findingObservation.findMany({ where: { findingId, workspaceId }, orderBy: { observedAt: "desc" }, take: 10 }),
      this.prisma.findingEvidence.findMany({ where: { findingId }, orderBy: { createdAt: "desc" }, take: 10 }),
      f.assetId ? this.prisma.asset.findFirst({ where: { id: f.assetId, workspaceId } }) : Promise.resolve(null),
      f.cve ? this.prisma.cveRecord.findFirst({ where: { cveId: f.cve } }) : Promise.resolve(null),
      f.cwe ? this.prisma.cweRecord.findFirst({ where: { cweId: f.cwe } }) : Promise.resolve(null),
      f.cve ? this.prisma.epssRecord.findFirst({ where: { cveId: f.cve }, orderBy: { date: "desc" } }) : Promise.resolve(null),
      f.cve ? this.prisma.kevRecord.findFirst({ where: { cveId: f.cve } }) : Promise.resolve(null),
    ]);
    return {
      id: f.id,
      workspaceId,
      title: f.title,
      description: f.description,
      severity: f.severity,
      status: f.status,
      lifecycleStatus: f.lifecycleStatus,
      verificationStatus: f.verificationStatus,
      confidence: f.confidence,
      cvssScore: f.cvssScore,
      cve: f.cve,
      cwe: f.cwe,
      sourceDomain: f.sourceDomain,
      category: f.category,
      fixedVersion: f.fixedVersion,
      filePath: f.filePath,
      remediation: f.remediation,
      riskScore: f.riskScore,
      riskBand: f.riskBand,
      riskExplanation: (f.riskExplanation as AiFindingContextInput["riskExplanation"]) ?? null,
      epssScore: f.epssScore,
      kevListed: f.kevListed,
      asset: asset ? { id: asset.id, name: asset.host, type: asset.type, environment: f.environment ?? undefined, exposure: undefined } : null,
      observations: observations.map((o) => ({ id: o.id, summary: o.summary ?? `${o.sourceTool} observation`, observedAt: o.observedAt?.toISOString() })),
      evidence: evidence.map((e) => ({ id: e.id, sourceTool: e.sourceTool, summary: e.summary ?? "", fingerprint: e.fingerprint })),
      codeSnippet: null, // snippets live in evidence rows (redacted at storage, P12 §62); the builder adds them only when a caller supplies one explicitly
      intel: cve || kev || epss ? {
        cveDescription: cve?.description,
        cvssScore: cve?.cvssScore ?? f.intelCvssScore,
        cweName: cwe?.name,
        epssScore: epss?.score ?? f.epssScore,
        epssPercentile: epss?.percentile ?? f.epssPercentile,
        kevListed: !!kev || f.kevListed,
        kevRequiredAction: kev?.requiredAction ?? undefined,
        fixedVersion: f.fixedVersion ?? undefined,
      } : null,
    };
  }

  async buildFindingContext(workspaceId: string, findingId: string, task: AiTaskType, maxTokens?: number): Promise<{ input: AiFindingContextInput; context: AiBuiltContext }> {
    const input = await this.loadFindingInput(workspaceId, findingId);
    return { input, context: buildFindingContext(input, task, { maxTokens }) };
  }

  /** Aggregate context for scan/asset summaries (§46/§48): a meta
   *  record + per-finding TRUSTED core records, capped by the budget's
   *  retrieval limit. Limitations are first-class records so summaries
   *  must disclose them (§47). */
  buildAggregateContext(params: {
    meta: AiContextRecord;
    findings: { id: string; title: string; severity: string; lifecycleStatus?: string; verificationStatus?: string; cve?: string | null; sourceDomain?: string | null; riskScore?: number | null }[];
    limitations: string[];
    maxRecords: number;
  }): AiBuiltContext {
    const records: AiContextRecord[] = [params.meta];
    for (const f of params.findings.slice(0, params.maxRecords)) {
      records.push({
        sourceType: "FINDING", sourceId: f.id, classification: "INTERNAL", trust: "TRUSTED",
        fields: {
          title: f.title, severity: f.severity,
          ...(f.lifecycleStatus ? { status: f.lifecycleStatus } : {}),
          ...(f.verificationStatus ? { verificationStatus: f.verificationStatus } : {}),
          ...(f.cve ? { cve: f.cve } : {}),
          ...(f.sourceDomain ? { domain: f.sourceDomain } : {}),
          ...(f.riskScore != null ? { riskScore: String(f.riskScore) } : {}),
        },
      });
    }
    if (params.limitations.length > 0) {
      records.push({
        sourceType: "DOCUMENTATION", sourceId: `limitations:${params.meta.sourceId}`, classification: "INTERNAL", trust: "TRUSTED",
        fields: { limitations: params.limitations.join("; ") },
      });
    }
    const serialized = JSON.stringify(records);
    return {
      records,
      maxClassification: "INTERNAL",
      includesSourceCode: false,
      includesRawEvidence: false,
      estimatedTokens: estimateTokens(serialized),
      contextHash: createHash("sha256").update(serialized).digest("hex"),
    };
  }

  async loadScanContext(workspaceId: string, scanId: string, maxRecords: number): Promise<AiBuiltContext> {
    const scan = await this.prisma.scan.findFirst({ where: { id: scanId, workspaceId } });
    if (!scan) throw new NotFoundException("scan not found in this workspace");
    const [findings, stages, executions] = await Promise.all([
      this.prisma.finding.findMany({ where: { workspaceId, scanId }, orderBy: { riskScore: "desc" }, take: 500 }),
      this.prisma.scanStage.findMany({ where: { scanId } }),
      this.prisma.toolExecution.findMany({ where: { scanId } }),
    ]);
    const failedTools = executions.filter((e) => e.status === "FAILED" || e.status === "TIMED_OUT");
    const failedStages = stages.filter((s) => s.status === "FAILED");
    const limitations: string[] = [];
    if (failedTools.length) limitations.push(`${failedTools.length} tool execution(s) failed — affected coverage is unknown`);
    if (failedStages.length) limitations.push(`${failedStages.length} stage(s) failed: ${failedStages.map((s) => s.type).join(", ")}`);
    if (scan.status !== "COMPLETED") limitations.push(`scan status is ${scan.status}, not COMPLETED — results may be partial`);
    if (findings.length > maxRecords) limitations.push(`context limited to the top ${maxRecords} findings by risk of ${findings.length} total`);
    return this.buildAggregateContext({
      meta: {
        sourceType: "DOCUMENTATION", sourceId: scan.id, classification: "INTERNAL", trust: "TRUSTED",
        fields: { kind: "SCAN", status: scan.status, progress: String(scan.progress), findingCount: String(findings.length), criticalCount: String(findings.filter((f) => f.severity === "CRITICAL").length), highCount: String(findings.filter((f) => f.severity === "HIGH").length), verifiedCount: String(findings.filter((f) => f.verificationStatus === "CONFIRMED").length) },
      },
      findings, limitations, maxRecords,
    });
  }

  async loadAssetContext(workspaceId: string, assetId: string, maxRecords: number): Promise<AiBuiltContext> {
    const asset = await this.prisma.asset.findFirst({ where: { id: assetId, workspaceId } });
    if (!asset) throw new NotFoundException("asset not found in this workspace");
    const findings = await this.prisma.finding.findMany({ where: { workspaceId, assetId }, orderBy: { riskScore: "desc" }, take: 500 });
    const limitations: string[] = [];
    if (findings.length === 0) limitations.push("no findings are recorded for this asset — posture summary is limited to inventory data");
    if (findings.length > maxRecords) limitations.push(`context limited to the top ${maxRecords} findings by risk of ${findings.length} total`);
    return this.buildAggregateContext({
      meta: {
        sourceType: "ASSET", sourceId: asset.id, classification: "INTERNAL", trust: "TRUSTED",
        fields: { name: asset.host, type: asset.type, criticality: asset.criticality, scopeStatus: asset.scopeStatus, findingCount: String(findings.length), domains: [...new Set(findings.map((f) => f.sourceDomain).filter(Boolean))].join(", ") },
      },
      findings, limitations, maxRecords,
    });
  }

  /** §49/§102: report drafting reads the IMMUTABLE snapshot only —
   *  never live findings — so an issued report's context cannot drift. */
  async loadReportSnapshotContext(workspaceId: string, reportId: string): Promise<{ context: AiBuiltContext; snapshotHash: string }> {
    const snapshot = await this.prisma.reportSnapshot.findFirst({ where: { reportId, workspaceId } });
    if (!snapshot) throw new NotFoundException("report snapshot not found in this workspace (generate the report first)");
    const data = (snapshot.data ?? {}) as { findings?: { id: string; title: string; severity: string; cve?: string | null }[]; title?: string };
    const records: AiContextRecord[] = [{
      sourceType: "DOCUMENTATION", sourceId: snapshot.id, classification: "INTERNAL", trust: "TRUSTED",
      fields: { kind: "REPORT_SNAPSHOT", contentHash: snapshot.contentHash, findingCount: String(snapshot.findingCount), ...(data.title ? { title: data.title } : {}) },
    }];
    for (const f of (data.findings ?? []).slice(0, 50)) {
      records.push({ sourceType: "FINDING", sourceId: f.id, classification: "INTERNAL", trust: "TRUSTED", fields: { title: f.title, severity: f.severity, ...(f.cve ? { cve: f.cve } : {}) } });
    }
    const serialized = JSON.stringify(records);
    return {
      snapshotHash: snapshot.contentHash,
      context: {
        records, maxClassification: "INTERNAL", includesSourceCode: false, includesRawEvidence: false,
        estimatedTokens: estimateTokens(serialized),
        contextHash: createHash("sha256").update(serialized).digest("hex"),
      },
    };
  }
}
