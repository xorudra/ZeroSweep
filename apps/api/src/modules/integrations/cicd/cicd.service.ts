import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  buildSarifLog,
  sanitizeBranchName,
  sanitizeUntrustedText,
  type SanitizedFindingView,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireIntegrationPermission } from "../permissions";
import { QualityGatesService } from "../quality-gates/quality-gates.service";
import { ScanTriggerService } from "./scan-trigger.service";
import { EventsService } from "../events/events.service";
import type { CreatePipelineRunBody } from "../dto/schemas";

type Row = Record<string, unknown>;

/**
 * CI/CD security service (Prompt 24 §32–§35) + PR/MR assessment
 * lifecycle (§18–§22). Pipeline identities authenticate with scoped
 * API keys (`pipelines:security-scan` to request, `pipelines:gate-read`
 * to read a verdict, §35) — never administrator credentials (§34).
 * Everything a pipeline receives back is the sanitized summary (§42):
 * finding IDs, counts, redacted locations — never a secret value.
 */
@Injectable()
export class CicdService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly gates: QualityGatesService,
    private readonly triggers: ScanTriggerService,
    private readonly events: EventsService,
  ) {}

  /* --------------------------- pipeline runs --------------------------- */

  async requestPipelineRun(principal: {
    organizationId: string; workspaceId: string | null; ownerId: string; ownerKind: string;
  }, body: CreatePipelineRunBody) {
    if (!principal.workspaceId) {
      throw new BadRequestException("Pipeline requests require a service-account API key bound to a workspace (§34/§35)");
    }
    const workspaceId = principal.workspaceId;
    const repository = await this.resolveRepository(workspaceId, body);
    const existing = await this.prisma.securityPipelineRun.findFirst({
      where: { workspaceId, provider: (body.provider as string) ?? "GENERIC_CI", externalPipelineId: body.externalPipelineId },
    });
    if (existing) return this.presentPipelineRun(existing as Row); // idempotent re-request
    const run = await this.prisma.securityPipelineRun.create({
      data: {
        workspaceId,
        provider: (body.provider as string) ?? "GENERIC_CI",
        repositoryId: (repository?.id as string) ?? null,
        externalRepositoryId: (body.externalRepositoryId as string) ?? null,
        commitSha: body.commitSha,
        branch: sanitizeBranchName(body.branch),
        prNumber: (body.prNumber as number) ?? null,
        externalPipelineId: body.externalPipelineId,
        status: "REQUESTED",
        requestedByKind: principal.ownerKind === "SERVICE_ACCOUNT" ? "SERVICE_ACCOUNT" : "API_KEY",
        requestedById: principal.ownerId,
      },
    });
    await this.audit.record({
      organizationId: principal.organizationId, workspaceId,
      action: "PIPELINE_SCAN_REQUESTED", resourceType: "SecurityPipelineRun", resourceId: run.id as string,
      metadata: { provider: run.provider, externalPipelineId: body.externalPipelineId },
    });
    if (repository) {
      const policy = await this.prisma.repositorySecurityPolicy.findFirst({
        where: { workspaceId, sourceRepositoryId: repository.id as string },
      });
      const link = await this.prisma.repositoryIntegrationLink.findFirst({
        where: { workspaceId, sourceRepositoryId: repository.id as string },
      });
      const actorUserId = (link?.createdBy as string) ?? (repository.createdBy as string);
      const outcome = await this.triggers.triggerRepositoryScan({
        workspaceId, repository, actorUserId, purpose: "pipeline",
      });
      const updated = await this.prisma.securityPipelineRun.update({
        where: { id: run.id as string },
        data: {
          status: outcome.started ? "RUNNING" : "BLOCKED",
          blockReason: outcome.started ? null : (outcome.reasonCode ?? null),
          scanIds: outcome.scanId ? [outcome.scanId] : [],
          summary: { trigger: outcome.detail, policyConfigured: Boolean(policy) },
        },
      });
      return this.presentPipelineRun(updated as Row);
    }
    return this.presentPipelineRun(run as Row);
  }

  async getPipelineRunForPrincipal(principal: { organizationId: string; workspaceId: string | null }, id: string) {
    const run = await this.prisma.securityPipelineRun.findFirst({ where: { id } });
    if (!run || run.workspaceId !== principal.workspaceId) throw new NotFoundException("Pipeline run not found");
    return this.presentPipelineRun(run as Row);
  }

  async getPipelineRun(user: RequestUser, workspaceId: string, id: string) {
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    const run = await this.prisma.securityPipelineRun.findFirst({ where: { id, workspaceId } });
    if (!run) throw new NotFoundException("Pipeline run not found");
    return this.presentPipelineRun(run as Row);
  }

  /** Refresh a pipeline run from its scans: when every scan finished,
   *  evaluate the gate and finalize the sanitized summary (§32). */
  async refreshPipelineRun(user: RequestUser, workspaceId: string, id: string) {
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    const run = await this.prisma.securityPipelineRun.findFirst({ where: { id, workspaceId } });
    if (!run) throw new NotFoundException("Pipeline run not found");
    return this.refreshRun(run as Row, user.id);
  }

  async refreshRun(run: Row, actorId?: string) {
    const scanIds = (run.scanIds as string[]) ?? [];
    if (scanIds.length === 0 || !run.repositoryId) return this.presentPipelineRun(run);
    const scans = await this.prisma.scan.findMany({ where: { id: { in: scanIds } } });
    const allDone = scans.every((s) => ["COMPLETED", "FAILED", "CANCELLED"].includes(s.status as string));
    if (!allDone) return this.presentPipelineRun(run);
    const policy = await this.prisma.repositorySecurityPolicy.findFirst({
      where: { workspaceId: run.workspaceId as string, sourceRepositoryId: run.repositoryId as string },
    });
    const gate = await this.gates.evaluateForScan({
      workspaceId: run.workspaceId as string,
      repositoryId: run.repositoryId as string,
      scanId: scanIds[0]!,
      context: "PIPELINE_RUN",
      pipelineRunId: run.id as string,
      gatePolicyId: policy?.gatePolicyId as string | undefined,
      prGatePreset: policy?.prGatePreset as string | undefined,
      actorId,
    });
    const summary = await this.sanitizedSummary(run.workspaceId as string, scanIds[0]!);
    const updated = await this.prisma.securityPipelineRun.update({
      where: { id: run.id as string },
      data: {
        status: "COMPLETED",
        gateResult: gate.result,
        gateEvaluationId: (gate.evaluation as Row).id as string,
        summary: summary as never,
        completedAt: new Date(),
      },
    });
    if (gate.result === "FAIL") {
      await this.events.publish({
        workspaceId: run.workspaceId as string,
        eventType: "quality_gate.failed",
        resourceType: "SecurityPipelineRun",
        resourceId: run.id as string,
        payload: { gateResult: gate.result, newTotal: gate.summary.newTotal },
      }).catch(() => undefined);
    }
    return this.presentPipelineRun(updated as Row);
  }

  /* ------------------------- PR/MR assessments ------------------------- */

  async getPullRequestAssessment(user: RequestUser, workspaceId: string, id: string) {
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    const row = await this.prisma.pullRequestSecurityAssessment.findFirst({ where: { id, workspaceId } });
    if (!row) throw new NotFoundException("Pull request assessment not found");
    return row;
  }

  async listPullRequestAssessments(user: RequestUser, workspaceId: string, repositoryId?: string) {
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    return this.prisma.pullRequestSecurityAssessment.findMany({
      where: { workspaceId, ...(repositoryId ? { repositoryId } : {}) },
      orderBy: { createdAt: "desc" },
      take: 100,
    });
  }

  /** §43: SARIF for a completed PR/pipeline scan — redacted (§45). */
  async sarifForAssessment(user: RequestUser, workspaceId: string, id: string) {
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    const row = await this.prisma.pullRequestSecurityAssessment.findFirst({ where: { id, workspaceId } });
    if (!row) throw new NotFoundException("Pull request assessment not found");
    if (!row.scanId) throw new BadRequestException("Assessment has no completed scan to export");
    return this.sarifForScan(workspaceId, row.scanId as string);
  }

  async sarifForScan(workspaceId: string, scanId: string) {
    const findings = await this.prisma.finding.findMany({ where: { scanId, workspaceId } });
    const views = (findings as Row[]).map((f) => this.toSanitizedView(f));
    const { sarif, redactions } = buildSarifLog({
      toolName: "ZeroSweep",
      findings: views.map((v, i) => ({ ...v, ruleId: (findings[i] as Row).ruleId as string | undefined, cwe: (findings[i] as Row).cwe as string | undefined })),
    });
    return { sarif, redactions };
  }

  /* ------------------------------ helpers ------------------------------ */

  private async resolveRepository(workspaceId: string, body: Record<string, unknown>): Promise<Row | null> {
    if (body.repositoryId) {
      const repo = await this.prisma.sourceRepository.findFirst({ where: { id: body.repositoryId, workspaceId } });
      if (!repo) throw new NotFoundException("Repository not found in this workspace");
      return repo as Row;
    }
    if (body.externalRepositoryId) {
      const link = await this.prisma.repositoryIntegrationLink.findFirst({
        where: { workspaceId, externalRepositoryId: body.externalRepositoryId },
      });
      if (!link) throw new NotFoundException("No repository link for that external repository id");
      const repo = await this.prisma.sourceRepository.findFirst({ where: { id: link.sourceRepositoryId, workspaceId } });
      return (repo as Row) ?? null;
    }
    return null;
  }

  /** §42: the ONLY summary a pipeline ever receives — ids, counts,
   *  redacted repository-relative locations. Never a secret value. */
  async sanitizedSummary(workspaceId: string, scanId: string) {
    const findings = await this.prisma.finding.findMany({ where: { scanId, workspaceId } });
    const counts: Record<string, number> = {};
    for (const f of findings as Row[]) counts[f.severity as string] = (counts[f.severity as string] ?? 0) + 1;
    return {
      scanId,
      totalFindings: findings.length,
      bySeverity: counts,
      secretFindings: (findings as Row[])
        .filter((f) => ((f.vulnClass as string) ?? "").toUpperCase().includes("SECRET"))
        .map((f) => ({
          findingId: f.id as string,
          file: (f.filePath as string) ?? null,
          line: (f.startLine as number) ?? null,
          severity: f.severity as string,
          guidance: "Rotate the credential and remove it from history — the value is never shown (§42)",
        })),
    };
  }

  toSanitizedView(f: Row): SanitizedFindingView {
    return {
      id: f.id as string,
      title: sanitizeUntrustedText(f.title, 300),
      severity: f.severity as string,
      priority: (f.priority as string) ?? undefined,
      status: f.status as string,
      lifecycleStatus: f.lifecycleStatus as string,
      verificationStatus: f.verificationStatus as string,
      kevListed: f.kevListed === true,
      isSecretFinding: ((f.vulnClass as string) ?? "").toUpperCase().includes("SECRET"),
      filePath: (f.filePath as string) ?? undefined,
      startLine: (f.startLine as number) ?? undefined,
      remediation: (f.remediation as string) ?? undefined,
      riskExplanation: typeof f.riskExplanation === "string"
        ? (f.riskExplanation as string)
        : (((f.riskExplanation as Row | null)?.summary as string) ?? undefined),
      dsrcloneReference: `finding:${f.id}`,
    };
  }

  presentPipelineRun(run: Row) {
    return {
      id: run.id,
      provider: run.provider,
      repositoryId: run.repositoryId,
      externalRepositoryId: run.externalRepositoryId,
      commitSha: run.commitSha,
      branch: run.branch,
      prNumber: run.prNumber,
      externalPipelineId: run.externalPipelineId,
      status: run.status,
      blockReason: run.blockReason ?? null,
      gateResult: run.gateResult ?? null,
      scanIds: run.scanIds ?? [],
      summary: run.summary ?? {},
      startedAt: run.startedAt,
      completedAt: run.completedAt ?? null,
    };
  }
}
