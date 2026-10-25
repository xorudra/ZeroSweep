import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  classifyAgainstBaseline,
  evaluateGate,
  parseGateRules,
  prPresetToRules,
  type GateRule,
  type PrGatePreset,
  type SanitizedFindingView,
  type ScannerFailureBehavior,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireIntegrationPermission } from "../permissions";
import type { CreateBaselineBody, CreateGatePolicyBody } from "../dto/schemas";

type Row = Record<string, unknown>;

/**
 * Security quality gates + baselines (Prompt 24 §36–§42).
 * Policies are versioned typed data (§37/§38); evaluations are
 * recorded so every verdict is explainable after the fact. Baselines
 * are bound to immutable commits + finding fingerprints (§41).
 */
@Injectable()
export class QualityGatesService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async createPolicy(user: RequestUser, workspaceId: string, body: CreateGatePolicyBody) {
    requireIntegrationPermission(user, "MANAGE_REPOSITORY_INTEGRATIONS");
    const parsed = parseGateRules(body.rules ?? []);
    if (!parsed.ok) throw new BadRequestException(`Invalid gate rules: ${parsed.errors.join("; ")}`);
    const existing = await this.prisma.securityGatePolicy.findFirst({
      where: { workspaceId, name: body.name },
    });
    if (existing) {
      // Policies are versioned (§37): an update bumps the version so
      // historical evaluations keep pointing at the rules that ran.
      const updated = await this.prisma.securityGatePolicy.update({
        where: { id: existing.id },
        data: {
          rules: parsed.rules as never,
          repositorySelector: (body.repositorySelector ?? existing.repositorySelector) as never,
          branchSelector: (body.branchSelector ?? existing.branchSelector) as never,
          scannerFailureBehavior: body.scannerFailureBehavior ?? (existing.scannerFailureBehavior as string),
          version: (existing.version as number) + 1,
        },
      });
      return updated;
    }
    return this.prisma.securityGatePolicy.create({
      data: {
        workspaceId,
        name: body.name,
        repositorySelector: (body.repositorySelector ?? {}) as never,
        branchSelector: (body.branchSelector ?? {}) as never,
        rules: parsed.rules as never,
        scannerFailureBehavior: (body.scannerFailureBehavior as string) ?? "FAIL_CLOSED",
        createdBy: user.id,
      },
    });
  }

  async listPolicies(user: RequestUser, workspaceId: string) {
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    return this.prisma.securityGatePolicy.findMany({
      where: { workspaceId },
      orderBy: { createdAt: "desc" },
    });
  }

  /** §40/§41: capture a baseline from a COMPLETED scan's findings at
   *  an immutable commit. Never from a branch name alone. */
  async createBaseline(user: RequestUser, workspaceId: string, repositoryId: string, body: CreateBaselineBody) {
    requireIntegrationPermission(user, "MANAGE_REPOSITORY_INTEGRATIONS");
    const repository = await this.prisma.sourceRepository.findFirst({ where: { id: repositoryId, workspaceId } });
    if (!repository) throw new NotFoundException("Source repository not found");
    const scanId = body.scanId as string | undefined;
    let fingerprints: string[] = [];
    let snapshotId = (body.snapshotId as string | undefined) ?? null;
    if (scanId) {
      const scan = await this.prisma.scan.findFirst({ where: { id: scanId, workspaceId } });
      if (!scan) throw new NotFoundException("Scan not found");
      const findings = await this.prisma.finding.findMany({ where: { scanId, workspaceId } });
      fingerprints = [...new Set(findings.map((f) => f.fingerprint as string))];
      const snapshot = findings.find((f) => f.snapshotId)?.snapshotId as string | undefined;
      if (snapshot) snapshotId = snapshot;
    }
    const existing = await this.prisma.securityBaseline.findFirst({
      where: { repositoryId, commitSha: body.commitSha },
    });
    if (existing) throw new BadRequestException("A baseline already exists for this repository + commit (§41: baselines are immutable)");
    const baseline = await this.prisma.securityBaseline.create({
      data: {
        workspaceId, repositoryId,
        commitSha: body.commitSha,
        snapshotId, scanId: scanId ?? null,
        fingerprints, findingCount: fingerprints.length,
        createdBy: user.id,
      },
    });
    return baseline;
  }

  async latestBaseline(workspaceId: string, repositoryId: string): Promise<Row | null> {
    const rows = await this.prisma.securityBaseline.findMany({
      where: { workspaceId, repositoryId },
      orderBy: { createdAt: "desc" },
      take: 1,
    });
    return (rows[0] as Row) ?? null;
  }

  /**
   * §19/§36: classify a scan's repository findings against the latest
   * baseline, then evaluate the effective gate policy (explicit
   * policy wins over the repository PR preset; default FAIL_CLOSED).
   */
  async evaluateForScan(input: {
    workspaceId: string;
    repositoryId: string;
    scanId: string;
    context: "PR_ASSESSMENT" | "PIPELINE_RUN" | "SCAN";
    pullRequestAssessmentId?: string;
    pipelineRunId?: string;
    gatePolicyId?: string | null;
    prGatePreset?: string | null;
    actorId?: string;
  }) {
    const findings = await this.prisma.finding.findMany({
      where: { scanId: input.scanId, workspaceId: input.workspaceId },
    });
    const baseline = await this.latestBaseline(input.workspaceId, input.repositoryId);
    const resolvedRows = await this.prisma.finding.findMany({
      where: { workspaceId: input.workspaceId, repositoryId: input.repositoryId, lifecycleStatus: "RESOLVED" },
    });
    const classification = classifyAgainstBaseline({
      baselineFingerprints: baseline ? ((baseline.fingerprints as string[]) ?? []) : [],
      currentFingerprints: findings.map((f) => f.fingerprint as string),
      previouslyResolvedFingerprints: [...new Set(resolvedRows.map((f) => f.fingerprint as string))],
    });
    const byFingerprint = new Map<string, Row>();
    for (const f of findings as Row[]) byFingerprint.set(f.fingerprint as string, f);
    const classOf = new Map(classification.perFinding.map((c) => [c.fingerprint, c.classification]));
    const newFindings = findings.filter((f) => classOf.get(f.fingerprint as string) === "NEW");
    const toGateView = (f: Row): SanitizedFindingView & { policyViolation?: boolean } => ({
      id: f.id as string,
      title: f.title as string,
      severity: f.severity as string,
      status: f.status as string,
      lifecycleStatus: f.lifecycleStatus as string,
      verificationStatus: f.verificationStatus as string,
      kevListed: f.kevListed === true,
      isSecretFinding: (f.sourceDomain as string) === "CODE" && ((f.vulnClass as string) ?? "").toUpperCase().includes("SECRET"),
      policyViolation: false,
      zerosweepReference: `finding:${f.id}`,
    });

    let rules: GateRule[] = [];
    let behavior: ScannerFailureBehavior = "FAIL_CLOSED";
    let policyId: string | null = null;
    let policyVersion: number | null = null;
    if (input.gatePolicyId) {
      const policy = await this.prisma.securityGatePolicy.findFirst({
        where: { id: input.gatePolicyId, workspaceId: input.workspaceId },
      });
      if (policy) {
        const parsed = parseGateRules(policy.rules ?? []);
        rules = parsed.rules;
        behavior = (policy.scannerFailureBehavior as ScannerFailureBehavior) ?? "FAIL_CLOSED";
        policyId = policy.id as string;
        policyVersion = policy.version as number;
      }
    }
    if (rules.length === 0 && input.prGatePreset) {
      rules = prPresetToRules(input.prGatePreset as PrGatePreset);
    }
    // Scanner results derive from the scan's tool executions: a
    // required scanner that FAILED is visible to the gate (§39).
    const executions = await this.prisma.toolExecution.findMany({ where: { scanId: input.scanId } });
    const scannerResults = (executions as Row[]).map((e) => ({
      scanner: (e.adapterKey as string) ?? (e.toolId as string) ?? "unknown",
      status: (e.status as string) === "COMPLETED" ? ("COMPLETED" as const)
        : (e.status as string) === "FAILED" ? ("FAILED" as const) : ("SKIPPED" as const),
    }));
    const evaluation = evaluateGate(
      { newFindings: newFindings.map((f) => toGateView(f as Row)), coveragePercent: null, scannerResults },
      { rules, scannerFailureBehavior: behavior },
    );
    const record = await this.prisma.securityGateEvaluation.create({
      data: {
        workspaceId: input.workspaceId,
        policyId, policyVersion,
        context: input.context,
        pullRequestAssessmentId: input.pullRequestAssessmentId ?? null,
        pipelineRunId: input.pipelineRunId ?? null,
        scanId: input.scanId,
        result: evaluation.result,
        ruleResults: evaluation.ruleResults as never,
        summary: ({
          ...evaluation.summary,
          newFindingIds: newFindings.map((f) => f.id),
          resolvedFindingIds: classification.resolvedFingerprints
            .map((fp) => (resolvedRows as Row[]).find((r) => r.fingerprint === fp)?.id)
            .filter(Boolean),
          regressedFindingIds: classification.regressedFingerprints
            .map((fp) => byFingerprint.get(fp)?.id)
            .filter(Boolean),
          preExistingCount: classification.preExistingFingerprints.length,
          baselineCommit: (baseline?.commitSha as string) ?? null,
        }) as never,
        evaluatedBy: input.actorId ?? null,
      },
    });
    if (evaluation.result === "PASS" || evaluation.result === "FAIL") {
      await this.audit.record({
        actorId: input.actorId, workspaceId: input.workspaceId,
        action: evaluation.result === "PASS" ? "QUALITY_GATE_PASSED" : "QUALITY_GATE_FAILED",
        resourceType: "SecurityGateEvaluation", resourceId: record.id as string,
        metadata: { context: input.context, scanId: input.scanId, newTotal: evaluation.summary.newTotal },
      }).catch(() => undefined);
    }
    return {
      evaluation: record,
      result: evaluation.result,
      summary: evaluation.summary,
      newFindingIds: newFindings.map((f) => f.id as string),
      resolvedFingerprints: classification.resolvedFingerprints,
      regressedFingerprints: classification.regressedFingerprints,
      classification,
    };
  }
}
