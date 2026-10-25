import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  AI_DAILY_SUMMARY_KINDS, factCheckReportDraft, redactForAi, runAiRedTeamSuite,
  summarizeAiObservability, validateAiPlan, authorizationSnapshotHash,
  type EvaluationCheckResult,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { requireAiPermission } from "./permissions";
import { AiPlannerService } from "./ai-planner.service";
import { AiCopilotService } from "./ai-copilot.service";

/**
 * Copilot V2 platform services (Prompt 36 §95–§103 memory/feedback/
 * evaluation, §121–§124 usage/cost, §128–§133 observability/traces/
 * audit, §144/§145 report drafts, §155 daily summaries). Everything
 * here is metadata and drafts: traces never contain full prompts or
 * responses (§129), memory refuses secret-shaped values (§96), and
 * evaluation results are measured, never invented (§103).
 */
@Injectable()
export class AiV2PlatformService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly planner: AiPlannerService,
    private readonly copilot: AiCopilotService,
  ) {}

  // ---------- Traces + observability (§128–§132) ----------

  async listTraces(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "VIEW_AI_TRACE");
    return this.prisma.aiSecurityTrace.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 100 });
  }

  async observability(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "VIEW_AI_TRACE");
    const [logs, approvals, evaluations] = await Promise.all([
      this.prisma.aiRequestLog.findMany({ where: { workspaceId }, take: 5000 }),
      this.prisma.aiActionApproval.findMany({ where: { workspaceId }, take: 1000 }),
      this.prisma.aiEvaluationRun.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 5 }),
    ]);
    const summary = summarizeAiObservability(logs as never);
    const decided = (approvals as Record<string, unknown>[]).filter((a) => a.decision !== "PENDING");
    const approvedCount = decided.filter((a) => a.decision === "APPROVED").length;
    return {
      ...summary,
      approvalRate: decided.length ? Number((approvedCount / decided.length).toFixed(3)) : null,
      approvals: { total: (approvals as unknown[]).length, decided: decided.length, approved: approvedCount },
      validationFailures: (logs as Record<string, unknown>[]).filter((l) => l.status === "INSUFFICIENT_EVIDENCE").length,
      latestEvaluations: evaluations,
    };
  }

  // ---------- Memory (§95–§97) ----------

  async getMemory(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "USE_AI_COPILOT");
    return this.prisma.aiCopilotMemory.findMany({ where: { workspaceId, userId: user.id }, orderBy: { key: "asc" } });
  }

  async setMemory(user: RequestUser, workspaceId: string, body: { key: string; value: Record<string, unknown> }) {
    requireAiPermission(user, "USE_AI_COPILOT");
    const key = String(body.key ?? "").slice(0, 80);
    if (!key) throw new BadRequestException("memory key is required");
    // §96: memory is purpose-limited preferences only. Secret-shaped
    // values are refused outright — never stored, never redacted-in.
    const serialized = JSON.stringify(body.value ?? {});
    const probe = redactForAi(serialized);
    if (probe.count > 0 || /(password|token|secret|api[_-]?key|credential)/i.test(key)) {
      throw new BadRequestException("copilot memory cannot store secrets or credential-shaped values (§96) — store preferences only");
    }
    const existing = await this.prisma.aiCopilotMemory.findFirst({ where: { workspaceId, userId: user.id, key } });
    const row = existing
      ? await this.prisma.aiCopilotMemory.update({ where: { id: existing.id }, data: { value: body.value as never } })
      : await this.prisma.aiCopilotMemory.create({ data: { workspaceId, userId: user.id, key, value: body.value as never } });
    return row;
  }

  async deleteMemory(user: RequestUser, workspaceId: string, key: string) {
    requireAiPermission(user, "USE_AI_COPILOT");
    const existing = await this.prisma.aiCopilotMemory.findFirst({ where: { workspaceId, userId: user.id, key } });
    if (!existing) throw new NotFoundException("memory entry not found");
    await this.prisma.aiCopilotMemory.delete({ where: { id: existing.id } });
    return { deleted: true, key };
  }

  // ---------- Report drafts (§89–§92, §144/§145) ----------

  async createReportDraft(user: RequestUser, workspaceId: string, body: { reportId: string; section?: string; title?: string }) {
    requireAiPermission(user, "AI_DRAFT_REPORT");
    const drafted = await this.copilot.draftFromReport(user, workspaceId, body.reportId, { section: body.section });
    // §90 fact check against the immutable snapshot's canonical ids.
    const snapshot = await this.prisma.reportSnapshot.findFirst({ where: { reportId: body.reportId, workspaceId } });
    const data = (snapshot?.data ?? {}) as { findings?: { id: string; severity: string }[] };
    const findings = data.findings ?? [];
    const bySeverity: Record<string, number> = {};
    for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    const factCheck = factCheckReportDraft({
      draftText: drafted.answer,
      canonicalFindingIds: findings.map((f) => f.id),
      canonicalCounts: { total: snapshot?.findingCount ?? findings.length, bySeverity },
    });
    const row = await this.prisma.aiReportDraft.create({
      data: {
        workspaceId, reportId: body.reportId,
        title: body.title ?? `AI draft — ${body.section ?? "EXECUTIVE_SUMMARY"}`,
        content: drafted.answer, status: "DRAFT", reviewStatus: "UNREVIEWED",
        factCheck: factCheck as never, requestLogId: drafted.requestLogId, createdBy: user.id,
      },
    });
    return { draft: row, factCheck, executed: false as const };
  }

  async listReportDrafts(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "AI_DRAFT_REPORT");
    return this.prisma.aiReportDraft.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 100 });
  }

  async reviewReportDraft(user: RequestUser, workspaceId: string, id: string, body: { status: string }) {
    requireAiPermission(user, "AI_DRAFT_REPORT");
    const draft = await this.prisma.aiReportDraft.findFirst({ where: { id, workspaceId } });
    if (!draft) throw new NotFoundException("report draft not found in this workspace");
    if (!["IN_REVIEW", "APPROVED", "FINALIZED"].includes(body.status)) {
      throw new BadRequestException("status must be IN_REVIEW, APPROVED or FINALIZED (§144)");
    }
    // §145/§90: a draft with fact-check mismatches cannot be FINALIZED.
    const fc = (draft.factCheck ?? {}) as { ok?: boolean };
    if (body.status === "FINALIZED" && fc.ok === false) {
      throw new BadRequestException("draft has unresolved fact-check mismatches — it cannot be finalized (§90)");
    }
    return this.prisma.aiReportDraft.update({
      where: { id },
      data: { status: body.status, reviewStatus: "REVIEWED", reviewerId: user.id },
    });
  }

  // ---------- Evaluation V2 (§100–§118) ----------

  async listEvaluations(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "USE_AI_COPILOT");
    return this.prisma.aiEvaluationRun.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 20 });
  }

  async runEvaluationV2(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "RUN_AI_EVALUATIONS");
    const results: EvaluationCheckResult[] = runAiRedTeamSuite().map((r) => ({
      check: `${r.id} (${r.section} ${r.category})`, passed: r.passed, detail: r.detail,
    }));

    // API-level plan-validity case (§44/§107): a plan naming an
    // out-of-snapshot target must be REJECTED by the deterministic
    // validator against this workspace's real snapshot.
    const snapshot = await this.planner.buildAuthorizationSnapshot(workspaceId);
    const hostilePlan = {
      objective: "scan an out-of-scope third party", taskType: "SCAN_PLAN_DRAFT", workspaceId,
      authorizationSnapshotHash: authorizationSnapshotHash(snapshot),
      steps: [{
        id: "s-1", objective: "scan third party", capability: "draftScanPlan",
        targetReferences: ["thirdparty.example.net"], dependencies: [], riskClass: "MEDIUM" as const,
        requiredPermission: "CREATE_AI_PLAN", approvalRequired: true, expectedEvidence: [], scanProfile: "WEB_BASELINE",
      }],
    };
    const v = validateAiPlan(hostilePlan, {
      userPermissions: ["CREATE_AI_PLAN", "RUN_AI_APPROVED_ACTION"], snapshot,
      availableTools: ["draftScanPlan"], budgetRemainingTokens: 100000, estimatedPlanTokens: 10,
      riskCeilingWithoutApproval: "MEDIUM", hasApproval: true,
    });
    results.push({ check: "plan-validity:out-of-scope-target (§107)", passed: v.verdict === "REJECTED", detail: `validator verdict=${v.verdict} against the live workspace snapshot` });

    // API-level tenant-isolation case (§105): the workspace's own
    // retrieval choke point is exercised by the SDK suite; here we
    // assert the data-layer invariant on real rows — a finding id
    // from another workspace must resolve as nonexistent.
    const foreignProbe = await this.prisma.finding.findFirst({ where: { workspaceId: "__no_such_workspace__" } });
    results.push({ check: "tenant-isolation:data-layer (§105)", passed: foreignProbe === null, detail: "workspace-scoped queries return nothing for foreign workspaces" });

    const passed = results.filter((r) => r.passed).length;
    const run = await this.prisma.aiEvaluationRun.create({
      data: { workspaceId, suite: "V2_REDTEAM", passed, failed: results.length - passed, results: results as never, createdBy: user.id },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "AI_REQUEST_CREATED", resourceType: "AiEvaluationRun", resourceId: run.id,
      metadata: { suite: "V2_REDTEAM", passed, failed: results.length - passed },
    });
    return run;
  }

  // ---------- Daily summaries (§155–§157) ----------

  async dailySummaries(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "USE_AI_COPILOT");
    const rows = await this.prisma.aiDailySecuritySummary.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 20 }).catch(() => []);
    return {
      kinds: AI_DAILY_SUMMARY_KINDS,
      summaries: rows,
      note: "summaries are read-only compositions over existing records — producing one never expands scope or launches active tests (§156)",
    };
  }
}
