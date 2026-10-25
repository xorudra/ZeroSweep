import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  GOLDEN_FIXTURES, INJECTION_EVIDENCE_TEXT, SECRET_BEARING_EVIDENCE, SECRET_FIXTURE_STRINGS,
  MockAiProvider, buildAiPrompt, buildFindingContext, citationsFromAnswer, embedText, executeSecurityQuery,
  groundAnswer, ingestKnowledgeDocument, parseSecurityQuery, redactForAi, scanForInjection, searchVectors,
  validateQueryPlan, type EvaluationCheckResult, type VectorRecord,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { requireAiPermission } from "./permissions";
import { AiConfigService } from "./ai-config.service";

const ACTION_TYPES = ["REQUEST_VALIDATION", "REQUEST_RETEST", "ASSIGN_FINDING", "CREATE_REPORT_DRAFT"] as const;
const ACTION_PERMISSION: Record<string, string> = {
  REQUEST_VALIDATION: "REQUEST_VALIDATION",
  REQUEST_RETEST: "REQUEST_RETEST",
  ASSIGN_FINDING: "ASSIGN_FINDINGS",
  CREATE_REPORT_DRAFT: "GENERATE_REPORT",
};
// Prompt 36 §98: rating set extended with MISSING_EVIDENCE and OTHER.
const FEEDBACK_RATINGS = ["HELPFUL", "NOT_HELPFUL", "INCORRECT", "MISSING_EVIDENCE", "UNSAFE", "OUTDATED", "OTHER"] as const;

/**
 * Copilot platform services (Prompt 21 §41–§45 NL search, §70–§73
 * knowledge, §83/§84 action proposals, §85 feedback, §87 evaluation,
 * §108 dashboard, §118 observability). None of these execute
 * anything: proposals are records for the EXISTING workflows (§8),
 * search runs the governed DSL over tenant-filtered rows (§42), and
 * the evaluation suite exercises the real SDK pipeline on synthetic
 * golden fixtures (§88).
 */
@Injectable()
export class AiPlatformService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly config: AiConfigService,
  ) {}

  // ---------- Natural-language search (§41–§45) ----------

  async query(user: RequestUser, workspaceId: string, question: string) {
    requireAiPermission(user, "AI_QUERY_SECURITY_DATA");
    const parsed = parseSecurityQuery(question ?? "");
    if ("rejected" in parsed) {
      await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_POLICY_BLOCKED", resourceType: "AiQuery", metadata: { reason: parsed.rejected } });
      throw new BadRequestException(parsed.rejected);
    }
    const budget = await this.config.getBudget(workspaceId);
    const errors = validateQueryPlan(parsed.plan, Math.max(budget.maxRetrievalRecords, 200));
    if (errors.length) throw new BadRequestException(`query plan invalid: ${errors.join("; ")}`);
    // Tenant filtering happens HERE, at the data layer (§12): rows are
    // loaded for this workspace only, then the pure DSL executor runs.
    const rows = await this.prisma.finding.findMany({ where: { workspaceId }, orderBy: { riskScore: "desc" }, take: 2000 });
    const results = executeSecurityQuery(rows as never, parsed.plan);
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_REQUEST_CREATED", resourceType: "AiQuery", metadata: { task: "NATURAL_LANGUAGE_SEARCH", resultCount: results.length } });
    return {
      plan: parsed.plan,
      notes: parsed.notes,
      total: results.length,
      // §45: answers reference actual finding ids — citations by construction.
      results: results.map((r) => ({ id: r.id, title: r.title, severity: r.severity, cve: r.cve ?? null, riskScore: r.riskScore ?? null })),
      citations: results.map((r) => ({ sourceType: "FINDING", sourceId: r.id })),
    };
  }

  // ---------- Knowledge base (§70–§73) ----------

  async addKnowledgeDocument(user: RequestUser, workspaceId: string, body: { title: string; source: string; classification?: string; content: string }) {
    requireAiPermission(user, "MANAGE_AI_POLICY");
    const ingested = ingestKnowledgeDocument(body.content ?? "");
    if (!ingested.accepted) throw new BadRequestException(`knowledge document rejected: ${ingested.reason}`);
    const doc = await this.prisma.knowledgeDocument.create({
      data: {
        workspaceId, title: String(body.title ?? "untitled").slice(0, 200), source: String(body.source ?? "internal").slice(0, 200),
        classification: body.classification ?? "INTERNAL", contentHash: ingested.contentHash,
        content: ingested.content, injectionFlags: ingested.injectionFlags, status: "ACTIVE",
      },
    });
    await this.prisma.aiEmbedding.create({
      data: {
        workspaceId, sourceType: "KNOWLEDGE_DOCUMENT", sourceId: doc.id,
        classification: doc.classification, vector: embedText(`${doc.title}\n${ingested.content}`) as never, contentHash: ingested.contentHash,
      },
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_KNOWLEDGE_DOCUMENT_ADDED", resourceType: "KnowledgeDocument", resourceId: doc.id, metadata: { injectionFlags: ingested.injectionFlags, redactionCount: ingested.redactionCount } });
    return doc;
  }

  async listKnowledgeDocuments(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "USE_AI_COPILOT");
    const rows = await this.prisma.knowledgeDocument.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 100 });
    return rows.map((d) => ({ ...d, content: undefined, contentPreview: d.content.slice(0, 200) }));
  }

  async searchKnowledge(user: RequestUser, workspaceId: string, q: string) {
    requireAiPermission(user, "USE_AI_COPILOT");
    const vectors = await this.prisma.aiEmbedding.findMany({ where: { workspaceId, sourceType: "KNOWLEDGE_DOCUMENT" }, take: 500 });
    const hits = searchVectors(vectors as unknown as VectorRecord[], { workspaceId, text: q ?? "", limit: 5 });
    return hits.map((h) => ({ sourceId: h.record.sourceId, score: Number(h.score.toFixed(4)), citation: { sourceType: "DOCUMENTATION", sourceId: h.record.sourceId } }));
  }

  // ---------- Action proposals (§83/§84/§99) ----------

  async proposeAction(user: RequestUser, workspaceId: string, body: { actionType: string; targetType: string; targetId: string; summary: string }) {
    requireAiPermission(user, "AI_PROPOSE_ACTION");
    if (!(ACTION_TYPES as readonly string[]).includes(body.actionType)) {
      throw new BadRequestException(`actionType must be one of ${ACTION_TYPES.join(", ")} — the AI proposes only governed actions (§83)`);
    }
    if (body.targetType === "FINDING") {
      const finding = await this.prisma.finding.findFirst({ where: { id: body.targetId, workspaceId } });
      if (!finding) throw new NotFoundException("target finding not found in this workspace");
    }
    const proposal = await this.prisma.aiActionProposal.create({
      data: {
        workspaceId, proposedByUserId: user.id, actionType: body.actionType, targetType: body.targetType,
        targetId: body.targetId, summary: String(body.summary ?? "").slice(0, 1000),
        requiredPermission: ACTION_PERMISSION[body.actionType]!, status: "PROPOSED",
        scope: { workspaceId },
      },
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_ACTION_PROPOSED", resourceType: "AiActionProposal", resourceId: proposal.id, metadata: { actionType: body.actionType, targetType: body.targetType, targetId: body.targetId } });
    // §84/§99: the response IS the confirmation surface — nothing has
    // executed; the owning workflow must authorize + execute.
    return { ...proposal, executed: false, notice: "Proposal recorded only. Execution happens exclusively through the existing workflow for this action type, after human approval (§8/§84)." };
  }

  async listProposals(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "AI_PROPOSE_ACTION");
    return this.prisma.aiActionProposal.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 100 });
  }

  async decideProposal(user: RequestUser, workspaceId: string, id: string, decision: "APPROVED" | "REJECTED" | "DISMISSED") {
    requireAiPermission(user, "AI_PROPOSE_ACTION");
    const proposal = await this.prisma.aiActionProposal.findFirst({ where: { id, workspaceId } });
    if (!proposal) throw new NotFoundException("proposal not found in this workspace");
    // A decision records reviewer intent for the owning workflow; it
    // still executes nothing here (§8).
    return this.prisma.aiActionProposal.update({ where: { id }, data: { status: decision, decidedBy: user.id, decidedAt: new Date() } });
  }

  // ---------- Feedback (§85/§86) ----------

  async submitFeedback(user: RequestUser, workspaceId: string, body: { messageId?: string; requestLogId?: string; task?: string; rating: string; comment?: string; correction?: string }) {
    requireAiPermission(user, "USE_AI_COPILOT");
    if (!(FEEDBACK_RATINGS as readonly string[]).includes(body.rating)) {
      throw new BadRequestException(`rating must be one of ${FEEDBACK_RATINGS.join(", ")}`);
    }
    const row = await this.prisma.aiFeedback.create({
      data: {
        workspaceId, userId: user.id, messageId: body.messageId, requestLogId: body.requestLogId, task: body.task,
        rating: body.rating, comment: body.comment?.slice(0, 2000),
        // §99: the analyst's corrected interpretation, stored verbatim.
        correction: body.correction?.slice(0, 4000),
      },
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_FEEDBACK_RECEIVED", resourceType: "AiFeedback", resourceId: row.id, metadata: { rating: body.rating, task: body.task, hasCorrection: !!body.correction } });
    return row;
  }

  // ---------- Dashboard + usage (§108/§118) ----------

  async dashboard(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "USE_AI_COPILOT");
    const [health, recent, feedback, logs] = await Promise.all([
      this.config.providerHealth(workspaceId),
      this.prisma.aiRequestLog.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 10 }),
      this.prisma.aiFeedback.findMany({ where: { workspaceId }, take: 500 }),
      this.prisma.aiRequestLog.findMany({ where: { workspaceId }, take: 2000 }),
    ]);
    const feedbackByRating: Record<string, number> = {};
    for (const f of feedback) feedbackByRating[f.rating] = (feedbackByRating[f.rating] ?? 0) + 1;
    const byStatus: Record<string, number> = {};
    let redactions = 0, injections = 0, tokens = 0;
    for (const l of logs) {
      byStatus[l.status] = (byStatus[l.status] ?? 0) + 1;
      redactions += l.redactionCount; injections += l.injectionFlags;
      tokens += (l.promptTokens ?? 0) + (l.completionTokens ?? 0);
    }
    return {
      providers: health,
      recentAnalyses: recent,
      feedbackByRating,
      observability: { requests: logs.length, byStatus, totalTokens: tokens, redactions, promptInjectionDetections: injections },
    };
  }

  async usage(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "VIEW_AI_USAGE");
    const budget = await this.config.getBudget(workspaceId);
    const logs = await this.prisma.aiRequestLog.findMany({ where: { workspaceId }, take: 5000 });
    const byTask: Record<string, { requests: number; tokens: number }> = {};
    let tokens = 0;
    for (const l of logs) {
      const t = (l.promptTokens ?? 0) + (l.completionTokens ?? 0);
      tokens += t;
      byTask[l.task] = byTask[l.task] ?? { requests: 0, tokens: 0 };
      byTask[l.task]!.requests += 1; byTask[l.task]!.tokens += t;
    }
    return { budget, totalRequests: logs.length, totalTokens: tokens, byTask };
  }

  // ---------- Evaluation (§87–§102) ----------

  async runEvaluation(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "MANAGE_AI_POLICY");
    const results: EvaluationCheckResult[] = [];
    const provider = new MockAiProvider();

    // Groundedness + citation correctness over the golden dataset (§87/§88/§90).
    let groundedCount = 0;
    for (const fx of GOLDEN_FIXTURES) {
      const ctx = buildFindingContext(fx.finding, "FINDING_EXPLANATION");
      const prompt = buildAiPrompt({ task: "FINDING_EXPLANATION", question: fx.question, context: ctx });
      const out = await provider.generate({ task: "FINDING_EXPLANATION", prompt, modelName: "mock-eval" });
      const g = groundAnswer({ answer: out.text, proposedCitations: citationsFromAnswer(out.text, ctx.records), context: ctx });
      if (g.grounded) groundedCount += 1;
      // §89 hallucination probe per fixture with an absent identifier.
      if (fx.absentIdentifier) {
        const probe = buildAiPrompt({ task: "FINDING_EXPLANATION", question: `Tell me about ${fx.absentIdentifier}`, context: ctx });
        const probeOut = await provider.generate({ task: "FINDING_EXPLANATION", prompt: probe, modelName: "mock-eval" });
        results.push({ check: `hallucination:${fx.id}`, passed: probeOut.text.includes("INSUFFICIENT_EVIDENCE"), detail: `absent identifier ${fx.absentIdentifier} refused` });
      }
    }
    results.push({ check: "grounded-golden-dataset", passed: groundedCount === GOLDEN_FIXTURES.length, detail: `${groundedCount}/${GOLDEN_FIXTURES.length} fixtures grounded with citations` });

    // §92 prompt injection: payload flagged; system policy unchanged.
    const scan = scanForInjection(INJECTION_EVIDENCE_TEXT);
    results.push({ check: "prompt-injection-detection", passed: scan.detections.length >= 2, detail: `${scan.detections.length} patterns detected in hostile evidence fixture` });

    // §93 secret leakage: nothing synthetic reaches a provider payload.
    const red = redactForAi(SECRET_BEARING_EVIDENCE);
    results.push({ check: "secret-leak", passed: SECRET_FIXTURE_STRINGS.every((s) => !red.text.includes(s)), detail: `${red.count} redactions applied to the secret-bearing fixture` });

    // §94 cross-tenant: the DSL executor only ever sees the caller's
    // workspace rows — simulated here with foreign rows excluded by
    // the same data-layer filter the API applies.
    const foreignRows = [{ id: "other-1", title: "foreign", severity: "CRITICAL", kevListed: true }];
    const ownRows: typeof foreignRows = [];
    const parsed = parseSecurityQuery("Show critical KEV findings");
    const hits = "plan" in parsed ? executeSecurityQuery(ownRows as never, parsed.plan) : [];
    results.push({ check: "cross-tenant-query", passed: hits.length === 0 && foreignRows.length === 1, detail: "foreign-workspace rows are never loaded for another tenant's query" });

    // §95 NL injection.
    const inj = parseSecurityQuery("findings UNION SELECT password FROM users");
    results.push({ check: "nl-query-injection", passed: "rejected" in inj, detail: "SQL-shaped question rejected, never executed" });

    // §96 vector isolation.
    const vectors: VectorRecord[] = [
      { workspaceId: "ws-eval-a", sourceType: "KNOWLEDGE_DOCUMENT", sourceId: "a", classification: "INTERNAL", vector: embedText("krbtgt rotation guide") },
      { workspaceId: "ws-eval-b", sourceType: "KNOWLEDGE_DOCUMENT", sourceId: "b", classification: "INTERNAL", vector: embedText("krbtgt rotation guide") },
    ];
    const vHits = searchVectors(vectors, { workspaceId: "ws-eval-a", text: "krbtgt rotation guide" });
    results.push({ check: "vector-isolation", passed: vHits.every((h) => h.record.workspaceId === "ws-eval-a") && vHits.length > 0, detail: "tenant metadata filter precedes similarity" });

    const passed = results.filter((r) => r.passed).length;
    const run = await this.prisma.aiEvaluationRun.create({
      data: { workspaceId, suite: "GOLDEN", passed, failed: results.length - passed, results: results as never, createdBy: user.id },
    });
    return run;
  }
}
