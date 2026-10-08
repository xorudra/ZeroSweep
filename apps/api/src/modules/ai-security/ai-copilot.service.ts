import { BadRequestException, ForbiddenException, HttpException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  MockAiProvider, AiProviderError, buildAiPrompt,
  citationsFromAnswer, computeAiConfidence, evaluateAiBudget, evaluateAiTaskPolicy, groundAnswer,
  isExecutionShapedRequest, redactForAi, ruleBasedAnswer, sanitizeAiMarkdown, scanForInjection,
  type AIProvider, type AiBuiltContext, type AiTaskType, type GroundedResponse,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { requireAiPermission, TASK_PERMISSION } from "./permissions";
import { AiConfigService } from "./ai-config.service";
import { AiContextService } from "./ai-context.service";

export interface CopilotRunResult extends GroundedResponse {
  requestLogId: string;
  status: string;
  modelName?: string;
  providerName?: string;
  /** §54–§56: advisory only — never auto-applied. */
  suggestions: { kind: string; detail: string }[];
}

/** Extract a fenced diff block from a model answer for §34 patch records. */
export function extractSuggestedDiff(answer: string): string | null {
  const m = /```(?:diff)?\n((?:[-+@].*\n?)+)```/.exec(answer);
  return m ? m[1]!.trim() : null;
}

/**
 * The copilot pipeline (Prompt 21 §1): RBAC → tenant-filtered context
 * (§11/§12) → injection scan (§20) → redaction (§15) → task policy
 * (§6) → budget (§104) → provider (§3) → grounding (§21) → confidence
 * (§26) → output sanitization (§79) → request log (§63) + audit
 * (§117). The AI has NO execution path anywhere in this flow (§7/§8):
 * the only writes are copilot-owned records (logs, messages,
 * citations, proposals, patches-as-drafts).
 */
@Injectable()
export class AiCopilotService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly config: AiConfigService,
    private readonly contexts: AiContextService,
  ) {}

  private buildProvider(providerType: string): AIProvider {
    // Only the deterministic in-process MOCK transport is provisioned
    // in this build. External/LOCAL provider transports are honestly
    // reported as errors (the copilot degrades, the platform doesn't).
    if (providerType === "MOCK") return new MockAiProvider();
    return {
      name: "unprovisioned-transport",
      type: providerType,
      async generate(): Promise<never> {
        throw new AiProviderError("PROVIDER_ERROR", `provider transport for ${providerType} is not provisioned in this build`);
      },
      async healthCheck() { return { status: "NOT_CONFIGURED", latencyMs: 0 }; },
      capabilities() { return { generate: false, stream: false, embed: false }; },
      modelMetadata(modelName: string) { return { modelName, contextLimit: 0 }; },
    };
  }

  async runTask(user: RequestUser, workspaceId: string, task: AiTaskType, opts: {
    context: AiBuiltContext;
    question?: string;
    audience?: "EXECUTIVE" | "DEVELOPER" | "SECURITY_ANALYST";
    findingId?: string;
    verificationStatus?: string;
    scannerConfidence?: number;
  }): Promise<CopilotRunResult> {
    const permission = TASK_PERMISSION[task] ?? "USE_AI_COPILOT";
    requireAiPermission(user, permission); // §11/§116: RBAC before anything is retrieved or sent
    const started = Date.now();
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_REQUEST_CREATED", resourceType: "AiTask", resourceId: opts.findingId, metadata: { task } });

    const policy = await this.config.getPolicy(workspaceId);
    const budgetCfg = await this.config.getBudget(workspaceId);

    // §20: injection scan over UNTRUSTED context text.
    let injectionFlags = 0;
    let worstTrust = 1;
    for (const rec of opts.context.records) {
      if (rec.trust !== "UNTRUSTED") continue;
      const scan = scanForInjection(Object.values(rec.fields).join("\n"));
      injectionFlags += scan.detections.length;
      worstTrust = Math.min(worstTrust, scan.trustScore);
    }

    // §15: redact every field value before anything can reach a provider.
    let redactionCount = 0;
    const redactedRecords = opts.context.records.map((rec) => {
      const fields: Record<string, string> = {};
      for (const [k, v] of Object.entries(rec.fields)) {
        const r = redactForAi(v);
        redactionCount += r.count;
        fields[k] = r.text;
      }
      return { ...rec, fields };
    });
    const context: AiBuiltContext = { ...opts.context, records: redactedRecords };
    if (redactionCount > 0) {
      await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_CONTEXT_REDACTED", resourceType: "AiTask", metadata: { task, redactionCount } });
    }

    const resolved = await this.config.resolveProvider(workspaceId, policy);
    const decision = evaluateAiTaskPolicy({
      task,
      maxClassification: context.maxClassification,
      includesSourceCode: context.includesSourceCode,
      includesRawEvidence: context.includesRawEvidence,
      provider: resolved?.primary.dataPolicy ?? null,
      workspace: policy,
    });

    const persistLog = async (status: string, extra: { providerName?: string; modelName?: string; promptTokens?: number; completionTokens?: number; citationCount?: number }) => {
      const log = await this.prisma.aiRequestLog.create({
        data: {
          workspaceId, userId: user.id, task, status,
          policyDecision: decision.decision,
          providerName: extra.providerName, modelName: extra.modelName,
          latencyMs: Date.now() - started,
          promptTokens: extra.promptTokens, completionTokens: extra.completionTokens,
          redactionCount, injectionFlags, citationCount: extra.citationCount ?? 0,
          contextHash: context.contextHash,
        },
      });
      return log.id as string;
    };

    if (decision.decision === "DENY") {
      await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_POLICY_BLOCKED", resourceType: "AiTask", metadata: { task, reasons: decision.reasons } });
      const requestLogId = await persistLog("POLICY_BLOCKED", {});
      throw new ForbiddenException({ message: `AI task blocked by policy: ${decision.reasons.join("; ")}`, requestLogId });
    }

    // §104/§105 budget + rate gate (before any provider spend).
    const dayStart = new Date(); dayStart.setHours(0, 0, 0, 0);
    const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0, 0, 0, 0);
    const [dayLogs, monthLogs, userDayCount, taskDayCount] = await Promise.all([
      this.prisma.aiRequestLog.findMany({ where: { workspaceId, createdAt: { gte: dayStart } } }),
      this.prisma.aiRequestLog.findMany({ where: { workspaceId, createdAt: { gte: monthStart } } }),
      this.prisma.aiRequestLog.count({ where: { workspaceId, userId: user.id, createdAt: { gte: dayStart } } }),
      this.prisma.aiRequestLog.count({ where: { workspaceId, task, createdAt: { gte: dayStart } } }),
    ]);
    const sumTokens = (rows: { promptTokens?: number | null; completionTokens?: number | null }[]) =>
      rows.reduce((s, r) => s + (r.promptTokens ?? 0) + (r.completionTokens ?? 0), 0);
    const budget = evaluateAiBudget(
      { tokensToday: sumTokens(dayLogs), tokensThisMonth: sumTokens(monthLogs), requestsTodayByUser: userDayCount, requestsTodayByTask: taskDayCount },
      { dailyTokenLimit: budgetCfg.dailyTokenLimit, monthlyTokenLimit: budgetCfg.monthlyTokenLimit, perTaskTokenLimit: budgetCfg.perTaskTokenLimit, maxRequestsPerUserPerDay: 500, maxRequestsPerTaskPerDay: 2000 },
      context.estimatedTokens,
    );
    if (!budget.allowed) {
      const requestLogId = await persistLog("POLICY_BLOCKED", {});
      await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_POLICY_BLOCKED", resourceType: "AiTask", metadata: { task, reason: budget.reason } });
      throw new HttpException({ message: budget.reason, requestLogId }, 429);
    }

    const finish = async (response: GroundedResponse, status: string, extra: { providerName?: string; modelName?: string; promptTokens?: number; completionTokens?: number }): Promise<CopilotRunResult> => {
      const requestLogId = await persistLog(status, { ...extra, citationCount: response.citations.length });
      for (const c of response.citations) {
        await this.prisma.aiCitation.create({
          data: { workspaceId, requestLogId, claim: c.claim, sourceType: c.sourceType, sourceId: c.sourceId, evidenceReference: c.evidenceReference, confidence: c.confidence },
        });
      }
      await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_RESPONSE_GENERATED", resourceType: "AiTask", resourceId: opts.findingId, metadata: { task, status, origin: response.origin, citations: response.citations.length } });
      return { ...response, requestLogId, status, modelName: extra.modelName, providerName: extra.providerName, suggestions: this.deriveSuggestions(opts, response) };
    };

    // §103: no provider → honest NOT_CONFIGURED + RULE_BASED answer.
    if (!resolved) {
      const rb = ruleBasedAnswer(task, context, []);
      const citations = context.records.slice(0, 8).map((r) => ({ claim: `record included in rule-based summary`, sourceType: r.sourceType, sourceId: r.sourceId, confidence: 0.6 }));
      const withCitations = { ...rb, citations, injectionFlags, redactionCount };
      return finish(withCitations, "NOT_CONFIGURED", {});
    }

    const prompt = buildAiPrompt({ task, question: opts.question, context, audience: opts.audience });
    const attempt = async (candidate: NonNullable<typeof resolved>["primary"]): Promise<CopilotRunResult> => {
      const provider = this.buildProvider(candidate.dataPolicy.providerType);
      const out = await provider.generate({ task, prompt, modelName: candidate.modelName });
      const citations = citationsFromAnswer(out.text, context.records);
      const grounded = groundAnswer({ answer: out.text, proposedCitations: citations, context });
      const conf = computeAiConfidence({
        citationCoverage: grounded.citationCoverage,
        sourceQuality: context.records.length ? context.records.filter((r) => r.trust === "TRUSTED").length / context.records.length : 0,
        scannerConfidence: opts.scannerConfidence,
        verificationStatus: opts.verificationStatus,
        injectionTrust: worstTrust,
        missingFieldCount: 0,
      });
      const insufficient = out.text.includes("INSUFFICIENT_EVIDENCE") || grounded.unsupportedReferences.length > 0;
      const response: GroundedResponse = {
        answer: sanitizeAiMarkdown(out.text),
        citations: grounded.citations,
        confidence: conf.level,
        assumptions: [],
        missingData: grounded.unsupportedReferences.map((id) => `identifier not present in authorized context: ${id}`),
        origin: "MODEL",
        insufficientEvidence: insufficient,
        injectionFlags, redactionCount,
      };
      // §34: secure-code answers carrying a diff become PROPOSED patch records (review-only, §35).
      if (task === "SECURE_CODE_GUIDANCE" && opts.findingId) {
        const diff = extractSuggestedDiff(out.text);
        if (diff) {
          await this.prisma.aiSuggestedPatch.create({
            data: { workspaceId, findingId: opts.findingId, diff, modelName: candidate.modelName, citations: grounded.citations as never, confidence: conf.level, status: "PROPOSED" },
          });
        }
      }
      return finish(response, insufficient ? "INSUFFICIENT_EVIDENCE" : "COMPLETED", {
        providerName: candidate.dataPolicy.providerName, modelName: candidate.modelName,
        promptTokens: out.promptTokens, completionTokens: out.completionTokens,
      });
    };

    try {
      return await attempt(resolved.primary);
    } catch (err) {
      if (err instanceof AiProviderError) {
        // §107: policy-controlled fallback — the fallback provider is
        // policy-evaluated on its own merits; data policy never downgrades.
        if (resolved.fallback) {
          const fbDecision = evaluateAiTaskPolicy({
            task, maxClassification: context.maxClassification, includesSourceCode: context.includesSourceCode,
            includesRawEvidence: context.includesRawEvidence, provider: resolved.fallback.dataPolicy, workspace: policy,
          });
          if (fbDecision.decision !== "DENY") {
            try { return await attempt(resolved.fallback); } catch { /* fall through to rule-based */ }
          }
        }
        const rb = ruleBasedAnswer(task, context, []);
        const citations = context.records.slice(0, 8).map((r) => ({ claim: "record included in rule-based summary", sourceType: r.sourceType, sourceId: r.sourceId, confidence: 0.6 }));
        return finish({ ...rb, citations, injectionFlags, redactionCount }, "PROVIDER_ERROR", {});
      }
      throw err;
    }
  }

  /** §54–§56 advisory derivations — suggestions only, never applied. */
  private deriveSuggestions(opts: { findingId?: string; verificationStatus?: string; scannerConfidence?: number }, response: GroundedResponse): { kind: string; detail: string }[] {
    const out: { kind: string; detail: string }[] = [];
    if (opts.findingId && opts.verificationStatus === "UNVERIFIED" && (opts.scannerConfidence ?? 1) < 0.4 && response.citations.length <= 1) {
      out.push({ kind: "LIKELY_FALSE_POSITIVE", detail: "Low scanner confidence, unverified, thin evidence — an analyst should review; the AI cannot close findings (§54)." });
    }
    return out;
  }

  // ---------- Finding tasks (§28/§30/§32/§37) ----------

  async explainFinding(user: RequestUser, workspaceId: string, findingId: string, body: { audience?: "EXECUTIVE" | "DEVELOPER" | "SECURITY_ANALYST"; question?: string }) {
    const { input, context } = await this.contexts.buildFindingContext(workspaceId, findingId, "FINDING_EXPLANATION");
    return this.runTask(user, workspaceId, "FINDING_EXPLANATION", {
      context, question: body.question, audience: body.audience ?? "SECURITY_ANALYST", findingId,
      verificationStatus: input.verificationStatus, scannerConfidence: input.confidence,
    });
  }

  async findingTask(user: RequestUser, workspaceId: string, findingId: string, task: AiTaskType, body: { question?: string } = {}) {
    const { input, context } = await this.contexts.buildFindingContext(workspaceId, findingId, task);
    return this.runTask(user, workspaceId, task, {
      context, question: body.question, findingId,
      verificationStatus: input.verificationStatus, scannerConfidence: input.confidence,
    });
  }

  // ---------- Scan / asset summaries (§46–§48) ----------

  async scanSummary(user: RequestUser, workspaceId: string, scanId: string) {
    const budgetCfg = await this.config.getBudget(workspaceId);
    const context = await this.contexts.loadScanContext(workspaceId, scanId, budgetCfg.maxRetrievalRecords);
    return this.runTask(user, workspaceId, "SCAN_SUMMARY", { context });
  }

  async assetSummary(user: RequestUser, workspaceId: string, assetId: string) {
    const budgetCfg = await this.config.getBudget(workspaceId);
    const context = await this.contexts.loadAssetContext(workspaceId, assetId, budgetCfg.maxRetrievalRecords);
    return this.runTask(user, workspaceId, "ASSET_SUMMARY", { context });
  }

  // ---------- Report drafting (§49–§51) ----------

  async draftFromReport(user: RequestUser, workspaceId: string, reportId: string, body: { section?: string }) {
    requireAiPermission(user, "AI_DRAFT_REPORT");
    const { context, snapshotHash } = await this.contexts.loadReportSnapshotContext(workspaceId, reportId);
    const result = await this.runTask(user, workspaceId, "REPORT_DRAFTING", { context, question: body.section ?? "Draft the executive summary for this report." });
    // §51 provenance: the draft is traceable to model + snapshot.
    return { ...result, provenance: { snapshotHash, section: body.section ?? "EXECUTIVE_SUMMARY", reviewStatus: "UNREVIEWED" } };
  }

  // ---------- Workspace chat (§57–§62) ----------

  async listConversations(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "USE_AI_COPILOT");
    const policy = await this.prisma.aiWorkspacePolicy.findFirst({ where: { workspaceId } });
    const retentionDays = policy?.chatRetentionDays ?? 30;
    const cutoff = new Date(Date.now() - retentionDays * 86400000);
    const rows = await this.prisma.aiConversation.findMany({ where: { workspaceId, userId: user.id, updatedAt: { gte: cutoff } }, orderBy: { updatedAt: "desc" }, take: 50 });
    return rows;
  }

  async getConversation(user: RequestUser, workspaceId: string, id: string) {
    requireAiPermission(user, "USE_AI_COPILOT");
    const conv = await this.prisma.aiConversation.findFirst({ where: { id, workspaceId, userId: user.id } });
    if (!conv) throw new NotFoundException("conversation not found");
    const messages = await this.prisma.aiMessage.findMany({ where: { conversationId: id, workspaceId }, orderBy: { createdAt: "asc" }, take: 200 });
    return { conversation: conv, messages };
  }

  async chat(user: RequestUser, workspaceId: string, body: { conversationId?: string; message: string; contextType?: string; contextId?: string }) {
    requireAiPermission(user, "USE_AI_COPILOT");
    const message = (body.message ?? "").slice(0, 8000);
    if (!message.trim()) throw new BadRequestException("message is required");

    let conv = body.conversationId
      ? await this.prisma.aiConversation.findFirst({ where: { id: body.conversationId, workspaceId, userId: user.id } })
      : null;
    if (body.conversationId && !conv) throw new NotFoundException("conversation not found");
    if (!conv) {
      conv = await this.prisma.aiConversation.create({
        data: { workspaceId, userId: user.id, contextType: body.contextType ?? "WORKSPACE", contextId: body.contextId ?? null, title: message.slice(0, 80) },
      });
    }

    // User message is stored SANITIZED (§60) — and scanned: a user
    // asking the copilot to execute something is refused by policy
    // (§7/§120) and audited, never routed to any executor.
    const sanitizedUser = sanitizeAiMarkdown(message);
    await this.prisma.aiMessage.create({ data: { conversationId: conv.id, workspaceId, role: "USER", content: sanitizedUser } });

    if (isExecutionShapedRequest(message)) {
      await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_POLICY_BLOCKED", resourceType: "AiConversation", resourceId: conv.id, metadata: { task: "COPILOT_CHAT", reason: "execution-shaped request" } });
      const refusal = "The copilot is an analyst assistant: it cannot run scans, shell commands, SQL or any tool (§7/§120). I can explain findings, summarize evidence, draft remediation, or propose an action for the normal approval workflow.";
      const log = await this.prisma.aiRequestLog.create({ data: { workspaceId, userId: user.id, task: "COPILOT_CHAT", status: "POLICY_BLOCKED", policyDecision: "DENY" } });
      const assistant = await this.prisma.aiMessage.create({
        data: { conversationId: conv.id, workspaceId, role: "ASSISTANT", content: refusal, answerOrigin: "NONE", requestLogId: log.id },
      });
      return { conversationId: conv.id, message: assistant, response: { answer: refusal, citations: [], confidence: "HIGH", origin: "NONE", insufficientEvidence: false } };
    }

    // Contextual chat (§58): a bound context loads its governed context.
    let context: AiBuiltContext;
    const ctxType = body.contextType ?? conv.contextType;
    const ctxId = body.contextId ?? conv.contextId ?? undefined;
    if (ctxType === "FINDING" && ctxId) {
      context = (await this.contexts.buildFindingContext(workspaceId, ctxId, "COPILOT_CHAT")).context;
    } else if (ctxType === "ASSET" && ctxId) {
      const budgetCfg = await this.config.getBudget(workspaceId);
      context = await this.contexts.loadAssetContext(workspaceId, ctxId, budgetCfg.maxRetrievalRecords);
    } else if (ctxType === "SCAN" && ctxId) {
      const budgetCfg = await this.config.getBudget(workspaceId);
      context = await this.contexts.loadScanContext(workspaceId, ctxId, budgetCfg.maxRetrievalRecords);
    } else {
      // Workspace-level chat: top-risk findings as bounded context (§10).
      const budgetCfg = await this.config.getBudget(workspaceId);
      const findings = await this.prisma.finding.findMany({ where: { workspaceId }, orderBy: { riskScore: "desc" }, take: budgetCfg.maxRetrievalRecords });
      context = this.contexts.buildAggregateContext({
        meta: { sourceType: "DOCUMENTATION", sourceId: workspaceId, classification: "INTERNAL", trust: "TRUSTED", fields: { kind: "WORKSPACE_OVERVIEW", openFindingsInContext: String(findings.length) } },
        findings, limitations: findings.length === 0 ? ["no findings exist in this workspace yet"] : [], maxRecords: budgetCfg.maxRetrievalRecords,
      });
    }

    const result = await this.runTask(user, workspaceId, "COPILOT_CHAT", { context, question: message });
    const assistant = await this.prisma.aiMessage.create({
      data: {
        conversationId: conv.id, workspaceId, role: "ASSISTANT", content: result.answer,
        modelName: result.modelName, providerName: result.providerName, answerOrigin: result.origin,
        confidence: result.confidence, citations: result.citations as never, requestLogId: result.requestLogId,
      },
    });
    await this.prisma.aiConversation.update({ where: { id: conv.id }, data: { updatedAt: new Date() } });
    return { conversationId: conv.id, message: assistant, response: result };
  }
}
