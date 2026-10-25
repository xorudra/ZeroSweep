import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  APPLICATION_SECURITY_AGENT, CLOUD_SECURITY_AGENT, REMEDIATION_AGENT, SECURITY_ANALYSIS_AGENT,
  SOC_INVESTIGATION_AGENT, VULNERABILITY_ANALYSIS_AGENT, buildInvestigationTimeline,
  runBoundedAgent, validateAiStructuredOutput, type AiAgentDefinition, type AiSecurityResponse,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { aiPermissionsHeld, requireAiPermission } from "./permissions";
import { AiGatewayService } from "./ai-gateway.service";
import { AiCopilotService } from "./ai-copilot.service";
import { AiContextService } from "./ai-context.service";
import { AiRouterService } from "./ai-router.service";

/**
 * Security agents (Prompt 36 §51–§57) as bounded orchestrated
 * pipelines over the tool gateway + the governed copilot. Each agent
 * run: route (§5) → bounded tool intents through the gateway (§58)
 * → copilot narrative over governed context (Prompt 21 pipeline) →
 * schema-validated structured output (§65/§66) → sanitized trace
 * (§130). Agents produce analysis and drafts only; `executed` is
 * structurally false in every response (§51/§164).
 */
@Injectable()
export class AiAgentsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly gateway: AiGatewayService,
    private readonly copilot: AiCopilotService,
    private readonly contexts: AiContextService,
    private readonly router: AiRouterService,
  ) {}

  private async runAgent(user: RequestUser, workspaceId: string, agent: AiAgentDefinition, intents: { tool: string; args: Record<string, unknown> }[]) {
    return runBoundedAgent({
      agent,
      intents,
      gateContext: {
        userPermissions: aiPermissionsHeld(user), hasApproval: false, authorizationValid: false, callsThisHour: 0,
      },
      execute: async (tool, args) => {
        const out = await this.gateway.callTool(user, workspaceId, tool, args, { skipTrace: true });
        return { summary: out.summary, tokens: 25 };
      },
    });
  }

  private async trace(user: RequestUser, workspaceId: string, taskType: string, data: {
    requestLogId?: string; toolCalls: unknown; modelMetadata?: unknown; validationResults?: unknown;
  }) {
    await this.prisma.aiSecurityTrace.create({
      data: {
        workspaceId, userId: user.id, requestLogId: data.requestLogId ?? null, taskType,
        toolCalls: data.toolCalls as never, modelMetadata: (data.modelMetadata ?? {}) as never,
        validationResults: (data.validationResults ?? []) as never,
        timings: {},
      },
    });
  }

  /** §52 VulnerabilityAnalysisAgent + FINDING_EXPLANATION narrative. */
  async analyzeFinding(user: RequestUser, workspaceId: string, findingId: string): Promise<AiSecurityResponse & { agentRun: unknown; structuredOk: boolean }> {
    requireAiPermission(user, "AI_EXPLAIN_FINDING");
    const started = Date.now();
    const input = await this.contexts.loadFindingInput(workspaceId, findingId); // 404 cross-tenant
    const route = await this.router.route(user, workspaceId, "VULNERABILITY_ANALYSIS");
    const agentRun = await this.runAgent(user, workspaceId, VULNERABILITY_ANALYSIS_AGENT, [
      { tool: "getFinding", args: { findingId } },
      ...(input.cve ? [{ tool: "getCveIntel", args: { cveId: input.cve } }] : []),
      { tool: "getRiskExplanation", args: { findingId } },
      { tool: "getRemediationStatus", args: { findingId } },
    ]);
    const narrative = await this.copilot.findingTask(user, workspaceId, findingId, "FINDING_EXPLANATION");
    const structured = {
      findingId, summary: narrative.answer.slice(0, 2000),
      claims: narrative.citations.map((c) => ({ text: c.claim, kind: "OBSERVED" as const, citationSourceId: c.sourceId })),
    };
    const validation = validateAiStructuredOutput("FINDING_SUMMARY", structured);
    await this.trace(user, workspaceId, "VULNERABILITY_ANALYSIS", {
      requestLogId: narrative.requestLogId, toolCalls: agentRun.steps,
      modelMetadata: { routeStatus: route.status, providerName: narrative.providerName, modelName: narrative.modelName },
      validationResults: [validation],
    });
    return {
      requestId: narrative.requestLogId,
      answer: narrative.answer,
      structuredOutput: structured,
      citations: narrative.citations.map((c) => ({
        sourceType: c.sourceType, sourceId: c.sourceId, label: c.claim,
        confidence: c.confidence, accessReference: `${c.sourceType.toLowerCase()}:${c.sourceId}`, claimKind: "OBSERVED" as const,
      })),
      confidence: narrative.insufficientEvidence ? "INSUFFICIENT_EVIDENCE" : narrative.confidence,
      limitations: narrative.missingData,
      modelMetadata: { providerName: narrative.providerName, modelName: narrative.modelName, origin: narrative.origin, transportStatus: route.status },
      latencyMs: Date.now() - started,
      executed: false,
      createdAt: new Date().toISOString(),
      agentRun, structuredOk: validation.ok,
    };
  }

  /** §51/§55/§56 asset analysis — cloud/application agent chosen by
   *  asset type; narrative via the governed asset summary. */
  async analyzeAsset(user: RequestUser, workspaceId: string, assetId: string): Promise<AiSecurityResponse & { agentRun: unknown; agent: string }> {
    requireAiPermission(user, "USE_AI_COPILOT");
    const started = Date.now();
    const asset = await this.prisma.asset.findFirst({ where: { id: assetId, workspaceId } });
    if (!asset) throw new NotFoundException("asset not found in this workspace");
    const agent = /CLOUD|CONTAINER|KUBERNETES/i.test(String(asset.type ?? "")) ? CLOUD_SECURITY_AGENT : APPLICATION_SECURITY_AGENT;
    const route = await this.router.route(user, workspaceId, "ASSET_ANALYSIS");
    const agentRun = await this.runAgent(user, workspaceId, agent, [
      { tool: "getAsset", args: { assetId } },
      { tool: "searchFindings", args: { limit: 10 } },
      { tool: "summarizeCoverage", args: { limit: 5 } },
    ]);
    const narrative = await this.copilot.assetSummary(user, workspaceId, assetId);
    await this.trace(user, workspaceId, "ASSET_ANALYSIS", {
      requestLogId: narrative.requestLogId, toolCalls: agentRun.steps,
      modelMetadata: { routeStatus: route.status, agent: agent.name },
    });
    return {
      requestId: narrative.requestLogId,
      answer: narrative.answer,
      citations: narrative.citations.map((c) => ({
        sourceType: c.sourceType, sourceId: c.sourceId, label: c.claim, confidence: c.confidence,
        accessReference: `${c.sourceType.toLowerCase()}:${c.sourceId}`, claimKind: "OBSERVED" as const,
      })),
      confidence: narrative.insufficientEvidence ? "INSUFFICIENT_EVIDENCE" : narrative.confidence,
      limitations: narrative.missingData,
      modelMetadata: { providerName: narrative.providerName, modelName: narrative.modelName, origin: narrative.origin, transportStatus: route.status },
      latencyMs: Date.now() - started,
      executed: false,
      createdAt: new Date().toISOString(),
      agentRun, agent: agent.name,
    };
  }

  /** §54 SocInvestigationAgent — timeline (OBSERVED) + hypotheses
   *  (INFERRED, UNVERIFIED) + recommended analyst checks. No
   *  attribution claims and no response actions (§86, P28 guard). */
  async analyzeIncident(user: RequestUser, workspaceId: string, incidentId: string): Promise<AiSecurityResponse & { agentRun: unknown; structuredOk: boolean }> {
    requireAiPermission(user, "USE_AI_COPILOT");
    const started = Date.now();
    const route = await this.router.route(user, workspaceId, "SOC_INVESTIGATION");
    const agentRun = await this.runAgent(user, workspaceId, SOC_INVESTIGATION_AGENT, [
      { tool: "getIncident", args: { incidentId } },
      { tool: "searchFindings", args: { limit: 10 } },
    ]);
    const incidentStep = agentRun.steps.find((s) => s.tool === "getIncident");
    if (!incidentStep || incidentStep.verdict === "BLOCKED") {
      throw new NotFoundException("incident not found in this workspace");
    }
    const incident = await this.prisma.securityIncident.findFirst({ where: { id: incidentId, workspaceId } });
    if (!incident) throw new NotFoundException("incident not found in this workspace");
    const entries = await this.prisma.incidentTimelineEntry.findMany({ where: { incidentId, workspaceId }, orderBy: { createdAt: "asc" }, take: 50 });
    const links = await this.prisma.incidentLink.findMany({ where: { incidentId, workspaceId }, take: 50 }).catch(() => []);
    const timeline = buildInvestigationTimeline({
      events: (entries as Record<string, unknown>[]).map((e) => ({
        at: (e.createdAt as Date)?.toISOString?.() ?? String(e.createdAt), summary: String(e.summary ?? ""), sourceId: e.id as string,
      })),
      hypotheses: [
        `UNVERIFIED hypothesis: incident "${incident.title}" may correlate with ${(links as unknown[]).length} linked record(s) — an analyst must confirm against evidence before any conclusion.`,
      ],
    });
    const structured = { incidentId, events: timeline.events, hypotheses: timeline.hypotheses };
    const validation = validateAiStructuredOutput("INVESTIGATION_TIMELINE", structured);
    await this.trace(user, workspaceId, "SOC_INVESTIGATION", {
      toolCalls: agentRun.steps, modelMetadata: { routeStatus: route.status }, validationResults: [validation],
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "AI_REQUEST_CREATED", resourceType: "AiAgent", resourceId: incidentId,
      metadata: { task: "SOC_INVESTIGATION", agent: SOC_INVESTIGATION_AGENT.name },
    });
    return {
      requestId: `soc-${incidentId}`,
      answer: `Incident "${incident.title}" (${incident.severity}, ${incident.status}): ${timeline.events.length} timeline event(s) on record. Hypotheses are labelled UNVERIFIED and no attribution is made. Recommended analyst checks: review linked records, confirm containment state, and correlate related findings.`,
      structuredOutput: structured,
      citations: timeline.events.map((e) => ({
        sourceType: "SOC_INCIDENT", sourceId: incidentId, label: e.summary, confidence: 0.8,
        accessReference: `incident:${incidentId}`, claimKind: "OBSERVED" as const,
      })),
      confidence: timeline.events.length > 0 ? "MEDIUM" : "INSUFFICIENT_EVIDENCE",
      limitations: timeline.events.length === 0 ? ["no timeline entries recorded for this incident"] : [],
      modelMetadata: { origin: "RULE_BASED", transportStatus: route.status },
      latencyMs: Date.now() - started,
      executed: false,
      createdAt: new Date().toISOString(),
      agentRun, structuredOk: validation.ok,
    };
  }

  /** §53 RemediationAgent — draft guidance + verification
   *  recommendation for a finding (drafts only; §79–§83). */
  async remediationGuidance(user: RequestUser, workspaceId: string, findingId: string) {
    requireAiPermission(user, "AI_GENERATE_REMEDIATION");
    const agentRun = await this.runAgent(user, workspaceId, REMEDIATION_AGENT, [
      { tool: "getFinding", args: { findingId } },
      { tool: "getRemediationStatus", args: { findingId } },
      { tool: "draftRemediationPlan", args: { findingId } },
      { tool: "draftVerificationPlan", args: { findingId } },
    ]);
    const narrative = await this.copilot.findingTask(user, workspaceId, findingId, "REMEDIATION_GUIDANCE");
    await this.trace(user, workspaceId, "REMEDIATION_GUIDANCE", { requestLogId: narrative.requestLogId, toolCalls: agentRun.steps });
    return { agentRun, narrative, executed: false as const };
  }

  /** §51 general analysis agent over retrieval (§10) — the V2
   *  copilot entry point for SECURITY_QA / TREND_ANALYSIS. */
  async securityQa(user: RequestUser, workspaceId: string, body: { query: string; taskType?: string }) {
    requireAiPermission(user, "USE_AI_COPILOT");
    const narrative = await this.copilot.chat(user, workspaceId, { message: body.query });
    const requestLogId = (narrative.response as { requestLogId?: string }).requestLogId ?? undefined;
    await this.trace(user, workspaceId, body.taskType ?? "SECURITY_QA", { requestLogId, toolCalls: [] });
    return { ...narrative, executed: false as const };
  }
}
