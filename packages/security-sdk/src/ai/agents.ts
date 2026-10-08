import { detectToolLoop, evaluateAiToolCall, toolCallSignature, type AiToolCallContext } from "./gateway";

/**
 * Security agents + orchestrator (Prompt 36 §51–§60). Agents are
 * BOUNDED, structured pipelines over the tool gateway — not free-form
 * LLM loops (§58). Each agent declares the exact gateway tools it may
 * use and hard limits (max steps, tokens, tool calls, duration, §59);
 * the orchestrator executes a caller-supplied sequence of intended
 * tool calls through the gateway gate, detects loops (§60), and
 * terminates safely at any limit. Agent output is analysis and
 * recommendations only (§51): no agent definition includes an
 * execution capability, and the gateway would reject one anyway.
 */

export interface AiAgentDefinition {
  name: string;
  purpose: string;
  allowedTools: string[];
  maxSteps: number;
  maxTokens: number;
  maxToolCalls: number;
  maxDurationMs: number;
}

/** §51: the base analysis agent. */
export const SECURITY_ANALYSIS_AGENT: AiAgentDefinition = {
  name: "SecurityAnalysisAgent",
  purpose: "Retrieve, reason, correlate, plan, summarize and recommend over governed security data.",
  allowedTools: ["getAsset", "searchAssets", "getFinding", "searchFindings", "getScan", "getCoverage", "getRiskExplanation", "correlateFindings", "summarizeCoverage"],
  maxSteps: 8, maxTokens: 12000, maxToolCalls: 12, maxDurationMs: 60000,
};

/** §52: vulnerability analysis over finding + intel + verification. */
export const VULNERABILITY_ANALYSIS_AGENT: AiAgentDefinition = {
  name: "VulnerabilityAnalysisAgent",
  purpose: "Analyze finding, CVE/CVSS/EPSS/KEV, asset context, observations, verification and patch intelligence.",
  allowedTools: ["getFinding", "getCveIntel", "getRiskExplanation", "calculateExistingRisk", "getRemediationStatus", "getAsset"],
  maxSteps: 6, maxTokens: 10000, maxToolCalls: 8, maxDurationMs: 45000,
};

/** §53: remediation drafting (fix explanation, priority, owner
 *  suggestion, safe verification recommendation) — drafts only. */
export const REMEDIATION_AGENT: AiAgentDefinition = {
  name: "RemediationAgent",
  purpose: "Generate fix explanations, priorities, owner suggestions and safe verification recommendations.",
  allowedTools: ["getFinding", "getRemediationStatus", "getCveIntel", "draftRemediationPlan", "draftVerificationPlan"],
  maxSteps: 6, maxTokens: 10000, maxToolCalls: 8, maxDurationMs: 45000,
};

/** §54: SOC investigation — timeline + hypotheses (labelled
 *  unverified, §85). No destructive response capability (§86). */
export const SOC_INVESTIGATION_AGENT: AiAgentDefinition = {
  name: "SocInvestigationAgent",
  purpose: "Analyze alerts, events, assets, identities, findings and runtime signals into an incident timeline.",
  allowedTools: ["getIncident", "searchFindings", "getAsset", "searchAssets", "correlateFindings", "draftInvestigationPlan"],
  maxSteps: 8, maxTokens: 14000, maxToolCalls: 12, maxDurationMs: 60000,
};

/** §55: cloud posture analysis (posture, IAM, exposure, attack-path
 *  candidates, container/Kubernetes context) — analysis only. */
export const CLOUD_SECURITY_AGENT: AiAgentDefinition = {
  name: "CloudSecurityAnalysisAgent",
  purpose: "Analyze cloud posture, IAM, exposure and attack-path candidates with container/Kubernetes context.",
  allowedTools: ["getAsset", "searchAssets", "getFinding", "searchFindings", "buildAttackPathView", "getSBOM", "summarizeCoverage"],
  maxSteps: 8, maxTokens: 12000, maxToolCalls: 12, maxDurationMs: 60000,
};

/** §56: application security analysis (Web/API/SAST/dependencies/
 *  mobile/binary findings). */
export const APPLICATION_SECURITY_AGENT: AiAgentDefinition = {
  name: "ApplicationSecurityAgent",
  purpose: "Analyze Web, API, SAST, dependency, mobile and binary findings.",
  allowedTools: ["getFinding", "searchFindings", "getSBOM", "getCveIntel", "getRiskExplanation", "compareVersions"],
  maxSteps: 8, maxTokens: 12000, maxToolCalls: 12, maxDurationMs: 60000,
};

/** §57: report drafting (technical/executive/remediation/
 *  verification summaries) — drafts for human review (§144/§145). */
export const SECURITY_REPORT_AGENT: AiAgentDefinition = {
  name: "SecurityReportAgent",
  purpose: "Draft technical reports, executive summaries, remediation and verification summaries from canonical data.",
  allowedTools: ["getScan", "getCoverage", "searchFindings", "summarizeCoverage", "getRemediationStatus", "generateReportDraft"],
  maxSteps: 6, maxTokens: 14000, maxToolCalls: 8, maxDurationMs: 60000,
};

export const AI_AGENTS: AiAgentDefinition[] = [
  SECURITY_ANALYSIS_AGENT, VULNERABILITY_ANALYSIS_AGENT, REMEDIATION_AGENT,
  SOC_INVESTIGATION_AGENT, CLOUD_SECURITY_AGENT, APPLICATION_SECURITY_AGENT, SECURITY_REPORT_AGENT,
];

export function getAiAgent(name: string): AiAgentDefinition | undefined {
  return AI_AGENTS.find((a) => a.name === name);
}

export interface AiAgentToolIntent {
  tool: string;
  args: Record<string, unknown>;
  estimatedTokens?: number;
}

export interface AiAgentStepRecord {
  tool: string;
  verdict: "ALLOWED" | "BLOCKED";
  reason?: string;
  resultSummary?: string;
}

export interface AiAgentRunResult {
  agent: string;
  status: "COMPLETED" | "PARTIAL" | "TERMINATED_LOOP" | "TERMINATED_LIMIT" | "TERMINATED_DURATION";
  steps: AiAgentStepRecord[];
  toolCalls: number;
  tokensUsed: number;
  /** Agents never execute actions: always false (§51/§164). */
  executed: false;
}

/**
 * SecurityAgentOrchestrator core (§58–§60). Executes intended tool
 * calls in order through the gateway gate (§27) with the agent's
 * allowlist applied on top. The executor callback is supplied by the
 * API layer (governed read/analyze functions); the orchestrator
 * itself holds no data access. Any limit breach terminates the run
 * safely with the partial trace preserved.
 */
export async function runBoundedAgent(params: {
  agent: AiAgentDefinition;
  intents: AiAgentToolIntent[];
  gateContext: AiToolCallContext;
  execute: (tool: string, args: Record<string, unknown>) => Promise<{ summary: string; tokens?: number }>;
  now?: () => number;
}): Promise<AiAgentRunResult> {
  const now = params.now ?? Date.now;
  const started = now();
  const steps: AiAgentStepRecord[] = [];
  const signatures: string[] = [];
  let tokensUsed = 0;
  let toolCalls = 0;
  const finish = (status: AiAgentRunResult["status"]): AiAgentRunResult =>
    ({ agent: params.agent.name, status, steps, toolCalls, tokensUsed, executed: false });

  for (const intent of params.intents) {
    if (steps.length >= params.agent.maxSteps) return finish("TERMINATED_LIMIT");
    if (toolCalls >= params.agent.maxToolCalls) return finish("TERMINATED_LIMIT");
    if (now() - started > params.agent.maxDurationMs) return finish("TERMINATED_DURATION");
    if (tokensUsed + (intent.estimatedTokens ?? 0) > params.agent.maxTokens) return finish("TERMINATED_LIMIT");

    signatures.push(toolCallSignature(intent.tool, intent.args));
    const loop = detectToolLoop(signatures);
    if (loop.looping) {
      steps.push({ tool: intent.tool, verdict: "BLOCKED", reason: `loop detected: ${loop.signature} repeated ${loop.count} times — run terminated safely (§60)` });
      return finish("TERMINATED_LOOP");
    }
    if (!params.agent.allowedTools.includes(intent.tool)) {
      steps.push({ tool: intent.tool, verdict: "BLOCKED", reason: `tool ${intent.tool} is not in ${params.agent.name}'s allowlist (§51–§57)` });
      continue;
    }
    const verdict = evaluateAiToolCall(intent.tool, params.gateContext);
    if (!verdict.allowed) {
      steps.push({ tool: intent.tool, verdict: "BLOCKED", reason: verdict.reason });
      continue;
    }
    toolCalls += 1;
    const out = await params.execute(intent.tool, intent.args);
    tokensUsed += out.tokens ?? intent.estimatedTokens ?? 0;
    steps.push({ tool: intent.tool, verdict: "ALLOWED", resultSummary: out.summary });
  }
  const blocked = steps.some((s) => s.verdict === "BLOCKED");
  return finish(blocked ? "PARTIAL" : "COMPLETED");
}
