import type { AiDataClassification, AiTaskType } from "./types";
import { classificationRank } from "./types";

/**
 * AI Security Copilot V2 — provider/model routing (Prompt 36 §3–§9).
 *
 * V2 deepens the Prompt 21 provider abstraction on the SAME contract:
 * business logic depends on capabilities and policy only, never on a
 * vendor (§3). The router is deterministic: task type × data
 * classification × tenant (workspace) policy × model capability ×
 * cost × latency → one route decision with recorded reasons. Data
 * residency (§6) is a hard filter, not a preference: a model whose
 * provider region / externality violates the workspace data policy is
 * never selected, whatever its score.
 */

/** §9: V2 task types. The first block is new in Prompt 36; the rest
 *  re-uses the Prompt 21 task vocabulary unchanged. */
export const AI_TASK_TYPES_V2 = [
  "SECURITY_QA",
  "ASSET_ANALYSIS",
  "VULNERABILITY_ANALYSIS",
  "ATTACK_PATH_ANALYSIS",
  "SCAN_PLAN_DRAFT",
  "SOC_INVESTIGATION",
  "INCIDENT_SUMMARY",
  "GRC_EVIDENCE_SUMMARY",
  "EXECUTIVE_SUMMARY",
  "TREND_ANALYSIS",
  "VERSION_COMPARISON",
] as const;
export type AiTaskTypeV2 = (typeof AI_TASK_TYPES_V2)[number];
export type AiSecurityTaskType = AiTaskType | AiTaskTypeV2;

export function isAiTaskTypeV2(t: string): t is AiTaskTypeV2 {
  return (AI_TASK_TYPES_V2 as readonly string[]).includes(t);
}

/** §7: the governed request envelope. `requestedActions` are NAMES of
 *  gateway capabilities the caller hopes to use — they are validated
 *  by the tool gateway, never trusted (§27/§28). */
export interface AiSecurityRequest {
  workspaceId: string;
  userId: string;
  conversationId?: string;
  taskType: AiSecurityTaskType;
  query: string;
  retrievalScope?: { sourceTypes?: string[]; resourceIds?: string[]; maxRecords?: number };
  requestedActions?: string[];
  modelPolicy?: { preferredModelId?: string; maxCostClass?: AiCostClass; maxLatencyClass?: AiLatencyClass };
  createdAt: string; // ISO
}

/** §22: V2 confidence adds INSUFFICIENT_EVIDENCE as a first-class
 *  level (Prompt 21 used LOW + a boolean flag; V2 surfaces it). */
export type AiConfidenceV2 = "HIGH" | "MEDIUM" | "LOW" | "INSUFFICIENT_EVIDENCE";

/** §20/§23: V2 citation object — extends the Prompt 21 citation with
 *  label, evidence timestamp, claim kind and an access reference the
 *  UI resolves through the caller's own permissions (§136). */
export interface AiCitationV2 {
  sourceType: string;
  sourceId: string;
  label: string;
  evidenceTimestamp?: string;
  confidence: number;
  accessReference: string; // e.g. "finding:<id>" — resolved by the UI under the viewer's RBAC
  claimKind: "OBSERVED" | "INFERRED" | "RECOMMENDED";
}

/** §8: the governed response envelope. `executed` is structurally
 *  always false: a copilot response never executes anything (§26). */
export interface AiSecurityResponse {
  requestId: string;
  answer: string;
  structuredOutput?: Record<string, unknown>;
  citations: AiCitationV2[];
  confidence: AiConfidenceV2;
  limitations: string[];
  modelMetadata: { providerName?: string; modelName?: string; origin: "MODEL" | "RULE_BASED" | "NONE"; transportStatus: string };
  latencyMs: number;
  executed: false;
  createdAt: string; // ISO
}

/** §4: model capability record (mirrors the AiModel registry row). */
export type AiCostClass = "FREE" | "LOW" | "MEDIUM" | "HIGH";
export type AiLatencyClass = "FAST" | "STANDARD" | "SLOW";
export interface AiModelCapability {
  modelId: string;
  providerName: string;
  providerType: string; // OPENAI_COMPATIBLE | ANTHROPIC | AZURE_OPENAI | LOCAL | MOCK
  modelName: string;
  contextWindow: number;
  structuredOutputSupport: boolean;
  toolCallingSupport: boolean;
  embeddingSupport: boolean;
  generateSupport: boolean;
  availability: "AVAILABLE" | "DEGRADED" | "UNAVAILABLE" | "NOT_CONFIGURED";
  costClass: AiCostClass;
  latencyClass: AiLatencyClass;
  isExternal: boolean;
  region?: string | null;
  approvedClassifications: AiDataClassification[];
  enabled: boolean;
}

/** §5/§6: tenant routing policy — workspace data policy applied at
 *  selection time. */
export interface AiRoutingPolicy {
  allowedModelIds: string[]; // empty = all workspace models allowed
  dataResidencyRegion?: string | null; // when set, external providers must match region; LOCAL always allowed
  allowExternalProviders: boolean;
  maxCostClass?: AiCostClass;
  preferredModelId?: string | null;
}

export interface AiRouteDecision {
  status: "ROUTED" | "NOT_CONFIGURED";
  model?: AiModelCapability;
  reasons: string[];
  rejected: { modelId: string; reason: string }[];
}

const COST_RANK: Record<AiCostClass, number> = { FREE: 0, LOW: 1, MEDIUM: 2, HIGH: 3 };
const LATENCY_RANK: Record<AiLatencyClass, number> = { FAST: 0, STANDARD: 1, SLOW: 2 };

/** Tasks whose outputs are schema-validated (§65) need structured
 *  output support; planning/agent tasks need tool-calling support. */
const STRUCTURED_TASKS: ReadonlySet<string> = new Set([
  "SCAN_PLAN_DRAFT", "SOC_INVESTIGATION", "INCIDENT_SUMMARY", "VERSION_COMPARISON", "TREND_ANALYSIS",
]);
const TOOL_TASKS: ReadonlySet<string> = new Set([
  "SCAN_PLAN_DRAFT", "SOC_INVESTIGATION", "VULNERABILITY_ANALYSIS", "ATTACK_PATH_ANALYSIS", "ASSET_ANALYSIS",
]);

/**
 * SecurityAiModelRouter (§5). Pure + deterministic: same inputs →
 * same decision, with every rejection reason recorded for the trace
 * (§128/§131). A task that needs a capability no eligible model has
 * resolves NOT_CONFIGURED — the router never silently downgrades the
 * requirement (§107 of Prompt 21, carried forward).
 */
export function routeAiModel(params: {
  taskType: AiSecurityTaskType;
  maxClassification: AiDataClassification;
  models: AiModelCapability[];
  policy: AiRoutingPolicy;
  requestPolicy?: AiSecurityRequest["modelPolicy"];
}): AiRouteDecision {
  const reasons: string[] = [];
  const rejected: { modelId: string; reason: string }[] = [];
  const needStructured = STRUCTURED_TASKS.has(params.taskType);
  const needTools = TOOL_TASKS.has(params.taskType);
  const maxCost = params.requestPolicy?.maxCostClass ?? params.policy.maxCostClass;
  const maxLatency = params.requestPolicy?.maxLatencyClass;

  const eligible = params.models.filter((m) => {
    const reject = (reason: string) => { rejected.push({ modelId: m.modelId, reason }); return false; };
    if (!m.enabled) return reject("model disabled");
    if (m.availability === "UNAVAILABLE" || m.availability === "NOT_CONFIGURED") return reject(`model availability is ${m.availability}`);
    if (!m.generateSupport) return reject("model does not support generation");
    if (params.policy.allowedModelIds.length > 0 && !params.policy.allowedModelIds.includes(m.modelId)) return reject("model not in workspace allowed-model list (§139)");
    // §6 data residency: external providers must respect the region
    // policy; SECRET never routes externally (Prompt 21 §14 carried).
    if (m.isExternal && !params.policy.allowExternalProviders) return reject("workspace data policy forbids external providers (§6)");
    if (m.isExternal && params.policy.dataResidencyRegion && m.region !== params.policy.dataResidencyRegion) {
      return reject(`data residency: provider region ${m.region ?? "unknown"} != required ${params.policy.dataResidencyRegion} (§6)`);
    }
    if (params.maxClassification === "SECRET" && m.isExternal) return reject("SECRET-classified data never routes to an external provider (§14/§15)");
    const approvedRank = Math.max(...m.approvedClassifications.map(classificationRank), -1);
    if (classificationRank(params.maxClassification) > approvedRank) return reject(`classification ${params.maxClassification} exceeds model approvals (§64)`);
    if (needStructured && !m.structuredOutputSupport) return reject(`task ${params.taskType} requires structured-output support (§65)`);
    if (needTools && !m.toolCallingSupport) return reject(`task ${params.taskType} requires tool-calling support (§27)`);
    if (maxCost && COST_RANK[m.costClass] > COST_RANK[maxCost]) return reject(`cost class ${m.costClass} exceeds policy ceiling ${maxCost} (§121)`);
    if (maxLatency && LATENCY_RANK[m.latencyClass] > LATENCY_RANK[maxLatency]) return reject(`latency class ${m.latencyClass} exceeds request ceiling ${maxLatency}`);
    return true;
  });

  if (eligible.length === 0) {
    return { status: "NOT_CONFIGURED", reasons: ["no eligible model for this task under workspace data policy — copilot degrades honestly (NOT_CONFIGURED / RULE_BASED)"], rejected };
  }
  const preferredId = params.requestPolicy?.preferredModelId ?? params.policy.preferredModelId ?? null;
  eligible.sort((a, b) => {
    if (preferredId) {
      if (a.modelId === preferredId && b.modelId !== preferredId) return -1;
      if (b.modelId === preferredId && a.modelId !== preferredId) return 1;
    }
    const cost = COST_RANK[a.costClass] - COST_RANK[b.costClass];
    if (cost !== 0) return cost;
    const lat = LATENCY_RANK[a.latencyClass] - LATENCY_RANK[b.latencyClass];
    if (lat !== 0) return lat;
    return b.contextWindow - a.contextWindow;
  });
  const chosen = eligible[0]!;
  reasons.push(`routed task ${params.taskType} to ${chosen.providerName}/${chosen.modelName} (cost ${chosen.costClass}, latency ${chosen.latencyClass}, context ${chosen.contextWindow})`);
  if (preferredId && chosen.modelId === preferredId) reasons.push("workspace/request preferred model selected");
  return { status: "ROUTED", model: chosen, reasons, rejected };
}
