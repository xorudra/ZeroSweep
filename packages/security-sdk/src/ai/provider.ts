import type { AiPrompt } from "./prompts";
import type { AiCitation, AiTaskType, GroundedResponse } from "./types";

/**
 * AI provider abstraction (Prompt 21 §3/§65/§103/§107). Business
 * logic depends on this interface only — never on a vendor. Providers
 * receive the ALREADY redacted, policy-cleared prompt; they return
 * text + token metadata. A provider failure or absence degrades the
 * copilot to honest NOT_CONFIGURED / RULE_BASED behaviour — the core
 * platform never depends on AI (§103).
 */

export interface AiGenerateRequest {
  task: AiTaskType;
  prompt: AiPrompt;
  modelName: string;
  maxTokens?: number;
}

export interface AiGenerateResult {
  text: string;
  promptTokens: number;
  completionTokens: number;
  latencyMs: number;
}

export interface AiProviderCapabilities {
  generate: boolean;
  stream: boolean;
  embed: boolean;
}

export interface AIProvider {
  readonly name: string;
  readonly type: string;
  generate(req: AiGenerateRequest): Promise<AiGenerateResult>;
  healthCheck(): Promise<{ status: string; latencyMs: number }>;
  capabilities(): AiProviderCapabilities;
  modelMetadata(modelName: string): { modelName: string; contextLimit: number };
}

/** No provider configured (§103): every call reports NOT_CONFIGURED. */
export class UnconfiguredAiProvider implements AIProvider {
  readonly name = "unconfigured";
  readonly type = "NONE";
  async generate(): Promise<AiGenerateResult> {
    throw new AiProviderError("NOT_CONFIGURED", "no AI provider is configured for this workspace");
  }
  async healthCheck() {
    return { status: "NOT_CONFIGURED", latencyMs: 0 };
  }
  capabilities(): AiProviderCapabilities {
    return { generate: false, stream: false, embed: false };
  }
  modelMetadata(modelName: string) {
    return { modelName, contextLimit: 0 };
  }
}

export class AiProviderError extends Error {
  constructor(public readonly code: "NOT_CONFIGURED" | "PROVIDER_ERROR" | "RATE_LIMITED" | "BUDGET_EXHAUSTED", message: string) {
    super(message);
    this.name = "AiProviderError";
  }
}

/**
 * Deterministic mock provider for tests and offline development. It
 * is deliberately a FAITHFUL stand-in: it composes its answer ONLY
 * from records present in the prompt's structured context, cites the
 * record ids it used, and produces INSUFFICIENT_EVIDENCE when the
 * question references an identifier that is not in context (§89).
 * It never invents findings, CVEs or assets.
 */
export class MockAiProvider implements AIProvider {
  readonly name = "mock";
  readonly type = "MOCK";
  constructor(private readonly failMode: "NONE" | "ERROR" | "RATE_LIMITED" = "NONE") {}

  async generate(req: AiGenerateRequest): Promise<AiGenerateResult> {
    const started = Date.now();
    if (this.failMode === "ERROR") throw new AiProviderError("PROVIDER_ERROR", "mock provider failure (fixture)");
    if (this.failMode === "RATE_LIMITED") throw new AiProviderError("RATE_LIMITED", "mock provider rate limited (fixture)");
    const trusted = JSON.parse(req.prompt.sections.trusted) as { sourceType: string; sourceId: string; fields: Record<string, string> }[];
    const question = /QUESTION: (.+)/.exec(req.prompt.user)?.[1] ?? "";
    const mentionedCve = question.match(/\bCVE-\d{4}-\d{4,7}\b/)?.[0];
    const contextIds = new Set(trusted.map((r) => r.sourceId));
    let text: string;
    if (mentionedCve && !contextIds.has(mentionedCve)) {
      text = `INSUFFICIENT_EVIDENCE: ${mentionedCve} is not present in the authorized workspace context, so no grounded statement can be made about it.`;
    } else if (trusted.length === 0) {
      text = "INSUFFICIENT_EVIDENCE: no authorized context records were available for this task.";
    } else {
      const finding = trusted.find((r) => r.sourceType === "FINDING");
      const parts = trusted.slice(0, 6).map((r) => {
        const f = r.fields;
        const summary = f.title ?? f.description ?? f.name ?? f.summary ?? Object.values(f).slice(0, 2).join(" — ");
        return `[${r.sourceType}:${r.sourceId}] ${summary}`;
      });
      text = `${req.task} grounded in ${trusted.length} context record(s)${finding ? ` for finding ${finding.sourceId}` : ""}: ${parts.join("; ")}`;
    }
    return {
      text,
      promptTokens: Math.ceil((req.prompt.system.length + req.prompt.user.length) / 4),
      completionTokens: Math.ceil(text.length / 4),
      latencyMs: Date.now() - started,
    };
  }

  async healthCheck() {
    return { status: this.failMode === "NONE" ? "HEALTHY" : "UNAVAILABLE", latencyMs: 1 };
  }
  capabilities(): AiProviderCapabilities {
    return { generate: true, stream: false, embed: true };
  }
  modelMetadata(modelName: string) {
    return { modelName, contextLimit: 16384 };
  }
}

/** Build citation proposals from the record ids a provider answer referenced. */
export function citationsFromAnswer(answer: string, contextRecords: { sourceType: AiCitation["sourceType"]; sourceId: string }[]): AiCitation[] {
  const out: AiCitation[] = [];
  for (const r of contextRecords) {
    if (answer.includes(r.sourceId)) {
      out.push({ claim: `statement grounded in ${r.sourceType} ${r.sourceId}`, sourceType: r.sourceType, sourceId: r.sourceId, confidence: 0.8 });
    }
  }
  return out;
}

/**
 * §103/§24 RULE_BASED fallback: a deterministic, template-composed
 * answer built purely from context records. It is always labelled
 * RULE_BASED — never presented as model output.
 */
export function ruleBasedAnswer(task: AiTaskType, context: { records: { sourceType: string; sourceId: string; fields: Record<string, string> }[] }, citations: AiCitation[]): GroundedResponse {
  if (context.records.length === 0) {
    return {
      answer: "INSUFFICIENT_EVIDENCE: no authorized records were available, and no AI provider is configured (NOT_CONFIGURED).",
      citations: [], confidence: "LOW", assumptions: [], missingData: ["authorized context records", "configured AI provider"],
      origin: "RULE_BASED", insufficientEvidence: true, injectionFlags: 0, redactionCount: 0,
    };
  }
  const lines = context.records.slice(0, 8).map((r) => {
    const f = r.fields;
    const text = f.title ?? f.name ?? f.summary ?? f.description ?? Object.entries(f).map(([k, v]) => `${k}: ${v}`).join("; ");
    return `- [${r.sourceType} ${r.sourceId}] ${text}`.trim();
  });
  return {
    answer: `${task} (rule-based summary — no AI provider configured):\n${lines.join("\n")}`,
    citations, confidence: citations.length > 0 ? "MEDIUM" : "LOW",
    assumptions: ["Composed deterministically from stored records; no model inference."],
    missingData: [], origin: "RULE_BASED", insufficientEvidence: false, injectionFlags: 0, redactionCount: 0,
  };
}
