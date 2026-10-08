import type {
  AiDataClassification, AiPolicyDecision, AiProviderDataPolicy, AiTaskType, AiWorkspaceAccessPolicy,
} from "./types";
import { classificationRank } from "./types";

/**
 * AI task policy (Prompt 21 §6/§14/§16/§17/§64/§107). Maps
 * task × data classification × provider data policy × workspace
 * policy to ALLOW / DENY / REQUIRE_REDACTION / REQUIRE_REVIEW.
 * Deterministic and total: every combination resolves, and the
 * strictest applicable rule wins. A fallback model NEVER downgrades
 * data-policy requirements (§107) — evaluate against each candidate
 * provider separately.
 */

export interface AiTaskPolicyInput {
  task: AiTaskType;
  maxClassification: AiDataClassification;
  includesSourceCode: boolean;
  includesRawEvidence: boolean;
  provider: AiProviderDataPolicy | null; // null = no provider configured
  workspace: AiWorkspaceAccessPolicy;
}

export interface AiTaskPolicyResult {
  decision: AiPolicyDecision;
  reasons: string[];
  /** When no provider is configured the copilot is NOT_CONFIGURED —
   *  deterministic RULE_BASED answers may still be offered (§103). */
  providerConfigured: boolean;
}

const REVIEW_TASKS: AiTaskType[] = ["SECURE_CODE_GUIDANCE", "REPORT_DRAFTING"];

export function evaluateAiTaskPolicy(input: AiTaskPolicyInput): AiTaskPolicyResult {
  const reasons: string[] = [];
  const { provider, workspace } = input;

  if (workspace.enabledTasks.length > 0 && !workspace.enabledTasks.includes(input.task)) {
    return { decision: "DENY", reasons: [`task ${input.task} is disabled by workspace AI policy`], providerConfigured: !!provider };
  }

  if (!provider || !provider.enabled) {
    return { decision: "ALLOW", reasons: ["no AI provider configured — copilot operates NOT_CONFIGURED (rule-based answers only)"], providerConfigured: false };
  }

  // §14: SECRET-classified data NEVER leaves the platform to an
  // external provider, regardless of approvals. Local providers may
  // receive up to their approved classification.
  if (input.maxClassification === "SECRET" && provider.isExternal) {
    return { decision: "DENY", reasons: ["SECRET-classified data is never sent to an external model provider (§14)"], providerConfigured: true };
  }
  const maxRank = classificationRank(input.maxClassification);
  const approvedRank = Math.max(...provider.approvedClassifications.map(classificationRank), -1);
  if (maxRank > approvedRank) {
    return {
      decision: "DENY",
      reasons: [`data classification ${input.maxClassification} exceeds provider ${provider.providerName} approvals (${provider.approvedClassifications.join(", ") || "none"}) (§64)`],
      providerConfigured: true,
    };
  }

  // §16: source-code access is governed by BOTH workspace and provider policy.
  if (input.includesSourceCode) {
    if (workspace.sourceCodeAccess === "DISABLED" || provider.sourceCodeAllowance === "DISABLED") {
      return { decision: "DENY", reasons: ["source code access is DISABLED by policy (§16)"], providerConfigured: true };
    }
    if (workspace.sourceCodeAccess === "ALLOWED_FOR_APPROVED_PROVIDER" && provider.sourceCodeAllowance !== "ALLOWED") {
      return { decision: "DENY", reasons: ["workspace allows source code only for approved providers; this provider is not approved (§16)"], providerConfigured: true };
    }
    reasons.push("source code included under REDACTED policy — snippets are redacted before sending (§16)");
  }

  // §17: raw evidence access.
  if (input.includesRawEvidence) {
    if (workspace.rawEvidenceAccess === "DISABLED") {
      return { decision: "DENY", reasons: ["raw evidence access is DISABLED by workspace policy (§17)"], providerConfigured: true };
    }
    if (workspace.rawEvidenceAccess === "APPROVED_PROVIDER_ONLY" && provider.isExternal) {
      return { decision: "DENY", reasons: ["raw evidence may go only to an approved (non-external) provider (§17)"], providerConfigured: true };
    }
    reasons.push("evidence included SANITIZED_ONLY — redacted summaries, never raw payloads (§17)");
  }

  if (REVIEW_TASKS.includes(input.task)) {
    reasons.push(`task ${input.task} output is a draft that requires human review before use (§35/§50)`);
    return { decision: "REQUIRE_REVIEW", reasons, providerConfigured: true };
  }
  if (input.includesSourceCode || input.includesRawEvidence || maxRank >= classificationRank("CONFIDENTIAL")) {
    return { decision: "REQUIRE_REDACTION", reasons: [...reasons, "context passes the redaction engine before any provider call (§15)"], providerConfigured: true };
  }
  return { decision: "ALLOW", reasons, providerConfigured: true };
}

/**
 * §120/§7 hard boundary: tasks that would require the AI to execute
 * something are not task types at all. This guard exists so API layers
 * can refuse execution-shaped requests explicitly (and audit them)
 * instead of silently mapping them to an analysis task.
 */
const EXECUTION_SHAPES = [
  /\b(run|execute|launch|start|trigger)\b.*\b(scan|scanner|shell|command|exploit|metasploit|nmap|sql)\b/i,
  /\b(shell|terminal|exec|raw sql|arbitrary code)\b/i,
];
export function isExecutionShapedRequest(text: string): boolean {
  return EXECUTION_SHAPES.some((re) => re.test(text));
}
