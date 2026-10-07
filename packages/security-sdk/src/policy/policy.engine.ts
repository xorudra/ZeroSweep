import { RISK_ORDER, type ToolMetadata } from "../adapter/adapter.types";
import type { AuthorizationContext } from "../execution/execution.types";
import { blockedTargetReason, ScopeMatcher } from "../scope/scope.matcher";
import type { ScopeRules } from "@dsrclone/validation";

export type PolicyDecisionType = "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
export type PolicyReasonCode =
  | "OK" | "TARGET_NOT_VERIFIED" | "TARGET_OUT_OF_SCOPE" | "TOOL_DISABLED"
  | "ADAPTER_DISABLED" | "TARGET_TYPE_UNSUPPORTED" | "APPROVAL_REQUIRED"
  | "CREDENTIAL_REQUIRED" | "NETWORK_POLICY_DENIED" | "RATE_LIMIT_EXCEEDED"
  | "CONCURRENCY_LIMIT" | "TOOL_UNHEALTHY" | "ORGANIZATION_MISMATCH" | "TARGET_BLOCKED";

export interface PolicyDecision {
  decision: PolicyDecisionType;
  reasonCode: PolicyReasonCode;
  message: string;
  requiredAction?: string;
}

export interface PolicyInput {
  tool: ToolMetadata;
  toolEnabled: boolean;
  adapterEnabled: boolean;
  toolHealthy: boolean;
  targetType: string;
  targetHost: string;
  auth: AuthorizationContext;
  scopeRules?: ScopeRules;
  availableCredentialRefs: string[];
  currentConcurrency: number;
  maxConcurrency: number;
  internalEngagementApproved?: boolean;
  /** Network posture for this execution (Prompt 3 §13): false when the
   *  tool's network policy does not permit reaching the target at all. */
  networkPermitted?: boolean;
  /** Rate accounting for this tool in the current window (Prompt 3 §33). */
  requestsInWindow?: number;
  rateLimitPerMinute?: number;
}

const allow = (): PolicyDecision => ({ decision: "ALLOW", reasonCode: "OK", message: "Execution permitted by policy" });
const deny = (reasonCode: PolicyReasonCode, message: string): PolicyDecision => ({ decision: "DENY", reasonCode, message });

/**
 * ToolExecutionPolicyEngine — evaluated before ANY tool may run.
 * Any mandatory failure denies execution. The API never runs tools; the
 * worker re-evaluates this with trusted DB state before executing an adapter.
 */
export function evaluateToolPolicy(input: PolicyInput): PolicyDecision {
  const { tool, auth } = input;

  // Multi-tenant isolation: the target must belong to the caller's organization.
  if (auth.targetOrganizationId !== auth.organizationId) {
    return deny("ORGANIZATION_MISMATCH", "Target does not belong to the requesting organization");
  }
  if (!input.toolEnabled) return deny("TOOL_DISABLED", `Tool ${tool.slug} is disabled`);
  if (!input.adapterEnabled) return deny("ADAPTER_DISABLED", `Adapter for ${tool.slug} is disabled`);
  if (!input.toolHealthy) return deny("TOOL_UNHEALTHY", `Tool ${tool.slug} is not healthy`);
  if (!tool.supportedTargetTypes.includes(input.targetType as never)) {
    return deny("TARGET_TYPE_UNSUPPORTED", `Tool ${tool.slug} does not support target type ${input.targetType}`);
  }

  // SSRF / internal-target protection (skipped only for approved internal labs).
  const blocked = blockedTargetReason(input.targetHost);
  if (blocked && !input.internalEngagementApproved) {
    return deny("TARGET_BLOCKED", blocked);
  }

  // Risk-tier gates.
  const risk = RISK_ORDER[tool.riskLevel];
  if (tool.riskLevel === "RESTRICTED") {
    return deny("APPROVAL_REQUIRED", "RESTRICTED tools are disabled by default and never auto-selected");
  }
  if (risk >= RISK_ORDER.LOW && auth.verificationStatus !== "VERIFIED") {
    return deny("TARGET_NOT_VERIFIED", "Target ownership must be verified before active scanning");
  }
  if (risk >= RISK_ORDER.MODERATE && auth.approvalStatus !== "APPROVED" && auth.approvalStatus !== "NOT_REQUIRED") {
    return { decision: "REQUIRE_APPROVAL", reasonCode: "APPROVAL_REQUIRED", message: "Assessment must be approved", requiredAction: "Approve the assessment" };
  }
  if ((tool.requiresApproval || risk >= RISK_ORDER.INTRUSIVE) && auth.approvalStatus !== "APPROVED") {
    return { decision: "REQUIRE_APPROVAL", reasonCode: "APPROVAL_REQUIRED", message: "This tool requires explicit approval", requiredAction: "Approve the assessment" };
  }

  // Scope: discovered/explicit target host must be inside the assessment scope.
  if (input.scopeRules) {
    const matcher = new ScopeMatcher(input.scopeRules);
    if (!matcher.isHostAllowed(input.targetHost)) {
      return deny("TARGET_OUT_OF_SCOPE", "Target host is outside the approved scope");
    }
  }

  // Credentials are resolved by reference inside the worker boundary only.
  const missing = tool.requiresCredentials.filter((c) => !input.availableCredentialRefs.includes(c));
  if (missing.length > 0) {
    return deny("CREDENTIAL_REQUIRED", `Missing required credential reference(s): ${missing.join(", ")}`);
  }

  if (input.networkPermitted === false) {
    return deny("NETWORK_POLICY_DENIED", "The tool's network policy does not permit this execution");
  }
  if (input.requestsInWindow !== undefined && input.rateLimitPerMinute !== undefined
    && input.requestsInWindow >= input.rateLimitPerMinute) {
    return deny("RATE_LIMIT_EXCEEDED", "Tool rate limit exceeded for the current window");
  }
  if (input.currentConcurrency >= input.maxConcurrency) {
    return deny("CONCURRENCY_LIMIT", "Tool concurrency limit reached");
  }
  return allow();
}
