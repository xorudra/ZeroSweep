/**
 * AI Tool Gateway (Prompt 36 §27–§35, §59–§60). The LLM never
 * receives raw capabilities: it may only name tools from this closed,
 * typed catalog (§28). Each tool declares its input/output schema
 * fields, required permission, risk class, approval requirement,
 * authorization requirement and rate limit. Anything outside the
 * catalog — shell, SQL, kubectl, cloud CLIs, scanner invocations —
 * does not exist as a tool and is rejected by name (§26/§108–§111).
 *
 * Action tools (§33/§34) never perform the action themselves here:
 * the gateway classifies the call and the API layer routes it to the
 * EXISTING deterministic service or records a governed proposal. A
 * gateway verdict of ALLOWED for a SAFE_ACTION means "may be handed
 * to the owning workflow", never "the AI executed it".
 */

export const AI_TOOL_CATEGORIES = ["READ", "ANALYZE", "PLAN", "SAFE_ACTION", "RESTRICTED_ACTION"] as const;
export type AiToolCategory = (typeof AI_TOOL_CATEGORIES)[number];

export const AI_RISK_CLASSES = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type AiRiskClass = (typeof AI_RISK_CLASSES)[number];

export interface AiToolDefinition {
  name: string;
  description: string;
  category: AiToolCategory;
  inputFields: string[];
  outputFields: string[];
  requiredPermission: string;
  riskClass: AiRiskClass;
  /** NONE = no approval; HUMAN = a human approval record is required
   *  before the owning workflow may act (§35/§48). */
  approvalRequirement: "NONE" | "HUMAN";
  /** True when the call only makes sense inside a VERIFIED +
   *  APPROVED authorization snapshot (§35). */
  authorizationRequirement: boolean;
  rateLimitPerHour: number;
}

function tool(p: AiToolDefinition): AiToolDefinition { return p; }

const READ_PERM = "USE_AI_COPILOT";
export const AI_TOOL_CATALOG: AiToolDefinition[] = [
  // §30 READ tools — governed data access only.
  tool({ name: "getAsset", description: "Fetch one asset by id (workspace-scoped).", category: "READ", inputFields: ["assetId"], outputFields: ["asset", "findingCount"], requiredPermission: READ_PERM, riskClass: "NONE", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 600 }),
  tool({ name: "searchAssets", description: "Search assets by text/criticality inside the workspace.", category: "READ", inputFields: ["query", "limit"], outputFields: ["assets"], requiredPermission: READ_PERM, riskClass: "NONE", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 300 }),
  tool({ name: "getFinding", description: "Fetch one canonical finding with observations and evidence metadata.", category: "READ", inputFields: ["findingId"], outputFields: ["finding"], requiredPermission: "AI_EXPLAIN_FINDING", riskClass: "NONE", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 600 }),
  tool({ name: "searchFindings", description: "Governed finding search (typed filters; no raw query language).", category: "READ", inputFields: ["severity", "domain", "kevOnly", "limit"], outputFields: ["findings"], requiredPermission: "AI_QUERY_SECURITY_DATA", riskClass: "NONE", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 300 }),
  tool({ name: "getScan", description: "Fetch one scan with stage/tool status and limitations.", category: "READ", inputFields: ["scanId"], outputFields: ["scan", "limitations"], requiredPermission: READ_PERM, riskClass: "NONE", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 300 }),
  tool({ name: "getCoverage", description: "Coverage view for a scan (null coverage is reported as unknown, never 100%).", category: "READ", inputFields: ["scanId"], outputFields: ["coverage"], requiredPermission: READ_PERM, riskClass: "NONE", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 300 }),
  tool({ name: "getSBOM", description: "SBOM components for a repository/asset from the governed SBOM store.", category: "READ", inputFields: ["assetId"], outputFields: ["components"], requiredPermission: READ_PERM, riskClass: "NONE", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 300 }),
  tool({ name: "getCveIntel", description: "Vulnerability intelligence for a CVE id from the platform intel dataset (never invented).", category: "READ", inputFields: ["cveId"], outputFields: ["intel", "datasetStatus"], requiredPermission: READ_PERM, riskClass: "NONE", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 300 }),
  tool({ name: "getRiskExplanation", description: "Risk Engine V3 explanation for a finding (the engine stays authoritative, §70).", category: "READ", inputFields: ["findingId"], outputFields: ["riskScore", "factors", "adjustments"], requiredPermission: "AI_EXPLAIN_FINDING", riskClass: "NONE", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 600 }),
  tool({ name: "getRemediationStatus", description: "Remediation case status + SLA state for a finding (Prompt 31).", category: "READ", inputFields: ["findingId"], outputFields: ["case", "sla"], requiredPermission: READ_PERM, riskClass: "NONE", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 300 }),
  tool({ name: "getIncident", description: "SOC incident with timeline (Prompt 28).", category: "READ", inputFields: ["incidentId"], outputFields: ["incident", "timeline"], requiredPermission: READ_PERM, riskClass: "NONE", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 300 }),
  // §31 ANALYSIS tools — deterministic computation over governed data.
  tool({ name: "compareScans", description: "Diff two scans: new/resolved/persisting findings by canonical fingerprint.", category: "ANALYZE", inputFields: ["scanIdA", "scanIdB"], outputFields: ["added", "resolved", "persisting"], requiredPermission: READ_PERM, riskClass: "LOW", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 120 }),
  tool({ name: "compareVersions", description: "Compare two versions/snapshots of an asset or component set.", category: "ANALYZE", inputFields: ["subjectType", "subjectIdA", "subjectIdB"], outputFields: ["changes"], requiredPermission: READ_PERM, riskClass: "LOW", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 120 }),
  tool({ name: "correlateFindings", description: "Correlate findings sharing canonical fingerprints / assets (analysis only).", category: "ANALYZE", inputFields: ["findingIds"], outputFields: ["groups"], requiredPermission: READ_PERM, riskClass: "LOW", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 120 }),
  tool({ name: "calculateExistingRisk", description: "Re-read the stored Risk Engine V3 score for a finding — never recomputed by the AI (§70).", category: "ANALYZE", inputFields: ["findingId"], outputFields: ["riskScore", "riskBand"], requiredPermission: "AI_EXPLAIN_FINDING", riskClass: "LOW", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 300 }),
  tool({ name: "buildAttackPathView", description: "Analytical attack-path view from the asset graph; labelled OBSERVED/INFERRED/POTENTIAL, never executed (§71–§73).", category: "ANALYZE", inputFields: ["assetId"], outputFields: ["paths"], requiredPermission: READ_PERM, riskClass: "LOW", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 120 }),
  tool({ name: "summarizeCoverage", description: "Coverage summary across recent scans with honest unknowns.", category: "ANALYZE", inputFields: ["limit"], outputFields: ["summary"], requiredPermission: READ_PERM, riskClass: "LOW", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 120 }),
  // §32 PLANNING tools — produce plan DRAFTS for the deterministic validator.
  tool({ name: "draftScanPlan", description: "Draft a scan plan from approved profiles/tools/scope only (§74/§75).", category: "PLAN", inputFields: ["objective", "targetIds", "profile"], outputFields: ["plan"], requiredPermission: "CREATE_AI_PLAN", riskClass: "MEDIUM", approvalRequirement: "HUMAN", authorizationRequirement: true, rateLimitPerHour: 60 }),
  tool({ name: "draftVerificationPlan", description: "Draft a minimal targeted verification plan (executes via Prompt 31 only, §82/§83).", category: "PLAN", inputFields: ["findingId"], outputFields: ["plan"], requiredPermission: "CREATE_AI_PLAN", riskClass: "MEDIUM", approvalRequirement: "HUMAN", authorizationRequirement: true, rateLimitPerHour: 60 }),
  tool({ name: "draftRemediationPlan", description: "Draft a remediation plan (fix steps + verification) for a finding.", category: "PLAN", inputFields: ["findingId"], outputFields: ["plan"], requiredPermission: "CREATE_AI_PLAN", riskClass: "LOW", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 60 }),
  tool({ name: "draftInvestigationPlan", description: "Draft an SOC investigation plan (checks for an analyst; hypotheses labelled unverified).", category: "PLAN", inputFields: ["incidentId"], outputFields: ["plan"], requiredPermission: "CREATE_AI_PLAN", riskClass: "LOW", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 60 }),
  // §34 SAFE_ACTION tools — hand-off to existing deterministic
  // services via governed proposals; the AI never performs them.
  tool({ name: "createScanDraft", description: "Record a scan DRAFT through the orchestration intake (never starts a scan).", category: "SAFE_ACTION", inputFields: ["planId"], outputFields: ["proposalId"], requiredPermission: "RUN_AI_APPROVED_ACTION", riskClass: "MEDIUM", approvalRequirement: "HUMAN", authorizationRequirement: true, rateLimitPerHour: 30 }),
  tool({ name: "createRemediationTicket", description: "Propose a remediation ticket through the Prompt 31/24 governed path.", category: "SAFE_ACTION", inputFields: ["findingId", "summary"], outputFields: ["proposalId"], requiredPermission: "AI_PROPOSE_ACTION", riskClass: "LOW", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 60 }),
  tool({ name: "requestVerification", description: "Propose a verification request; only the Prompt 31 workflow can verify (§83/§151).", category: "SAFE_ACTION", inputFields: ["findingId"], outputFields: ["proposalId"], requiredPermission: "AI_PROPOSE_ACTION", riskClass: "LOW", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 60 }),
  tool({ name: "generateReportDraft", description: "Propose an AI report draft for human review (Prompt 20 reporting stays authoritative).", category: "SAFE_ACTION", inputFields: ["reportId", "section"], outputFields: ["draftId"], requiredPermission: "AI_DRAFT_REPORT", riskClass: "LOW", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 30 }),
  tool({ name: "createInvestigationCase", description: "Propose a SOC investigation case from an incident analysis.", category: "SAFE_ACTION", inputFields: ["incidentId", "summary"], outputFields: ["proposalId"], requiredPermission: "AI_PROPOSE_ACTION", riskClass: "LOW", approvalRequirement: "NONE", authorizationRequirement: false, rateLimitPerHour: 30 }),
  // §35 RESTRICTED_ACTION tools — exist so requests can be governed,
  // approved and audited; they additionally require an APPROVED
  // AiActionApproval bound to the exact call, and even then hand off
  // to the owning workflow. There is deliberately NO tool for shell,
  // SQL, cloud mutation, kubectl, exploitation or authorization changes.
  tool({ name: "scheduleApprovedScan", description: "Hand an APPROVED scan plan to the existing scheduler (Prompt 22 classes only).", category: "RESTRICTED_ACTION", inputFields: ["planId", "scheduleKind"], outputFields: ["proposalId"], requiredPermission: "RUN_AI_APPROVED_ACTION", riskClass: "HIGH", approvalRequirement: "HUMAN", authorizationRequirement: true, rateLimitPerHour: 10 }),
];

export function getAiTool(name: string): AiToolDefinition | undefined {
  return AI_TOOL_CATALOG.find((t) => t.name === name);
}

export interface AiToolCallContext {
  userPermissions: string[];
  /** An approval record exists for this exact tool + target (§48). */
  hasApproval: boolean;
  /** Call sits inside a VERIFIED + APPROVED authorization snapshot (§46). */
  authorizationValid: boolean;
  /** Calls of this tool by this user in the current hour (§28). */
  callsThisHour: number;
}

export type AiToolVerdict =
  | { allowed: true; tool: AiToolDefinition }
  | { allowed: false; tool?: AiToolDefinition; reason: string; code: "UNKNOWN_TOOL" | "PERMISSION" | "APPROVAL_REQUIRED" | "AUTHORIZATION_REQUIRED" | "RATE_LIMIT" };

/** Names that must NEVER resolve to a tool (§26/§108–§113). Checked
 *  explicitly so refusals are auditable rather than incidental. */
const FORBIDDEN_TOOL_SHAPES = /(shell|bash|exec|sql|kubectl|frida|metasploit|exploit|nmap\s|aws\s|gcloud|az\s|ssh|telnet|dump|payload)/i;

export function evaluateAiToolCall(name: string, ctx: AiToolCallContext): AiToolVerdict {
  const toolDef = getAiTool(name);
  if (!toolDef) {
    return {
      allowed: false,
      reason: FORBIDDEN_TOOL_SHAPES.test(name)
        ? `"${name}" is not an AI capability: the copilot has no shell/SQL/cloud/Kubernetes/device/exploit surface (§26)`
        : `unknown AI tool "${name}" — only the typed gateway catalog may be called (§27)`,
      code: "UNKNOWN_TOOL",
    };
  }
  if (!ctx.userPermissions.includes(toolDef.requiredPermission)) {
    return { allowed: false, tool: toolDef, reason: `caller lacks permission ${toolDef.requiredPermission} for ${toolDef.name} (§28)`, code: "PERMISSION" };
  }
  if (toolDef.authorizationRequirement && !ctx.authorizationValid) {
    return { allowed: false, tool: toolDef, reason: `${toolDef.name} requires a VERIFIED + APPROVED authorization snapshot (§35/§46)`, code: "AUTHORIZATION_REQUIRED" };
  }
  if (toolDef.approvalRequirement === "HUMAN" && !ctx.hasApproval) {
    return { allowed: false, tool: toolDef, reason: `${toolDef.name} requires a human approval record before hand-off (§35/§48)`, code: "APPROVAL_REQUIRED" };
  }
  if (ctx.callsThisHour >= toolDef.rateLimitPerHour) {
    return { allowed: false, tool: toolDef, reason: `${toolDef.name} rate limit reached (${toolDef.rateLimitPerHour}/hour, §28)`, code: "RATE_LIMIT" };
  }
  return { allowed: true, tool: toolDef };
}

/** §60: loop detection — the same (tool, canonical-args) signature
 *  repeated beyond the threshold marks the run as looping; the
 *  orchestrator terminates it safely. */
export function toolCallSignature(name: string, args: Record<string, unknown>): string {
  const stable = Object.keys(args).sort().map((k) => `${k}=${JSON.stringify(args[k])}`).join("&");
  return `${name}(${stable})`;
}

export function detectToolLoop(signatures: string[], repeatThreshold = 3): { looping: boolean; signature?: string; count: number } {
  const counts = new Map<string, number>();
  for (const s of signatures) counts.set(s, (counts.get(s) ?? 0) + 1);
  for (const [sig, count] of counts) {
    if (count >= repeatThreshold) return { looping: true, signature: sig, count };
  }
  return { looping: false, count: 0 };
}
