/**
 * AI Security Copilot core types (Prompt 21 §1–§6, §13, §22–§27).
 *
 * The copilot is an ANALYST ASSISTANT over normalized platform data
 * only. Nothing in this module executes anything: no shell, no SQL, no
 * scanner, no HTTP fetch (§7/§82/§120). All data flowing toward a model
 * provider passes classification → policy → redaction first (§13–§15),
 * and all evidence text is UNTRUSTED DATA, never instructions (§18/§19).
 */

export const AI_TASK_TYPES = [
  "FINDING_EXPLANATION",
  "FINDING_SUMMARY",
  "REMEDIATION_GUIDANCE",
  "SECURE_CODE_GUIDANCE",
  "EVIDENCE_SUMMARY",
  "ATTACK_PATH_EXPLANATION",
  "RISK_EXPLANATION",
  "REPORT_DRAFTING",
  "NATURAL_LANGUAGE_SEARCH",
  "SCAN_SUMMARY",
  "ASSET_SUMMARY",
  "COMPLIANCE_EXPLANATION",
  "RETEST_SUMMARY",
  "COPILOT_CHAT",
] as const;
export type AiTaskType = (typeof AI_TASK_TYPES)[number];

/** §13: data classification ladder. Higher rank = more sensitive. */
export const AI_DATA_CLASSIFICATIONS = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "SECRET"] as const;
export type AiDataClassification = (typeof AI_DATA_CLASSIFICATIONS)[number];

export function classificationRank(c: AiDataClassification): number {
  return AI_DATA_CLASSIFICATIONS.indexOf(c);
}

/** §23 citation source types. */
export const AI_CITATION_SOURCE_TYPES = [
  "FINDING", "OBSERVATION", "EVIDENCE", "ASSET", "CVE", "CWE", "KEV", "EPSS",
  "SBOM_COMPONENT", "GRAPH_RELATIONSHIP", "COMPLIANCE_CONTROL", "DOCUMENTATION",
] as const;
export type AiCitationSourceType = (typeof AI_CITATION_SOURCE_TYPES)[number];

export interface AiCitation {
  claim: string;
  sourceType: AiCitationSourceType;
  sourceId: string;
  evidenceReference?: string;
  confidence: number;
}

export type AiConfidenceLevel = "LOW" | "MEDIUM" | "HIGH";

/** §24: the grounded response envelope every evidence-dependent task returns. */
export interface GroundedResponse {
  answer: string;
  citations: AiCitation[];
  confidence: AiConfidenceLevel;
  assumptions: string[];
  missingData: string[];
  /** MODEL = produced by a configured model provider; RULE_BASED =
   *  deterministic template composed locally (never presented as AI);
   *  NONE = no answer could be produced (e.g. NOT_CONFIGURED). */
  origin: "MODEL" | "RULE_BASED" | "NONE";
  /** §25: true when evidence was insufficient — answer states it plainly. */
  insufficientEvidence: boolean;
  injectionFlags: number;
  redactionCount: number;
}

/** §64: provider data policy (mirrors AiProviderConfig columns). */
export interface AiProviderDataPolicy {
  providerName: string;
  providerType: string; // OPENAI_COMPATIBLE | ANTHROPIC | AZURE_OPENAI | LOCAL | MOCK
  isExternal: boolean;
  approvedClassifications: AiDataClassification[];
  sourceCodeAllowance: "DISABLED" | "REDACTED" | "ALLOWED";
  enabled: boolean;
}

/** §16/§17: workspace-level AI access policies. */
export interface AiWorkspaceAccessPolicy {
  sourceCodeAccess: "DISABLED" | "REDACTED" | "ALLOWED_FOR_APPROVED_PROVIDER";
  rawEvidenceAccess: "DISABLED" | "SANITIZED_ONLY" | "APPROVED_PROVIDER_ONLY";
  enabledTasks: AiTaskType[]; // empty = all tasks enabled
}

/** §6: task-policy decision. */
export type AiPolicyDecision = "ALLOW" | "DENY" | "REQUIRE_REDACTION" | "REQUIRE_REVIEW";

/** A normalized finding record as the context builder consumes it.
 *  This is a plain-data view of the canonical Finding + relations; the
 *  API layer builds it from tenant-filtered queries (§11/§12). */
export interface AiFindingContextInput {
  id: string;
  workspaceId: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  lifecycleStatus?: string;
  verificationStatus?: string;
  confidence?: number;
  cvssScore?: number | null;
  cve?: string | null;
  cwe?: string | null;
  sourceDomain?: string | null;
  category?: string | null;
  fixedVersion?: string | null;
  filePath?: string | null;
  remediation?: string | null;
  riskScore?: number | null;
  riskBand?: string | null;
  /** Risk Engine V3 explanation JSON (§23 of P20): signed signal list. */
  riskExplanation?: { factors?: string[]; adjustments?: { signal: string; delta: number; rationale: string }[]; missingInformation?: string[] } | null;
  epssScore?: number | null;
  kevListed?: boolean;
  asset?: { id: string; name: string; type?: string; environment?: string; exposure?: string } | null;
  observations?: { id: string; summary: string; observedAt?: string }[];
  /** Evidence summaries are ALREADY capped at storage time; they are
   *  still untrusted text (§18) and are redacted again here (§15). */
  evidence?: { id: string; sourceTool: string; summary: string; fingerprint?: string | null }[];
  /** Source-code snippet (SAST findings). Treated per §16 policy. */
  codeSnippet?: string | null;
  intel?: {
    cveDescription?: string;
    cvssScore?: number | null;
    cweName?: string;
    epssScore?: number | null;
    epssPercentile?: number | null;
    kevListed?: boolean;
    kevRequiredAction?: string;
    fixedVersion?: string;
  } | null;
  complianceControls?: { id: string; framework: string; title: string; status: string }[];
  attackPath?: { id: string; summary: string; steps: string[] } | null;
}

export interface AiContextRecord {
  sourceType: AiCitationSourceType;
  sourceId: string;
  classification: AiDataClassification;
  /** TRUSTED = platform-structured fields; UNTRUSTED = scanner/evidence text (§19). */
  trust: "TRUSTED" | "UNTRUSTED";
  fields: Record<string, string>;
}

export interface AiBuiltContext {
  records: AiContextRecord[];
  /** Highest classification present (drives §6 policy). */
  maxClassification: AiDataClassification;
  includesSourceCode: boolean;
  includesRawEvidence: boolean;
  /** Estimated token size of the serialized context (§106). */
  estimatedTokens: number;
  /** SHA-256 over the canonical context — cache + audit anchor (§75/§63). */
  contextHash: string;
}
