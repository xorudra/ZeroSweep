import { GRC_DISCLAIMER } from "./types";

/**
 * AI GRC assistant safety layer (Prompt 26 §88–§92, §137/§138).
 * Deterministic guard rails around any model output: the assistant
 * works only from grounded records passed in as context, cites them,
 * refuses to claim certification unless an approved organizational
 * certification record exists in context (§90), and answers
 * INSUFFICIENT_EVIDENCE when asked to justify a control outcome that
 * has no evidence (§92/§138). No AI-generated SQL anywhere (§93 is a
 * deterministic query-plan layer in the API service).
 */

export interface GrcAiContextRecord {
  kind: "REQUIREMENT" | "CONTROL" | "EVIDENCE" | "FINDING" | "RISK" | "POLICY" | "CERTIFICATION_RECORD";
  id: string;
  label: string;
  text: string;
}

export interface GrcAiAnswer {
  text: string;
  citations: string[];
  insufficientEvidence: boolean;
  certificationClaimBlocked: boolean;
}

const CERTIFICATION_CLAIM = /\b(is|are|was|were|become|became|now)\s+(iso|soc\s?2|pci|nist)?\s*(certified|attested|compliant certified)\b|\bcertified\s+(compliant|organization|organisation|company)\b|\byou are certified\b|\bwe are certified\b/i;
const CERTIFICATION_QUESTION = /\b(are|is|am)\s+(we|the organization|the organisation|the company|i)\s+.*\b(certified|attested)\b|\bcertification status\b/i;

export function containsCertificationClaim(text: string): boolean {
  return CERTIFICATION_CLAIM.test(text);
}

export function isCertificationQuestion(text: string): boolean {
  return CERTIFICATION_QUESTION.test(text);
}

/**
 * Compose a grounded GRC answer. `draft` is the model/rule-based text;
 * this function enforces the safety contract over it deterministically.
 */
export function composeGrcAnswer(input: {
  question: string;
  draft: string;
  context: GrcAiContextRecord[];
  /** Record ids the draft actually relies on — citations are limited to these. */
  citedRecordIds: string[];
}): GrcAiAnswer {
  const contextIds = new Set(input.context.map((r) => r.id));
  const hasCertificationRecord = input.context.some((r) => r.kind === "CERTIFICATION_RECORD");

  if (isCertificationQuestion(input.question) && !hasCertificationRecord) {
    return {
      text: `ZeroSweep holds no approved certification record for this organization, so no certification can be claimed. ${GRC_DISCLAIMER} Current ZeroSweep assessment data can be reviewed in the compliance dashboard.`,
      citations: [],
      insufficientEvidence: false,
      certificationClaimBlocked: true,
    };
  }

  // A justification request with no evidence in context → INSUFFICIENT_EVIDENCE (§138).
  const asksJustification = /\b(justify|prove|evidence|why (did|does|is)|passed|compliant)\b/i.test(input.question);
  const hasEvidence = input.context.some((r) => r.kind === "EVIDENCE");
  if (asksJustification && !hasEvidence) {
    return {
      text: "INSUFFICIENT_EVIDENCE: no compliance evidence is available in the authorized context for this question, so no grounded justification can be given. Collect evidence for the control first (§92).",
      citations: [],
      insufficientEvidence: true,
      certificationClaimBlocked: false,
    };
  }

  let text = input.draft;
  let blocked = false;
  if (!hasCertificationRecord && containsCertificationClaim(text)) {
    text = text.replace(CERTIFICATION_CLAIM, "assessed in ZeroSweep (not a certification)");
    blocked = true;
  }
  // Citations only for records that exist in the authorized context (§89).
  const citations = [...new Set(input.citedRecordIds.filter((id) => contextIds.has(id)))];
  if (citations.length === 0 && input.context.length > 0 && asksJustification) {
    return {
      text: "INSUFFICIENT_EVIDENCE: the draft answer cited no authorized context records, so it cannot be grounded (§89).",
      citations: [],
      insufficientEvidence: true,
      certificationClaimBlocked: blocked,
    };
  }
  return { text, citations, insufficientEvidence: false, certificationClaimBlocked: blocked };
}

/**
 * §93 natural-language GRC search: deterministic parser → typed query
 * plan. No AI-generated SQL; unknown phrasing yields an UNSUPPORTED
 * plan rather than a guess.
 */
export interface GrcQueryPlan {
  kind: "FAILED_CONTROLS_WITH_FINDINGS" | "STALE_EVIDENCE_CONTROLS" | "EXPIRING_RISK_ACCEPTANCES" | "UNSUPPORTED";
  frameworkKey?: string;
  minSeverity?: string;
  withinDays?: number;
  raw: string;
}

export function parseGrcQuery(text: string): GrcQueryPlan {
  const t = text.toLowerCase();
  const framework = /pci/.test(t) ? "PCI_DSS" : /iso/.test(t) ? "ISO_27001" : /nist csf/.test(t) ? "NIST_CSF"
    : /nist/.test(t) ? "NIST_800_53" : /soc\s?2/.test(t) ? "SOC_2" : /cis/.test(t) ? "CIS_CONTROLS" : undefined;
  if (/failed|failing/.test(t) && /control/.test(t)) {
    return {
      kind: "FAILED_CONTROLS_WITH_FINDINGS", frameworkKey: framework,
      minSeverity: /critical/.test(t) ? "CRITICAL" : /high/.test(t) ? "HIGH" : undefined, raw: text,
    };
  }
  if (/(stale|expired)/.test(t) && /evidence/.test(t)) {
    return { kind: "STALE_EVIDENCE_CONTROLS", frameworkKey: framework, raw: text };
  }
  if (/accepted risk|risk acceptance/.test(t) && /expir/.test(t)) {
    return { kind: "EXPIRING_RISK_ACCEPTANCES", withinDays: /month/.test(t) ? 31 : 30, raw: text };
  }
  return { kind: "UNSUPPORTED", raw: text };
}
