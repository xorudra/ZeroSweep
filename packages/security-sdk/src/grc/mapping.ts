import { FINDING_CONTROL_RULES } from "./controls-data";
import type { MappingConfidence } from "./types";

/**
 * Deterministic finding → control mapping (Prompt 26 §85–§87).
 * Returns the FIRST matching rule (rules are ordered specific →
 * general). The result is a suggestion-grade link with a confidence;
 * an analyst override replaces it and is preserved in audit history.
 */
export interface FindingLike {
  cweId?: string | null;
  category?: string | null;
  securityDomain?: string | null;
  title?: string | null;
}

export interface FindingControlSuggestion {
  controlCode: string;
  confidence: MappingConfidence;
  ruleId: string;
  rationale: string;
}

export function suggestControlForFinding(finding: FindingLike): FindingControlSuggestion | null {
  const category = (finding.category ?? "").toUpperCase();
  const domain = (finding.securityDomain ?? "").toUpperCase();
  for (const rule of FINDING_CONTROL_RULES) {
    if (rule.cwes && finding.cweId && rule.cwes.includes(finding.cweId.toUpperCase())) {
      return { controlCode: rule.controlCode, confidence: rule.confidence, ruleId: rule.id, rationale: rule.rationale };
    }
    if (rule.categoryIncludes && rule.categoryIncludes.some((c) => category.includes(c))) {
      if (!rule.domains || rule.domains.includes(domain)) {
        return { controlCode: rule.controlCode, confidence: rule.confidence, ruleId: rule.id, rationale: rule.rationale };
      }
    }
    if (rule.domains && !rule.cwes && !rule.categoryIncludes && rule.domains.includes(domain)) {
      return { controlCode: rule.controlCode, confidence: rule.confidence, ruleId: rule.id, rationale: rule.rationale };
    }
  }
  return null;
}
