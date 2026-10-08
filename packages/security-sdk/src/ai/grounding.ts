import type { AiBuiltContext, AiCitation, AiConfidenceLevel } from "./types";

/**
 * Grounding + confidence (Prompt 21 §21/§24–§27/§89–§91). A claim is
 * grounded only if its citation points at a record that was actually
 * in the context. Identifiers (CVE ids, finding ids) mentioned in an
 * answer but absent from the context are UNSUPPORTED — the hallucination
 * trip (§89). Confidence is a heuristic over citation coverage, source
 * quality, agreement, verification state and freshness — it is NOT
 * certainty (§27).
 */

export interface GroundingResult {
  citations: AiCitation[];
  unsupportedReferences: string[];
  citationCoverage: number; // 0..1 of answer identifier references that are grounded
  grounded: boolean;
}

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/g;

export function groundAnswer(params: {
  answer: string;
  proposedCitations: AiCitation[];
  context: AiBuiltContext;
}): GroundingResult {
  const contextIds = new Set<string>();
  for (const r of params.context.records) contextIds.add(r.sourceId);
  // Citations keep only references that truly exist in the context.
  const citations = params.proposedCitations.filter((c) => contextIds.has(c.sourceId));
  const mentioned = new Set<string>(params.answer.match(CVE_RE) ?? []);
  for (const id of contextIds) if (params.answer.includes(id)) mentioned.add(id);
  const unsupported = [...mentioned].filter((id) => !contextIds.has(id));
  const total = mentioned.size;
  const coverage = total === 0 ? (citations.length > 0 ? 1 : 0) : (total - unsupported.length) / total;
  return {
    citations,
    unsupportedReferences: unsupported,
    citationCoverage: coverage,
    grounded: unsupported.length === 0 && citations.length > 0,
  };
}

export interface ConfidenceSignals {
  citationCoverage: number;
  /** 0..1 — fraction of context records that are TRUSTED structured data. */
  sourceQuality: number;
  /** Scanner-reported confidence of the underlying finding, if any. */
  scannerConfidence?: number;
  verificationStatus?: string;
  /** Injection trust multiplier (1 = clean) from the injection scan. */
  injectionTrust: number;
  missingFieldCount: number;
}

export function computeAiConfidence(s: ConfidenceSignals): { level: AiConfidenceLevel; score: number } {
  let score = 0.35 * s.citationCoverage + 0.25 * s.sourceQuality + 0.2 * (s.scannerConfidence ?? 0.5) + 0.2 * s.injectionTrust;
  if (s.verificationStatus === "CONFIRMED" || s.verificationStatus === "VERIFIED") score += 0.08;
  if (s.verificationStatus === "UNVERIFIED") score -= 0.05;
  score -= Math.min(0.2, s.missingFieldCount * 0.04);
  score = Math.max(0, Math.min(1, score));
  return { level: score >= 0.7 ? "HIGH" : score >= 0.4 ? "MEDIUM" : "LOW", score };
}

/** §78: structured-output validation — reject malformed/unexpected fields. */
export function validateStructuredOutput(value: unknown, requiredFields: string[]): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { ok: false, errors: ["output is not an object"] };
  }
  const obj = value as Record<string, unknown>;
  for (const f of requiredFields) {
    if (!(f in obj)) errors.push(`missing field: ${f}`);
  }
  for (const k of Object.keys(obj)) {
    if (!requiredFields.includes(k)) errors.push(`unexpected field: ${k}`);
  }
  return { ok: errors.length === 0, errors };
}
