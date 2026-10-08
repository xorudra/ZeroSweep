import { validateStructuredOutput } from "./grounding";

/**
 * Structured output + claim validation (Prompt 36 §23, §65–§70,
 * §81, §85, §90). Model-produced structured artifacts are schema
 * validated before use (§66); factual content inside them is checked
 * against governed sources: CVE mentions against vulnerability
 * intelligence (§68), fixed versions against trusted intel (§69),
 * report numbers against canonical counts (§90). Risk numbers are
 * only ever READ from Risk Engine V3 — an output that tries to set a
 * risk score is rejected, not adopted (§70/§154).
 */

/** §23: claim kinds. Statements in V2 outputs are explicitly typed —
 *  observed fact, inference, or recommendation — never blended. */
export type AiClaimKind = "OBSERVED" | "INFERRED" | "RECOMMENDED";
export interface AiClaim { text: string; kind: AiClaimKind; citationSourceId?: string }

/** §65/§66: schemas for the structured artifact kinds. */
export const AI_STRUCTURED_SCHEMAS: Record<string, { required: string[]; description: string }> = {
  PLAN: { required: ["objective", "steps"], description: "AI security plan (§41/§42)" },
  FINDING_SUMMARY: { required: ["findingId", "summary", "claims"], description: "grounded finding summary" },
  RISK_EXPLANATION: { required: ["findingId", "riskScore", "riskBand", "factors"], description: "Risk Engine V3 explanation (§70)" },
  REMEDIATION: { required: ["findingId", "steps", "patchConfidence"], description: "remediation guidance (§79–§81)" },
  REPORT_SECTION: { required: ["section", "body", "citations"], description: "report draft section (§89/§90)" },
  INVESTIGATION_TIMELINE: { required: ["incidentId", "events", "hypotheses"], description: "SOC investigation timeline (§84/§85)" },
};

export function validateAiStructuredOutput(kind: string, value: unknown): { ok: boolean; errors: string[] } {
  const schema = AI_STRUCTURED_SCHEMAS[kind];
  if (!schema) return { ok: false, errors: [`unknown structured output kind: ${kind}`] };
  const base = validateStructuredOutput(value, schema.required);
  const errors = [...base.errors];
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    // §70/§154: a RISK_EXPLANATION may quote the stored engine score
    // but the validator flags any attempt to attach a DIFFERENT
    // "aiRiskScore" — that field is not in the schema, already caught
    // by the unexpected-field rule; arrays must be arrays.
    for (const f of schema.required) {
      if (["steps", "claims", "factors", "citations", "events", "hypotheses"].includes(f) && f in obj && !Array.isArray(obj[f])) {
        errors.push(`field ${f} must be an array`);
      }
    }
  }
  return { ok: errors.length === 0, errors };
}

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/g;

/** §68: CVE validation. A CVE presented as environment-specific must
 *  exist in the finding evidence / vulnerability intelligence the
 *  caller supplies. Generic educational mentions are the caller's
 *  framing concern; this checks environment claims only. */
export function validateCveMentions(text: string, knownCveIds: Iterable<string>): {
  mentioned: string[];
  validated: string[];
  unvalidated: string[];
} {
  const known = new Set([...knownCveIds].map((c) => c.toUpperCase()));
  const mentioned = [...new Set((text.match(CVE_RE) ?? []).map((c) => c.toUpperCase()))];
  return {
    mentioned,
    validated: mentioned.filter((c) => known.has(c)),
    unvalidated: mentioned.filter((c) => !known.has(c)),
  };
}

/** §69/§81: remediation validation + patch confidence. A fixed
 *  version is VERIFIED_SOURCE only when it comes from trusted
 *  intelligence supplied by the caller; version-shaped claims without
 *  intel backing are GENERAL_GUIDANCE and flagged. */
export function assessPatchConfidence(params: {
  claimedFixedVersion?: string | null;
  intelFixedVersions: string[];
  hasFindingEvidence: boolean;
}): { confidence: "VERIFIED_SOURCE" | "LIKELY" | "GENERAL_GUIDANCE"; reason: string } {
  if (params.claimedFixedVersion) {
    if (params.intelFixedVersions.includes(params.claimedFixedVersion)) {
      return { confidence: "VERIFIED_SOURCE", reason: `fixed version ${params.claimedFixedVersion} matches trusted vulnerability intelligence (§69)` };
    }
    return { confidence: "GENERAL_GUIDANCE", reason: `fixed version ${params.claimedFixedVersion} is NOT in trusted intelligence — treat as unverified guidance (§69)` };
  }
  if (params.hasFindingEvidence) return { confidence: "LIKELY", reason: "recommendation grounded in finding evidence but no intel fixed version (§81)" };
  return { confidence: "GENERAL_GUIDANCE", reason: "general guidance without finding-specific evidence (§81)" };
}

/** §90: report fact check — validate draft claims (ids, counts,
 *  severities, risk) against canonical report data BEFORE a report
 *  can be finalized. Returns every mismatch; empty = fact-checked. */
export function factCheckReportDraft(params: {
  draftText: string;
  canonicalFindingIds: string[];
  canonicalCounts: { total: number; bySeverity: Record<string, number> };
  claimedCounts?: Record<string, number>;
}): { ok: boolean; mismatches: string[] } {
  const mismatches: string[] = [];
  const canonical = new Set(params.canonicalFindingIds);
  const uuidLike = params.draftText.match(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi) ?? [];
  for (const id of uuidLike) {
    if (!canonical.has(id)) mismatches.push(`draft references unknown finding/record id ${id} (§90)`);
  }
  if (params.claimedCounts) {
    for (const [k, v] of Object.entries(params.claimedCounts)) {
      const expected = k === "total" ? params.canonicalCounts.total : params.canonicalCounts.bySeverity[k];
      if (expected !== undefined && expected !== v) {
        mismatches.push(`draft claims ${k}=${v} but canonical count is ${expected} (§90)`);
      }
    }
  }
  // §92: unsupported catastrophic language is flagged for the human
  // reviewer — the checker never rewrites the draft itself.
  if (/\b(guaranteed breach|will be hacked|certain compromise|total devastation)\b/i.test(params.draftText)) {
    mismatches.push("draft contains unsupported catastrophic language (§92) — requires human revision");
  }
  return { ok: mismatches.length === 0, mismatches };
}

/** §85: hypotheses are structurally labelled UNVERIFIED — a timeline
 *  event can be OBSERVED, a hypothesis never can. */
export function buildInvestigationTimeline(params: {
  events: { at: string; summary: string; sourceId: string }[];
  hypotheses: string[];
}): { events: { at: string; summary: string; sourceId: string; kind: "OBSERVED" }[]; hypotheses: { text: string; kind: "INFERRED"; verificationStatus: "UNVERIFIED" }[] } {
  return {
    events: params.events.map((e) => ({ ...e, kind: "OBSERVED" as const })),
    hypotheses: params.hypotheses.map((h) => ({ text: h, kind: "INFERRED" as const, verificationStatus: "UNVERIFIED" as const })),
  };
}
