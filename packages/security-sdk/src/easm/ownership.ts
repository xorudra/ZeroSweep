import type { EasmOwnershipConfidence, EasmOwnershipStatus } from "./types";

/**
 * Ownership resolution (Prompt 29 §65–§69). Every conclusion carries
 * its evidence (§67): a confidence with no evidence references is a
 * bug, so the resolver refuses to emit one. Confidence is a ladder,
 * not a vote — the strongest single evidence class wins, corroboration
 * can raise LIKELY one step, and ONLY a completed verification
 * workflow (DNS TXT / file challenge / verified cloud integration)
 * or an explicit manual enterprise approval produces VERIFIED.
 */

export type OwnershipEvidenceKind =
  | "ROOT_RELATIONSHIP"        // candidate sits under a root asset
  | "DNS_TXT_VERIFIED"         // controlled DNS TXT challenge completed
  | "FILE_CHALLENGE_VERIFIED"  // controlled file challenge completed
  | "CERTIFICATE_SAN"          // certificate SAN mention (weak: shared certs exist)
  | "CLOUD_INTEGRATION"        // verified cloud/integration ownership
  | "REPOSITORY_CONFIGURATION" // repository/org configuration link
  | "MANUAL_APPROVAL"          // named human approval in the workflow
  | "HISTORICAL_OWNERSHIP"     // previously verified, since lapsed/aged
  | "THIRD_PARTY_DECLARATION"  // explicitly declared third-party (SaaS/CDN/vendor)
  | "SHARED_INFRASTRUCTURE";   // shared hosting / anycast / CDN edge

export interface OwnershipEvidenceInput {
  kind: OwnershipEvidenceKind;
  /** Record reference (observation id, verification id, approval id…). */
  reference: string;
  detail?: string;
}

export interface OwnershipResolution {
  status: EasmOwnershipStatus;
  confidence: EasmOwnershipConfidence;
  evidence: OwnershipEvidenceInput[];
  rationale: string;
}

const VERIFYING: OwnershipEvidenceKind[] = ["DNS_TXT_VERIFIED", "FILE_CHALLENGE_VERIFIED", "CLOUD_INTEGRATION", "MANUAL_APPROVAL"];

export function resolveOwnership(input: {
  evidence: OwnershipEvidenceInput[];
  /** Candidate is a subdomain/descendant of a root asset. */
  underRootAsset?: boolean;
}): OwnershipResolution {
  const evidence = [...input.evidence];
  if (input.underRootAsset && !evidence.some((e) => e.kind === "ROOT_RELATIONSHIP")) {
    evidence.push({ kind: "ROOT_RELATIONSHIP", reference: "root-asset", detail: "candidate is a descendant of a program root asset" });
  }
  const kinds = new Set(evidence.map((e) => e.kind));

  if (kinds.has("THIRD_PARTY_DECLARATION")) {
    return { status: "THIRD_PARTY", confidence: "HIGH", evidence, rationale: "explicitly declared third-party infrastructure (SaaS/CDN/vendor-hosted); active testing requires separate explicit authorization" };
  }
  if (VERIFYING.some((k) => kinds.has(k))) {
    return { status: "VERIFIED", confidence: "VERIFIED", evidence, rationale: "a controlled ownership-verification workflow completed (DNS TXT / file challenge / verified integration / manual enterprise approval)" };
  }
  if (kinds.has("SHARED_INFRASTRUCTURE")) {
    return { status: "SHARED", confidence: "MEDIUM", evidence, rationale: "infrastructure ownership is ambiguous/shared (shared hosting, CDN or anycast edge); conservative testing restrictions apply" };
  }
  const corroborating = ["ROOT_RELATIONSHIP", "CERTIFICATE_SAN", "REPOSITORY_CONFIGURATION", "HISTORICAL_OWNERSHIP"]
    .filter((k) => kinds.has(k as OwnershipEvidenceKind)).length;
  if (corroborating >= 2) {
    return { status: "LIKELY", confidence: "HIGH", evidence, rationale: "multiple independent ownership signals agree, but no verification workflow has completed" };
  }
  if (corroborating === 1) {
    return { status: "LIKELY", confidence: "MEDIUM", evidence, rationale: "one ownership signal present; verification workflow has not completed" };
  }
  return { status: "UNKNOWN", confidence: "UNKNOWN", evidence, rationale: "no ownership evidence recorded" };
}

/**
 * Promotion gate (§70–§71): a candidate may become a canonical asset
 * when ownership is VERIFIED, or LIKELY with HIGH confidence, AND the
 * program policy allows promotion. Promotion NEVER changes the
 * active-testing status — that is a separate authorization (§71).
 */
export function canPromoteCandidate(input: {
  ownershipStatus: EasmOwnershipStatus;
  ownershipConfidence: EasmOwnershipConfidence;
  policyAllowsPromotion: boolean;
}): { allowed: boolean; reason: string } {
  if (!input.policyAllowsPromotion) return { allowed: false, reason: "program policy does not allow promotion" };
  if (input.ownershipStatus === "THIRD_PARTY") return { allowed: false, reason: "third-party assets are tracked as candidates, never promoted into managed scope" };
  if (input.ownershipStatus === "VERIFIED") return { allowed: true, reason: "ownership verified" };
  if (input.ownershipStatus === "LIKELY" && input.ownershipConfidence === "HIGH") {
    return { allowed: true, reason: "ownership likely with high confidence (multiple corroborating signals)" };
  }
  return { allowed: false, reason: `ownership ${input.ownershipStatus}/${input.ownershipConfidence} does not meet the promotion bar (VERIFIED, or LIKELY with HIGH confidence)` };
}
