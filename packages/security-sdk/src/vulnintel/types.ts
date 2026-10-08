/**
 * Advanced vulnerability intelligence (Prompt 30). Shared types.
 *
 * Governing rules for the whole package:
 * - Every intelligence value carries provenance (source + observed time).
 *   Nothing here invents a score, a fixed version, or an affected range.
 * - EPSS history is append-only: yesterday's score is never overwritten.
 * - Exploit intelligence is DEFENSIVE METADATA ONLY (§72–§75): whether a
 *   public exploit is *reported*, with a source — never exploit code,
 *   never payloads, never operational instructions (§73/§159).
 * - Low-confidence matches stay POTENTIALLY_AFFECTED (§52/§56).
 */

export type CveStatus = "PUBLISHED" | "MODIFIED" | "REJECTED" | "WITHDRAWN" | "UNKNOWN";

/** Statuses that mean the CVE is NOT an active vulnerability (§5). */
export const INACTIVE_CVE_STATUSES: readonly CveStatus[] = ["REJECTED", "WITHDRAWN"];

export interface Provenance {
  source: string;
  /** ISO timestamp the value was observed from the source. */
  observedAt: string;
}

export interface CvssAssessmentData {
  cveId: string;
  version: "2.0" | "3.0" | "3.1" | "4.0";
  vector?: string;
  baseScore: number;
  severity?: string;
  temporalScore?: number;
  environmentalScore?: number;
  source: string;
  publishedAt?: string;
  observedAt: string;
}

export interface EpssPoint {
  cveId: string;
  /** Probability 0..1 — context, never severity. Missing stays absent, never 0. */
  score: number;
  percentile: number; // 0..1
  date: string; // ISO date of the EPSS snapshot
  source: string;
}

export interface KevEntryData {
  cveId: string;
  catalogSource: string;
  dateAdded?: string;
  requiredAction?: string;
  dueDate?: string;
  ransomwareAssociation?: string; // known | unknown (as the source states)
  notes?: string;
  vendorProject?: string;
  product?: string;
  status: "ACTIVE" | "REMOVED";
  source: string;
}

export interface AffectedRangeData {
  cveId: string;
  vendor: string;
  product: string;
  ecosystem?: string;
  introducedVersion?: string;
  fixedVersion?: string;
  lastAffectedVersion?: string;
  rangeExpression?: string;
  /** §36: LOW | MEDIUM | HIGH, from source quality. */
  confidence: "LOW" | "MEDIUM" | "HIGH";
  source: string;
}

export interface AdvisoryData {
  provider: string;
  advisoryId: string;
  title: string;
  publishedAt?: string;
  updatedAt?: string;
  /** Validated http/https references only (§128). */
  references: { label: string; url: string }[];
  cveIds: string[];
  /** productKey -> fixed versions exactly as the advisory states them. */
  fixedVersions: Record<string, string[]>;
  mitigations: { productKey: string; text: string }[];
  source: string;
}

export interface PatchRecordData {
  cveId: string;
  productKey: string; // normalized vendor:product
  affectedRange?: string;
  fixedVersion?: string;
  advisoryId?: string;
  mitigation?: string;
  releaseDate?: string;
  status: PatchStatus;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  source: string;
}

export type PatchStatus =
  | "PATCH_AVAILABLE"
  | "FIXED_VERSION_AVAILABLE"
  | "MITIGATION_ONLY"
  | "NO_KNOWN_FIX"
  | "UNKNOWN";

export type ExploitMaturity =
  | "UNKNOWN"
  | "THEORETICAL"
  | "PROOF_OF_CONCEPT_REPORTED"
  | "FUNCTIONAL_REPORTED"
  | "ACTIVE_EXPLOITATION_REPORTED";

export interface ExploitContextData {
  cveId: string;
  publicExploitKnown: boolean;
  exploitationObserved: boolean;
  kevListed: boolean;
  exploitMaturity: ExploitMaturity;
  /** §75: maturity is meaningless without its source. */
  source: string;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  references: { label: string; url: string }[];
}

export type MatchType =
  | "PURL_EXACT"
  | "CPE_EXACT"
  | "PACKAGE_EXACT"
  | "VERSION_RANGE"
  | "SCANNER_CONFIRMED"
  | "HEURISTIC";

export type MatchConfidence = "EXACT" | "HIGH" | "MEDIUM" | "LOW" | "AMBIGUOUS";

export type AffectedStatus = "AFFECTED" | "NOT_AFFECTED" | "POTENTIALLY_AFFECTED" | "UNKNOWN";

export interface ComponentMatchResult {
  matchType: MatchType;
  confidence: MatchConfidence;
  affectedStatus: AffectedStatus;
  evidence: string[];
}
