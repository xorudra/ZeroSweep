import type { NormalizedFinding } from "../findings/finding.types";

/**
 * Prompt 7 normalized vulnerability finding: the common Finding schema
 * (§17) plus the provenance/correlation fields the pipeline needs. Every
 * field a scanner did not actually provide stays undefined — CVE/CWE/CVSS
 * are NEVER invented (§17/§26/§27); CWE/OWASP are filled only from the
 * platform's curated taxonomy (taxonomy.ts) keyed by vulnerability class.
 */
export interface FindingEvidenceDetail {
  /** Redacted, size-capped HTTP request text (never raw secrets, §30/§31). */
  request?: string;
  /** Redacted, size-capped HTTP response text. */
  response?: string;
  /** Where the tool matched (URL / host:port), redacted at the URL level. */
  matchedAt?: string;
  /** Object-storage reference of the raw artifact this evidence came from. */
  artifactRef?: string;
  /** Nuclei template id / Nikto check id / TLS check id, when applicable. */
  checkId?: string;
  /** Scanner signature family: two tools sharing a family may be reporting
   *  the SAME upstream signature — corroboration must not double-count it
   *  (§22). */
  signatureFamily?: string;
  /** Scanner metadata blob (already redacted/sanitized by the parser). */
  metadata?: Record<string, string>;
}

export interface NormalizedReference {
  type: "CVE" | "CWE" | "OWASP" | "VENDOR" | "URL";
  label: string;
  url: string;
}

export interface NormalizedVulnFinding extends NormalizedFinding {
  /** Curated vulnerability class (taxonomy.ts) — the correlation key part
   *  that lets DIFFERENT tools' reports of one issue merge (§19–§21). */
  vulnClass: string;
  protocol?: string;
  technicalImpact?: string;
  businessImpact?: string;
  cvssVersion?: string;
  /** Structured references with validated URLs only (§54). */
  referencesDetailed: NormalizedReference[];
  evidenceDetail?: FindingEvidenceDetail;
  /** Nuclei template id that produced this finding, when applicable. */
  templateId?: string;
  signatureFamily?: string;
  /** Per-source confidence 0..1 assigned by the parser's evidence model. */
  sourceConfidence: number;
  /** Asset criticality known at processing time (§36); UNSPECIFIED default. */
  assetCriticality?: string;
  /** Whether the affected service is internet-exposed (§34 signal). */
  internetExposed?: boolean;
  verificationStatus?: "UNVERIFIED" | "LIKELY" | "CONFIRMED" | "REJECTED";
}

/** One tool's contribution to a (possibly merged) canonical finding. */
export interface FindingSource {
  tool: string;
  summary: string;
  evidence?: FindingEvidenceDetail;
  sourceFingerprint: string;
  templateId?: string;
  signatureFamily?: string;
  confidence: number;
}

export type DedupState = "UNIQUE" | "POSSIBLE_DUPLICATE" | "DUPLICATE";

export interface CorrelatedFinding {
  finding: NormalizedVulnFinding;
  /** Canonical cross-tool fingerprint (no tool component, §19). */
  canonicalFingerprint: string;
  sources: FindingSource[];
  dedupState: DedupState;
  /** Canonical fingerprints of findings that look similar but were NOT
   *  merged (§20 POSSIBLE_DUPLICATE links). */
  possibleDuplicates: string[];
  /** Confidence after cross-tool corroboration (§22). */
  confidenceScore: number;
  confidenceBand: "LOW" | "MEDIUM" | "HIGH" | "CONFIRMED";
  verificationStatus: "UNVERIFIED" | "LIKELY" | "CONFIRMED" | "REJECTED";
  confidenceRationale: string[];
  /** Deterministic risk (§34/§35). */
  riskScore: number;
  riskBand: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  riskExplanation: string[];
}

export interface CorrelationStats {
  /** Findings fed into correlation (post-normalization). */
  total: number;
  /** Canonical findings after merging. */
  unique: number;
  /** Findings merged away as duplicates (evidence preserved as sources). */
  duplicatesMerged: number;
  /** Canonical findings backed by ≥2 independent tools. */
  corroborated: number;
  byTool: Record<string, { total: number; unique: number; corroborated: number }>;
  /** Present when maxFindings truncated the canonical list (§51). */
  limitEvent?: { type: "MAX_FINDINGS_REACHED"; kept: number; dropped: number };
}
