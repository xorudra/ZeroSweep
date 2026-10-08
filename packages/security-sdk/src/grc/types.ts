/**
 * GRC engine shared types (Prompt 26). The GRC layer NEVER certifies:
 * every status produced here is an assessment state derived from
 * evidence, and a control or requirement without evidence is
 * NOT_EVALUATED / NOT_ASSESSED — never compliant by default (§37,
 * §143). Framework content is versioned reference data (§4).
 */

export const GRC_DISCLAIMER =
  "DSRclone provides technical evidence, control monitoring, assessment support, risk tracking and audit preparation. " +
  "It does not certify or attest compliance. Certification/attestation remains the responsibility of qualified auditors/assessors and the organization.";

export type FrameworkKey =
  | "ISO_27001" | "SOC_2" | "PCI_DSS" | "NIST_CSF" | "NIST_800_53"
  | "CIS_CONTROLS" | "CIS_BENCHMARK" | "OWASP_ASVS" | "OWASP_TOP_10";

export type FrameworkStatus = "DRAFT" | "ACTIVE" | "DEPRECATED" | "RETIRED";

export interface FrameworkRequirementData {
  requirementId: string; // e.g. "A.8.5", "CC6.1", "8.4", "PR.AA", "IA-2"
  parentRequirementId?: string;
  title: string;
  description: string;
  category: string;
  level: number;
}

export interface FrameworkData {
  key: FrameworkKey;
  name: string;
  publisher: string;
  version: string;
  effectiveDate: string; // ISO date
  requirements: FrameworkRequirementData[];
}

export type ControlType = "PREVENTIVE" | "DETECTIVE" | "CORRECTIVE" | "GOVERNANCE";
export type ImplementationType = "TECHNICAL" | "ADMINISTRATIVE" | "PHYSICAL" | "HYBRID";
export type ControlImplementationStatus =
  | "NOT_IMPLEMENTED" | "PLANNED" | "IMPLEMENTED" | "PARTIALLY_IMPLEMENTED" | "NOT_APPLICABLE";
export type ControlEffectiveness =
  | "NOT_TESTED" | "EFFECTIVE" | "PARTIALLY_EFFECTIVE" | "INEFFECTIVE" | "INCONCLUSIVE";
export type MappingType = "DIRECT" | "PARTIAL" | "SUPPORTING";
export type MappingConfidence = "HIGH" | "MEDIUM" | "LOW";
export type TestMethod = "AUTOMATED" | "MANUAL" | "HYBRID";
export type AutomationLevel = "FULL" | "PARTIAL" | "NONE";

export interface SecurityControlData {
  code: string;
  title: string;
  description: string;
  controlType: ControlType;
  implementationType: ImplementationType;
  /** Signal keys this control is evaluated from (technical controls). */
  signals: string[];
  /** Evidence source types that can support this control (§19). */
  evidenceSources: string[];
  testName: string;
  testMethod: TestMethod;
  automationLevel: AutomationLevel;
  testFrequency: string; // e.g. CONTINUOUS | DAILY | WEEKLY | MONTHLY | QUARTERLY | ANNUAL
  expectedResult: string;
}

export interface ControlMappingData {
  controlCode: string;
  frameworkKey: FrameworkKey;
  frameworkVersion: string;
  requirementId: string;
  mappingType: MappingType;
  coverage: number; // 0..1 — share of the requirement this control covers
  notes: string;
  source: string;
}

export type EvidenceSourceType =
  | "ASSET_INVENTORY" | "WEB_FINDING" | "NETWORK_FINDING" | "API_FINDING"
  | "CLOUD_FINDING" | "CONTAINER_FINDING" | "KUBERNETES_FINDING" | "SAST"
  | "SCA" | "SBOM" | "SECRETS" | "IDENTITY_POSTURE" | "MFA_CONFIGURATION"
  | "SSO_CONFIGURATION" | "DEVSECOPS_GATE" | "BACKUP_VERIFICATION" | "DR_TEST"
  | "AUDIT_EVENT" | "CONTINUOUS_SNAPSHOT" | "MANUAL_UPLOAD" | "ACCESS_REVIEW";

export type EvidenceClassification = "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED";
export type EvidenceStatus = "CURRENT" | "STALE" | "EXPIRED" | "INVALID" | "SUPERSEDED";

export interface EvidenceSnapshot {
  sourceType: EvidenceSourceType | string;
  sourceId: string;
  /** Canonical snapshot content — hashed at collection time (§21/§22). */
  snapshot: Record<string, unknown>;
  classification: EvidenceClassification;
  collectedAt: string;
}

export type ControlResult = "PASS" | "FAIL" | "PARTIAL" | "INCONCLUSIVE" | "NOT_APPLICABLE";
export type ControlConfidence = "LOW" | "MEDIUM" | "HIGH";

export interface ControlSignalData {
  key: string;
  /** PASS/FAIL/PARTIAL observed state of the signal, or null when unknown. */
  state: "PASS" | "FAIL" | "PARTIAL" | null;
  detail: string;
  evidenceRefs: string[];
  observedAt: string;
}

export type RequirementResult =
  | "COMPLIANT" | "PARTIALLY_COMPLIANT" | "NON_COMPLIANT" | "NOT_APPLICABLE" | "NOT_ASSESSED";

export type RiskSource =
  | "TECHNICAL_FINDING" | "CONTROL_FAILURE" | "AUDIT_FINDING" | "MANUAL" | "VENDOR" | "BUSINESS";
export type RiskStatus =
  | "IDENTIFIED" | "ASSESSED" | "TREATMENT_PLANNED" | "IN_TREATMENT" | "MONITORING" | "ACCEPTED" | "CLOSED";
export type TreatmentStrategy = "MITIGATE" | "AVOID" | "TRANSFER" | "ACCEPT";

export const IMPACT_DIMENSIONS = [
  "confidentiality", "integrity", "availability", "financial", "operational", "regulatory", "reputation",
] as const;
export type ImpactDimension = (typeof IMPACT_DIMENSIONS)[number];

export type DriftEventType =
  | "CONTROL_FAILED" | "CONTROL_RECOVERED" | "EVIDENCE_STALE" | "EVIDENCE_EXPIRED" | "NEW_GAP" | "RISK_INCREASED";

export const GRC_AUDIT_ACTIONS = [
  "FRAMEWORK_IMPORTED", "CONTROL_CREATED", "CONTROL_UPDATED", "CONTROL_TESTED",
  "CONTROL_FAILED", "CONTROL_RECOVERED", "EVIDENCE_COLLECTED", "EVIDENCE_UPLOADED",
  "EVIDENCE_EXPIRED", "ASSESSMENT_CREATED", "GRC_ASSESSMENT_COMPLETED", "RISK_CREATED",
  "RISK_UPDATED", "RISK_ACCEPTED", "RISK_ACCEPTANCE_EXPIRED", "POLICY_APPROVED",
  "AUDIT_CREATED", "AUDIT_EVIDENCE_SUBMITTED", "AUDIT_EVIDENCE_ACCEPTED", "AUDIT_PACKAGE_GENERATED",
] as const;

export const GRC_PERMISSIONS = [
  "VIEW_GRC", "MANAGE_FRAMEWORKS", "VIEW_CONTROLS", "MANAGE_CONTROLS", "TEST_CONTROLS",
  "VIEW_COMPLIANCE_EVIDENCE", "UPLOAD_COMPLIANCE_EVIDENCE", "VIEW_RESTRICTED_EVIDENCE",
  "MANAGE_ASSESSMENTS", "REVIEW_ASSESSMENTS", "VIEW_RISK_REGISTER", "MANAGE_RISKS",
  "APPROVE_RISK_ACCEPTANCE", "MANAGE_POLICIES", "VIEW_AUDITS", "MANAGE_AUDITS",
  "REVIEW_AUDIT_EVIDENCE", "GENERATE_AUDIT_PACKAGE", "MANAGE_VENDOR_RISK",
] as const;
export type GrcPermission = (typeof GRC_PERMISSIONS)[number];
