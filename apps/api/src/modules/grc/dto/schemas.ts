import { z } from "zod";

/** Zod DTOs for the GRC API (Prompt 26 §109). All inputs validated at
 *  the trust boundary; enums mirror the SDK value sets. */

const str = (max = 500) => z.string().min(1).max(max);
const optStr = (max = 500) => z.string().max(max).optional();
const isoDate = z.string().datetime().optional();

export const importFrameworkSchema = z.object({
  key: str(64),
  name: str(200),
  publisher: optStr(200),
  version: str(32),
  effectiveDate: isoDate,
  requirements: z.array(z.object({
    requirementId: str(64),
    parentRequirementId: z.string().max(64).optional(),
    title: str(300),
    description: z.string().max(4000).optional(),
    category: optStr(120),
    level: z.number().int().min(1).max(9).optional(),
  })).min(1).max(5000),
});
export type ImportFrameworkInput = z.infer<typeof importFrameworkSchema>;

export const createControlSchema = z.object({
  code: str(64),
  title: str(300),
  description: z.string().max(4000).optional(),
  controlType: z.enum(["PREVENTIVE", "DETECTIVE", "CORRECTIVE", "GOVERNANCE"]),
  implementationType: z.enum(["TECHNICAL", "ADMINISTRATIVE", "PHYSICAL", "HYBRID"]),
  implementationStatus: z.enum(["NOT_IMPLEMENTED", "PLANNED", "IMPLEMENTED", "PARTIALLY_IMPLEMENTED", "NOT_APPLICABLE"]).optional(),
  ownerType: z.enum(["USER", "TEAM", "BUSINESS_UNIT"]).optional(),
  ownerRef: optStr(200),
});
export type CreateControlInput = z.infer<typeof createControlSchema>;

export const updateControlSchema = createControlSchema.partial().omit({ code: true });
export type UpdateControlInput = z.infer<typeof updateControlSchema>;

export const createMappingSchema = z.object({
  controlId: str(64),
  requirementId: str(64),
  mappingType: z.enum(["DIRECT", "PARTIAL", "SUPPORTING"]),
  coverage: z.number().min(0).max(1),
  notes: z.string().max(2000).optional(),
  source: optStr(300),
});
export type CreateMappingInput = z.infer<typeof createMappingSchema>;

export const recordSignalSchema = z.object({
  controlId: str(64),
  signalKey: str(120),
  state: z.enum(["PASS", "FAIL", "PARTIAL"]).nullable(),
  detail: z.string().max(2000).optional(),
  sourceType: optStr(64),
  evidenceRefs: z.array(z.string().max(200)).max(50).optional(),
});
export type RecordSignalInput = z.infer<typeof recordSignalSchema>;

export const collectEvidenceSchema = z.object({
  controlId: str(64),
  sourceType: str(64),
  sourceId: str(200),
  snapshot: z.record(z.unknown()),
  classification: z.enum(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]).optional(),
});
export type CollectEvidenceInput = z.infer<typeof collectEvidenceSchema>;

export const uploadEvidenceSchema = z.object({
  controlId: str(64),
  filename: str(300),
  contentType: str(120),
  /** Base64 content — size-capped by the SDK validator (§40). */
  contentBase64: z.string().max(14_000_000),
  classification: z.enum(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]).optional(),
  notes: z.string().max(2000).optional(),
});
export type UploadEvidenceInput = z.infer<typeof uploadEvidenceSchema>;

export const reviewEvidenceSchema = z.object({
  decision: z.enum(["APPROVED", "REJECTED", "CHANGES_REQUESTED"]),
  notes: z.string().max(2000).optional(),
});
export type ReviewEvidenceInput = z.infer<typeof reviewEvidenceSchema>;

export const createAssessmentSchema = z.object({
  frameworkId: str(64),
  name: str(300),
  scope: z.record(z.unknown()).optional(),
  periodStart: isoDate,
  periodEnd: isoDate,
  reviewerId: optStr(64),
});
export type CreateAssessmentInput = z.infer<typeof createAssessmentSchema>;

export const reviewRequirementSchema = z.object({
  decision: z.enum(["APPROVED", "REJECTED", "CHANGES_REQUESTED"]),
  notes: z.string().max(2000).optional(),
});
export type ReviewRequirementInput = z.infer<typeof reviewRequirementSchema>;

export const createRiskSchema = z.object({
  title: str(300),
  description: z.string().max(4000).optional(),
  category: optStr(120),
  source: z.enum(["TECHNICAL_FINDING", "CONTROL_FAILURE", "AUDIT_FINDING", "MANUAL", "VENDOR", "BUSINESS"]),
  sourceRef: optStr(64),
  likelihood: z.number().int().min(1).max(5),
  impacts: z.record(z.number().int().min(1).max(5)),
  ownerId: optStr(64),
  reviewDate: isoDate,
  links: z.array(z.object({ linkType: z.enum(["FINDING", "ASSET", "CONTROL", "REQUIREMENT"]), linkId: str(64) })).max(50).optional(),
});
export type CreateRiskInput = z.infer<typeof createRiskSchema>;

export const updateRiskSchema = z.object({
  title: optStr(300),
  description: z.string().max(4000).optional(),
  category: optStr(120),
  likelihood: z.number().int().min(1).max(5).optional(),
  impacts: z.record(z.number().int().min(1).max(5)).optional(),
  ownerId: optStr(64),
  status: z.enum(["IDENTIFIED", "ASSESSED", "TREATMENT_PLANNED", "IN_TREATMENT", "MONITORING", "ACCEPTED", "CLOSED"]).optional(),
  reviewDate: isoDate,
});
export type UpdateRiskInput = z.infer<typeof updateRiskSchema>;

export const createTreatmentSchema = z.object({
  strategy: z.enum(["MITIGATE", "AVOID", "TRANSFER", "ACCEPT"]),
  description: z.string().max(4000).optional(),
  actions: z.array(z.object({
    action: str(500),
    ownerId: optStr(64),
    dueDate: isoDate,
    relatedFindingId: optStr(64),
    relatedControlId: optStr(64),
    ticketRef: optStr(200),
  })).max(100).optional(),
});
export type CreateTreatmentInput = z.infer<typeof createTreatmentSchema>;

export const requestAcceptanceSchema = z.object({
  reason: str(2000),
  scope: z.record(z.unknown()).optional(),
  compensatingControls: z.array(z.string().max(200)).max(50).optional(),
  expiresAt: z.string().datetime(),
});
export type RequestAcceptanceInput = z.infer<typeof requestAcceptanceSchema>;

export const decideAcceptanceSchema = z.object({
  decision: z.enum(["ACCEPTED", "REJECTED"]),
});
export type DecideAcceptanceInput = z.infer<typeof decideAcceptanceSchema>;

export const createReviewSchema = z.object({
  decision: z.enum(["CONFIRMED", "CHANGED", "ESCALATED", "CLOSED"]),
  changes: z.string().max(4000).optional(),
  nextReviewAt: isoDate,
});
export type CreateReviewInput = z.infer<typeof createReviewSchema>;

export const createPolicySchema = z.object({
  title: str(300),
  version: str(32),
  classification: z.enum(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]).optional(),
  documentRef: optStr(500),
  contentHash: optStr(128),
  effectiveDate: isoDate,
  reviewDate: isoDate,
});
export type CreatePolicyInput = z.infer<typeof createPolicySchema>;

export const transitionPolicySchema = z.object({
  status: z.enum(["REVIEW", "APPROVED", "ACTIVE", "RETIRED"]),
});
export type TransitionPolicyInput = z.infer<typeof transitionPolicySchema>;

export const createAuditSchema = z.object({
  frameworkId: optStr(64),
  assessmentId: optStr(64),
  type: z.enum(["INTERNAL", "EXTERNAL", "READINESS", "CUSTOMER", "REGULATORY"]),
  auditorRef: optStr(300),
  scope: z.record(z.unknown()).optional(),
  periodStart: isoDate,
  periodEnd: isoDate,
});
export type CreateAuditInput = z.infer<typeof createAuditSchema>;

export const createEvidenceRequestSchema = z.object({
  title: str(300),
  controlId: optStr(64),
  requirementId: optStr(64),
  ownerId: str(64),
  dueDate: isoDate,
});
export type CreateEvidenceRequestInput = z.infer<typeof createEvidenceRequestSchema>;

export const submitEvidenceRequestSchema = z.object({
  evidenceIds: z.array(z.string().max(64)).min(1).max(100),
});
export type SubmitEvidenceRequestInput = z.infer<typeof submitEvidenceRequestSchema>;

export const createAuditFindingSchema = z.object({
  title: str(300),
  description: z.string().max(4000).optional(),
  severity: z.enum(["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional(),
  requirementId: optStr(64),
  ownerId: str(64),
  dueDate: isoDate,
  linkedFindingIds: z.array(z.string().max(64)).max(100).optional(),
});
export type CreateAuditFindingInput = z.infer<typeof createAuditFindingSchema>;

export const grantAuditorAccessSchema = z.object({
  userId: str(64),
  assessmentIds: z.array(z.string().max(64)).max(100),
  evidenceIds: z.array(z.string().max(64)).max(500).optional(),
  expiresAt: z.string().datetime().refine((v) => { const t = new Date(v).getTime(); const now = Date.now(); return t > now && t <= now + 90 * 86400000; }, { message: 'expiresAt must be in the future and within 90 days' }),
});
export type GrantAuditorAccessInput = z.infer<typeof grantAuditorAccessSchema>;

export const createVendorSchema = z.object({
  name: str(300),
  criticality: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional(),
  serviceDescription: z.string().max(2000).optional(),
  reviewDate: isoDate,
});
export type CreateVendorInput = z.infer<typeof createVendorSchema>;

export const assessVendorSchema = z.object({
  method: z.enum(["QUESTIONNAIRE", "MANUAL_EVIDENCE", "INTEGRATION"]).optional(),
  riskRating: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  findings: z.string().max(4000).optional(),
  treatment: z.string().max(4000).optional(),
  evidenceIds: z.array(z.string().max(64)).max(100).optional(),
});
export type AssessVendorInput = z.infer<typeof assessVendorSchema>;

export const createReportSchema = z.object({
  reportType: z.enum(["COMPLIANCE_ASSESSMENT", "CONTROL_EFFECTIVENESS", "RISK_REGISTER", "RISK_TREATMENT", "AUDIT_READINESS", "EVIDENCE_FRESHNESS", "EXECUTIVE_GRC"]),
  assessmentId: optStr(64),
});
export type CreateReportInput = z.infer<typeof createReportSchema>;

export const aiAskSchema = z.object({
  question: str(2000),
  controlId: optStr(64),
  requirementId: optStr(64),
  riskId: optStr(64),
});
export type AiAskInput = z.infer<typeof aiAskSchema>;

export const overrideFindingLinkSchema = z.object({
  controlId: str(64),
  rationale: z.string().max(1000).optional(),
});
export type OverrideFindingLinkInput = z.infer<typeof overrideFindingLinkSchema>;

export const updateMatrixSchema = z.object({
  bands: z.object({ lowMax: z.number(), mediumMax: z.number(), highMax: z.number() }),
  effectivenessMultipliers: z.object({
    EFFECTIVE: z.number(), PARTIALLY_EFFECTIVE: z.number(), INEFFECTIVE: z.number(),
  }),
});
export type UpdateMatrixInput = z.infer<typeof updateMatrixSchema>;

export const createScheduleSchema = z.object({
  controlId: str(64),
  cron: str(120),
});
export type CreateScheduleInput = z.infer<typeof createScheduleSchema>;

/** Backup restore bundle (§141): validated like every neighbouring
 *  handler. `mac` is the keyed integrity proof issued at export time —
 *  a bundle without a server-issued MAC is not restorable. State is a
 *  map of table name → row objects; per-row field whitelisting and
 *  reference validation happen in GrcBackupService. */
export const restoreBundleSchema = z.object({
  workspaceId: z.string().max(64).optional(),
  hash: z.string().max(128).optional(),
  mac: z.string().min(32).max(128),
  exportedAt: z.string().datetime(),
  confirm: z.boolean().optional(),
  state: z.record(z.array(z.record(z.unknown()))),
});
export type RestoreBundleInput = z.infer<typeof restoreBundleSchema>;

export const retentionSchema = z.object({
  assessmentRetentionDays: z.number().int().min(30).max(36500).optional(),
  evidenceRetentionDays: z.number().int().min(30).max(36500).optional(),
  packageRetentionDays: z.number().int().min(30).max(36500).optional(),
  riskRetentionDays: z.number().int().min(30).max(36500).optional(),
  auditRetentionDays: z.number().int().min(30).max(36500).optional(),
});
export type RetentionInput = z.infer<typeof retentionSchema>;
