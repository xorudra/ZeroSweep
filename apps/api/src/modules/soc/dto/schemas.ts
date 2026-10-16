import { z } from "zod";

/**
 * Prompt 28 DTO schemas. Rule definitions, playbook steps and STIX
 * bundles are parsed as DATA only — the SDK compilers reject anything
 * code-shaped (§18/§85/§134). Secret values are never accepted:
 * sources carry authentication REFERENCES (§58/§59).
 */

const sev = z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);

export const ingestTelemetrySchema = z.object({
  source: z.string().min(1).max(120).optional(),
  /** Ingestion authentication evidence (§9): the caller must present
   *  a scoped API key, a service account, or a signed webhook — the
   *  service verifies it; an unauthenticated mode does not exist. */
  auth: z.object({
    kind: z.enum(["API_KEY", "SERVICE_ACCOUNT", "SIGNED_WEBHOOK", "USER_SESSION"]),
    reference: z.string().min(1).max(300),
    /** Required for SIGNED_WEBHOOK: hex HMAC-SHA256 of the canonical
     *  events payload under the integration's resolved secret. A bare
     *  integration id is an identifier, not a credential — the service
     *  rejects a signed-webhook ingest without a valid signature. */
    signature: z.string().min(1).max(256).optional(),
  }),
  events: z.array(z.unknown()).min(1).max(500),
});

export const createTelemetrySourceSchema = z.object({
  name: z.string().min(1).max(120),
  sourceCategory: z.string().min(1).max(60),
  authReference: z.string().max(300).optional(),
  expectedIntervalSeconds: z.number().int().min(30).max(7 * 24 * 3600).optional(),
});

export const createDetectionRuleSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().max(2000).optional(),
  category: z.string().min(1).max(80),
  severity: sev,
  templateKey: z.string().max(120).optional(),
  definition: z.unknown(),
  attackMappings: z.array(z.unknown()).max(20).optional(),
  dataSources: z.array(z.string().max(60)).max(20).optional(),
});

export const updateDetectionRuleSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  description: z.string().max(2000).optional(),
  severity: sev.optional(),
  definition: z.unknown().optional(),
  attackMappings: z.array(z.unknown()).max(20).optional(),
  dataSources: z.array(z.string().max(60)).max(20).optional(),
});

export const ruleStatusSchema = z.object({
  status: z.enum(["TESTING", "ACTIVE", "DISABLED", "DEPRECATED"]),
});

export const testRuleSchema = z.object({
  events: z.array(z.unknown()).min(1).max(200),
});

export const triageAlertSchema = z.object({
  decision: z.enum(["TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_EXPECTED", "NEEDS_INVESTIGATION", "DUPLICATE"]),
  reason: z.string().max(1000).optional(),
  notes: z.string().max(4000).optional(),
});

export const patchAlertSchema = z.object({
  status: z.enum(["TRIAGED", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]).optional(),
  ownerId: z.string().max(120).optional(),
});

export const createSuppressionSchema = z.object({
  ruleId: z.string().max(120).optional(),
  assetId: z.string().max(120).optional(),
  identityReference: z.string().max(300).optional(),
  reason: z.string().min(1).max(1000),
  expiresAt: z.string().datetime(),
  approvedBy: z.string().max(120).optional(),
});

export const createIncidentSchema = z.object({
  title: z.string().min(1).max(300),
  description: z.string().max(8000).optional(),
  severity: sev,
  priority: z.enum(["P1", "P2", "P3", "P4"]).optional(),
  category: z.string().max(80).optional(),
  alertIds: z.array(z.string()).max(100).optional(),
  classification: z.enum(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]).optional(),
});

export const patchIncidentSchema = z.object({
  status: z.enum(["DECLARED", "INVESTIGATING", "CONTAINING", "CONTAINED", "ERADICATING", "RECOVERING", "MONITORING", "CLOSED"]).optional(),
  commanderId: z.string().max(120).optional(),
  businessImpact: z.string().max(4000).optional(),
  severity: sev.optional(),
  priority: z.enum(["P1", "P2", "P3", "P4"]).optional(),
});

export const addTimelineEntrySchema = z.object({
  entryType: z.enum(["ANALYST_NOTE", "COMMUNICATION", "SYSTEM"]).default("ANALYST_NOTE"),
  summary: z.string().min(1).max(2000),
  amendsEntryId: z.string().max(120).optional(),
});

export const addEvidenceSchema = z.object({
  source: z.enum(["TELEMETRY_EVENT", "FILE", "REPORT", "MANUAL"]),
  classification: z.enum(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]).optional(),
  objectReference: z.string().min(1).max(600),
  description: z.string().max(2000).optional(),
  /** The content whose sha256 becomes the integrity anchor (§49).
   *  For telemetry evidence this is the event's canonical body; the
   *  service verifies it against the stored event hash (§143). */
  content: z.string().max(200000),
  relatedEventId: z.string().max(120).optional(),
  relatedAssetId: z.string().max(120).optional(),
});

export const createCaseSchema = z.object({
  title: z.string().min(1).max(300),
  description: z.string().max(8000).optional(),
  severity: sev.optional(),
  linkedAlertIds: z.array(z.string()).max(100).optional(),
  linkedEventIds: z.array(z.string()).max(100).optional(),
});

export const createIntelSourceSchema = z.object({
  name: z.string().min(1).max(160),
  type: z.enum(["STIX_TAXII", "COMMERCIAL_FEED", "PUBLIC_FEED", "INTERNAL", "FIXTURE"]),
  trustLevel: z.number().int().min(0).max(100).optional(),
  authenticationReference: z.string().max(300).optional(),
  syncFrequencyMinutes: z.number().int().min(5).max(10080).optional(),
});

export const importIntelSchema = z.object({
  /** Recorded/fixture STIX bundle or plain indicator list (§59/§60).
   *  Live feed transports are not wired — import is the ingestion path. */
  format: z.enum(["STIX", "INDICATORS"]),
  bundle: z.unknown().optional(),
  indicators: z.array(z.object({
    type: z.enum(["IP", "DOMAIN", "URL", "FILE_HASH", "EMAIL_DOMAIN", "CERTIFICATE_FINGERPRINT"]),
    value: z.string().min(1).max(2048),
    confidence: z.number().int().min(0).max(100).optional(),
    severity: sev.optional(),
    validUntil: z.string().datetime().optional(),
    tags: z.array(z.string().max(60)).max(16).optional(),
  })).max(5000).optional(),
});

export const addIndicatorSchema = z.object({
  sourceId: z.string().min(1).max(120),
  type: z.enum(["IP", "DOMAIN", "URL", "FILE_HASH", "EMAIL_DOMAIN", "CERTIFICATE_FINGERPRINT"]),
  value: z.string().min(1).max(2048),
  confidence: z.number().int().min(0).max(100).optional(),
  severity: sev.optional(),
  validUntil: z.string().datetime().optional(),
  tags: z.array(z.string().max(60)).max(16).optional(),
});

export const proposeActionSchema = z.object({
  actionKey: z.string().min(1).max(80),
  targetReference: z.string().min(1).max(300),
  nonce: z.string().min(1).max(120),
});

export const approveActionSchema = z.object({
  decision: z.enum(["APPROVED", "REJECTED"]),
  reason: z.string().max(1000).optional(),
});

export const startPlaybookSchema = z.object({
  playbookKey: z.string().min(1).max(120),
});

export const advancePlaybookSchema = z.object({
  stepKey: z.string().min(1).max(120),
  note: z.string().max(2000).optional(),
});

export const addCommunicationSchema = z.object({
  audience: z.enum(["INTERNAL", "EXECUTIVE", "TECHNICAL", "CUSTOMER"]),
  channel: z.enum(["IN_APP", "EMAIL", "SLACK", "TEAMS", "WEBHOOK"]),
  template: z.enum(["INTERNAL_STATUS", "EXECUTIVE_UPDATE", "TECHNICAL_UPDATE", "RESOLUTION_NOTICE"]).optional(),
  message: z.string().min(1).max(8000),
});

export const upsertPirSchema = z.object({
  summary: z.string().max(8000).optional(),
  impact: z.string().max(8000).optional(),
  rootCause: z.string().max(8000).optional(),
  rootCauseState: z.enum(["CONFIRMED", "LIKELY", "UNKNOWN"]).optional(),
  detectionGaps: z.array(z.string().max(1000)).max(50).optional(),
  responseGaps: z.array(z.string().max(1000)).max(50).optional(),
  lessons: z.array(z.string().max(1000)).max(50).optional(),
  followUpActions: z.array(z.unknown()).max(50).optional(),
  ownerId: z.string().max(120).optional(),
  status: z.enum(["DRAFT", "COMPLETED"]).optional(),
});

export const socAskSchema = z.object({
  question: z.string().min(1).max(2000),
  incidentId: z.string().max(120).optional(),
  alertId: z.string().max(120).optional(),
});
