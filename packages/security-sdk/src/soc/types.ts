/**
 * SOC domain vocabulary (Prompt 28). Defensive security operations
 * only: telemetry → detection → alerts → incidents → approved,
 * bounded, predefined response. There is deliberately NO vocabulary
 * here for arbitrary commands, scripts or offensive actions (§161).
 */

export const SOC_CLASSIFICATIONS = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] as const;
export type SocClassification = (typeof SOC_CLASSIFICATIONS)[number];

export const SOC_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
export type SocSeverity = (typeof SOC_SEVERITIES)[number];

export const TELEMETRY_SOURCE_CATEGORIES = [
  "DSRCLONE_INTERNAL", "AUTHENTICATION", "CLOUD", "CONTAINER_RUNTIME", "KUBERNETES",
  "DEVSECOPS", "WAF_PROXY", "IDS_IPS", "ENDPOINT", "FIREWALL", "DNS", "SIEM_IMPORT",
] as const;
export type TelemetrySourceCategory = (typeof TELEMETRY_SOURCE_CATEGORIES)[number];

/** Canonical telemetry event (§3). `rawReference` points at the raw
 *  record in approved storage; the raw body itself is never copied
 *  into the canonical store (§6). */
export interface CanonicalTelemetryEvent {
  providerEventId?: string;
  eventTime: string; // ISO
  source: string;
  sourceCategory: string;
  eventCategory: string;
  eventAction: string;
  assetId?: string;
  identityReference?: string;
  severity: SocSeverity;
  classification: SocClassification;
  attributes: Record<string, unknown>;
  rawReference?: string;
  schemaVersion: string;
}

export const DETECTION_TYPES = ["SINGLE_EVENT", "THRESHOLD", "SEQUENCE", "CORRELATION", "ANOMALY_SIGNAL"] as const;
export type DetectionType = (typeof DETECTION_TYPES)[number];

export const DETECTION_RULE_STATUSES = ["DRAFT", "TESTING", "ACTIVE", "DISABLED", "DEPRECATED"] as const;
export type DetectionRuleStatus = (typeof DETECTION_RULE_STATUSES)[number];

export const DETECTION_CONFIDENCES = ["LOW", "MEDIUM", "HIGH"] as const;
export type DetectionConfidence = (typeof DETECTION_CONFIDENCES)[number];

export const ALERT_STATUSES = ["NEW", "TRIAGED", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED", "SUPPRESSED"] as const;
export type AlertStatus = (typeof ALERT_STATUSES)[number];

export const ALERT_PRIORITIES = ["P1", "P2", "P3", "P4"] as const;
export type AlertPriority = (typeof ALERT_PRIORITIES)[number];

export const TRIAGE_DECISIONS = ["TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_EXPECTED", "NEEDS_INVESTIGATION", "DUPLICATE"] as const;
export type TriageDecision = (typeof TRIAGE_DECISIONS)[number];

export const INCIDENT_STATUSES = [
  "DRAFT", "DECLARED", "INVESTIGATING", "CONTAINING", "CONTAINED",
  "ERADICATING", "RECOVERING", "MONITORING", "CLOSED",
] as const;
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];

export const CASE_STATUSES = ["OPEN", "INVESTIGATING", "ESCALATED", "CLOSED"] as const;
export type CaseStatus = (typeof CASE_STATUSES)[number];

export const INDICATOR_TYPES = ["IP", "DOMAIN", "URL", "FILE_HASH", "EMAIL_DOMAIN", "CERTIFICATE_FINGERPRINT"] as const;
export type IndicatorType = (typeof INDICATOR_TYPES)[number];

export const INDICATOR_STATUSES = ["ACTIVE", "EXPIRED", "REVOKED", "FALSE_POSITIVE"] as const;
export type IndicatorStatus = (typeof INDICATOR_STATUSES)[number];

export const TIMELINE_ENTRY_TYPES = [
  "EVENT", "ALERT", "ANALYST_NOTE", "STATUS_CHANGE", "EVIDENCE",
  "RESPONSE_ACTION", "TICKET", "COMMUNICATION", "SYSTEM",
] as const;
export type TimelineEntryType = (typeof TIMELINE_ENTRY_TYPES)[number];

/** §123: SOC SLA targets in minutes, per priority. Configurable per
 *  workspace; these are the shipped defaults. */
export const DEFAULT_SOC_SLA_MINUTES: Record<AlertPriority, { triage: number; acknowledge: number; containment: number; recovery: number }> = {
  P1: { triage: 15, acknowledge: 30, containment: 240, recovery: 1440 },
  P2: { triage: 60, acknowledge: 240, containment: 1440, recovery: 4320 },
  P3: { triage: 240, acknowledge: 1440, containment: 4320, recovery: 10080 },
  P4: { triage: 1440, acknowledge: 4320, containment: 10080, recovery: 20160 },
};
