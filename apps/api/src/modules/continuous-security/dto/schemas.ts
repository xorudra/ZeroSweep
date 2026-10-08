import { z } from "zod";

/**
 * Request DTOs for the continuous-security module (Prompt 22 §86).
 * Everything is a closed zod schema: unknown keys are stripped, code-
 * shaped workflow content is rejected again by the SDK DSL validator
 * (§61/§62), and schedule expressions are validated by the governed
 * cron parser — never by a general-purpose cron library.
 */

export const targetSelectorSchema = z.object({
  assetIds: z.array(z.string().min(1)).max(500).optional(),
  targetIds: z.array(z.string().min(1)).max(500).optional(),
  assessmentIds: z.array(z.string().min(1)).max(500).optional(),
  tags: z.array(z.string().min(1).max(64)).max(50).optional(),
  environment: z.string().max(64).optional(),
  businessUnit: z.string().max(128).optional(),
  assetTypes: z.array(z.string().min(1).max(64)).max(50).optional(),
  criticalities: z.array(z.string().min(1).max(32)).max(10).optional(),
}).strict();

export const createPolicySchema = z.object({
  name: z.string().min(1).max(200),
  enabled: z.boolean().optional(),
  targetSelector: targetSelectorSchema.default({}),
  scanProfile: z.string().min(1).max(64),
  frequency: z.enum(["HOURLY", "DAILY", "WEEKLY", "MONTHLY", "CUSTOM"]).default("DAILY"),
  cronExpression: z.string().min(1).max(120).optional(),
  timezone: z.string().min(1).max(64).default("UTC"),
  safeOnly: z.boolean().default(true),
  riskThreshold: z.number().min(0).max(100).optional(),
  retestPolicy: z.record(z.unknown()).default({}),
  notificationPolicy: z.record(z.unknown()).default({}),
});

export const updatePolicySchema = createPolicySchema.partial().extend({
  name: z.string().min(1).max(200).optional(),
});

export const createScheduleSchema = z.object({
  name: z.string().min(1).max(200),
  kind: z.enum(["SCAN", "REPORT", "REVALIDATION", "INTEL_SYNC", "RETEST"]).default("SCAN"),
  policyId: z.string().min(1).optional(),
  assessmentId: z.string().min(1).optional(),
  reportScheduleId: z.string().min(1).optional(),
  frequency: z.enum(["HOURLY", "DAILY", "WEEKLY", "MONTHLY", "CUSTOM"]).default("DAILY"),
  cronExpression: z.string().min(1).max(120).optional(),
  timezone: z.string().min(1).max(64).default("UTC"),
  missedRunPolicy: z.enum(["SKIP", "RUN_ONCE", "CATCH_UP_LIMITED"]).default("RUN_ONCE"),
  allowConcurrent: z.boolean().default(false),
  enabled: z.boolean().default(true),
});

export const updateScheduleSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  frequency: z.enum(["HOURLY", "DAILY", "WEEKLY", "MONTHLY", "CUSTOM"]).optional(),
  cronExpression: z.string().min(1).max(120).optional(),
  timezone: z.string().min(1).max(64).optional(),
  missedRunPolicy: z.enum(["SKIP", "RUN_ONCE", "CATCH_UP_LIMITED"]).optional(),
  allowConcurrent: z.boolean().optional(),
  enabled: z.boolean().optional(),
});

export const maintenanceWindowSchema = z.object({
  name: z.string().min(1).max(200),
  policyId: z.string().min(1).optional(),
  daysOfWeek: z.array(z.number().int().min(0).max(6)).max(7).default([]),
  startTime: z.string().regex(/^\d{2}:\d{2}$/),
  endTime: z.string().regex(/^\d{2}:\d{2}$/),
  timezone: z.string().min(1).max(64).default("UTC"),
  mode: z.enum(["ALLOWED_HOURS", "BLOCKED_HOURS"]).default("ALLOWED_HOURS"),
});

export const blackoutWindowSchema = z.object({
  name: z.string().min(1).max(200),
  reason: z.string().max(500).optional(),
  startsAt: z.coerce.date(),
  endsAt: z.coerce.date(),
});

export const schedulerSettingsSchema = z.object({
  maxConcurrentScheduledScans: z.number().int().min(1).max(50).optional(),
  dailyRunBudget: z.number().int().min(1).max(100000).optional(),
  queueDepthThreshold: z.number().int().min(1).max(100000).optional(),
  leaseTtlSeconds: z.number().int().min(30).max(3600).optional(),
  maxRetryAttempts: z.number().int().min(0).max(10).optional(),
});

export const workflowConditionSchema = z.object({
  field: z.enum(["severity", "priority", "environment", "assetType", "verification", "kev", "riskScore", "owner", "tag", "domain"]),
  operator: z.enum(["eq", "neq", "in", "gte", "lte", "contains"]),
  value: z.unknown(),
});

export const workflowActionSchema = z.object({
  type: z.enum(["CREATE_NOTIFICATION", "ASSIGN_FINDING", "SET_PRIORITY", "REQUEST_SAFE_RETEST", "CREATE_REPORT_DRAFT", "CREATE_ANALYST_TASK", "ADD_TAG"]),
  params: z.record(z.union([z.string(), z.number(), z.boolean()])).optional(),
});

export const createWorkflowSchema = z.object({
  name: z.string().min(1).max(200),
  trigger: z.enum(["FINDING_CREATED", "FINDING_VERIFIED", "FINDING_REOPENED", "KEV_DETECTED", "SLA_DUE_SOON", "SLA_OVERDUE", "NEW_PUBLIC_ASSET", "RISK_INCREASED", "SCAN_FAILED", "REPORT_READY"]),
  conditions: z.array(workflowConditionSchema).max(20).default([]),
  actions: z.array(workflowActionSchema).min(1).max(10),
  enabled: z.boolean().default(true),
});

export const updateWorkflowSchema = createWorkflowSchema.partial();

export const notificationPolicySchema = z.object({
  name: z.string().min(1).max(200),
  eventTypes: z.array(z.string().min(1).max(64)).min(1).max(50),
  minSeverity: z.enum(["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional(),
  minPriority: z.enum(["P0", "P1", "P2", "P3", "P4"]).optional(),
  riskThreshold: z.number().min(0).max(100).optional(),
  channels: z.array(z.enum(["IN_APP", "EMAIL", "SLACK", "TEAMS", "WEBHOOK"])).min(1).max(5),
  recipients: z.array(z.string().max(200)).max(100).default([]),
  dedupWindowMinutes: z.number().int().min(0).max(10080).default(60),
  quietHours: z.object({
    startTime: z.string().regex(/^\d{2}:\d{2}$/),
    endTime: z.string().regex(/^\d{2}:\d{2}$/),
    timezone: z.string().min(1).max(64),
  }).nullable().optional(),
  emergencySeverities: z.array(z.string().max(32)).max(5).default(["CRITICAL"]),
  throttlePerHour: z.number().int().min(1).max(10000).default(60),
  webhook: z.object({
    url: z.string().url().max(2000),
    allowlist: z.array(z.string().max(200)).max(50).default([]),
    signingSecretRef: z.string().max(200).optional(),
  }).optional(),
  enabled: z.boolean().default(true),
});

export const escalationPolicySchema = z.object({
  name: z.string().min(1).max(200),
  priorities: z.array(z.enum(["P0", "P1", "P2", "P3", "P4"])).min(1).max(5).default(["P0", "P1"]),
  escalateAfterMinutes: z.number().int().min(1).max(43200).default(240),
  escalateTo: z.array(z.string().max(200)).max(50).default([]),
  enabled: z.boolean().default(true),
});

export const autoRetestPolicySchema = z.object({
  enabled: z.boolean(),
  triggers: z.array(z.enum(["SCHEDULED", "NEW_DEPLOYMENT_OR_BUILD", "NEW_SCAN_OBSERVATION", "REMEDIATION_MARKER"])).max(4).default([]),
  maxPerDay: z.number().int().min(1).max(1000).default(50),
});
