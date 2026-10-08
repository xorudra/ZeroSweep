import { z } from "zod";

/** Prompt 40 request DTOs. Bodies are validated with zod via parseOrThrow
 *  (the platform's standard §227 error shape) — the client-portal 500-on-
 *  malformed-body class of bug (RC1-M1) must not recur here. */

export const signupSchema = z.object({
  name: z.string().min(1).max(120),
  email: z.string().email().max(254),
  password: z.string().min(10).max(200),
  organizationName: z.string().min(1).max(160),
  slug: z.string().min(3).max(64),
});

export const verifyEmailSchema = z.object({ token: z.string().min(16).max(512) });

export const completeStepSchema = z.object({ attested: z.boolean().optional() }).optional();

export const installLicenseSchema = z.object({
  document: z.string().min(20).max(100_000),
});

export const createPlanSchema = z.object({
  code: z.string().min(2).max(64),
  name: z.string().min(1).max(160),
  description: z.string().max(1000).optional(),
  productMode: z.enum(["COMMUNITY", "SELF_HOSTED", "SAAS", "ENTERPRISE"]),
  entitlements: z.array(z.object({
    featureKey: z.string().min(1).max(64),
    enabled: z.boolean(),
    limit: z.number().int().nullable().optional(),
    configuration: z.record(z.unknown()).optional(),
  })).max(64),
  quotas: z.record(z.number().int().nullable()).optional(),
});

export const updatePlanSchema = z.object({
  name: z.string().min(1).max(160).optional(),
  description: z.string().max(1000).optional(),
  entitlements: createPlanSchema.shape.entitlements,
  quotas: z.record(z.number().int().nullable()).optional(),
});

export const planStatusSchema = z.object({ status: z.enum(["DRAFT", "ACTIVE", "DEPRECATED", "RETIRED"]) });

export const createSubscriptionSchema = z.object({
  organizationId: z.string().uuid(),
  planVersionId: z.string().uuid(),
  status: z.enum(["TRIALING", "ACTIVE", "PAST_DUE", "SUSPENDED", "CANCELLED", "EXPIRED"]).optional(),
  externalBillingReference: z.string().max(200).nullable().optional(),
});

export const changePlanSchema = z.object({
  planVersionId: z.string().uuid(),
  impactAcknowledged: z.boolean().optional(),
});

export const cancelSubscriptionSchema = z.object({ atPeriodEnd: z.boolean().default(true) });

export const quotaOverrideSchema = z.object({
  organizationId: z.string().uuid(),
  metric: z.string().min(1).max(64),
  newLimit: z.number().int().min(0),
  reason: z.string().min(3).max(500),
  expiresAt: z.string().datetime().nullable().optional(),
});

export const recordUsageSchema = z.object({
  metric: z.string().min(1).max(64),
  quantity: z.number().positive().max(1e12).default(1),
  source: z.string().min(1).max(64),
  reference: z.string().max(200).optional(),
  idempotencyKey: z.string().min(1).max(200),
  workspaceId: z.string().uuid().optional(),
});

export const manualInvoiceSchema = z.object({
  organizationId: z.string().uuid(),
  externalInvoiceId: z.string().min(1).max(200),
  status: z.string().min(1).max(64),
  currency: z.string().max(8).optional(),
  amountCents: z.number().int().min(0).optional(),
  hostedInvoiceRef: z.string().max(500).optional(),
});

export const supportAccessCreateSchema = z.object({
  organizationId: z.string().uuid(),
  reason: z.string().min(10).max(1000),
  scope: z.object({ areas: z.array(z.string().max(64)).max(16) }),
  expiresInHours: z.number().int().min(1).max(168).default(8),
  tenantApproved: z.boolean().default(false),
});

export const deletionRequestSchema = z.object({
  typedConfirmation: z.string().min(1).max(64),
});

export const legalHoldSchema = z.object({ hold: z.boolean() });
