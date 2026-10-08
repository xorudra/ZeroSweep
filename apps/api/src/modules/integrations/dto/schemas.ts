import { z } from "zod";

/**
 * Prompt 24 DTO schemas. Configurations are NON-SECRET by construction:
 * any secret-shaped value (a token, a private key, a password) in a
 * create/update body is rejected — credentials are secret REFERENCES
 * only (§7). A zod schema cannot hold what it refuses to parse.
 */

const SECRET_SHAPED = /(-----BEGIN [A-Z ]*PRIVATE KEY-----|^(gh[pousr]|glpat-|xox[baprs]-|AKIA)[A-Za-z0-9_-]{8,})/;

export const nonSecretConfig = z.record(z.unknown()).superRefine((config, ctx) => {
  const walk = (value: unknown, path: string): void => {
    if (typeof value === "string" && SECRET_SHAPED.test(value)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom, path: [path],
        message: "configuration must not contain secret values — use a secretReference instead (§7)",
      });
    }
    if (Array.isArray(value)) value.forEach((v, i) => walk(v, `${path}[${i}]`));
    if (typeof value === "object" && value !== null) {
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) walk(v, path ? `${path}.${k}` : k);
    }
  };
  walk(config, "");
});

const INTEGRATION_TYPES = [
  // Prompt 20 platform types (unchanged)
  "DEFECTDOJO", "FARADAY", "DRADIS", "PLEXTRAC", "SERPICO", "SHODAN", "CENSYS", "CUSTOM",
  // Prompt 24 §4
  "GITHUB", "GITLAB", "BITBUCKET", "JIRA", "SLACK", "MICROSOFT_TEAMS", "SIEM", "GENERIC_WEBHOOK",
] as const;

export const createIntegrationSchema = z.object({
  type: z.enum(INTEGRATION_TYPES),
  name: z.string().min(1).max(200),
  config: nonSecretConfig.optional(),
  configuration: nonSecretConfig.optional(),
  /** A secret REFERENCE name (e.g. a Credential name or env:VAR) — never a value. */
  secretReference: z.string().min(1).max(300).optional(),
  credentialType: z.string().max(60).optional(),
  enabled: z.boolean().optional(),
});

export const updateIntegrationSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  config: nonSecretConfig.optional(),
  configuration: nonSecretConfig.optional(),
  enabled: z.boolean().optional(),
  status: z.enum(["PENDING", "CONNECTED", "DEGRADED", "DISCONNECTED", "DISABLED"]).optional(),
});

export const rotateCredentialSchema = z.object({
  secretReference: z.string().min(1).max(300),
  credentialType: z.string().max(60).optional(),
});

export const createRepositoryLinkSchema = z.object({
  integrationId: z.string().min(1),
  sourceRepositoryId: z.string().min(1),
  /** The provider's immutable repository id (§29) — required: a link
   *  keyed on a mutable name alone is not an identity. */
  externalRepositoryId: z.string().min(1).max(300),
  externalRepositoryRef: z.string().max(1000).optional(),
  installationId: z.string().max(300).optional(),
});

export const repositorySyncSchema = z.object({
  integrationId: z.string().min(1),
});

export const updateRepositoryPolicySchema = z.object({
  scanOnPush: z.boolean().optional(),
  scanOnPullRequest: z.boolean().optional(),
  scanDefaultBranch: z.boolean().optional(),
  sastEnabled: z.boolean().optional(),
  scaEnabled: z.boolean().optional(),
  secretScanEnabled: z.boolean().optional(),
  sbomEnabled: z.boolean().optional(),
  containerScanEnabled: z.boolean().optional(),
  gatePolicyId: z.string().nullable().optional(),
  prGatePreset: z.enum([
    "FAIL_ON_NEW_CRITICAL", "FAIL_ON_NEW_HIGH", "FAIL_ON_NEW_VERIFIED_HIGH",
    "FAIL_ON_NEW_KEV", "FAIL_ON_NEW_SECRET", "FAIL_ON_POLICY_VIOLATION",
  ]).nullable().optional(),
  autoRetest: z.boolean().optional(),
});

export const createGatePolicySchema = z.object({
  name: z.string().min(1).max(200),
  repositorySelector: z.record(z.unknown()).optional(),
  branchSelector: z.record(z.unknown()).optional(),
  rules: z.array(z.record(z.unknown())).max(50),
  scannerFailureBehavior: z.enum(["FAIL_CLOSED", "WARN", "FAIL_OPEN"]).optional(),
});

export const createBaselineSchema = z.object({
  commitSha: z.string().min(7).max(64),
  scanId: z.string().optional(),
  snapshotId: z.string().optional(),
});

export const createPipelineRunSchema = z.object({
  provider: z.enum(["GITHUB", "GITLAB", "BITBUCKET", "GENERIC_CI"]).optional(),
  repositoryId: z.string().optional(),
  externalRepositoryId: z.string().optional(),
  commitSha: z.string().min(7).max(64),
  branch: z.string().max(255).optional(),
  prNumber: z.number().int().positive().optional(),
  externalPipelineId: z.string().min(1).max(200),
});

export const createJiraMappingSchema = z.object({
  integrationId: z.string().min(1),
  findingType: z.string().max(120).optional(),
  team: z.string().max(120).optional(),
  assetGroup: z.string().max(120).optional(),
  projectKey: z.string().min(1).max(30),
  issueType: z.string().max(60).optional(),
});

export const createTicketSchema = z.object({
  integrationId: z.string().optional(),
});

export const resolveConflictSchema = z.object({
  resolution: z.enum(["RESOLVED_KEEP_LOCAL", "RESOLVED_TAKE_EXTERNAL"]),
});

export const createWebhookSubscriptionSchema = z.object({
  endpoint: z.string().url().max(2000),
  events: z.array(z.string().max(80)).min(1).max(30),
  secretReference: z.string().max(300).optional(),
  enabled: z.boolean().optional(),
});

export const siemExportSchema = z.object({
  integrationId: z.string().min(1),
  format: z.enum(["JSON", "CEF", "LEEF"]).optional(),
  eventType: z.string().max(80),
  severity: z.string().max(30),
  status: z.string().max(60),
  findingId: z.string().optional(),
  assetReference: z.string().max(300).optional(),
  riskScore: z.number().optional(),
  cve: z.string().max(30).optional(),
  cwe: z.string().max(30).optional(),
});

export type CreateIntegrationBody = z.infer<typeof createIntegrationSchema>;
export type UpdateIntegrationBody = z.infer<typeof updateIntegrationSchema>;
export type RotateCredentialBody = z.infer<typeof rotateCredentialSchema>;
export type CreateRepositoryLinkBody = z.infer<typeof createRepositoryLinkSchema>;
export type UpdateRepositoryPolicyBody = z.infer<typeof updateRepositoryPolicySchema>;
export type CreateGatePolicyBody = z.infer<typeof createGatePolicySchema>;
export type CreateBaselineBody = z.infer<typeof createBaselineSchema>;
export type CreatePipelineRunBody = z.infer<typeof createPipelineRunSchema>;
export type CreateJiraMappingBody = z.infer<typeof createJiraMappingSchema>;
export type CreateTicketBody = z.infer<typeof createTicketSchema>;
export type ResolveConflictBody = z.infer<typeof resolveConflictSchema>;
export type CreateWebhookSubscriptionBody = z.infer<typeof createWebhookSubscriptionSchema>;
export type SiemExportBody = z.infer<typeof siemExportSchema>;
