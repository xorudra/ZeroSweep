/**
 * Prompt 14 — Multi-Cloud Security Engine: shared domain types (§2–§90).
 *
 * The engine assesses authorized AWS / Azure / GCP estates READ-ONLY
 * (§7): inventory collects security-relevant METADATA only (§13),
 * credentials exist exclusively as secret REFERENCES (§6), and no code
 * path in this module can create, modify, delete, stop, restart or
 * otherwise alter a cloud resource (§106). Pacu is registered as a
 * DISABLED offensive capability (§34) — it has no adapter here.
 */
import type {
  NormalizedCloudData, NormalizedCloudIdentity, NormalizedCloudResource,
  NormalizedControlAssessment,
} from "../findings/finding.types";

export type {
  NormalizedCloudData, NormalizedCloudIdentity, NormalizedCloudResource, NormalizedControlAssessment,
};

export const CLOUD_PROVIDERS = ["AWS", "AZURE", "GCP"] as const;
export type CloudProvider = (typeof CLOUD_PROVIDERS)[number];

export const CLOUD_SEC_PROFILES = [
  "CLOUD_INVENTORY", "CLOUD_BASELINE", "CLOUD_COMPREHENSIVE", "IAM_REVIEW",
  "PUBLIC_EXPOSURE_REVIEW", "COMPLIANCE_ASSESSMENT", "IAC_TO_CLOUD_CORRELATION",
] as const;
export type CloudSecProfile = (typeof CLOUD_SEC_PROFILES)[number];

/** A registered cloud account as the store resolves it (§4): identity +
 *  credential REFERENCE only. There is deliberately no field that could
 *  hold a secret key, client secret, private key or token (§6). */
export interface CloudAccountRecord {
  id: string;
  provider: CloudProvider;
  name: string;
  externalAccountId: string;
  environment?: string;
  criticality?: string;
  credentialReference?: string;
}

/** The assessed-estate boundary (§5). Empty include lists mean "the
 *  whole registered account"; exclusions always win. */
export interface CloudScopeDef {
  includeRegions: string[];
  excludeRegions: string[];
  includeUnits: string[];
  excludeUnits: string[];
  includeResources: string[];
  excludeResources: string[];
}

export const EMPTY_CLOUD_SCOPE: CloudScopeDef = {
  includeRegions: [], excludeRegions: [], includeUnits: [],
  excludeUnits: [], includeResources: [], excludeResources: [],
};

export function isResourceInCloudScope(
  resource: { region?: string; providerResourceId: string },
  scope: CloudScopeDef,
): boolean {
  if (scope.excludeResources.includes(resource.providerResourceId)) return false;
  if (resource.region && scope.excludeRegions.includes(resource.region)) return false;
  if (scope.includeResources.length > 0 && !scope.includeResources.includes(resource.providerResourceId)) return false;
  if (resource.region && scope.includeRegions.length > 0 && !scope.includeRegions.includes(resource.region)) return false;
  return true;
}

/** The read-only assessment policy (§7). READ_ONLY is the only mode:
 *  mutation, privilege escalation and secret-value retrieval are not
 *  configuration options anywhere in the platform — they are absent. */
export interface CloudAssessmentPolicy {
  mode: "READ_ONLY";
  allowMutations: false;
  allowPrivilegeEscalation: false;
  allowSecretValueRetrieval: false;
  allowDataDownload: false;
}

export const CLOUD_ASSESSMENT_POLICY: CloudAssessmentPolicy = {
  mode: "READ_ONLY",
  allowMutations: false,
  allowPrivilegeEscalation: false,
  allowSecretValueRetrieval: false,
  allowDataDownload: false,
};

/** Documented least-privilege permission sets per provider (§7/§8):
 *  temporary / role-based / federated identities are preferred over
 *  long-lived static keys wherever the provider supports them. */
export const PROVIDER_READ_ONLY_GUIDANCE: Record<CloudProvider, { preferredIdentity: string; permissions: string[] }> = {
  AWS: {
    preferredIdentity: "Cross-account IAM role assumed with an external ID (short-lived STS credentials); long-lived access keys are discouraged (§8)",
    permissions: ["arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"],
  },
  AZURE: {
    preferredIdentity: "Microsoft Entra workload / managed identity with subscription Reader + Security Reader (§8)",
    permissions: ["Reader (subscription scope)", "Security Reader (subscription scope)"],
  },
  GCP: {
    preferredIdentity: "Service account impersonation with short-lived tokens, or Workload Identity Federation (§8)",
    permissions: ["roles/viewer", "roles/iam.securityReviewer", "roles/cloudasset.viewer"],
  },
};

/** An ephemeral credential lease record (§11): reference NAME +
 *  lifecycle only. The secret value is resolved inside the trusted
 *  CLOUD_ANALYSIS worker boundary at execution time and is removed
 *  from worker memory/files when the job ends — it never appears in
 *  this record, a queue payload, a log line or an API response (§100). */
export interface CredentialLeaseRecord {
  cloudAccountId: string;
  credentialReference: string;
  scanId?: string;
  purpose: string;
  status: "ISSUED" | "CONSUMED" | "EXPIRED" | "RELEASED";
  issuedAt: string; // ISO
  expiresAt: string; // ISO
}

/** Lease TTL is capped at one hour (§11): a lease is a job-scoped
 *  grant, never a standing credential. */
export const MAX_CREDENTIAL_LEASE_SECONDS = 3600;

export function issueCredentialLease(input: {
  cloudAccountId: string; credentialReference: string; scanId?: string;
  purpose?: string; ttlSeconds?: number; now?: Date;
}): CredentialLeaseRecord {
  const now = input.now ?? new Date();
  const ttl = Math.min(Math.max(input.ttlSeconds ?? 900, 60), MAX_CREDENTIAL_LEASE_SECONDS);
  return {
    cloudAccountId: input.cloudAccountId,
    credentialReference: input.credentialReference,
    ...(input.scanId ? { scanId: input.scanId } : {}),
    purpose: input.purpose ?? "CLOUD_ASSESSMENT",
    status: "ISSUED",
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttl * 1000).toISOString(),
  };
}

export function isLeaseActive(lease: CredentialLeaseRecord, now: Date = new Date()): boolean {
  return lease.status === "ISSUED" && new Date(lease.expiresAt).getTime() > now.getTime();
}

/** Cloud scan budget (§74): every dimension bounded, hard-capped.
 *  Budgets may be tightened per engagement, never raised past caps. */
export interface CloudBudget {
  maxCloudAccounts: number;
  maxRegions: number;
  maxResources: number;
  maxApiRequests: number;
  maxIamRelationships: number;
  maxFindings: number;
  maxArtifacts: number;
  maxScanDurationSeconds: number;
}

export const DEFAULT_CLOUD_BUDGET: CloudBudget = {
  maxCloudAccounts: 1, maxRegions: 20, maxResources: 10000, maxApiRequests: 5000,
  maxIamRelationships: 5000, maxFindings: 2000, maxArtifacts: 50, maxScanDurationSeconds: 3600,
};

export const CLOUD_BUDGET_CAPS: CloudBudget = {
  maxCloudAccounts: 25, maxRegions: 100, maxResources: 100000, maxApiRequests: 50000,
  maxIamRelationships: 50000, maxFindings: 20000, maxArtifacts: 500, maxScanDurationSeconds: 14400,
};

export function clampCloudBudget(input: Partial<CloudBudget> = {}): CloudBudget {
  const out = { ...DEFAULT_CLOUD_BUDGET };
  for (const key of Object.keys(out) as (keyof CloudBudget)[]) {
    const v = input[key];
    if (typeof v === "number" && Number.isFinite(v) && v > 0) {
      out[key] = Math.min(Math.floor(v), CLOUD_BUDGET_CAPS[key]);
    }
  }
  return out;
}

/** Provider throttling discipline (§75): bounded concurrency, jittered
 *  exponential backoff, bounded retries. Pure/deterministic with an
 *  injected jitter source so tests never sleep. */
export interface ProviderThrottlePolicy {
  maxConcurrency: number;
  maxRetries: number;
  backoffBaseMs: number;
  backoffMaxMs: number;
}

export const DEFAULT_PROVIDER_THROTTLE: ProviderThrottlePolicy = {
  maxConcurrency: 4, maxRetries: 3, backoffBaseMs: 250, backoffMaxMs: 8000,
};

export function backoffDelayMs(attempt: number, policy: ProviderThrottlePolicy = DEFAULT_PROVIDER_THROTTLE, jitter: () => number = Math.random): number {
  const base = Math.min(policy.backoffBaseMs * 2 ** Math.max(0, attempt - 1), policy.backoffMaxMs);
  return Math.round(base * (0.5 + jitter() * 0.5));
}

/** Compliance frameworks the engine maps evidence onto (§68/§69).
 *  Mappings are versioned and support reporting structure ONLY — the
 *  platform never claims certification. */
export const CLOUD_COMPLIANCE_FRAMEWORKS = [
  { key: "CIS_AWS", name: "CIS Amazon Web Services Foundations Benchmark", version: "1.5.0" },
  { key: "CIS_AZURE", name: "CIS Microsoft Azure Foundations Benchmark", version: "2.1.0" },
  { key: "CIS_GCP", name: "CIS Google Cloud Platform Foundation Benchmark", version: "1.6.0" },
  { key: "NIST_800_53", name: "NIST SP 800-53 (control mapping)", version: "Rev. 5" },
  { key: "PCI_DSS", name: "PCI DSS (control mapping)", version: "4.0" },
  { key: "SOC2", name: "SOC 2 (criteria mapping)", version: "2017 TSC" },
  { key: "ISO_27001", name: "ISO/IEC 27001 (control mapping)", version: "2022" },
] as const;
export type CloudComplianceFrameworkKey = (typeof CLOUD_COMPLIANCE_FRAMEWORKS)[number]["key"];

/** Pacu registration (§34/§35/§89): an OFFENSIVE cloud-testing tool,
 *  classified and DISABLED. It exists in the registry so policy can
 *  name it — there is no adapter, no stage selects it, and no
 *  automatic execution path exists in this phase (§106). */
export const PACU_REGISTRATION = {
  slug: "pacu",
  name: "Pacu",
  classification: "CLOUD_OFFENSIVE_TESTING",
  riskLevel: "INTRUSIVE",
  status: "DISABLED",
  enabled: false,
  requiresApproval: true,
  note: "Offensive cloud testing — requires an explicit authorized assessment; never part of CLOUD_BASELINE (§35).",
} as const;
