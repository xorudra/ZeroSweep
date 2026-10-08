/**
 * Enterprise integration types (Prompt 24 §3–§6, §18, §21, §33, §62,
 * §73, §76). Integrations are least-privilege connectors around the
 * platform: they may REQUEST governed work (a scan of an already
 * VERIFIED target under an already APPROVED assessment, a gate
 * evaluation, a ticket) but they can never approve anything, verify a
 * target, widen scope, or override the finding lifecycle (§136).
 */

export const ENTERPRISE_INTEGRATION_TYPES = [
  "GITHUB", "GITLAB", "BITBUCKET", "JIRA", "SLACK", "MICROSOFT_TEAMS", "SIEM", "GENERIC_WEBHOOK",
] as const;
export type EnterpriseIntegrationType = (typeof ENTERPRISE_INTEGRATION_TYPES)[number];

/** §5: integration lifecycle status. */
export const INTEGRATION_STATUSES = [
  "PENDING", "CONNECTED", "DEGRADED", "DISCONNECTED", "DISABLED", "AUTHENTICATION_FAILED",
] as const;
export type IntegrationStatus = (typeof INTEGRATION_STATUSES)[number];

/** §22/§95: health error categories (never free-text provider errors,
 *  which could carry secrets). */
export const INTEGRATION_ERROR_CATEGORIES = [
  "AUTH", "RATE_LIMIT", "NETWORK", "PROVIDER_ERROR", "NOT_CONFIGURED", "VALIDATION",
] as const;
export type IntegrationErrorCategory = (typeof INTEGRATION_ERROR_CATEGORIES)[number];

export interface IntegrationHealth {
  status: IntegrationStatus | "NOT_CONFIGURED";
  reachable: boolean;
  authenticated: boolean;
  rateLimit?: { remaining: number; resetAt?: string };
  webhookState?: "CONFIGURED" | "UNCONFIGURED" | "FAILING";
  lastSuccessAt?: string;
  errorCategory?: IntegrationErrorCategory;
  detail: string;
}

/**
 * Transport seam for provider HTTP calls. The default implementation
 * is deliberately UNCONFIGURED: no provider endpoint, token or network
 * call exists in this build, so every live operation honestly reports
 * NOT_CONFIGURED (§65/§104 pattern from prior phases). Tests inject
 * fixture transports serving recorded provider payloads — no network.
 */
export interface IntegrationTransport {
  request(input: {
    method: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
    path: string;
    body?: unknown;
    query?: Record<string, string>;
  }): Promise<{ status: number; body: unknown; headers?: Record<string, string> }>;
}

export class IntegrationNotConfiguredError extends Error {
  readonly category: IntegrationErrorCategory = "NOT_CONFIGURED";
  constructor(kind: string) {
    super(`${kind} transport is not configured in this deployment — no provider call was made`);
    this.name = "IntegrationNotConfiguredError";
  }
}

export class UnconfiguredIntegrationTransport implements IntegrationTransport {
  constructor(private readonly kind: string) {}
  async request(): Promise<never> {
    throw new IntegrationNotConfiguredError(this.kind);
  }
}

/** §6: the connector contract every enterprise connector implements. */
export interface EnterpriseIntegrationConnector {
  readonly kind: EnterpriseIntegrationType;
  capabilities(): string[];
  validateConfiguration(config: Record<string, unknown>): { ok: boolean; errors: string[] };
  healthCheck(): Promise<IntegrationHealth>;
  testConnection(): Promise<IntegrationHealth>;
  sync?(input: { resourceKind: string; cursor?: string }): Promise<{ items: unknown[]; nextCursor?: string }>;
  handleWebhook?(input: { eventType: string; deliveryId: string; payload: unknown }): Promise<{ accepted: boolean; detail: string }>;
  rotateCredentialReference(newReference: string): { rotated: boolean; reference: string };
}

/** §28: common source-control provider surface. */
export interface SourceControlProvider {
  readonly provider: "GITHUB" | "GITLAB" | "BITBUCKET";
  listRepositories(input?: { cursor?: string }): Promise<{ repositories: ExternalRepository[]; nextCursor?: string }>;
  getRepository(externalId: string): Promise<ExternalRepository | null>;
  getCommit(externalRepoId: string, sha: string): Promise<{ sha: string; branch?: string } | null>;
  getPullRequest(externalRepoId: string, number: number): Promise<ExternalPullRequest | null>;
  publishCheck(input: PublishCheckInput): Promise<{ published: boolean; detail: string }>;
  validateWebhook(input: { headers: Record<string, string | undefined>; rawBody: string; secret: string }): WebhookVerification;
  handleEvent(input: { eventType: string; payload: unknown }): NormalizedSourceEvent | null;
}

/** §13/§29: a provider repository normalized into platform terms.
 *  Identity is (provider, externalId, installationId) — never the
 *  mutable name alone (§29). */
export interface ExternalRepository {
  provider: "GITHUB" | "GITLAB" | "BITBUCKET";
  externalId: string;
  fullName: string;
  url: string;
  installationId?: string;
  defaultBranch?: string;
  visibility: "PUBLIC" | "PRIVATE" | "INTERNAL";
  archived: boolean;
  languages: string[];
}

export interface ExternalPullRequest {
  provider: "GITHUB" | "GITLAB" | "BITBUCKET";
  externalRepoId: string;
  number: number;
  title: string;
  state: string;
  baseBranch?: string;
  headBranch?: string;
  baseCommit?: string;
  headCommit: string;
}

/** §22: concise check/status publication. Counts + reference only —
 *  never raw secrets or evidence. */
export interface PublishCheckInput {
  externalRepoId: string;
  commitSha: string;
  status: "PASS" | "FAIL" | "WARN" | "ERROR" | "SKIPPED";
  summary: string;
  counts: { newCritical: number; newHigh: number; newTotal: number; resolved: number };
  dsrcloneReference: string;
}

export interface WebhookVerification {
  ok: boolean;
  reasonCode?: "SIGNATURE_INVALID" | "SIGNATURE_MISSING" | "TOKEN_INVALID" | "TIMESTAMP_SKEW" | "PAYLOAD_TOO_LARGE";
  detail: string;
}

/** A provider webhook normalized into ONE platform shape (§14/§23/§27).
 *  All string fields are UNTRUSTED provider data (§83) and must pass
 *  through the sanitizer before storage or display. */
export interface NormalizedSourceEvent {
  provider: "GITHUB" | "GITLAB" | "BITBUCKET";
  kind: "PUSH" | "PULL_REQUEST" | "REPOSITORY" | "INSTALLATION" | "PIPELINE" | "UNKNOWN";
  action?: string;
  externalRepoId: string;
  repositoryFullName: string;
  installationId?: string;
  branch?: string;
  commitSha?: string;
  pullRequest?: {
    number: number;
    title: string;
    state: string;
    baseBranch?: string;
    headBranch?: string;
    baseCommit?: string;
    headCommit: string;
  };
}

/** §62: SIEM event types. */
export const SIEM_EVENT_TYPES = [
  "FINDING_CREATED", "FINDING_VERIFIED", "CRITICAL_FINDING", "KEV_DETECTED",
  "ASSET_EXPOSURE_CHANGED", "AUTHENTICATION_SECURITY_EVENT", "SCAN_FAILED",
  "RISK_INCREASED", "SLA_OVERDUE", "POLICY_VIOLATION",
  // Prompt 28: SOC alert/incident forwarding uses the same governed
  // outbox + SIEM shape as Prompt 24.
  "ALERT_CREATED", "INCIDENT_DECLARED",
] as const;
export type SiemEventType = (typeof SIEM_EVENT_TYPES)[number];

/** §73: outbound webhook event types. */
export const WEBHOOK_EVENT_TYPES = [
  "finding.created", "finding.updated", "finding.resolved", "finding.reopened",
  "risk.changed", "scan.completed", "scan.failed", "report.ready",
  "asset.exposure.changed", "quality_gate.failed",
] as const;
export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

/** §76/§77: the canonical event envelope. */
export interface SecurityEventEnvelope<T = Record<string, unknown>> {
  eventId: string;
  eventType: string;
  workspaceId: string;
  timestamp: string;
  resourceType: string;
  resourceId: string;
  schemaVersion: string;
  payload: T;
}

export const EVENT_SCHEMA_VERSION = "1.0";

/** §21: gate results. */
export const GATE_RESULTS = ["PASS", "FAIL", "WARN", "ERROR", "SKIPPED"] as const;
export type GateResult = (typeof GATE_RESULTS)[number];

/** §20: PR gate policy presets (mapped to typed rules in gate.ts). */
export const PR_GATE_PRESETS = [
  "FAIL_ON_NEW_CRITICAL", "FAIL_ON_NEW_HIGH", "FAIL_ON_NEW_VERIFIED_HIGH",
  "FAIL_ON_NEW_KEV", "FAIL_ON_NEW_SECRET", "FAIL_ON_POLICY_VIOLATION",
] as const;
export type PrGatePreset = (typeof PR_GATE_PRESETS)[number];

/** §39: scanner-failure behavior for required scanners. */
export const SCANNER_FAILURE_BEHAVIORS = ["FAIL_CLOSED", "WARN", "FAIL_OPEN"] as const;
export type ScannerFailureBehavior = (typeof SCANNER_FAILURE_BEHAVIORS)[number];

/** Sanitized finding view — the ONLY finding shape that may leave the
 *  platform through an integration (§42/§50/§56). Locations are
 *  repository-relative and secret values are never present. */
export interface SanitizedFindingView {
  id: string;
  title: string;
  severity: string;
  priority?: string;
  status: string;
  lifecycleStatus: string;
  verificationStatus: string;
  kevListed: boolean;
  isSecretFinding: boolean;
  filePath?: string;
  startLine?: number;
  assetReference?: string;
  remediation?: string;
  riskExplanation?: string;
  dsrcloneReference: string;
}
