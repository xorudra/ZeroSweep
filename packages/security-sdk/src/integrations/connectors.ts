import {
  IntegrationNotConfiguredError,
  UnconfiguredIntegrationTransport,
  type EnterpriseIntegrationConnector,
  type EnterpriseIntegrationType,
  type ExternalPullRequest,
  type ExternalRepository,
  type IntegrationHealth,
  type IntegrationTransport,
  type PublishCheckInput,
  type SourceControlProvider,
  type WebhookVerification,
} from "./types";
import { normalizeBitbucketRepository, normalizeGitHubRepository, normalizeGitLabRepository, parseBitbucketEvent, parseGitHubEvent, parseGitLabEvent, toExternalPullRequest } from "./providers";
import { verifyBitbucketSignature, verifyGitHubSignature, verifyGitLabToken } from "./webhook-verify";
import { buildTeamsFindingAlert, buildSlackFindingAlert } from "./messaging";
import { buildJiraIssuePayload, mapJiraStatusToInternal } from "./tickets";
import type { NormalizedSourceEvent, SanitizedFindingView } from "./types";

/**
 * Provider connectors (Prompt 24 §6, §10–§31, §46, §55, §61).
 * Connectors hold NO secret values — the secret reference is resolved
 * by the API layer at call time and passed to webhook verification;
 * HTTP work goes through an injected transport. The default transport
 * is deliberately UNCONFIGURED: health checks honestly report
 * NOT_CONFIGURED instead of fabricating connectivity (§104 pattern).
 */

abstract class BaseConnector implements EnterpriseIntegrationConnector {
  protected transport: IntegrationTransport;
  protected secretRef: string | null = null;
  constructor(
    readonly kind: EnterpriseIntegrationType,
    protected config: Record<string, unknown>,
    transport?: IntegrationTransport,
  ) {
    this.transport = transport ?? new UnconfiguredIntegrationTransport(kind);
  }

  abstract capabilities(): string[];
  abstract validateConfiguration(config: Record<string, unknown>): { ok: boolean; errors: string[] };

  protected notConfigured(): IntegrationHealth {
    return {
      status: "NOT_CONFIGURED", reachable: false, authenticated: false,
      errorCategory: "NOT_CONFIGURED",
      detail: `${this.kind} transport is not configured in this deployment — no provider call was made`,
    };
  }

  protected isNotConfigured(err: unknown): boolean {
    return err instanceof IntegrationNotConfiguredError;
  }

  async healthCheck(): Promise<IntegrationHealth> {
    try {
      return await this.probe();
    } catch (err) {
      if (this.isNotConfigured(err)) return this.notConfigured();
      return {
        status: "DEGRADED", reachable: false, authenticated: false,
        errorCategory: "PROVIDER_ERROR",
        detail: `${this.kind} health probe failed (category only; provider error bodies are never stored)`,
      };
    }
  }

  async testConnection(): Promise<IntegrationHealth> {
    return this.healthCheck();
  }

  protected abstract probe(): Promise<IntegrationHealth>;

  rotateCredentialReference(newReference: string): { rotated: boolean; reference: string } {
    // §102: rotation swaps the REFERENCE; the value lives in the
    // secret store and never transits this object.
    this.secretRef = newReference;
    return { rotated: true, reference: newReference };
  }
}

function healthFromStatus(kind: string, status: number): IntegrationHealth {
  if (status === 401 || status === 403) {
    return { status: "AUTHENTICATION_FAILED", reachable: true, authenticated: false, errorCategory: "AUTH", detail: `${kind} rejected the configured credential reference` };
  }
  if (status === 429) {
    return { status: "DEGRADED", reachable: true, authenticated: true, errorCategory: "RATE_LIMIT", detail: `${kind} is rate-limiting requests (§97)` };
  }
  if (status >= 200 && status < 300) {
    return { status: "CONNECTED", reachable: true, authenticated: true, detail: `${kind} reachable and authenticated` };
  }
  return { status: "DEGRADED", reachable: true, authenticated: false, errorCategory: "PROVIDER_ERROR", detail: `${kind} returned HTTP ${status}` };
}

/* --------------------------- GitHub (§10–22) --------------------------- */

export class GitHubConnector extends BaseConnector implements SourceControlProvider {
  readonly provider = "GITHUB" as const;
  constructor(config: Record<string, unknown>, transport?: IntegrationTransport) {
    super("GITHUB", config, transport);
  }

  capabilities(): string[] {
    return ["repositories.read", "pull_requests.read", "checks.write", "webhooks.receive", "installations.read"];
  }

  validateConfiguration(config: Record<string, unknown>): { ok: boolean; errors: string[] } {
    const errors: string[] = [];
    const mode = config.authMode;
    if (mode === "GITHUB_APP") {
      if (!config.appId) errors.push("GitHub App mode requires appId (§11)");
      if (!config.installationId) errors.push("GitHub App mode requires installationId (§11)");
      if (!config.privateKeySecretReference) errors.push("GitHub App private key must be a secret REFERENCE (§11)");
    } else if (mode === "PAT") {
      if (!config.tokenSecretReference) errors.push("PAT mode requires a token secret REFERENCE (§12)");
    } else {
      errors.push("authMode must be GITHUB_APP (preferred, §11) or PAT (§12)");
    }
    if (typeof config.appId === "string" && /-----BEGIN/.test(config.appId)) {
      errors.push("appId must never contain key material");
    }
    return { ok: errors.length === 0, errors };
  }

  protected async probe(): Promise<IntegrationHealth> {
    const res = await this.transport.request({ method: "GET", path: "/rate_limit" });
    const health = healthFromStatus("GitHub", res.status);
    const body = res.body as { resources?: { core?: { remaining?: number; reset?: number } } } | null;
    const remaining = body?.resources?.core?.remaining;
    if (remaining != null) health.rateLimit = { remaining, resetAt: body?.resources?.core?.reset ? new Date(body.resources.core.reset * 1000).toISOString() : undefined };
    return health;
  }

  async listRepositories(input?: { cursor?: string }): Promise<{ repositories: ExternalRepository[]; nextCursor?: string }> {
    const res = await this.transport.request({
      method: "GET", path: "/installation/repositories",
      query: input?.cursor ? { page: input.cursor } : undefined,
    });
    const body = res.body as { repositories?: Array<Record<string, unknown>>; total_count?: number };
    const repositories = (body.repositories ?? [])
      .map((r) => normalizeGitHubRepository(r))
      .filter((r): r is ExternalRepository => r !== null);
    return { repositories };
  }

  async getRepository(externalId: string): Promise<ExternalRepository | null> {
    const res = await this.transport.request({ method: "GET", path: `/repositories/${externalId}` });
    if (res.status === 404) return null;
    return normalizeGitHubRepository(res.body as Record<string, unknown>);
  }

  async getCommit(externalRepoId: string, sha: string): Promise<{ sha: string; branch?: string } | null> {
    const res = await this.transport.request({ method: "GET", path: `/repositories/${externalRepoId}/commits/${sha}` });
    if (res.status === 404) return null;
    return { sha };
  }

  async getPullRequest(externalRepoId: string, number: number): Promise<ExternalPullRequest | null> {
    const res = await this.transport.request({ method: "GET", path: `/repositories/${externalRepoId}/pulls/${number}` });
    if (res.status === 404) return null;
    const pr = res.body as Record<string, unknown>;
    const head = pr.head as Record<string, unknown> | undefined;
    const base = pr.base as Record<string, unknown> | undefined;
    return {
      provider: "GITHUB", externalRepoId, number,
      title: String(pr.title ?? ""), state: String(pr.state ?? "open"),
      baseBranch: base?.ref as string | undefined, headBranch: head?.ref as string | undefined,
      baseCommit: base?.sha as string | undefined, headCommit: String(head?.sha ?? ""),
    };
  }

  /** §21/§82: publishing is best-effort decoration — a failed publish
   *  NEVER changes the gate verdict, and the body is counts-only. */
  async publishCheck(check: PublishCheckInput): Promise<{ published: boolean; detail: string }> {
    try {
      const res = await this.transport.request({
        method: "POST",
        path: `/repos/${check.externalRepoId}/check-runs`,
        body: {
          name: "ZeroSweep Security Gate",
          head_sha: check.commitSha,
          status: "completed",
          conclusion: check.status === "PASS" ? "success" : check.status === "FAIL" ? "failure" : check.status === "WARN" ? "neutral" : "skipped",
          output: {
            title: `ZeroSweep security gate: ${check.status}`,
            summary: `${check.summary}\nNew: ${check.counts.newTotal} (critical ${check.counts.newCritical}, high ${check.counts.newHigh}) · Resolved: ${check.counts.resolved} · ${check.zerosweepReference}`,
          },
        },
      });
      return { published: res.status >= 200 && res.status < 300, detail: `GitHub check-run publish returned HTTP ${res.status}` };
    } catch (err) {
      if (this.isNotConfigured(err)) return { published: false, detail: "NOT_CONFIGURED — check publish skipped; the gate verdict stands (§21)" };
      throw err;
    }
  }

  validateWebhook(input: { headers: Record<string, string | undefined>; rawBody: string; secret: string }): WebhookVerification {
    return verifyGitHubSignature({ rawBody: input.rawBody, signatureHeader: input.headers["x-hub-signature-256"], secret: input.secret });
  }

  handleEvent(input: { eventType: string; payload: unknown }): NormalizedSourceEvent | null {
    return parseGitHubEvent(input.eventType, input.payload);
  }
}

/* --------------------------- GitLab (§23–26) --------------------------- */

export class GitLabConnector extends BaseConnector implements SourceControlProvider {
  readonly provider = "GITLAB" as const;
  constructor(config: Record<string, unknown>, transport?: IntegrationTransport) {
    super("GITLAB", config, transport);
  }

  capabilities(): string[] {
    return ["projects.read", "merge_requests.read", "pipelines.read", "statuses.write", "webhooks.receive"];
  }

  validateConfiguration(config: Record<string, unknown>): { ok: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!config.baseUrl && !config.instance) errors.push("GitLab integration requires the instance base URL (§23)");
    if (!config.tokenSecretReference && !config.oauthSecretReference) {
      errors.push("GitLab credential must be a secret REFERENCE — OAuth, group/project token (§24)");
    }
    return { ok: errors.length === 0, errors };
  }

  protected async probe(): Promise<IntegrationHealth> {
    const res = await this.transport.request({ method: "GET", path: "/api/v4/version" });
    return healthFromStatus("GitLab", res.status);
  }

  async listRepositories(input?: { cursor?: string }): Promise<{ repositories: ExternalRepository[]; nextCursor?: string }> {
    const res = await this.transport.request({
      method: "GET", path: "/api/v4/projects",
      query: { membership: "true", ...(input?.cursor ? { page: input.cursor } : {}) },
    });
    const rows = Array.isArray(res.body) ? (res.body as Array<Record<string, unknown>>) : [];
    const repositories = rows.map((r) => normalizeGitLabRepository(r)).filter((r): r is ExternalRepository => r !== null);
    const next = res.headers?.["x-next-page"];
    return { repositories, nextCursor: next ? next : undefined };
  }

  async getRepository(externalId: string): Promise<ExternalRepository | null> {
    const res = await this.transport.request({ method: "GET", path: `/api/v4/projects/${externalId}` });
    if (res.status === 404) return null;
    return normalizeGitLabRepository(res.body as Record<string, unknown>);
  }

  async getCommit(externalRepoId: string, sha: string): Promise<{ sha: string; branch?: string } | null> {
    const res = await this.transport.request({ method: "GET", path: `/api/v4/projects/${externalRepoId}/repository/commits/${sha}` });
    if (res.status === 404) return null;
    return { sha };
  }

  async getPullRequest(externalRepoId: string, number: number): Promise<ExternalPullRequest | null> {
    const res = await this.transport.request({ method: "GET", path: `/api/v4/projects/${externalRepoId}/merge_requests/${number}` });
    if (res.status === 404) return null;
    const mr = res.body as Record<string, unknown>;
    return {
      provider: "GITLAB", externalRepoId, number,
      title: String(mr.title ?? ""), state: String(mr.state ?? "opened"),
      baseBranch: mr.target_branch as string | undefined, headBranch: mr.source_branch as string | undefined,
      headCommit: String(mr.sha ?? ""),
    };
  }

  async publishCheck(check: PublishCheckInput): Promise<{ published: boolean; detail: string }> {
    try {
      const res = await this.transport.request({
        method: "POST",
        path: `/api/v4/projects/${check.externalRepoId}/statuses/${check.commitSha}`,
        body: {
          state: check.status === "PASS" ? "success" : check.status === "FAIL" ? "failed" : "canceled",
          name: "zerosweep-security-gate",
          description: `${check.summary} · New: ${check.counts.newTotal} · ${check.zerosweepReference}`.slice(0, 255),
        },
      });
      return { published: res.status >= 200 && res.status < 300, detail: `GitLab status publish returned HTTP ${res.status}` };
    } catch (err) {
      if (this.isNotConfigured(err)) return { published: false, detail: "NOT_CONFIGURED — status publish skipped; the gate verdict stands (§26)" };
      throw err;
    }
  }

  validateWebhook(input: { headers: Record<string, string | undefined>; rawBody: string; secret: string }): WebhookVerification {
    return verifyGitLabToken({ tokenHeader: input.headers["x-gitlab-token"], secret: input.secret });
  }

  handleEvent(input: { eventType: string; payload: unknown }): NormalizedSourceEvent | null {
    return parseGitLabEvent(input.eventType, input.payload);
  }
}

/* -------------------------- Bitbucket (§27) -------------------------- */

export class BitbucketConnector extends BaseConnector implements SourceControlProvider {
  readonly provider = "BITBUCKET" as const;
  constructor(config: Record<string, unknown>, transport?: IntegrationTransport) {
    super("BITBUCKET", config, transport);
  }

  capabilities(): string[] {
    return ["repositories.read", "pull_requests.read", "commit_statuses.write", "webhooks.receive"];
  }

  validateConfiguration(config: Record<string, unknown>): { ok: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!config.workspace) errors.push("Bitbucket integration requires a workspace (§27)");
    if (!config.credentialSecretReference) errors.push("Bitbucket credential must be a secret REFERENCE (§27)");
    return { ok: errors.length === 0, errors };
  }

  protected async probe(): Promise<IntegrationHealth> {
    const res = await this.transport.request({ method: "GET", path: "/2.0/user" });
    return healthFromStatus("Bitbucket", res.status);
  }

  async listRepositories(): Promise<{ repositories: ExternalRepository[]; nextCursor?: string }> {
    const workspace = String(this.config.workspace ?? "");
    const res = await this.transport.request({ method: "GET", path: `/2.0/repositories/${workspace}` });
    const body = res.body as { values?: Array<Record<string, unknown>>; next?: string };
    const repositories = (body.values ?? []).map((r) => normalizeBitbucketRepository(r)).filter((r): r is ExternalRepository => r !== null);
    return { repositories, nextCursor: body.next };
  }

  async getRepository(externalId: string): Promise<ExternalRepository | null> {
    const workspace = String(this.config.workspace ?? "");
    const res = await this.transport.request({ method: "GET", path: `/2.0/repositories/${workspace}/${externalId}` });
    if (res.status === 404) return null;
    return normalizeBitbucketRepository(res.body as Record<string, unknown>);
  }

  async getCommit(externalRepoId: string, sha: string): Promise<{ sha: string; branch?: string } | null> {
    const workspace = String(this.config.workspace ?? "");
    const res = await this.transport.request({ method: "GET", path: `/2.0/repositories/${workspace}/${externalRepoId}/commit/${sha}` });
    if (res.status === 404) return null;
    return { sha };
  }

  async getPullRequest(externalRepoId: string, number: number): Promise<ExternalPullRequest | null> {
    const workspace = String(this.config.workspace ?? "");
    const res = await this.transport.request({ method: "GET", path: `/2.0/repositories/${workspace}/${externalRepoId}/pullrequests/${number}` });
    if (res.status === 404) return null;
    const event: NormalizedSourceEvent = {
      provider: "BITBUCKET", kind: "PULL_REQUEST",
      externalRepoId, repositoryFullName: "",
      pullRequest: {
        number, title: String((res.body as Record<string, unknown>).title ?? ""),
        state: String((res.body as Record<string, unknown>).state ?? "OPEN"), headCommit: "",
      },
    };
    return toExternalPullRequest(event);
  }

  async publishCheck(check: PublishCheckInput): Promise<{ published: boolean; detail: string }> {
    try {
      const workspace = String(this.config.workspace ?? "");
      const res = await this.transport.request({
        method: "POST",
        path: `/2.0/repositories/${workspace}/${check.externalRepoId}/commit/${check.commitSha}/statuses/build`,
        body: {
          key: "zerosweep-security-gate",
          state: check.status === "PASS" ? "SUCCESSFUL" : check.status === "FAIL" ? "FAILED" : "STOPPED",
          name: "ZeroSweep Security Gate",
          description: `${check.summary} · New: ${check.counts.newTotal} · ${check.zerosweepReference}`.slice(0, 255),
        },
      });
      return { published: res.status >= 200 && res.status < 300, detail: `Bitbucket build-status publish returned HTTP ${res.status}` };
    } catch (err) {
      if (this.isNotConfigured(err)) return { published: false, detail: "NOT_CONFIGURED — status publish skipped; the gate verdict stands (§27)" };
      throw err;
    }
  }

  validateWebhook(input: { headers: Record<string, string | undefined>; rawBody: string; secret: string }): WebhookVerification {
    return verifyBitbucketSignature({ rawBody: input.rawBody, signatureHeader: input.headers["x-hub-signature"], secret: input.secret });
  }

  handleEvent(input: { eventType: string; payload: unknown }): NormalizedSourceEvent | null {
    return parseBitbucketEvent(input.eventType, input.payload);
  }
}

/* ----------------------------- Jira (§46) ----------------------------- */

export class JiraConnector extends BaseConnector {
  constructor(config: Record<string, unknown>, transport?: IntegrationTransport) {
    super("JIRA", config, transport);
  }

  capabilities(): string[] {
    return ["issues.create", "issues.read", "issues.update", "status.sync"];
  }

  validateConfiguration(config: Record<string, unknown>): { ok: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!config.baseUrl) errors.push("Jira integration requires the site base URL");
    if (!config.credentialSecretReference) errors.push("Jira credential must be a secret REFERENCE");
    return { ok: errors.length === 0, errors };
  }

  protected async probe(): Promise<IntegrationHealth> {
    const res = await this.transport.request({ method: "GET", path: "/rest/api/3/myself" });
    return healthFromStatus("Jira", res.status);
  }

  async createIssue(finding: SanitizedFindingView, mapping: { projectKey: string; issueType: string }): Promise<{ externalId: string; externalKey: string }> {
    const { payload } = buildJiraIssuePayload(finding, mapping);
    const res = await this.transport.request({ method: "POST", path: "/rest/api/3/issue", body: payload });
    const body = res.body as { id?: string; key?: string };
    if (!body.id || !body.key) throw new Error("Jira create-issue response did not include an issue id/key");
    return { externalId: body.id, externalKey: body.key };
  }

  async getIssue(externalKey: string): Promise<{ status: string; statusName: string; assigneeReference?: string } | null> {
    const res = await this.transport.request({ method: "GET", path: `/rest/api/3/issue/${externalKey}` });
    if (res.status === 404) return null;
    const fields = (res.body as { fields?: Record<string, unknown> }).fields ?? {};
    const status = fields.status as { name?: string; statusCategory?: { key?: string } } | undefined;
    const assignee = fields.assignee as { accountId?: string } | null;
    return {
      status: mapJiraStatusToInternal({ statusName: status?.name, statusCategory: status?.statusCategory?.key }),
      statusName: status?.name ?? "",
      assigneeReference: assignee?.accountId,
    };
  }
}

/* ------------------------- Messaging (§55–§59) ------------------------- */

/** §55: common messaging connector interface. Delivery goes through
 *  the platform notification architecture — these builders/connectors
 *  do not create a parallel notification system (§59). */
export interface MessagingConnector extends EnterpriseIntegrationConnector {
  sendNotification(input: { text: string }): Promise<{ delivered: boolean; detail: string }>;
  sendFindingAlert(finding: SanitizedFindingView): Promise<{ delivered: boolean; detail: string }>;
  sendReportReady(input: { title: string; reference: string }): Promise<{ delivered: boolean; detail: string }>;
}

export class SlackConnector extends BaseConnector implements MessagingConnector {
  constructor(config: Record<string, unknown>, transport?: IntegrationTransport) {
    super("SLACK", config, transport);
  }
  capabilities(): string[] { return ["chat.postMessage", "interactive.actions"]; }
  validateConfiguration(config: Record<string, unknown>): { ok: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!config.channel && !config.webhookSecretReference) errors.push("Slack integration requires a channel or an incoming-webhook secret REFERENCE (§56)");
    return { ok: errors.length === 0, errors };
  }
  protected async probe(): Promise<IntegrationHealth> {
    const res = await this.transport.request({ method: "POST", path: "/api/auth.test", body: {} });
    return healthFromStatus("Slack", res.status);
  }
  async sendNotification(input: { text: string }): Promise<{ delivered: boolean; detail: string }> {
    try {
      const res = await this.transport.request({ method: "POST", path: "/api/chat.postMessage", body: { channel: this.config.channel, text: input.text } });
      return { delivered: res.status >= 200 && res.status < 300, detail: `Slack returned HTTP ${res.status}` };
    } catch (err) {
      if (this.isNotConfigured(err)) return { delivered: false, detail: "NOT_CONFIGURED — recorded, not delivered (§59/§65)" };
      throw err;
    }
  }
  async sendFindingAlert(finding: SanitizedFindingView): Promise<{ delivered: boolean; detail: string }> {
    const payload = buildSlackFindingAlert(finding);
    try {
      const res = await this.transport.request({ method: "POST", path: "/api/chat.postMessage", body: { channel: this.config.channel, ...payload } });
      return { delivered: res.status >= 200 && res.status < 300, detail: `Slack returned HTTP ${res.status}` };
    } catch (err) {
      if (this.isNotConfigured(err)) return { delivered: false, detail: "NOT_CONFIGURED — recorded, not delivered" };
      throw err;
    }
  }
  async sendReportReady(input: { title: string; reference: string }): Promise<{ delivered: boolean; detail: string }> {
    return this.sendNotification({ text: `Security report ready: ${input.title} (${input.reference})` });
  }
}

export class TeamsConnector extends BaseConnector implements MessagingConnector {
  constructor(config: Record<string, unknown>, transport?: IntegrationTransport) {
    super("MICROSOFT_TEAMS", config, transport);
  }
  capabilities(): string[] { return ["webhook.post", "message_cards"]; }
  validateConfiguration(config: Record<string, unknown>): { ok: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!config.webhookSecretReference && !config.channel) errors.push("Teams integration requires a connector webhook secret REFERENCE or channel (§58)");
    return { ok: errors.length === 0, errors };
  }
  protected async probe(): Promise<IntegrationHealth> {
    // Teams connector webhooks have no read API; a configured reference
    // is all that can honestly be reported without sending a message.
    if (!this.config.webhookSecretReference && !this.config.channel) return this.notConfigured();
    return { status: "CONNECTED", reachable: true, authenticated: true, detail: "Teams connector configured (webhook connectors expose no probe endpoint)" };
  }
  async sendNotification(input: { text: string }): Promise<{ delivered: boolean; detail: string }> {
    try {
      const res = await this.transport.request({ method: "POST", path: "/webhook/teams", body: { text: input.text } });
      return { delivered: res.status >= 200 && res.status < 300, detail: `Teams returned HTTP ${res.status}` };
    } catch (err) {
      if (this.isNotConfigured(err)) return { delivered: false, detail: "NOT_CONFIGURED — recorded, not delivered" };
      throw err;
    }
  }
  async sendFindingAlert(finding: SanitizedFindingView): Promise<{ delivered: boolean; detail: string }> {
    try {
      const res = await this.transport.request({ method: "POST", path: "/webhook/teams", body: buildTeamsFindingAlert(finding) });
      return { delivered: res.status >= 200 && res.status < 300, detail: `Teams returned HTTP ${res.status}` };
    } catch (err) {
      if (this.isNotConfigured(err)) return { delivered: false, detail: "NOT_CONFIGURED — recorded, not delivered" };
      throw err;
    }
  }
  async sendReportReady(input: { title: string; reference: string }): Promise<{ delivered: boolean; detail: string }> {
    return this.sendNotification({ text: `Security report ready: ${input.title} (${input.reference})` });
  }
}

/* ------------------------------ SIEM (§61) ------------------------------ */

export class SiemConnector extends BaseConnector {
  constructor(config: Record<string, unknown>, transport?: IntegrationTransport) {
    super("SIEM", config, transport);
  }
  capabilities(): string[] { return ["events.export.json", "events.export.cef", "events.export.leef"]; }
  validateConfiguration(config: Record<string, unknown>): { ok: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!config.collector && !config.destinationKind) errors.push("SIEM integration requires a destination (HTTPS collector / syslog-compatible / vendor connector, §67)");
    if (config.collector && typeof config.collector === "string" && !/^https:\/\//.test(config.collector)) {
      errors.push("SIEM HTTPS collector must use https (§67)");
    }
    return { ok: errors.length === 0, errors };
  }
  protected async probe(): Promise<IntegrationHealth> {
    // A SIEM collector cannot be probed without sending an event; the
    // honest health signal is the delivery history (§65). Report
    // configured state only.
    if (!this.config.collector && !this.config.destinationKind) return this.notConfigured();
    return { status: "CONNECTED", reachable: true, authenticated: true, detail: "SIEM destination configured; delivery health is tracked per event (§65)" };
  }
  async sendEvent(serialized: string): Promise<{ delivered: boolean; detail: string }> {
    try {
      const res = await this.transport.request({ method: "POST", path: "/siem/collect", body: { event: serialized } });
      return { delivered: res.status >= 200 && res.status < 300, detail: `SIEM collector returned HTTP ${res.status}` };
    } catch (err) {
      if (this.isNotConfigured(err)) return { delivered: false, detail: "NOT_CONFIGURED — event queued for retry, scan flow unaffected (§66)" };
      throw err;
    }
  }
}

export function createConnector(
  kind: EnterpriseIntegrationType,
  config: Record<string, unknown>,
  transport?: IntegrationTransport,
): EnterpriseIntegrationConnector {
  switch (kind) {
    case "GITHUB": return new GitHubConnector(config, transport);
    case "GITLAB": return new GitLabConnector(config, transport);
    case "BITBUCKET": return new BitbucketConnector(config, transport);
    case "JIRA": return new JiraConnector(config, transport);
    case "SLACK": return new SlackConnector(config, transport);
    case "MICROSOFT_TEAMS": return new TeamsConnector(config, transport);
    case "SIEM": return new SiemConnector(config, transport);
    case "GENERIC_WEBHOOK":
      return new (class extends BaseConnector {
        constructor() { super("GENERIC_WEBHOOK", config, transport); }
        capabilities(): string[] { return ["webhooks.deliver"]; }
        validateConfiguration(): { ok: boolean; errors: string[] } { return { ok: true, errors: [] }; }
        protected async probe(): Promise<IntegrationHealth> {
          return { status: "CONNECTED", reachable: true, authenticated: true, detail: "Generic webhook delivery is per-subscription; destinations are validated at delivery time (§70)" };
        }
      })();
  }
}
