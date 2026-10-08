import { createHmac } from "node:crypto";
import {
  generateApiKey,
  githubPullRequestPayload,
  githubPushPayload,
  gitlabMergeRequestPayload,
  type IntegrationTransport,
} from "@dsrclone/security-sdk";
import { AuditService } from "../audit/audit.service";
import { KeysService } from "../identity/keys/keys.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { IntegrationsService } from "./core/integrations.service";
import { IntegrationSecretResolver, IntegrationTransportFactory } from "./core/transport";
import { RepositoriesIntegrationService } from "./repositories/repositories-integration.service";
import { QualityGatesService } from "./quality-gates/quality-gates.service";
import { ScanTriggerService } from "./cicd/scan-trigger.service";
import { CicdService } from "./cicd/cicd.service";
import { WebhooksService } from "./webhooks/webhooks.service";
import { WebhookSubscriptionsService } from "./webhooks/webhook-subscriptions.service";
import { TicketsService } from "./tickets/tickets.service";
import { MessagingService } from "./messaging/messaging.service";
import { SiemService } from "./siem/siem.service";
import { EventsService } from "./events/events.service";
import { OutboxProcessorService } from "./events/outbox-processor.service";
import { createIntegrationSchema } from "./dto/schemas";

/* ------------------------------------------------------------------ */
/* In-memory fake Prisma (same pattern as prior phase specs).          */
/* ------------------------------------------------------------------ */

function mockFn(impl: (...args: never[]) => Promise<unknown>) {
  const calls: unknown[][] = [];
  const fn = async (...args: unknown[]) => {
    calls.push(args);
    return impl(...(args as never[]));
  };
  return Object.assign(fn, { calls });
}
type Row = Record<string, unknown> & { id: string };

function cmp(a: unknown, b: unknown): number {
  const av = a instanceof Date ? a.getTime() : (a as number);
  const bv = b instanceof Date ? b.getTime() : (b as number);
  return av < bv ? -1 : av > bv ? 1 : 0;
}

function matches(row: Row, where: Record<string, unknown> = {}): boolean {
  for (const [key, cond] of Object.entries(where)) {
    const value = row[key];
    if (cond === null) { if (value !== null && value !== undefined) return false; continue; }
    if (cond instanceof Date || typeof cond !== "object") { if (value !== cond) return false; continue; }
    const c = cond as Record<string, unknown>;
    if ("in" in c) { if (!(c.in as unknown[]).includes(value)) return false; continue; }
    if ("not" in c) {
      if (c.not === null) { if (value === null || value === undefined) return false; }
      else if (value === c.not) return false;
      continue;
    }
    if ("gte" in c && cmp(value, c.gte) < 0) return false;
    if ("lte" in c && cmp(value, c.lte) > 0) return false;
    if ("gt" in c && cmp(value, c.gt) <= 0) return false;
    if ("lt" in c && cmp(value, c.lt) >= 0) return false;
    if (!("gte" in c) && !("lte" in c) && !("gt" in c) && !("lt" in c)) return false;
  }
  return true;
}

let seq = 0;
function makeTable(name: string) {
  const rows: Row[] = [];
  const table = {
    rows,
    async create({ data }: { data: Row }) {
      const stamp = new Date(Date.now() + ++seq);
      const row: Row = { createdAt: stamp, updatedAt: stamp, ...data, id: data.id ?? `${name}-${seq}` };
      if (row.startedAt === undefined) row.startedAt = stamp;
      rows.push(row);
      return row;
    },
    async createMany({ data }: { data: Row[] }) {
      for (const d of data) await table.create({ data: d });
      return { count: data.length };
    },
    async findUnique({ where }: { where: Record<string, unknown> }) {
      return rows.find((r) => matches(r, where)) ?? null;
    },
    async findFirst(args: { where?: Record<string, unknown>; orderBy?: Record<string, string> } = {}) {
      const list = await table.findMany({ ...args, take: 1 });
      return list[0] ?? null;
    },
    async findMany(args: { where?: Record<string, unknown>; take?: number; orderBy?: Record<string, string> | Array<Record<string, string>> } = {}) {
      let out = rows.filter((r) => matches(r, args.where));
      const orderBy = Array.isArray(args.orderBy) ? args.orderBy[0] : args.orderBy;
      if (orderBy) {
        const [field, dir] = Object.entries(orderBy)[0]!;
        out = [...out].sort((a, b) => cmp(a[field], b[field]) * (dir === "desc" ? -1 : 1));
      }
      if (args.take) out = out.slice(0, args.take);
      return out;
    },
    async update({ where, data }: { where: Record<string, unknown>; data: Partial<Row> }) {
      const row = rows.find((r) => matches(r, where));
      if (!row) throw new Error(`row not found in ${name}`);
      Object.assign(row, data);
      return row;
    },
    async updateMany({ where, data }: { where?: Record<string, unknown>; data: Partial<Row> }) {
      let count = 0;
      for (const r of rows) if (matches(r, where)) { Object.assign(r, data); count++; }
      return { count };
    },
    async delete({ where }: { where: Record<string, unknown> }) {
      const i = rows.findIndex((r) => matches(r, where));
      if (i >= 0) rows.splice(i, 1);
      return {};
    },
    async count(args: { where?: Record<string, unknown> } = {}) {
      return rows.filter((r) => matches(r, args.where)).length;
    },
  };
  return table;
}

const TABLES = [
  "integration", "repositoryIntegrationLink", "repositorySecurityPolicy",
  "pullRequestSecurityAssessment", "securityGatePolicy", "securityGateEvaluation",
  "securityBaseline", "securityPipelineRun", "jiraProjectMapping", "remediationTicket",
  "ticketSyncConflict", "webhookSubscription", "securityEventOutbox", "integrationDelivery",
  "inboundIntegrationEvent", "integrationSyncCheckpoint", "integrationJob",
  "sourceRepository", "sourceSnapshot", "target", "scope", "assessment", "scan", "finding",
  "toolExecution", "user", "workspace", "membership", "organization", "auditLog",
  "apiKey", "serviceAccount", "organizationSecurityPolicy",
] as const;

function makeFake() {
  const db: Record<string, ReturnType<typeof makeTable>> = {};
  for (const t of TABLES) db[t] = makeTable(t);
  return db as unknown as Record<string, ReturnType<typeof makeTable>> & {
    [K in (typeof TABLES)[number]]: ReturnType<typeof makeTable>;
  };
}

/* ------------------------------------------------------------------ */

const ADMIN: RequestUser = { id: "u-admin", email: "rudra@example.com", organizationId: "org-1", role: "OWNER" };
const VIEWER: RequestUser = { id: "u-viewer", email: "viewer@example.com", organizationId: "org-1", role: "VIEWER" };
const OTHER_ADMIN: RequestUser = { id: "u-other", email: "other@example.com", organizationId: "org-2", role: "OWNER" };
const WS = "ws-1";
const WS2 = "ws-2";
const GH_SECRET = "p24-fixture-github-secret";
const GL_SECRET = "p24-fixture-gitlab-secret";

process.env.P24_GH_SECRET = GH_SECRET;
process.env.P24_GL_SECRET = GL_SECRET;

class FixtureTransportFactory extends IntegrationTransportFactory {
  fixtures = new Map<string, IntegrationTransport>();
  override forIntegration(integration: { type: string } & Record<string, unknown>): IntegrationTransport {
    const found = this.fixtures.get(integration.id as string);
    if (found) return found;
    return super.forIntegration(integration as { type: string });
  }
}

const okTransport = (handler: (path: string, body?: unknown) => { status: number; body: unknown }): IntegrationTransport => ({
  request: async ({ path, body }) => handler(path, body),
});

function makeStack() {
  const prisma = makeFake();
  const audit = new AuditService(prisma as never);
  const transports = new FixtureTransportFactory();
  const secrets = new IntegrationSecretResolver();
  const integrations = new IntegrationsService(prisma as never, audit, transports);
  const repositories = new RepositoriesIntegrationService(prisma as never, audit, transports, integrations);
  const gates = new QualityGatesService(prisma as never, audit);
  const orchestration = { startScan: mockFn(async () => ({ scanId: "scan-1", status: "QUEUED" })) };
  const triggers = new ScanTriggerService(prisma as never, audit, orchestration as never);
  triggers.resolver = async () => ["93.184.216.34"];
  const events = new EventsService(prisma as never);
  const cicd = new CicdService(prisma as never, audit, gates, triggers, events);
  const webhooks = new WebhooksService(prisma as never, audit, secrets, triggers, gates, repositories);
  const subscriptions = new WebhookSubscriptionsService(prisma as never, audit, async (host) => {
    if (host === "hooks.example.com") return ["93.184.216.34"];
    if (host === "metadata.example.com") return ["169.254.169.254"];
    return [];
  });
  const tickets = new TicketsService(prisma as never, audit, transports, integrations, cicd);
  const messaging = new MessagingService(prisma as never, events, cicd);
  const siem = new SiemService(prisma as never, audit, events);
  const keys = new KeysService(prisma as never, audit);
  return {
    prisma, audit, transports, secrets, integrations, repositories, gates,
    orchestration, triggers, events, cicd, webhooks, subscriptions, tickets,
    messaging, siem, keys,
  };
}

type Stack = ReturnType<typeof makeStack>;

async function seedBase(stack: Stack) {
  const { prisma } = stack;
  await prisma.user.create({ data: { id: ADMIN.id, email: ADMIN.email, name: "Rudra" } as never });
  await prisma.workspace.create({ data: { id: WS, organizationId: "org-1", name: "Default" } as never });
  await prisma.workspace.create({ data: { id: WS2, organizationId: "org-2", name: "Other" } as never });
  await prisma.membership.create({ data: { id: "m-1", userId: ADMIN.id, organizationId: "org-1", role: "OWNER" } as never });
}

async function seedRepoScenario(stack: Stack, overrides: Record<string, unknown> = {}) {
  const { prisma } = stack;
  await seedBase(stack);
  await prisma.target.create({
    data: {
      id: "t-1", workspaceId: WS, name: "Example Service", type: "SOURCE_REPOSITORY",
      value: "example.com", status: "VERIFIED", verified: true, createdBy: ADMIN.id,
      ...(overrides.target as Record<string, unknown> ?? {}),
    } as never,
  });
  await prisma.scope.create({
    data: {
      id: "scope-1", workspaceId: WS, targetId: "t-1", name: "Scope",
      rules: { includeHosts: ["example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
    } as never,
  });
  await prisma.assessment.create({
    data: {
      id: "a-1", workspaceId: WS, targetId: "t-1", scopeId: "scope-1", name: "Source baseline",
      profile: "SOURCE_BASELINE", status: "APPROVED", createdBy: ADMIN.id,
      ...(overrides.assessment as Record<string, unknown> ?? {}),
    } as never,
  });
  await prisma.sourceRepository.create({
    data: {
      id: "repo-1", organizationId: "org-1", workspaceId: WS, targetId: "t-1",
      name: "rudra/example-service", provider: "GITHUB",
      remoteUrl: "https://github.com/rudra/example-service", defaultBranch: "main",
      visibility: "PRIVATE", sourceKind: "GIT_REPOSITORY", createdBy: ADMIN.id,
    } as never,
  });
  await prisma.integration.create({
    data: {
      id: "gh-1", workspaceId: WS, organizationId: "org-1", type: "GITHUB", name: "GitHub",
      status: "PENDING", enabled: true, capabilities: [],
      configuration: {
        authMode: "GITHUB_APP", appId: "123", installationId: "777",
        privateKeySecretReference: "env:P24_GH_KEY", webhookSecretReference: "env:P24_GH_SECRET",
      },
      secretReference: "env:P24_GH_SECRET", credentialType: "GITHUB_APP", createdBy: ADMIN.id,
      ...(overrides.integration as Record<string, unknown> ?? {}),
    } as never,
  });
  await prisma.repositoryIntegrationLink.create({
    data: {
      id: "link-1", workspaceId: WS, integrationId: "gh-1", sourceRepositoryId: "repo-1",
      provider: "GITHUB", externalRepositoryId: "424242",
      externalRepositoryRef: "https://github.com/rudra/example-service",
      installationId: "777", defaultBranch: "main", visibility: "PRIVATE",
      languages: ["TypeScript"], createdBy: ADMIN.id,
    } as never,
  });
  await prisma.repositorySecurityPolicy.create({
    data: {
      id: "pol-1", workspaceId: WS, sourceRepositoryId: "repo-1",
      scanOnPush: true, scanOnPullRequest: true, scanDefaultBranch: true,
      sastEnabled: true, scaEnabled: true, secretScanEnabled: true, sbomEnabled: true,
      containerScanEnabled: false, gatePolicyId: null, prGatePreset: "FAIL_ON_NEW_CRITICAL",
      autoRetest: false, createdBy: ADMIN.id,
      ...(overrides.policy as Record<string, unknown> ?? {}),
    } as never,
  });
}

function githubHeaders(event: string, delivery: string, body: string, secret = GH_SECRET) {
  return {
    "x-github-event": event,
    "x-github-delivery": delivery,
    "x-hub-signature-256": `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`,
  };
}


describe("integration registry (§3–§9, §103)", () => {
  it("creates an integration storing only a secret REFERENCE (§7/§8)", async () => {
    const stack = makeStack();
    await seedBase(stack);
    const created = await stack.integrations.create(ADMIN, WS, {
      type: "GITHUB", name: "GitHub",
      configuration: { authMode: "GITHUB_APP", appId: "1", installationId: "2", privateKeySecretReference: "env:GH_KEY" },
      secretReference: "env:GH_WEBHOOK", credentialType: "GITHUB_APP",
    });
    expect(created.secretConfigured).toBe(true);
    expect(created.secretReference).toBe("env:GH_WEBHOOK");
    expect(created.status).toBe("PENDING");
    // The configuration carries the reference NAME (env:GH_KEY) — a
    // pointer into the secret store, never key material (§7/§8).
    expect((created.configuration as Record<string, unknown>).privateKeySecretReference).toBe("env:GH_KEY");
    expect(JSON.stringify(created)).not.toContain("BEGIN PRIVATE KEY");
    const audits = await stack.prisma.auditLog.findMany({ where: { action: "INTEGRATION_CREATED" } });
    expect(audits).toHaveLength(1);
  });

  it("rejects secret VALUES in configuration at the schema boundary (§7)", () => {
    expect(() => createIntegrationSchema.parse({
      type: "GITHUB", name: "x",
      configuration: { authMode: "PAT", token: "ghp_1234567890abcdefghijklmnopqrstuv" },
    })).toThrow(/secret values/);
    expect(() => createIntegrationSchema.parse({
      type: "SLACK", name: "x",
      configuration: { signingSecret: "-----BEGIN PRIVATE KEY-----\nabc" },
    })).toThrow(/secret values/);
  });

  it("viewers cannot create integrations (§9)", async () => {
    const stack = makeStack();
    await seedBase(stack);
    await expect(stack.integrations.create(VIEWER, WS, { type: "SLACK", name: "s", configuration: { channel: "#sec" } }))
      .rejects.toThrow(/lacks the CREATE_INTEGRATION permission/);
  });

  it("test-connection honestly reports NOT_CONFIGURED without a transport (§104)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    const result = await stack.integrations.test(ADMIN, WS, "gh-1");
    expect(result.health?.status).toBe("NOT_CONFIGURED");
    const row = await stack.prisma.integration.findFirst({ where: { id: "gh-1" } });
    expect(row!.status).toBe("PENDING"); // never fabricated CONNECTED
    expect(row!.lastErrorCategory).toBe("NOT_CONFIGURED");
  });

  it("rotation swaps only the reference and stamps the rotation time (§8/§102)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    const rotated = await stack.integrations.rotateCredential(ADMIN, WS, "gh-1", { secretReference: "env:P24_GH_SECRET_V2" });
    expect(rotated.secretReference).toBe("env:P24_GH_SECRET_V2");
    expect(rotated.secretRotatedAt).toBeTruthy();
  });

  it("deletion removes the integration but preserves findings and tickets (§103)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    await stack.prisma.finding.create({
      data: { id: "f-keep", workspaceId: WS, scanId: "s-0", title: "x", severity: "LOW", fingerprint: "fp-keep", status: "OPEN", lifecycleStatus: "NEW", verificationStatus: "UNVERIFIED", sources: [] } as never,
    });
    const result = await stack.integrations.remove(ADMIN, WS, "gh-1");
    expect(result.deleted).toBe(true);
    expect(await stack.prisma.integration.findFirst({ where: { id: "gh-1" } })).toBeNull();
    expect(await stack.prisma.finding.findFirst({ where: { id: "f-keep" } })).not.toBeNull();
  });

  it("an integration from another organization is invisible (§133)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    await expect(stack.integrations.get(OTHER_ADMIN, WS2, "gh-1")).rejects.toThrow(/not found/);
  });
});

describe("inbound webhooks (§15–§17, §81, §111–§116)", () => {
  it("accepts a validly signed GitHub push and starts a governed scan (§111)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    const body = JSON.stringify(githubPushPayload);
    const receipt = await stack.webhooks.receive("GITHUB", githubHeaders("push", "del-1", body), body);
    expect(receipt.status).toBe("PROCESSED");
    expect(receipt.scanId).toBe("scan-1");
    expect(stack.orchestration.startScan.calls).toHaveLength(1);
    const inbound = await stack.prisma.inboundIntegrationEvent.findMany({ where: { workspaceId: WS } });
    expect(inbound).toHaveLength(1);
    expect(inbound[0]!.signatureStatus).toBe("VALID");
    expect(inbound[0]!.processingStatus).toBe("PROCESSED");
  });

  it("rejects an invalid GitHub signature before any processing (§112)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    const body = JSON.stringify(githubPushPayload);
    const receipt = await stack.webhooks.receive("GITHUB", githubHeaders("push", "del-bad", body, "wrong-secret"), body);
    expect(receipt.status).toBe("REJECTED");
    expect(receipt.httpStatus).toBe(401);
    expect(stack.orchestration.startScan.calls).toHaveLength(0);
    const inbound = await stack.prisma.inboundIntegrationEvent.findMany({});
    expect(inbound[0]!.signatureStatus).toBe("INVALID");
  });

  it("ignores a replayed delivery id — exactly one processing (§16)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    const body = JSON.stringify(githubPushPayload);
    const headers = githubHeaders("push", "del-replay", body);
    const first = await stack.webhooks.receive("GITHUB", headers, body);
    const second = await stack.webhooks.receive("GITHUB", headers, body);
    expect(first.status).toBe("PROCESSED");
    expect(second.status).toBe("IGNORED_DUPLICATE");
    expect(stack.orchestration.startScan.calls).toHaveLength(1);
    expect(await stack.prisma.inboundIntegrationEvent.count({})).toBe(1);
  });

  it("creates a PR assessment for a signed pull_request webhook; hostile title stored sanitized (§114)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    const body = JSON.stringify(githubPullRequestPayload);
    const receipt = await stack.webhooks.receive("GITHUB", githubHeaders("pull_request", "del-pr-1", body), body);
    expect(receipt.status).toBe("PROCESSED");
    expect(receipt.assessmentId).toBeTruthy();
    const assessment = await stack.prisma.pullRequestSecurityAssessment.findFirst({ where: { id: receipt.assessmentId } });
    expect(assessment!.prNumber).toBe(17);
    expect(assessment!.scanStatus).toBe("RUNNING");
    expect(assessment!.title as string).not.toContain("\u001b");
    expect(assessment!.headBranch).toBe("feature/auth; rm -rf /"); // inert data (§115)
  });

  it("blocks the trigger when NO approved assessment exists — and creates none (§136)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack, { assessment: { status: "DRAFT" } });
    const body = JSON.stringify(githubPushPayload);
    const receipt = await stack.webhooks.receive("GITHUB", githubHeaders("push", "del-noapprove", body), body);
    expect(receipt.status).toBe("BLOCKED");
    expect(receipt.reasonCode).toBe("NO_APPROVED_ASSESSMENT");
    expect(stack.orchestration.startScan.calls).toHaveLength(0);
    // The webhook must not have approved or created anything:
    const assessments = await stack.prisma.assessment.findMany({});
    expect(assessments).toHaveLength(1);
    expect(assessments[0]!.status).toBe("DRAFT");
  });

  it("blocks the trigger when the target is not VERIFIED (§136)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack, { target: { verified: false, status: "DISCOVERED" } });
    const body = JSON.stringify(githubPushPayload);
    const receipt = await stack.webhooks.receive("GITHUB", githubHeaders("push", "del-unverified", body), body);
    expect(receipt.status).toBe("BLOCKED");
    expect(receipt.reasonCode).toBe("TARGET_NOT_VERIFIED");
    expect(stack.orchestration.startScan.calls).toHaveLength(0);
  });

  it("an unlinked repository can never trigger a scan — the allowlist is the link table (§116)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    const payload = { ...githubPushPayload, repository: { ...githubPushPayload.repository, id: 999999 } };
    const body = JSON.stringify(payload);
    const receipt = await stack.webhooks.receive("GITHUB", githubHeaders("push", "del-unlinked", body), body);
    expect(receipt.status).toBe("IGNORED");
    expect(receipt.reasonCode).toBe("REPOSITORY_NOT_LINKED");
    expect(stack.orchestration.startScan.calls).toHaveLength(0);
  });

  it("respects the repository policy: push scans disabled → ignored (§31)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack, { policy: { scanOnPush: false, scanDefaultBranch: false } });
    const body = JSON.stringify(githubPushPayload);
    const receipt = await stack.webhooks.receive("GITHUB", githubHeaders("push", "del-policy", body), body);
    expect(receipt.status).toBe("IGNORED");
    expect(stack.orchestration.startScan.calls).toHaveLength(0);
  });

  it("rejects a GitLab webhook with the wrong token (§113) and accepts the right one", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    await stack.prisma.integration.create({
      data: {
        id: "gl-1", workspaceId: WS, organizationId: "org-1", type: "GITLAB", name: "GitLab",
        status: "PENDING", enabled: true, capabilities: [],
        configuration: { baseUrl: "https://gitlab.example.com", tokenSecretReference: "env:P24_GL_SECRET", webhookSecretReference: "env:P24_GL_SECRET" },
        secretReference: "env:P24_GL_SECRET", createdBy: ADMIN.id,
      } as never,
    });
    await stack.prisma.repositoryIntegrationLink.create({
      data: {
        id: "link-gl", workspaceId: WS, integrationId: "gl-1", sourceRepositoryId: "repo-1",
        provider: "GITLAB", externalRepositoryId: "909", externalRepositoryRef: "https://gitlab.example.com/rudra/example-service",
        defaultBranch: "main", visibility: "PRIVATE", languages: [], createdBy: ADMIN.id,
      } as never,
    });
    const body = JSON.stringify(gitlabMergeRequestPayload);
    const bad = await stack.webhooks.receive("GITLAB", { "x-gitlab-event": "Merge Request Hook", "x-gitlab-token": "wrong" }, body);
    expect(bad.status).toBe("REJECTED");
    const good = await stack.webhooks.receive("GITLAB", { "x-gitlab-event": "Merge Request Hook", "x-gitlab-token": GL_SECRET }, body);
    expect(good.status).toBe("PROCESSED");
    const assessment = await stack.prisma.pullRequestSecurityAssessment.findFirst({ where: { provider: "GITLAB" } });
    expect(assessment!.prNumber).toBe(42);
  });

  it("a webhook verified for tenant B cannot reach tenant A's linked repository (§133)", async () => {
    // Tenant B has its OWN GitHub integration (verifying with the same
    // fixture secret) but NO repository link — the link table is
    // workspace-scoped, so tenant A's repository is unreachable.
    const stack = makeStack();
    await seedBase(stack);
    await stack.prisma.integration.create({
      data: {
        id: "gh-b", workspaceId: WS2, organizationId: "org-2", type: "GITHUB", name: "GitHub B",
        status: "PENDING", enabled: true, capabilities: [],
        configuration: { webhookSecretReference: "env:P24_GH_SECRET" },
        secretReference: "env:P24_GH_SECRET", createdBy: OTHER_ADMIN.id,
      } as never,
    });
    const body = JSON.stringify(githubPushPayload);
    const receipt = await stack.webhooks.receive("GITHUB", githubHeaders("push", "del-xtenant", body), body);
    expect(receipt.status).toBe("IGNORED");
    expect(receipt.reasonCode).toBe("REPOSITORY_NOT_LINKED");
    expect(stack.orchestration.startScan.calls).toHaveLength(0);
  });
});

describe("quality gates + baselines (§36–§42, §120–§123)", () => {
  async function seedScanFindings(stack: Stack) {
    await stack.prisma.scan.create({
      data: { id: "scan-gate", workspaceId: WS, assessmentId: "a-1", targetId: "t-1", status: "COMPLETED", profile: "SOURCE_BASELINE" } as never,
    });
    await stack.prisma.finding.create({
      data: { id: "f-old", workspaceId: WS, scanId: "scan-gate", repositoryId: "repo-1", title: "Old high", severity: "HIGH", fingerprint: "fp-old", status: "OPEN", lifecycleStatus: "TRIAGED", verificationStatus: "UNVERIFIED", sources: [], kevListed: false } as never,
    });
    await stack.prisma.finding.create({
      data: { id: "f-crit", workspaceId: WS, scanId: "scan-gate", repositoryId: "repo-1", title: "New critical", severity: "CRITICAL", fingerprint: "fp-crit", status: "OPEN", lifecycleStatus: "NEW", verificationStatus: "UNVERIFIED", sources: [], kevListed: false } as never,
    });
    await stack.prisma.securityBaseline.create({
      data: { id: "base-1", workspaceId: WS, repositoryId: "repo-1", commitSha: "aaaaaaa", fingerprints: ["fp-old"], findingCount: 1, createdBy: ADMIN.id } as never,
    });
  }

  it("fails the gate on a NEW critical; the pre-existing high is not NEW (§120/§121)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    await seedScanFindings(stack);
    const result = await stack.gates.evaluateForScan({
      workspaceId: WS, repositoryId: "repo-1", scanId: "scan-gate",
      context: "PR_ASSESSMENT", prGatePreset: "FAIL_ON_NEW_CRITICAL", actorId: ADMIN.id,
    });
    expect(result.result).toBe("FAIL");
    expect(result.newFindingIds).toEqual(["f-crit"]);
    expect(result.classification.preExistingFingerprints).toEqual(["fp-old"]);
    const audits = await stack.prisma.auditLog.findMany({ where: { action: "QUALITY_GATE_FAILED" } });
    expect(audits).toHaveLength(1);
  });

  it("classifies a reappearing resolved fingerprint as REGRESSED (§122)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    await seedScanFindings(stack);
    await stack.prisma.finding.create({
      data: { id: "f-resolved", workspaceId: WS, scanId: "scan-older", repositoryId: "repo-1", title: "Was fixed", severity: "MEDIUM", fingerprint: "fp-back", status: "RESOLVED", lifecycleStatus: "RESOLVED", verificationStatus: "CONFIRMED", sources: [], kevListed: false } as never,
    });
    await stack.prisma.finding.create({
      data: { id: "f-back", workspaceId: WS, scanId: "scan-gate", repositoryId: "repo-1", title: "It is back", severity: "MEDIUM", fingerprint: "fp-back", status: "OPEN", lifecycleStatus: "REOPENED", verificationStatus: "UNVERIFIED", sources: [], kevListed: false } as never,
    });
    const result = await stack.gates.evaluateForScan({
      workspaceId: WS, repositoryId: "repo-1", scanId: "scan-gate",
      context: "PR_ASSESSMENT", prGatePreset: "FAIL_ON_NEW_CRITICAL", actorId: ADMIN.id,
    });
    expect(result.classification.regressedFingerprints).toEqual(["fp-back"]);
    expect(result.newFindingIds).toEqual(["f-crit"]);
  });

  it("applies FAIL_CLOSED / WARN / FAIL_OPEN for required-scanner failures (§123)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    await seedScanFindings(stack);
    await stack.prisma.toolExecution.create({
      data: { id: "te-1", scanId: "scan-gate", toolId: "semgrep", status: "FAILED" } as never,
    });
    for (const [behavior, expected] of [["FAIL_CLOSED", "FAIL"], ["WARN", "WARN"], ["FAIL_OPEN", "PASS"]] as const) {
      const policy = await stack.gates.createPolicy(ADMIN, WS, {
        name: `gate-${behavior}`,
        rules: [{ kind: "requiredScanners", scanners: ["semgrep"] }],
        scannerFailureBehavior: behavior,
      });
      const result = await stack.gates.evaluateForScan({
        workspaceId: WS, repositoryId: "repo-1", scanId: "scan-gate",
        context: "SCAN", gatePolicyId: policy.id as string, actorId: ADMIN.id,
      });
      expect(result.result).toBe(expected);
    }
  });

  it("baselines are immutable per commit (§41)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    await seedScanFindings(stack);
    await expect(stack.gates.createBaseline(ADMIN, WS, "repo-1", { commitSha: "aaaaaaa", scanId: "scan-gate" }))
      .rejects.toThrow(/immutable/);
    const created = await stack.gates.createBaseline(ADMIN, WS, "repo-1", { commitSha: "bbbbbbb", scanId: "scan-gate" });
    expect(created.findingCount).toBe(2);
  });
});


describe("remediation tickets (§46–§54, §124–§126)", () => {
  async function seedTicketScenario(stack: Stack, withTransport = true) {
    await seedRepoScenario(stack);
    await stack.prisma.integration.create({
      data: {
        id: "jira-1", workspaceId: WS, organizationId: "org-1", type: "JIRA", name: "Jira",
        status: "PENDING", enabled: true, capabilities: [],
        configuration: { baseUrl: "https://example.atlassian.net", credentialSecretReference: "env:JIRA_TOKEN" },
        secretReference: "env:JIRA_TOKEN", createdBy: ADMIN.id,
      } as never,
    });
    await stack.prisma.jiraProjectMapping.create({
      data: { id: "map-1", workspaceId: WS, integrationId: "jira-1", projectKey: "SEC", issueType: "Task", createdBy: ADMIN.id } as never,
    });
    await stack.prisma.finding.create({
      data: {
        id: "f-ticket", workspaceId: WS, scanId: "scan-gate", repositoryId: "repo-1",
        title: "SQL injection in login", severity: "HIGH", fingerprint: "fp-ticket",
        status: "OPEN", lifecycleStatus: "NEW", verificationStatus: "UNVERIFIED",
        sources: [], kevListed: false, filePath: "src/auth/login.ts", startLine: 42,
        remediation: "Use parameterized queries",
      } as never,
    });
    if (withTransport) {
      stack.transports.fixtures.set("jira-1", okTransport((path, body) => {
        if (path === "/rest/api/3/issue" && body) return { status: 201, body: { id: "10001", key: "SEC-123" } };
        if (path === "/rest/api/3/issue/SEC-123") {
          return { status: 200, body: { fields: { status: { name: "Done", statusCategory: { key: "done" } }, assignee: null } } };
        }
        return { status: 200, body: {} };
      }));
    }
  }

  it("creates exactly one external ticket per finding (§124)", async () => {
    const stack = makeStack();
    await seedTicketScenario(stack);
    const first = await stack.tickets.createTicketForFinding(ADMIN, WS, "f-ticket", {});
    expect(first.created).toBe(true);
    expect((first.ticket as Row).externalKey).toBe("SEC-123");
    expect((first.ticket as Row).syncState).toBe("IN_SYNC");
    const second = await stack.tickets.createTicketForFinding(ADMIN, WS, "f-ticket", {});
    expect(second.created).toBe(false);
    expect((second as { duplicatePrevented?: boolean }).duplicatePrevented).toBe(true);
    expect(await stack.prisma.remediationTicket.count({})).toBe(1);
  });

  it("a CLOSED Jira ticket does NOT resolve the platform finding (§125)", async () => {
    const stack = makeStack();
    await seedTicketScenario(stack);
    const { ticket } = await stack.tickets.createTicketForFinding(ADMIN, WS, "f-ticket", {});
    const synced = await stack.tickets.syncTicket(ADMIN, WS, (ticket as Row).id as string);
    expect(synced.synced).toBe(true);
    const ticketAfter = await stack.prisma.remediationTicket.findFirst({ where: { id: (ticket as Row).id } });
    expect(ticketAfter!.status).toBe("CLOSED");
    const findingAfter = await stack.prisma.finding.findFirst({ where: { id: "f-ticket" } });
    expect(findingAfter!.lifecycleStatus).toBe("NEW"); // unchanged — resolution needs evidence/retest (§52)
    const auditRow = await stack.prisma.auditLog.findMany({ where: { action: "REMEDIATION_TICKET_SYNCED" } });
    expect((auditRow[0]!.metadata as Row).findingLifecycleChanged).toBe(false);
  });

  it("a two-sided status change produces a TicketSyncConflict, never a silent overwrite (§126)", async () => {
    const stack = makeStack();
    await seedTicketScenario(stack);
    const { ticket } = await stack.tickets.createTicketForFinding(ADMIN, WS, "f-ticket", {});
    // Analyst moved the local ticket to IN_PROGRESS after last sync…
    await stack.prisma.remediationTicket.update({
      where: { id: (ticket as Row).id },
      data: { status: "IN_PROGRESS" },
    });
    // …while Jira moved to Done/CLOSED. Both sides changed → conflict.
    const synced = await stack.tickets.syncTicket(ADMIN, WS, (ticket as Row).id as string);
    expect(synced.synced).toBe(false);
    const conflicts = await stack.prisma.ticketSyncConflict.findMany({ where: { status: "OPEN" } });
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0]!.field).toBe("status");
    expect(conflicts[0]!.localValue).toBe("IN_PROGRESS");
    expect(conflicts[0]!.externalValue).toBe("CLOSED");
    const ticketAfter = await stack.prisma.remediationTicket.findFirst({ where: { id: (ticket as Row).id } });
    expect(ticketAfter!.status).toBe("IN_PROGRESS"); // local analyst decision preserved
    expect(ticketAfter!.syncState).toBe("CONFLICT");
  });

  it("without a Jira transport the ticket is honestly NOT_CONFIGURED — no fake external key", async () => {
    const stack = makeStack();
    await seedTicketScenario(stack, false);
    const result = await stack.tickets.createTicketForFinding(ADMIN, WS, "f-ticket", {});
    expect((result as { externalStatus?: string }).externalStatus).toBe("NOT_CONFIGURED");
    expect((result.ticket as Row).externalKey).toBeFalsy();
    expect((result.ticket as Row).syncState).toBe("NOT_CONFIGURED");
  });

  it("cross-tenant ticket creation is refused — the finding is invisible (§134)", async () => {
    const stack = makeStack();
    await seedTicketScenario(stack);
    await expect(stack.tickets.createTicketForFinding(OTHER_ADMIN, WS2, "f-ticket", {}))
      .rejects.toThrow(/not found/);
  });
});

describe("event bus + outbox delivery (§75–§80, §128–§132)", () => {
  const resolver = async (host: string): Promise<string[]> => {
    if (host === "hooks.example.com") return ["93.184.216.34"];
    if (host === "metadata.example.com") return ["169.254.169.254"];
    return [];
  };

  function makeProcessor(stack: Stack, http: (req: { url: string; headers: Record<string, string>; body: string }) => Promise<{ status: number; headers?: Record<string, string>; location?: string }>) {
    return new OutboxProcessorService(
      stack.prisma as never, stack.audit, stack.transports, stack.secrets,
      http as never, resolver,
    );
  }

  async function seedSubscription(stack: Stack, endpoint = "https://hooks.example.com/dsrclone") {
    await seedBase(stack);
    await stack.prisma.webhookSubscription.create({
      data: {
        id: "sub-1", workspaceId: WS, endpoint, events: ["finding.created"],
        secretReference: "env:P24_GH_SECRET", enabled: true, createdBy: ADMIN.id,
      } as never,
    });
  }

  it("delivers a signed event after a simulated crash — exactly once (§131)", async () => {
    const stack = makeStack();
    await seedSubscription(stack);
    const calls: Array<{ headers: Record<string, string>; body: string }> = [];
    const processor = makeProcessor(stack, async (req) => { calls.push(req); return { status: 200 }; });
    const { envelope, deliveries } = await stack.events.publish({
      workspaceId: WS, eventType: "finding.created", resourceType: "Finding",
      resourceId: "f-1", payload: { severity: "CRITICAL" },
    });
    expect(deliveries).toBe(1);
    // "Crash": nothing processed yet. The processor later drains it.
    const first = await processor.processDue(new Date());
    expect(first.delivered).toBe(1);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.headers["x-dsrclone-signature"]).toBe(
      `sha256=${createHmac("sha256", GH_SECRET).update(calls[0]!.body).digest("hex")}`,
    );
    expect(JSON.parse(calls[0]!.body).eventId).toBe(envelope.eventId);
    const outbox = await stack.prisma.securityEventOutbox.findFirst({ where: { eventId: envelope.eventId } });
    expect(outbox!.status).toBe("DELIVERED");
    // Processing again must not re-deliver (consumer idempotency).
    const second = await processor.processDue(new Date());
    expect(second.processed).toBe(0);
    expect(calls).toHaveLength(1);
  });

  it("dead-letters an SSRF destination at delivery time without requesting it (§128)", async () => {
    const stack = makeStack();
    await seedSubscription(stack, "https://metadata.example.com/hook");
    let calls = 0;
    const processor = makeProcessor(stack, async () => { calls += 1; return { status: 200 }; });
    await stack.events.publish({
      workspaceId: WS, eventType: "finding.created", resourceType: "Finding", resourceId: "f-1", payload: {},
    });
    const summary = await processor.processDue(new Date());
    expect(summary.deadLettered).toBe(1);
    expect(calls).toBe(0);
    const delivery = await stack.prisma.integrationDelivery.findFirst({});
    expect(delivery!.status).toBe("DEAD_LETTER");
    expect((delivery!.responseMetadata as Row).category).toBe("SSRF_BLOCKED");
  });

  it("blocks a redirect into a private address after re-validation (§129)", async () => {
    const stack = makeStack();
    await seedSubscription(stack);
    const urls: string[] = [];
    const processor = makeProcessor(stack, async (req) => {
      urls.push(req.url);
      return { status: 302, location: "https://metadata.example.com/hook" };
    });
    await stack.events.publish({
      workspaceId: WS, eventType: "finding.created", resourceType: "Finding", resourceId: "f-1", payload: {},
    });
    const summary = await processor.processDue(new Date());
    expect(summary.deadLettered).toBe(1);
    expect(urls).toEqual(["https://hooks.example.com/dsrclone"]);
  });

  it("a SIEM outage never blocks the producing flow; the event retries then dead-letters (§130)", async () => {
    const stack = makeStack();
    await seedBase(stack);
    await stack.prisma.integration.create({
      data: {
        id: "siem-1", workspaceId: WS, organizationId: "org-1", type: "SIEM", name: "SIEM",
        status: "PENDING", enabled: true, capabilities: [],
        configuration: { collector: "https://siem.example.com/collect" }, createdBy: ADMIN.id,
      } as never,
    });
    // Transport that simulates a hard outage (not a config absence).
    stack.transports.fixtures.set("siem-1", {
      request: async () => { throw new Error("connect ECONNREFUSED"); },
    });
    const queued = await stack.siem.exportEvent(ADMIN, WS, {
      integrationId: "siem-1", eventType: "CRITICAL_FINDING", severity: "CRITICAL",
      status: "OPEN", findingId: "f-1",
    });
    expect(queued.queued).toBe(true); // the export call itself succeeded — async (§66)
    const processor = makeProcessor(stack, async () => ({ status: 200 }));
    const t0 = new Date("2026-10-08T00:00:00Z");
    const first = await processor.processDue(t0);
    expect(first.failed).toBe(1);
    let delivery = await stack.prisma.integrationDelivery.findFirst({});
    expect(delivery!.status).toBe("PENDING");
    expect((delivery!.responseMetadata as Row).nextAttemptAt).toBeTruthy();
    // Drive the remaining attempts, advancing the clock past each
    // scheduled backoff (the processor correctly refuses early retries).
    for (let i = 0; i < 6; i += 1) await processor.processDue(new Date(Date.UTC(2999, 0, 1 + i)));
    delivery = await stack.prisma.integrationDelivery.findFirst({});
    expect(delivery!.status).toBe("DEAD_LETTER");
  });

  it("subscription creation refuses SSRF destinations up front (§70/§128)", async () => {
    const stack = makeStack();
    await seedBase(stack);
    await expect(stack.subscriptions.create(ADMIN, WS, {
      endpoint: "https://127.0.0.1/hook", events: ["finding.created"],
    })).rejects.toThrow(/refused/);
    await expect(stack.subscriptions.create(ADMIN, WS, {
      endpoint: "http://hooks.example.com/hook", events: ["finding.created"],
    })).rejects.toThrow(/refused/);
    const ok = await stack.subscriptions.create(ADMIN, WS, {
      endpoint: "https://hooks.example.com/hook", events: ["finding.created"], secretReference: "env:P24_GH_SECRET",
    });
    expect(ok.secretConfigured).toBe(true);
  });

  it("Slack alerts are queued through the outbox and recorded NOT_CONFIGURED without a transport (§59)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    await stack.prisma.integration.create({
      data: {
        id: "slack-1", workspaceId: WS, organizationId: "org-1", type: "SLACK", name: "Slack",
        status: "PENDING", enabled: true, capabilities: [],
        configuration: { channel: "#security" }, createdBy: ADMIN.id,
      } as never,
    });
    await stack.prisma.finding.create({
      data: {
        id: "f-alert", workspaceId: WS, scanId: "s-1", title: "Critical RCE", severity: "CRITICAL",
        fingerprint: "fp-alert", status: "OPEN", lifecycleStatus: "NEW",
        verificationStatus: "UNVERIFIED", sources: [], kevListed: false,
      } as never,
    });
    const queued = await stack.messaging.sendFindingAlert(ADMIN, WS, "f-alert");
    expect(queued.queued).toBe(1);
    const processor = makeProcessor(stack, async () => ({ status: 200 }));
    await processor.processDue(new Date());
    const delivery = await stack.prisma.integrationDelivery.findFirst({ where: { destinationKind: "SLACK" } });
    expect(delivery!.status).toBe("NOT_CONFIGURED"); // recorded honestly, never "sent"
  });
});

describe("repository sync (§13, §98, §99)", () => {
  it("imports provider repositories into staging rows + links, then updates incrementally", async () => {
    const stack = makeStack();
    await seedBase(stack);
    await stack.prisma.integration.create({
      data: {
        id: "gh-sync", workspaceId: WS, organizationId: "org-1", type: "GITHUB", name: "GitHub",
        status: "PENDING", enabled: true, capabilities: [],
        configuration: { authMode: "GITHUB_APP", appId: "1", installationId: "2", privateKeySecretReference: "env:K" },
        createdBy: ADMIN.id,
      } as never,
    });
    stack.transports.fixtures.set("gh-sync", okTransport((path) => {
      if (path === "/installation/repositories") {
        return { status: 200, body: { repositories: [githubPushPayload.repository] } };
      }
      return { status: 200, body: { resources: { core: { remaining: 5000 } } } };
    }));
    const first = await stack.repositories.syncRepositories(ADMIN, WS, "gh-sync");
    expect(first).toMatchObject({ imported: 1, updated: 0, status: "COMPLETED" });
    const repos = await stack.prisma.sourceRepository.findMany({ where: { workspaceId: WS } });
    expect(repos).toHaveLength(1);
    expect(repos[0]!.targetId ?? null).toBeNull(); // staging only — no target created/verified
    const second = await stack.repositories.syncRepositories(ADMIN, WS, "gh-sync");
    expect(second).toMatchObject({ imported: 0, updated: 1, status: "COMPLETED" });
    const checkpoint = await stack.prisma.integrationSyncCheckpoint.findFirst({ where: { integrationId: "gh-sync" } });
    expect(checkpoint).not.toBeNull();
    expect(checkpoint!.lastSuccessAt).toBeTruthy();
  });

  it("reports NOT_CONFIGURED without a transport and imports nothing", async () => {
    const stack = makeStack();
    await seedBase(stack);
    await stack.prisma.integration.create({
      data: {
        id: "gh-none", workspaceId: WS, organizationId: "org-1", type: "GITHUB", name: "GitHub",
        status: "PENDING", enabled: true, capabilities: [],
        configuration: { authMode: "GITHUB_APP", appId: "1", installationId: "2", privateKeySecretReference: "env:K" },
        createdBy: ADMIN.id,
      } as never,
    });
    const result = await stack.repositories.syncRepositories(ADMIN, WS, "gh-none");
    expect(result.status).toBe("NOT_CONFIGURED");
    expect(await stack.prisma.sourceRepository.count({})).toBe(0);
  });
});

describe("CI/CD pipeline API (§32–§35)", () => {
  async function seedPipelineKey(stack: Stack, scopes: string[]) {
    await stack.prisma.serviceAccount.create({
      data: {
        id: "sa-ci", organizationId: "org-1", workspaceId: WS, name: "ci-runner",
        status: "ACTIVE", scopes, createdBy: ADMIN.id,
      } as never,
    });
    const generated = generateApiKey();
    await stack.prisma.apiKey.create({
      data: {
        id: "key-ci", ownerKind: "SERVICE_ACCOUNT", ownerId: "sa-ci", organizationId: "org-1",
        name: "ci", prefix: generated.prefix, secretHash: generated.secretHash,
        scopes, expiresAt: null,
      } as never,
    });
    return generated.plaintext;
  }

  it("a scoped service-account key requests a governed pipeline run; re-request is idempotent", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    const plaintext = await seedPipelineKey(stack, ["pipelines:security-scan", "pipelines:gate-read"]);
    const auth = await stack.keys.authenticateApiKey(plaintext, "pipelines:security-scan");
    expect(auth.ok).toBe(true);
    if (!auth.ok) throw new Error("unreachable");
    expect(auth.workspaceId).toBe(WS);
    const run = await stack.cicd.requestPipelineRun(auth, {
      provider: "GITHUB", repositoryId: "repo-1", commitSha: "9f2c1a4b8d3e5f60718293a4b5c6d7e8f9012345",
      branch: "main", externalPipelineId: "gh-actions-1001",
    });
    expect(run.status).toBe("RUNNING");
    expect(run.scanIds).toEqual(["scan-1"]);
    const again = await stack.cicd.requestPipelineRun(auth, {
      provider: "GITHUB", repositoryId: "repo-1", commitSha: "9f2c1a4b8d3e5f60718293a4b5c6d7e8f9012345",
      branch: "main", externalPipelineId: "gh-actions-1001",
    });
    expect(again.id).toBe(run.id);
    expect(stack.orchestration.startScan.calls).toHaveLength(1);
    // Gate read is workspace-bound: another tenant's principal sees nothing.
    await expect(stack.cicd.getPipelineRunForPrincipal(
      { organizationId: "org-2", workspaceId: WS2 }, run.id as string,
    )).rejects.toThrow(/not found/);
  });

  it("a key without the pipeline scope is rejected (§35); a personal key cannot bind a workspace (§34)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    const plaintext = await seedPipelineKey(stack, ["scans:read"]);
    const denied = await stack.keys.authenticateApiKey(plaintext, "pipelines:security-scan");
    expect(denied).toMatchObject({ ok: false, reason: "INSUFFICIENT_SCOPE" });
    await expect(stack.cicd.requestPipelineRun(
      { organizationId: "org-1", workspaceId: null, ownerId: "u-admin", ownerKind: "USER" },
      { commitSha: "9f2c1a4b", externalPipelineId: "x-1" },
    )).rejects.toThrow(/service-account API key bound to a workspace/);
  });

  it("refresh evaluates the gate and the summary never contains secret values (§42)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    await stack.prisma.scan.create({
      data: { id: "scan-1", workspaceId: WS, assessmentId: "a-1", targetId: "t-1", status: "COMPLETED", profile: "SOURCE_BASELINE" } as never,
    });
    await stack.prisma.finding.create({
      data: {
        id: "f-secret", workspaceId: WS, scanId: "scan-1", repositoryId: "repo-1",
        title: "Hardcoded AWS key AKIAIOSFODNN7EXAMPLE in config", severity: "CRITICAL",
        fingerprint: "fp-secret", status: "OPEN", lifecycleStatus: "NEW",
        verificationStatus: "UNVERIFIED", sources: [], kevListed: false,
        vulnClass: "SECRET", filePath: "config/prod.ts", startLine: 7,
      } as never,
    });
    await stack.prisma.securityPipelineRun.create({
      data: {
        id: "run-1", workspaceId: WS, provider: "GITHUB", repositoryId: "repo-1",
        commitSha: "9f2c1a4b", externalPipelineId: "gh-1", scanIds: ["scan-1"],
        status: "RUNNING", requestedByKind: "SERVICE_ACCOUNT", requestedById: "sa-ci", summary: {},
      } as never,
    });
    const refreshed = await stack.cicd.refreshPipelineRun(ADMIN, WS, "run-1");
    expect(refreshed.status).toBe("COMPLETED");
    expect(refreshed.gateResult).toBe("FAIL"); // FAIL_ON_NEW_CRITICAL preset from the repo policy
    const summaryJson = JSON.stringify(refreshed.summary);
    expect(summaryJson).toContain("f-secret");
    expect(summaryJson).toContain("config/prod.ts");
    expect(summaryJson).not.toContain("AKIAIOSFODNN7EXAMPLE"); // location + id only (§42)
  });

  it("SARIF export redacts secret-shaped content (§43–§45, §119)", async () => {
    const stack = makeStack();
    await seedRepoScenario(stack);
    await stack.prisma.finding.create({
      data: {
        id: "f-sarif", workspaceId: WS, scanId: "scan-1", repositoryId: "repo-1",
        title: "Leaked key AKIAIOSFODNN7EXAMPLE", severity: "HIGH", fingerprint: "fp-sarif",
        status: "OPEN", lifecycleStatus: "NEW", verificationStatus: "UNVERIFIED",
        sources: [], kevListed: false, ruleId: "secrets/aws", cwe: "CWE-798", filePath: "a.ts", startLine: 3,
      } as never,
    });
    const { sarif } = await stack.cicd.sarifForScan(WS, "scan-1");
    expect((sarif as Row).version).toBe("2.1.0");
    expect(JSON.stringify(sarif)).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(JSON.stringify(sarif)).toContain("[REDACTED]");
  });
});
