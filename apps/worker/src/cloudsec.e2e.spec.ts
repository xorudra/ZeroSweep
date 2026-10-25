import { describe, expect, it } from "vitest";
import {
  AWS_FIXTURE_INVENTORY, AZURE_FIXTURE_INVENTORY, GCP_FIXTURE_INVENTORY,
  FIXTURE_AWS_ACCOUNT_ID, FIXTURE_AZURE_SUBSCRIPTION_ID, FIXTURE_GCP_PROJECT_ID,
  HOSTILE_SECRET_FIXTURE, PROWLER_FIXTURE, SCOUTSUITE_FIXTURE, STEAMPIPE_FIXTURE_ROWS,
  FixtureToolRunner, LocalEchoAdapter, MockSecurityAdapter, ToolRegistry,
  cloudFingerprint, cloudSecHealthBySlug, createCloudSecAdapters, createFixtureCloudTransport,
  normalizeProviderInventory,
  type CloudAccountRecord, type CloudConnectorDeps, type CloudProvider,
  type FixtureResponse, type RawCloudInventory,
} from "@zerosweep/security-sdk";
import { StageExecutor, EXECUTABLE_SLUGS } from "./executors/stage-executor";
import { DagRunner } from "./consumers/dag-runner";
import { RetestRunner, type RetestStore } from "./executors/retest-runner";
import { FakeStore } from "./testing/fake-store";

/**
 * Prompt 14 end-to-end scenarios (§90–§102): the real cloud-security
 * adapters run the full pipeline over RECORDED provider fixture
 * payloads. No live cloud account is contacted, no credential value
 * exists anywhere (references only), transports expose no mutation
 * surface (§93), and unconfigured accounts fail honestly (§9).
 */

type CloudProfile = "CLOUD_BASELINE" | "CLOUD_INVENTORY";

const ACCOUNT_RECORDS: Record<string, CloudAccountRecord> = {
  "acct-aws": { id: "acct-aws", provider: "AWS", name: "fixture-aws", externalAccountId: FIXTURE_AWS_ACCOUNT_ID, credentialReference: "vault:fixture/aws/assessment-role", environment: "production" },
  "acct-azure": { id: "acct-azure", provider: "AZURE", name: "fixture-azure", externalAccountId: FIXTURE_AZURE_SUBSCRIPTION_ID, credentialReference: "vault:fixture/azure/assessment-role", environment: "production" },
  "acct-gcp": { id: "acct-gcp", provider: "GCP", name: "fixture-gcp", externalAccountId: FIXTURE_GCP_PROJECT_ID, credentialReference: "vault:fixture/gcp/assessment-role", environment: "production" },
};

function fixtureDeps(payloads: Partial<Record<CloudProvider, RawCloudInventory>>): { deps: CloudConnectorDeps; transports: Partial<Record<CloudProvider, ReturnType<typeof createFixtureCloudTransport>>> } {
  const transports: Partial<Record<CloudProvider, ReturnType<typeof createFixtureCloudTransport>>> = {};
  for (const provider of Object.keys(payloads) as CloudProvider[]) {
    transports[provider] = createFixtureCloudTransport(provider, payloads[provider]!);
  }
  const deps: CloudConnectorDeps = {
    accounts: {
      async getById(id: string) { return ACCOUNT_RECORDS[id] ?? null; },
    },
    transports,
  };
  return { deps, transports };
}

function scopeFor(ref: string) {
  return { includeHosts: [ref], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] };
}

function makeWorld(
  fixtures: Record<string, FixtureResponse>,
  profile: CloudProfile,
  opts: {
    targetType: "AWS" | "AZURE" | "GCP";
    accountRef: string;
    payloads: Partial<Record<CloudProvider, RawCloudInventory>>;
    cloudSecFixtures?: InstanceType<typeof FakeStore>["cloudSecFixtures"];
    workerCapabilities?: string[];
  },
) {
  const { deps, transports } = fixtureDeps(opts.payloads);
  const planAdapters = createCloudSecAdapters(new FixtureToolRunner(fixtures), deps);
  const planRegistry = new ToolRegistry();
  planRegistry.register(new MockSecurityAdapter());
  planRegistry.register(new LocalEchoAdapter());
  for (const a of planAdapters) planRegistry.register(a);
  const health = cloudSecHealthBySlug(planAdapters);
  // A registered + configured account makes its OWN provider connector
  // selectable at plan time (mirrors the per-account health model, §9);
  // import connectors stay NOT_CONFIGURED — no recorded export exists.
  if (opts.cloudSecFixtures?.accountId) {
    health[`${opts.targetType.toLowerCase()}-inventory`] = "HEALTHY";
  }
  const store = new FakeStore(profile, {
    planRegistry,
    healthBySlug: health,
    executableSlugs: [...EXECUTABLE_SLUGS],
    targetType: opts.targetType,
    networkTarget: { targetValue: opts.accountRef, targetHost: opts.accountRef, scope: scopeFor(opts.accountRef) },
    ...(opts.cloudSecFixtures ? { cloudSecFixtures: opts.cloudSecFixtures } : {}),
  });
  const runner = new FixtureToolRunner(fixtures);
  const execRegistry = new ToolRegistry();
  execRegistry.register(new MockSecurityAdapter());
  execRegistry.register(new LocalEchoAdapter());
  for (const a of createCloudSecAdapters(runner, deps)) execRegistry.register(a);
  const executor = new StageExecutor(execRegistry, store, undefined, {
    workerCapabilities: opts.workerCapabilities ?? ["CLOUD_ANALYSIS"],
  });
  return { runner, store, executor, dag: new DagRunner(store, executor), transports };
}

const AWS_TOOL_FIXTURES: Record<string, FixtureResponse> = {
  prowler: { stdout: JSON.stringify(PROWLER_FIXTURE), version: "5.3.0" },
  scout: { stdout: JSON.stringify(SCOUTSUITE_FIXTURE), version: "5.14.0" },
  steampipe: { stdout: JSON.stringify(STEAMPIPE_FIXTURE_ROWS), version: "1.2.0" },
};

const AWS_ACCOUNT_FIXTURE: InstanceType<typeof FakeStore>["cloudSecFixtures"] = {
  accountId: "acct-aws", accountRef: FIXTURE_AWS_ACCOUNT_ID, provider: "AWS",
  credentialReference: "vault:fixture/aws/assessment-role",
  regions: ["us-east-1", "eu-west-1"], environment: "production", queryPack: "aws-cis-foundations",
};

describe("Prompt 14 E2E — AWS CLOUD_BASELINE over the fixture account (§90)", () => {
  it("validates, inventories, analyzes, correlates Prowler+ScoutSuite+native into ONE canonical finding (§95)", async () => {
    const { store, dag, transports } = makeWorld(AWS_TOOL_FIXTURES, "CLOUD_BASELINE", {
      targetType: "AWS", accountRef: FIXTURE_AWS_ACCOUNT_ID,
      payloads: { AWS: AWS_FIXTURE_INVENTORY },
      cloudSecFixtures: AWS_ACCOUNT_FIXTURE,
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.cloudAccountStatus).toBe("VALIDATED");
    expect(store.events.some((e) => e.type === "cloud.account_validated")).toBe(true);
    expect(store.events.some((e) => e.type === "cloud.scan_completed")).toBe(true);

    // Inventory (§16): normalized resources + identities + snapshot,
    // AWS-only — no other provider's data ever enters this scan (§102).
    expect(store.cloudResources.length).toBeGreaterThanOrEqual(10);
    expect(store.cloudResources.every((r) => r.resourceType.startsWith("AWS_"))).toBe(true);
    const bucket = store.cloudResources.find((r) => r.providerResourceId === "arn:aws:s3:::public-assets-fixture");
    expect(bucket?.exposure).toBe("PUBLIC");
    expect(store.cloudIdentities.some((i) => i.name === "rudra-admin-fixture")).toBe(true);
    expect(store.cloudSnapshots).toHaveLength(1);
    expect(store.cloudRelationships.length).toBeGreaterThan(0); // §98: identity/cluster links are evidence-backed

    // Native analysis sections (§36–§57) over the persisted inventory.
    expect(store.events.some((e) => e.type === "cloud.iam_risk_detected")).toBe(true);
    expect(store.findings.some((f) => f.ruleId === "iam-admin-equivalent")).toBe(true);
    expect(store.findings.some((f) => f.ruleId === "iam-broad-trust")).toBe(true);
    expect(store.findings.some((f) => f.ruleId === "mfa-not-enabled")).toBe(true);
    expect(store.findings.some((f) => f.ruleId === "firewall-sensitive-port-world")).toBe(true);
    expect(store.findings.some((f) => f.ruleId === "database-public-access")).toBe(true);
    expect(store.findings.some((f) => f.ruleId === "kms-rotation-disabled")).toBe(true);
    expect(store.findings.some((f) => f.ruleId === "audit-logging-disabled")).toBe(true);

    // §95: Prowler FAIL + ScoutSuite danger + native storage analysis
    // of the SAME public bucket merge into one canonical finding.
    const canonical = store.correlatedFindings;
    const pub = canonical.filter((f) => f.ruleId === "storage-public-access" && f.providerResourceId === "arn:aws:s3:::public-assets-fixture");
    expect(pub).toHaveLength(1);
    expect(pub[0]?.sources).toEqual(expect.arrayContaining(["prowler", "scoutsuite", "cloud-platform-analysis"]));
    // Prowler PASS never became a finding (§23).
    expect(canonical.some((f) => f.providerResourceId === "arn:aws:s3:::private-data-fixture" && f.ruleId === "storage-encryption")).toBe(false);

    // Compliance (§84): CIS assessments recorded; gate evaluated as a
    // RESULT — the scan completed even though the gate failed (§70).
    expect(store.controlAssessments.some((a) => a.frameworkKey === "CIS_AWS")).toBe(true);
    expect(store.events.some((e) => e.type === "cloud.compliance_assessed")).toBe(true);
    expect(store.cloudGateRecord?.status).toBe("FAILED");
    // Risk paths (§67/§97): public network path evidence assembled.
    expect(store.cloudRiskPaths.length).toBeGreaterThan(0);

    // §93/§100: the transport recorded no mutation call, and no
    // credential VALUE exists in state — only the reference name.
    expect(transports.AWS?.mutationCalls).toEqual([]);
    expect(JSON.stringify(store)).not.toContain("AKIA");
    expect(JSON.stringify(store)).not.toContain("credentialValue");
  });

  it("records drift against the previous inventory (§64): logging change + removed resource", async () => {
    const previousRaw = structuredClone(AWS_FIXTURE_INVENTORY);
    (previousRaw.resources!.find((r) => r.name === "main-trail")!.config as Record<string, unknown>).enabled = true;
    previousRaw.resources!.push({
      type: "s3_bucket", id: "arn:aws:s3:::retired-fixture", name: "retired-fixture", region: "us-east-1",
      config: { publicAccess: false, encryption: "KMS" },
    });
    const previous = normalizeProviderInventory("AWS", previousRaw, {
      accountId: "acct-aws", accountRef: FIXTURE_AWS_ACCOUNT_ID, toolSlug: "aws-inventory",
    });
    const { store, dag } = makeWorld(AWS_TOOL_FIXTURES, "CLOUD_BASELINE", {
      targetType: "AWS", accountRef: FIXTURE_AWS_ACCOUNT_ID,
      payloads: { AWS: AWS_FIXTURE_INVENTORY },
      cloudSecFixtures: { ...AWS_ACCOUNT_FIXTURE, previousResources: previous.resources, previousIdentities: previous.identities },
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.cloudDrift.some((d) => d.kind === "LOGGING_CHANGED")).toBe(true);
    expect(store.cloudDrift.some((d) => d.kind === "RESOURCE_REMOVED")).toBe(true);
    expect(store.events.some((e) => e.type === "cloud.drift_detected")).toBe(true);
  });

  it("hostile fixture secret material is redacted before persistence (§100)", async () => {
    const { store, dag } = makeWorld({}, "CLOUD_INVENTORY", {
      targetType: "AWS", accountRef: FIXTURE_AWS_ACCOUNT_ID,
      payloads: { AWS: HOSTILE_SECRET_FIXTURE },
      cloudSecFixtures: AWS_ACCOUNT_FIXTURE,
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.cloudResources.some((r) => r.name === "tagged-fixture")).toBe(true);
    const state = JSON.stringify(store);
    expect(state).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(state).not.toContain("wJalrXUtnFEMI");
  });
});

describe("Prompt 14 E2E — Azure + GCP fixture accounts (§91/§92)", () => {
  it("Azure: NSG RDP exposure, public storage, privileged RBAC identity", async () => {
    const { store, dag } = makeWorld({}, "CLOUD_BASELINE", {
      targetType: "AZURE", accountRef: FIXTURE_AZURE_SUBSCRIPTION_ID,
      payloads: { AZURE: AZURE_FIXTURE_INVENTORY },
      cloudSecFixtures: {
        accountId: "acct-azure", accountRef: FIXTURE_AZURE_SUBSCRIPTION_ID, provider: "AZURE",
        credentialReference: "vault:fixture/azure/assessment-role", regions: ["eastus"], environment: "production",
      },
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.cloudResources.every((r) => r.resourceType.startsWith("AZURE_"))).toBe(true);
    expect(store.findings.some((f) => f.ruleId === "firewall-sensitive-port-world")).toBe(true);
    expect(store.findings.some((f) => f.ruleId === "storage-public-access")).toBe(true);
    expect(store.findings.some((f) => f.ruleId === "iam-admin-equivalent")).toBe(true);
    expect(store.controlAssessments.some((a) => a.frameworkKey === "CIS_AZURE")).toBe(true);
  });

  it("GCP: world-open SSH firewall, public bucket, owner service account", async () => {
    const { store, dag } = makeWorld({}, "CLOUD_BASELINE", {
      targetType: "GCP", accountRef: FIXTURE_GCP_PROJECT_ID,
      payloads: { GCP: GCP_FIXTURE_INVENTORY },
      cloudSecFixtures: {
        accountId: "acct-gcp", accountRef: FIXTURE_GCP_PROJECT_ID, provider: "GCP",
        credentialReference: "vault:fixture/gcp/assessment-role", regions: ["us-central1"], environment: "production",
      },
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.cloudResources.every((r) => r.resourceType.startsWith("GCP_"))).toBe(true);
    expect(store.findings.some((f) => f.ruleId === "firewall-sensitive-port-world")).toBe(true);
    expect(store.findings.some((f) => f.ruleId === "storage-public-access")).toBe(true);
    expect(store.findings.some((f) => f.ruleId === "iam-admin-equivalent")).toBe(true);
    expect(store.controlAssessments.some((a) => a.frameworkKey === "CIS_GCP")).toBe(true);
  });
});

describe("Prompt 14 E2E — honest configuration states (§9)", () => {
  it("unregistered account: CLOUD_AUTH fails the scan with CLOUD_NOT_CONFIGURED", async () => {
    const { store, dag } = makeWorld(AWS_TOOL_FIXTURES, "CLOUD_BASELINE", {
      targetType: "AWS", accountRef: FIXTURE_AWS_ACCOUNT_ID,
      payloads: { AWS: AWS_FIXTURE_INVENTORY },
      cloudSecFixtures: { provider: "AWS", accountRef: FIXTURE_AWS_ACCOUNT_ID },
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("FAILED");
    expect(store.events.some((e) => e.type === "policy.denied" && e.payload.reasonCode === "CLOUD_NOT_CONFIGURED")).toBe(true);
    expect(store.cloudResources).toHaveLength(0);
    expect(store.findings).toHaveLength(0);
  });

  it("registered account without a credential reference reports NOT_CONFIGURED (§6/§9)", async () => {
    const { store, dag } = makeWorld(AWS_TOOL_FIXTURES, "CLOUD_BASELINE", {
      targetType: "AWS", accountRef: FIXTURE_AWS_ACCOUNT_ID,
      payloads: { AWS: AWS_FIXTURE_INVENTORY },
      cloudSecFixtures: { accountId: "acct-aws", accountRef: FIXTURE_AWS_ACCOUNT_ID, provider: "AWS", regions: ["us-east-1"] },
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("FAILED");
    expect(store.cloudAccountStatus).toBe("NOT_CONFIGURED");
    expect(store.cloudResources).toHaveLength(0);
  });

  it("cloud adapters are denied on a worker without the CLOUD_ANALYSIS capability", async () => {
    const { store, dag } = makeWorld(AWS_TOOL_FIXTURES, "CLOUD_BASELINE", {
      targetType: "AWS", accountRef: FIXTURE_AWS_ACCOUNT_ID,
      payloads: { AWS: AWS_FIXTURE_INVENTORY },
      cloudSecFixtures: AWS_ACCOUNT_FIXTURE,
      workerCapabilities: [],
    });
    const result = await dag.run("scan-1");
    expect(result.status).not.toBe("COMPLETED");
    expect(store.events.some((e) => e.type === "policy.denied" && e.payload.reasonCode === "UNAVAILABLE_FOR_WORKER")).toBe(true);
    expect(store.cloudResources).toHaveLength(0);
  });
});

describe("Prompt 14 E2E — targeted cloud retest (§73)", () => {
  const bucketFingerprint = cloudFingerprint({
    provider: "AWS", accountRef: FIXTURE_AWS_ACCOUNT_ID, region: "us-east-1",
    providerResourceId: "arn:aws:s3:::public-assets-fixture",
    ruleId: "storage-public-access", findingClass: "PUBLIC_EXPOSURE",
  });

  function retestStoreFor(store: FakeStore): RetestStore {
    return {
      async prepareRetestExecution() {
        const exec = await store.ensureExecution("scan-1", "CLOUD_INVENTORY", "aws-inventory", 1);
        return {
          executionId: exec.id, scanId: "scan-1", canonicalFingerprint: bucketFingerprint,
          stageId: "CLOUD_INVENTORY", cloudAnalysisSection: "STORAGE_ANALYSIS",
        };
      },
      async retestScanFingerprints() { return store.findings.map((f) => f.fingerprint); },
      async completeRetest(_id, outcome) { (store as unknown as { retestOutcome?: string }).retestOutcome = outcome; },
      analyzeCloudSection: (scanId, section) => store.analyzeCloudSection(scanId, section),
    };
  }

  it("REOPENED when the re-check still observes the public bucket", async () => {
    const { store, executor } = makeWorld({}, "CLOUD_BASELINE", {
      targetType: "AWS", accountRef: FIXTURE_AWS_ACCOUNT_ID,
      payloads: { AWS: AWS_FIXTURE_INVENTORY },
      cloudSecFixtures: AWS_ACCOUNT_FIXTURE,
    });
    const runner = new RetestRunner(retestStoreFor(store), executor);
    const result = await runner.runRetest("retest-1");
    expect(result).toEqual({ status: "COMPLETED", outcome: "REOPENED" });
  });

  it("RESOLVED when the re-check observes the bucket fixed", async () => {
    const fixed = structuredClone(AWS_FIXTURE_INVENTORY);
    const bucketCfg = fixed.resources!.find((r) => r.name === "public-assets-fixture")!.config as Record<string, unknown>;
    bucketCfg.publicAccess = false;
    bucketCfg.publicAccessBlock = true;
    bucketCfg.aclPublic = false;
    const { store, executor } = makeWorld({}, "CLOUD_BASELINE", {
      targetType: "AWS", accountRef: FIXTURE_AWS_ACCOUNT_ID,
      payloads: { AWS: fixed },
      cloudSecFixtures: AWS_ACCOUNT_FIXTURE,
    });
    const runner = new RetestRunner(retestStoreFor(store), executor);
    const result = await runner.runRetest("retest-1");
    expect(result).toEqual({ status: "COMPLETED", outcome: "RESOLVED" });
  });
});
