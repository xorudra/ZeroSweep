import { describe, expect, it } from "vitest";
import {
  FIXTURE_BLOODHOUND_EXPORT, FIXTURE_CERTIPY_JSON, FIXTURE_CREDENTIAL_MARKER, FIXTURE_DOMAIN_RECORD,
  FIXTURE_PINGCASTLE_XML, FixtureToolRunner, LocalEchoAdapter, MockSecurityAdapter,
  ToolRegistry, createDirectoryAdapters, createFixtureDirectoryTransport,
  directoryHealthBySlug, fixturePreviousBloodHoundExport, parseBloodHoundExport,
  type DirectoryConnectorDeps, type FixtureResponse, type NormalizedDirectoryData,
} from "@dsrclone/security-sdk";
import { StageExecutor, EXECUTABLE_SLUGS } from "./executors/stage-executor";
import { DagRunner } from "./consumers/dag-runner";
import { RetestRunner, type RetestStore } from "./executors/retest-runner";
import { FakeStore } from "./testing/fake-store";

/**
 * Prompt 15 end-to-end scenarios (§104–§116): the real directory
 * adapters run the full pipeline over RECORDED fixture exports for
 * the fictional corp.example domain. No live directory is contacted,
 * no credential value exists anywhere (references only), collection
 * is read-only, offensive tools exist as DISABLED registrations
 * only, and unregistered domains fail honestly (§9/§15).
 */

const PARSE_CTX = { domainDnsName: "corp.example", source: "bloodhound-connector", includeLocalAdmins: true };

function fixtureDirectory(includeLocalAdmins = true): NormalizedDirectoryData {
  return parseBloodHoundExport(FIXTURE_BLOODHOUND_EXPORT, { ...PARSE_CTX, includeLocalAdmins }).directory;
}

function fixtureDeps(directory: NormalizedDirectoryData): DirectoryConnectorDeps {
  const transport = createFixtureDirectoryTransport(directory);
  return {
    domains: {
      async getDomain(id: string) {
        return id === FIXTURE_DOMAIN_RECORD.id ? FIXTURE_DOMAIN_RECORD : undefined;
      },
    },
    transports: { bloodhound: transport, ldap: transport },
  };
}

const TOOL_FIXTURES: Record<string, FixtureResponse> = {
  // FixtureToolRunner keys fixtures by EXECUTABLE name.
  PingCastle: { stdout: FIXTURE_PINGCASTLE_XML, version: "2.11.0" },
  certipy: { stdout: JSON.stringify(FIXTURE_CERTIPY_JSON), version: "4.8.0" },
};

async function makeWorld(opts: {
  directory?: NormalizedDirectoryData;
  directoryFixtures?: InstanceType<typeof FakeStore>["directoryFixtures"];
  workerCapabilities?: string[];
} = {}) {
  const deps = fixtureDeps(opts.directory ?? fixtureDirectory());
  const planAdapters = createDirectoryAdapters(new FixtureToolRunner(TOOL_FIXTURES), deps);
  const planRegistry = new ToolRegistry();
  planRegistry.register(new MockSecurityAdapter());
  planRegistry.register(new LocalEchoAdapter());
  for (const a of planAdapters) planRegistry.register(a);
  const health: Record<string, string> = {};
  for (const [slug, h] of await directoryHealthBySlug(planAdapters, deps)) health[slug] = h.status;
  const store = new FakeStore("AD_BASELINE", {
    planRegistry,
    healthBySlug: health,
    executableSlugs: [...EXECUTABLE_SLUGS],
    targetType: "ACTIVE_DIRECTORY_DOMAIN",
    networkTarget: {
      targetValue: "corp.example", targetHost: "corp.example",
      scope: { includeHosts: ["corp.example"], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
    },
    directoryFixtures: opts.directoryFixtures ?? {
      domainId: "fixture-domain-1", domainRef: "corp.example",
      credentialReference: "vault:fixtures/ad/corp-example", identityKind: "READ_ONLY_DOMAIN",
      dcHosts: ["DC01.CORP.EXAMPLE", "DC02.CORP.EXAMPLE"],
      previousData: parseBloodHoundExport(fixturePreviousBloodHoundExport(), PARSE_CTX).directory,
    },
  });
  const runner = new FixtureToolRunner(TOOL_FIXTURES);
  const execRegistry = new ToolRegistry();
  execRegistry.register(new MockSecurityAdapter());
  execRegistry.register(new LocalEchoAdapter());
  for (const a of createDirectoryAdapters(runner, deps)) execRegistry.register(a);
  const executor = new StageExecutor(execRegistry, store, undefined, {
    workerCapabilities: opts.workerCapabilities ?? ["DIRECTORY_ANALYSIS"],
  });
  return { store, executor, dag: new DagRunner(store, executor), execRegistry };
}

describe("Prompt 15 E2E — AD_BASELINE over the fixture corp.example domain (§104)", () => {
  it("validates, collects, graphs, models paths and reports — fixture-only, read-only", async () => {
    const { store, dag } = await makeWorld();
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.directoryDomainStatus).toBe("VALIDATED");
    expect(store.events.some((e) => e.type === "ad.domain_validated")).toBe(true);
    expect(store.events.some((e) => e.type === "ad.scan_completed")).toBe(true);
    expect(store.events.some((e) => e.type === "ad.inventory_recorded")).toBe(true);

    // Inventory (§18/§106): the full fixture directory persisted.
    expect(store.directoryData.users).toHaveLength(8);
    expect(store.directoryData.computers).toHaveLength(4);
    expect(store.directoryData.domainControllers).toHaveLength(2);
    expect(store.directoryData.trusts).toHaveLength(1);
    expect(store.directorySnapshots.length).toBeGreaterThanOrEqual(1);
    expect(store.directorySnapshots[0]!.snapshotHash).toMatch(/^[a-f0-9]{64}$/);

    // Posture findings (§57–§78) joined the common pipeline.
    const ruleIds = new Set(store.findings.map((f) => f.ruleId));
    expect(ruleIds.has("AD_LDAP_SIGNING_NOT_REQUIRED")).toBe(true);
    expect(ruleIds.has("AD_SMB1_ENABLED")).toBe(true);
    expect(ruleIds.has("AD_STALE_ENABLED_ACCOUNT")).toBe(true);
    expect(ruleIds.has("AD_UNCONSTRAINED_DELEGATION")).toBe(true);
    expect(store.controlAssessments.some((a) => a.frameworkKey === "MS_AD_BASELINE")).toBe(true);

    // PingCastle + native krbtgt observations converge on ONE
    // canonical finding (§61/§109).
    await store.correlateScanFindings();
    const krbtgt = store.correlatedFindings.filter((f) => f.ruleId === "AD_KRBTGT_OLD");
    expect(krbtgt).toHaveLength(1);
    expect(krbtgt[0]!.sources.length).toBeGreaterThanOrEqual(2);

    // Identity graph + attack paths (§34–§37/§107): modeled, never
    // executed, never COMPROMISED.
    expect(store.events.some((e) => e.type === "ad.graph_built")).toBe(true);
    expect(store.events.some((e) => e.type === "ad.privileged_identity_detected")).toBe(true);
    expect(store.events.some((e) => e.type === "ad.attack_path_detected")).toBe(true);
    expect(store.attackPaths.length).toBeGreaterThanOrEqual(1);
    expect(store.attackPaths.some((p) => p.title.includes("DC02"))).toBe(true);
    expect(store.attackPaths.every((p) => p.status !== "COMPROMISED")).toBe(true);

    // Drift (§79/§80): new privileged member + new trust vs the
    // previous snapshot fixture.
    expect(store.events.some((e) => e.type === "ad.drift_detected")).toBe(true);
    expect(store.adDrift.some((d) => d.kind === "NEW_PRIVILEGED_MEMBER")).toBe(true);
    expect(store.adDrift.some((d) => d.kind === "NEW_TRUST")).toBe(true);

    // §113: the planted credential marker appears NOWHERE — not in
    // findings, not in events, not in the persisted directory state.
    const blob = JSON.stringify({ findings: store.findings, events: store.events, directory: store.directoryData });
    expect(blob).not.toContain(FIXTURE_CREDENTIAL_MARKER);
  });

  it("a worker without DIRECTORY_ANALYSIS capability collects nothing (§10/§11)", async () => {
    const { store, dag } = await makeWorld({ workerCapabilities: [] });
    const result = await dag.run("scan-1");
    expect(result.status).not.toBe("COMPLETED");
    expect(store.directoryData.users).toHaveLength(0);
    expect(store.directorySnapshots).toHaveLength(0);
  });

  it("an unregistered domain fails the scan honestly at DOMAIN_DISCOVERY (§9/§15)", async () => {
    const { store, dag } = await makeWorld({ directoryFixtures: {} });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("FAILED");
    expect(store.events.some((e) => e.type === "policy.denied")).toBe(true);
    expect(store.directoryData.users).toHaveLength(0);
  });

  it("offensive tools are not executable by any stage (§51–§56/§112)", async () => {
    const { execRegistry } = await makeWorld();
    for (const slug of ["netexec", "impacket", "kerbrute", "responder", "powerview", "adexplorer"]) {
      expect(execRegistry.resolve(slug)).toBeUndefined();
      expect(EXECUTABLE_SLUGS).not.toContain(slug);
    }
  });

  describe("targeted retest (§84)", () => {
    function retestStoreFor(store: FakeStore, fingerprint: string): RetestStore {
      return {
        async prepareRetestExecution() {
          const exec = await store.ensureExecution("scan-1", "DIRECTORY_INVENTORY", "bloodhound-connector", 1);
          return {
            executionId: exec.id, scanId: "scan-1", canonicalFingerprint: fingerprint,
            stageId: "DIRECTORY_INVENTORY", directoryAnalysisSection: "LDAP_POSTURE",
          };
        },
        async retestScanFingerprints() { return store.findings.map((f) => f.fingerprint); },
        async completeRetest() { /* recorded by assertions on outcome */ },
        analyzeDirectoryLdapPosture: () => store.analyzeDirectoryLdapPosture(),
      };
    }

    it("REOPENED while LDAP signing is still not required; RESOLVED once the re-check observes it fixed", async () => {
      const first = await makeWorld();
      await first.dag.run("scan-1");
      const ldapFinding = first.store.findings.find((f) => f.ruleId === "AD_LDAP_SIGNING_NOT_REQUIRED")!;
      expect(ldapFinding).toBeDefined();
      const reopened = await new RetestRunner(retestStoreFor(first.store, ldapFinding.fingerprint), first.executor).runRetest("retest-1");
      expect(reopened).toEqual({ status: "COMPLETED", outcome: "REOPENED" });

      const fixedDirectory = fixtureDirectory();
      for (const dc of fixedDirectory.domainControllers) {
        dc.services = { ...dc.services, ldapSigningRequired: true };
      }
      const second = await makeWorld({ directory: fixedDirectory });
      const resolved = await new RetestRunner(retestStoreFor(second.store, ldapFinding.fingerprint), second.executor).runRetest("retest-1");
      expect(resolved).toEqual({ status: "COMPLETED", outcome: "RESOLVED" });
    });
  });
});
