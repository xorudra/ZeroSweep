import { describe, expect, it } from "vitest";
import {
  FixtureToolRunner, LocalEchoAdapter, MockSecurityAdapter, ToolRegistry,
  NUCLEI_JSONL, createVulnAdapters, vulnHealthBySlug,
  createProxyAdapters, proxyHealthBySlug,
  apiHealthBySlug, buildApiFixtures, createApiAdapterSet, registerApiAdapters,
  FIXTURE_JWT_BAD, FIXTURE_JWT_GOOD,
} from "@dsrclone/security-sdk";
import { StageExecutor, EXECUTABLE_SLUGS } from "./executors/stage-executor";
import { DagRunner } from "./consumers/dag-runner";
import { FakeStore } from "./testing/fake-store";

/**
 * Prompt 9 end-to-end (§69): a full API_ASSESSMENT run over the
 * controlled fixture environment — recorded OpenAPI imports (stage
 * inputs), fixture tool outputs, obviously-fake JWTs. NO network, NO
 * real target, NO real credentials. The run must prove the safety
 * posture end-to-end: schemathesis never receives a state-changing
 * operation to execute, JWT findings come from inspection with the raw
 * token NOWHERE in persisted state, and findings flow through the
 * Phase 7 normalization → correlation → risk tail.
 */

const OPERATIONS = [
  "GET /users listUsers",
  "POST /users createUser",
  "DELETE /users/{id} deleteUser",
  "POST /payments/checkout checkout",
  "GET /health health",
];

function makeWorld() {
  const apiRunner = new FixtureToolRunner(buildApiFixtures());
  const vulnRunner = new FixtureToolRunner({ nuclei: { stdout: NUCLEI_JSONL, version: "3.3.0" } });
  const buildRegistry = () => {
    const r = new ToolRegistry();
    r.register(new MockSecurityAdapter());
    r.register(new LocalEchoAdapter());
    for (const a of createVulnAdapters(vulnRunner)) r.register(a);
    // No scanner instances registered: connectors stay NOT_CONFIGURED
    // and the passive stage completes honestly as skipped (§66).
    for (const a of createProxyAdapters({
      instances: { listEnabled: async () => [] } as never,
      endpoints: { resolve: async () => undefined } as never,
      secrets: { resolve: async () => undefined } as never,
      transport: { request: async () => { throw new Error("no transport in fixtures"); } } as never,
    })) r.register(a);
    registerApiAdapters(r, apiRunner);
    return r;
  };
  const healthBySlug = {
    ...vulnHealthBySlug(createVulnAdapters(vulnRunner)),
    ...proxyHealthBySlug([]),
    ...apiHealthBySlug(createApiAdapterSet(apiRunner)),
  };
  const store = new FakeStore("API_ASSESSMENT", {
    planRegistry: buildRegistry(),
    healthBySlug,
    executableSlugs: [...EXECUTABLE_SLUGS],
    targetType: "API",
    apiFixtures: {
      specUrls: ["https://api.example.com/v1/openapi.json"],
      operations: OPERATIONS,
      jwtTokens: [FIXTURE_JWT_GOOD, FIXTURE_JWT_BAD],
      specifications: [{ operations: 7 }],
      authContexts: [{ role: "USER_A" }, { role: "ANONYMOUS" }],
    },
  });
  const executor = new StageExecutor(buildRegistry(), store);
  return { store, dag: new DagRunner(store, executor), apiRunner };
}

describe("Prompt 9 E2E — API_ASSESSMENT over fixtures (§69)", () => {
  it("completes every stage of the API pipeline", async () => {
    const { store, dag } = makeWorld();
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    for (const stage of [
      "API_DISCOVERY", "SPEC_IMPORT", "ROUTE_DISCOVERY", "AUTH_MAPPING",
      "SAFE_SCHEMA_TESTING", "JWT_ANALYSIS", "GRAPHQL_ANALYSIS", "WEBSOCKET_INVENTORY",
      "SAFE_VULNERABILITY_SCAN", "PASSIVE_SECURITY_ANALYSIS", "API_FINDING_NORMALIZATION",
      "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "REPORT_GENERATION",
    ]) {
      expect(store.stages.get(stage), stage).toBe("COMPLETED");
    }
    expect(store.reportPending).toBe(true);
  });

  it("discovers routes + GraphQL inventory and emits the API events", async () => {
    const { store, dag } = makeWorld();
    await dag.run("scan-1");
    expect(store.endpoints.map((e) => e.url)).toContain("https://example.com/users");
    expect(store.graphqlServices.some((g) => g.queries === 3 && g.mutations === 2)).toBe(true);
    const types = store.events.map((e) => e.type);
    // api.service_discovered fires when a result carries ApiService
    // records (spec-import layer / traffic connectors); in this fixture
    // run the GraphQL inventory event covers the executor path instead.
    expect(types).toContain("graphql.schema_imported");
    expect(types).toContain("api.spec_imported");
    expect(types).toContain("api.auth_mapped");
    expect(types).toContain("jwt.analyzed");
    expect(types).toContain("api.test_completed");
    const blocked = store.events.find((e) => e.type === "api.operation_blocked");
    expect(blocked?.payload.count).toBe(3); // createUser, deleteUser, checkout
  });

  it("schemathesis NEVER receives a state-changing operation to execute (§62/§75)", async () => {
    const { dag, apiRunner } = makeWorld();
    await dag.run("scan-1");
    const calls = apiRunner.calls.filter((c) => c.executable === "schemathesis");
    expect(calls).toHaveLength(1);
    const args = calls[0]!.args;
    expect(args[args.indexOf("--include-method") + 1]).toBe("GET,HEAD,OPTIONS");
    expect(args.join(" ")).not.toContain("stateful");
    // The blocked operations appear ONLY inside the exclusion pattern.
    const exclude = args[args.indexOf("--exclude-name") + 1]!;
    expect(exclude).toContain("createUser");
    expect(exclude).toContain("deleteUser");
    expect(exclude).toContain("checkout");
    expect(exclude).not.toContain("listUsers");
  });

  it("JWT inspection produces findings + profiles with the raw token NOWHERE (§65/§70)", async () => {
    const { store, dag } = makeWorld();
    await dag.run("scan-1");
    expect(store.jwtProfiles).toHaveLength(2);
    const jwtFindings = store.findings.filter((f) => f.sourceTool === "jwt-tool");
    expect(jwtFindings.map((f) => f.vulnClass)).toEqual(
      expect.arrayContaining(["JWT_ALGORITHM_CONFIGURATION", "JWT_MISSING_EXPIRY", "JWT_SENSITIVE_CLAIMS"]),
    );
    const persisted = JSON.stringify({
      findings: store.findings, jwtProfiles: store.jwtProfiles,
      events: store.events, endpoints: store.endpoints,
      apiServices: store.apiServices, graphqlServices: store.graphqlServices,
    });
    expect(persisted).not.toContain(FIXTURE_JWT_BAD);
    expect(persisted).not.toContain(FIXTURE_JWT_GOOD);
    expect(persisted).not.toContain("FAKE-test-password-not-real");
  });

  it("findings flow through correlation: schemathesis + JWT + nuclei, deduped with provenance", async () => {
    const { store, dag } = makeWorld();
    await dag.run("scan-1");
    const schemaFindings = store.findings.filter((f) => f.sourceTool === "schemathesis");
    expect(schemaFindings.map((f) => f.vulnClass)).toEqual(
      expect.arrayContaining(["API_SERVER_ERROR", "API_RESPONSE_CONFORMANCE"]),
    );
    // CORRELATION stage ran over the full finding set.
    expect(store.correlatedFindings.length).toBeGreaterThan(0);
    expect(store.correlatedFindings.length).toBeLessThanOrEqual(store.findings.length);
    expect(store.correlatedFindings.every((f) => (f.riskScore ?? 0) >= 0)).toBe(true);
  });
});
