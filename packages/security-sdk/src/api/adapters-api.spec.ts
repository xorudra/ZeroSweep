import { describe, expect, it } from "vitest";
import { AdapterConfigurationError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import { FixtureToolRunner } from "../recon/runner";
import { InqlAdapter, JwtToolAdapter, KiterunnerAdapter, SchemathesisAdapter, SCHEMATHESIS_SAFE_CHECKS } from "./adapters-api";
import { parseGraphqlmapOutput, parseInqlOutput, parseKiterunnerOutput, parseSchemathesisJUnit } from "./parsers-api";
import { MitmproxyFlowParser } from "../proxy/parsers-proxy";
import {
  buildApiFixtures, FIXTURE_GRAPHQL_INTROSPECTION, FIXTURE_JWT_GOOD, FIXTURE_MITMPROXY_FLOWS,
  FIXTURE_SCHEMATHESIS_JUNIT,
} from "./fixtures";
import { NUCLEI_TEMPLATE_CATALOG, selectTemplates } from "../vuln/template-policy";

const target: AdapterTarget = { type: "API", value: "https://api.example.com", host: "api.example.com" };

/**
 * API adapters + parsers (Prompt 9 §13/§15/§27/§28/§62/§71–§73): plans
 * are argv-only and policy-shaped; parsers turn recorded tool output
 * into inventory/findings; WebSocket and GraphQL fixtures prove the
 * inventory-only posture (introspection/mutations never become
 * findings, WebSocket auth is presence-only).
 */
describe("KiterunnerAdapter (§13/§72)", () => {
  it("plans a governed-wordlist scan against the in-scope base URL", async () => {
    const adapter = new KiterunnerAdapter(new FixtureToolRunner(buildApiFixtures()));
    const plan = await adapter.buildExecutionPlan(target, { urls: ["https://api.example.com/v1"], wordlistProfile: "SMALL" });
    expect(plan.executable).toBe("kr");
    expect(plan.arguments).toContain("https://api.example.com/v1");
    const wIdx = plan.arguments.indexOf("-w");
    expect(plan.arguments[wIdx + 1]).toContain("api-routes-small");
    expect(plan.arguments.join(" ")).not.toMatch(/;|&&|\|\||\$\(/);
  });

  it("executes against fixtures and parses routes into API endpoints", async () => {
    const adapter = new KiterunnerAdapter(new FixtureToolRunner(buildApiFixtures()));
    const plan = await adapter.buildExecutionPlan(target, { urls: ["https://api.example.com/v1"] });
    const { rawOutput } = await adapter.execute(plan);
    const parsed = (await adapter.parse(rawOutput ?? "")) as Awaited<ReturnType<KiterunnerAdapter["parse"]>>;
    const normalized = await adapter.normalize(parsed);
    expect(normalized.endpoints.map((e) => e.url)).toContain("https://api.example.com/v1/users");
    expect(normalized.endpoints.every((e) => e.endpointType === "API")).toBe(true);
    expect(normalized.findings).toEqual([]); // discovery is inventory (§13)
    expect(normalized.metrics.parserWarnings).toBeGreaterThanOrEqual(1); // the malformed line warned, not failed
  });

  it("parser tolerates empty output", () => {
    expect(parseKiterunnerOutput("", "kiterunner", "https://api.example.com").endpoints).toEqual([]);
  });
});

describe("SchemathesisAdapter (§15/§62)", () => {
  const operations = [
    "GET /users listUsers",
    "POST /users createUser",
    "DELETE /users/{id} deleteUser",
    "POST /payments/checkout checkout",
  ];

  it("requires an imported schema location — no schema, no plan", async () => {
    const adapter = new SchemathesisAdapter(new FixtureToolRunner(buildApiFixtures()));
    await expect(adapter.buildExecutionPlan(target, { operations })).rejects.toBeInstanceOf(AdapterConfigurationError);
  });

  it("plan excludes every non-safe operation by id AND by method, with safe checks only", async () => {
    const adapter = new SchemathesisAdapter(new FixtureToolRunner(buildApiFixtures()));
    const plan = await adapter.buildExecutionPlan(target, { schemaUrl: "https://api.example.com/v1/openapi.json", operations });
    const args = plan.arguments;
    expect(args).toContain("--include-method");
    expect(args[args.indexOf("--include-method") + 1]).toBe("GET,HEAD,OPTIONS");
    const exclude = args[args.indexOf("--exclude-name") + 1]!;
    expect(exclude).toContain("createUser");
    expect(exclude).toContain("deleteUser");
    expect(exclude).toContain("checkout");
    expect(exclude).not.toContain("listUsers");
    const checks = args[args.indexOf("--checks") + 1]!;
    expect(checks.split(",")).toEqual([...SCHEMATHESIS_SAFE_CHECKS]);
    // Stateful chaining (which replays state-changing operations) is off.
    expect(args[args.indexOf("--phases") + 1]).toBe("examples,coverage");
    expect(adapter.blockedOperations.map((b) => b.operationId)).toEqual(expect.arrayContaining(["createUser", "deleteUser", "checkout"]));
  });

  it("parses JUnit failures into conformance findings; passes produce none", () => {
    const parsed = parseSchemathesisJUnit(FIXTURE_SCHEMATHESIS_JUNIT, "schemathesis");
    expect(parsed.metrics).toMatchObject({ executedCases: 3, failures: 2 });
    expect(parsed.findings).toHaveLength(2);
    const classes = parsed.findings.map((f) => f.vulnClass);
    expect(classes).toContain("API_SERVER_ERROR");
    expect(classes).toContain("API_RESPONSE_CONFORMANCE");
    expect(parsed.findings.every((f) => f.sourceTool === "schemathesis")).toBe(true);
  });

  it("executes the full lifecycle against the fixture runner", async () => {
    const adapter = new SchemathesisAdapter(new FixtureToolRunner(buildApiFixtures()));
    const plan = await adapter.buildExecutionPlan(target, { schemaUrl: "https://api.example.com/v1/openapi.json", operations });
    const { rawOutput } = await adapter.execute(plan);
    const normalized = await adapter.normalize(await adapter.parse(rawOutput ?? ""));
    expect(normalized.findings).toHaveLength(2);
    expect(normalized.metrics.blockedOperations).toBe(3);
  });
});

describe("GraphQL adapters (§27/§28/§71)", () => {
  it("InQL parses introspection into inventory — never findings", () => {
    const parsed = parseInqlOutput(FIXTURE_GRAPHQL_INTROSPECTION, "inql", "https://api.example.com/graphql");
    expect(parsed.findings).toEqual([]);
    expect(parsed.graphqlServices[0]).toMatchObject({ queries: 3, mutations: 2, schemaAvailable: true });
    expect(parsed.warnings.some((w) => w.includes("NOT automatically tested"))).toBe(true);
  });

  it("InQL adapter plan targets the GraphQL URL from stage inputs", async () => {
    const adapter = new InqlAdapter(new FixtureToolRunner(buildApiFixtures()));
    const plan = await adapter.buildExecutionPlan(target, { urls: ["https://api.example.com/app", "https://api.example.com/graphql"] });
    expect(plan.arguments).toEqual(["-t", "https://api.example.com/graphql"]);
  });

  it("GraphQLmap output yields inventory facts only (§28/§29)", () => {
    const parsed = parseGraphqlmapOutput(buildApiFixtures().graphqlmap!.stdout, "graphqlmap", "https://api.example.com/graphql");
    expect(parsed.findings).toEqual([]);
    expect(parsed.graphqlServices).toHaveLength(1);
    expect(parsed.graphqlServices[0]?.schemaAvailable).toBe(true);
    expect(parseGraphqlmapOutput("", "graphqlmap", "https://api.example.com/graphql").graphqlServices).toEqual([]);
  });
});

describe("JwtToolAdapter (§22)", () => {
  it("inspects provided tokens without any subprocess plan carrying them", async () => {
    const adapter = new JwtToolAdapter();
    const plan = await adapter.buildExecutionPlan(target, { tokens: [FIXTURE_JWT_GOOD] });
    expect(JSON.stringify(plan)).not.toContain(FIXTURE_JWT_GOOD);
    const parsed = adapter.inspectTokens({ tokens: [FIXTURE_JWT_GOOD] });
    expect(parsed.jwtProfiles).toHaveLength(1);
    expect(parsed.findings).toEqual([]);
    expect(JSON.stringify(parsed)).not.toContain(FIXTURE_JWT_GOOD);
  });
});

describe("MitmproxyFlowParser (§33/§73)", () => {
  const parsed = new MitmproxyFlowParser().parse(JSON.parse(FIXTURE_MITMPROXY_FLOWS), "mitmproxy");

  it("turns flows into transactions + API endpoints, redacting credentials", () => {
    expect(parsed.transactions).toHaveLength(2);
    expect(parsed.endpoints.map((e) => e.url)).toContain("https://api.example.com/v1/users");
    expect(parsed.endpoints.some((e) => e.endpointType === "API")).toBe(true);
    const serialized = JSON.stringify(parsed);
    expect(serialized).not.toContain("FAKE-FIXTURE-TOKEN");
    expect(serialized).not.toContain("FAKE-FIXTURE"); // cookie value redacted too
    expect(parsed.findings).toEqual([]); // traffic intelligence, not findings
  });

  it("inventories the WebSocket handshake with auth PRESENCE only (§32/§73)", () => {
    expect(parsed.webSockets).toHaveLength(1);
    const ws = parsed.webSockets[0]!;
    expect(ws.url).toBe("wss://api.example.com/v1/stream");
    expect(ws.subprotocol).toBe("v1.stream");
    expect(ws.authPresent).toBe(false); // the fixture handshake carries no auth material
  });
});

describe("Nuclei API-safe templates (§38)", () => {
  it("adds the API exposure checks as SAFE, selectable templates", () => {
    const apiTemplates = NUCLEI_TEMPLATE_CATALOG.filter((t) => t.tags.includes("api"));
    expect(apiTemplates.map((t) => t.id)).toEqual(expect.arrayContaining(["exposed-openapi-spec", "api-debug-endpoint-exposure"]));
    expect(apiTemplates.every((t) => t.classification === "SAFE")).toBe(true);
    const { selected } = selectTemplates();
    expect(selected.map((t) => t.id)).toContain("exposed-openapi-spec");
    // Nothing in the API set performs exploitation (§38/§79).
    expect(apiTemplates.every((t) => !/inject|bypass|exploit|brute/i.test(t.name))).toBe(true);
  });
});
