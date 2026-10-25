import { describe, expect, it } from "vitest";
import {
  FixtureToolRunner, MockSecurityAdapter, ToolRegistry,
  apiHealthBySlug, buildApiFixtures, createApiAdapterSet, proxyHealthBySlug,
  registerApiAdapters, registerProxyAdapters, registerReconAdapters,
  registerVulnAdapters, registerWebDiscoveryAdapters,
} from "@zerosweep/security-sdk";
import { buildScanPlan } from "./plan";
import { PROFILE_TEMPLATES, STAGE_LIBRARY, resolveTemplate } from "./profiles";

/**
 * Prompt 9 stage model (§39/§43): API_ASSESSMENT is the dedicated API
 * pipeline — validation → API discovery → spec import → route
 * discovery → auth mapping → safe schema testing → JWT analysis →
 * GraphQL analysis → WebSocket inventory → API-safe vulnerability scan
 * → passive analysis → API normalization → shared tail. State-changing
 * capability has NO stage here: schemathesis is admitted only under
 * the operation policy, JWT is a platform inspection hook, and the
 * ACTIVE stage stays absent (§40/§79).
 */
const scope = { includeHosts: ["example.com", "api.example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [443], allowedPaths: [], excludedPaths: [] };

const EXECUTABLE = [
  "mock", "subfinder", "amass", "assetfinder", "findomain", "dnsx", "httpx", "whatweb", "gau", "waybackurls", "katana",
  "ffuf", "feroxbuster", "gobuster", "wfuzz", "arjun",
  "nuclei", "nikto", "testssl", "sslyze",
  "owasp-zap", "burp-suite-professional", "caido", "mitmproxy",
  "kiterunner", "schemathesis", "inql", "graphqlmap",
];

function registry(): ToolRegistry {
  const r = new ToolRegistry();
  r.register(new MockSecurityAdapter());
  const runner = new FixtureToolRunner(buildApiFixtures());
  registerReconAdapters(r, runner);
  registerWebDiscoveryAdapters(r, runner);
  registerVulnAdapters(r, runner);
  registerProxyAdapters(r);
  registerApiAdapters(r, runner);
  return r;
}

function apiPlan() {
  return buildScanPlan({
    scanId: "scan-1", assessmentId: "a-1", targetId: "t-1", workspaceId: "w-1", organizationId: "org-1",
    profile: "API_ASSESSMENT",
    targetType: "API", targetValue: "https://api.example.com", targetHost: "api.example.com",
    scope, targetVerified: true, assessmentApproved: true,
    registry: registry(),
    selection: {
      executableSlugs: EXECUTABLE,
      healthBySlug: { ...apiHealthBySlug(createApiAdapterSet(new FixtureToolRunner(buildApiFixtures()))), ...proxyHealthBySlug([]) },
    },
  });
}

describe("Prompt 9 API_ASSESSMENT template (§39)", () => {
  it("has the exact API pipeline stage order", () => {
    const types = PROFILE_TEMPLATES.API_ASSESSMENT.map((s) => s.type);
    expect(types).toEqual([
      "AUTHORIZATION_CHECK", "SCOPE_VALIDATION",
      "API_DISCOVERY", "SPEC_IMPORT", "ROUTE_DISCOVERY", "AUTH_MAPPING",
      "SAFE_SCHEMA_TESTING", "JWT_ANALYSIS", "GRAPHQL_ANALYSIS", "WEBSOCKET_INVENTORY",
      "SAFE_VULNERABILITY_SCAN", "PASSIVE_SECURITY_ANALYSIS", "API_FINDING_NORMALIZATION",
      "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "REPORT_GENERATION",
    ]);
    expect(types).not.toContain("ACTIVE_SECURITY_ANALYSIS");
  });

  it("builds a valid plan: tool stages select only their governed adapters", () => {
    const { plan } = apiPlan();
    const byType = (t: string) => plan.stages.find((s) => s.type === t)!;
    expect(byType("ROUTE_DISCOVERY").selectedAdapters.map((a) => a.slug)).toEqual(["kiterunner"]);
    expect(byType("SAFE_SCHEMA_TESTING").selectedAdapters.map((a) => a.slug)).toEqual(["schemathesis"]);
    expect(byType("GRAPHQL_ANALYSIS").selectedAdapters.map((a) => a.slug).sort()).toEqual(["graphqlmap", "inql"]);
    // §38: Nuclei only in the API profile's vulnerability stage.
    expect(byType("SAFE_VULNERABILITY_SCAN").selectedAdapters.map((a) => a.slug)).toEqual(["nuclei"]);
    expect(byType("SAFE_VULNERABILITY_SCAN").adapterAllowlist).toEqual(["nuclei"]);
  });

  it("platform stages select no adapters — jwt-tool is never stage-selected (§22)", () => {
    const { plan } = apiPlan();
    for (const t of ["API_DISCOVERY", "SPEC_IMPORT", "AUTH_MAPPING", "JWT_ANALYSIS", "WEBSOCKET_INVENTORY", "API_FINDING_NORMALIZATION"]) {
      expect(plan.stages.find((s) => s.type === t)!.selectedAdapters).toEqual([]);
    }
    const allSelected = plan.stages.flatMap((s) => s.selectedAdapters.map((a) => a.slug));
    expect(allSelected).not.toContain("jwt-tool");
    // No adapter anywhere in the plan can execute state-changing or
    // destructive API operations: the only network testing adapters are
    // the governed four + nuclei, all policy-bound.
    expect(new Set(allSelected)).toEqual(new Set(["kiterunner", "schemathesis", "inql", "graphqlmap", "nuclei"]));
  });

  it("dependency chain: NORMALIZATION follows API_FINDING_NORMALIZATION", () => {
    const { plan } = apiPlan();
    expect(plan.stages.find((s) => s.type === "NORMALIZATION")!.dependencies).toEqual(["API_FINDING_NORMALIZATION"]);
    expect(plan.stages.find((s) => s.type === "API_FINDING_NORMALIZATION")!.dependencies).toEqual(["PASSIVE_SECURITY_ANALYSIS"]);
    expect(plan.stages.find((s) => s.type === "SAFE_SCHEMA_TESTING")!.dependencies).toEqual(["AUTH_MAPPING"]);
    const types = plan.stages.map((s) => s.type);
    expect(types.indexOf("PASSIVE_SECURITY_ANALYSIS")).toBe(types.indexOf("SAFE_VULNERABILITY_SCAN") + 1);
  });

  it("stage library: safe-schema stage is network-capable + partial-tolerant; JWT stage is not network-capable", () => {
    expect(STAGE_LIBRARY.SAFE_SCHEMA_TESTING.networkCapable).toBe(true);
    expect(STAGE_LIBRARY.SAFE_SCHEMA_TESTING.failureStrategy).toBe("CONTINUE_WITH_PARTIAL_DATA");
    expect(STAGE_LIBRARY.JWT_ANALYSIS.networkCapable).toBe(false);
    expect(STAGE_LIBRARY.ROUTE_DISCOVERY.requiredCapabilities).toEqual(["ROUTE_DISCOVERY"]);
    // resolveTemplate keeps the API allowlist on the resolved defs.
    const resolved = resolveTemplate("API_ASSESSMENT");
    expect(resolved.find((d) => d.type === "SAFE_VULNERABILITY_SCAN")!.adapterAllowlist).toEqual(["nuclei"]);
  });
});
