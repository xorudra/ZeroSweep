import { describe, expect, it } from "vitest";
import {
  MockSecurityAdapter, ToolRegistry,
  createProxyAdapters, proxyHealthBySlug,
  InMemoryScannerInstanceProvider, MapEndpointResolver, MapSecretResolver,
  FIXTURE_INSTANCES, FIXTURE_ENDPOINTS, FIXTURE_SECRETS,
  createFixtureTransport,
} from "@dsrclone/security-sdk";
import { buildScanPlan } from "./plan";
import { PROFILE_TEMPLATES, STAGE_LIBRARY } from "./profiles";
import { selectAdaptersForStage } from "./tool-selector";

const scope = { includeHosts: ["example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [443], allowedPaths: [], excludedPaths: [] };

function registry(withConnectors: boolean): ToolRegistry {
  const r = new ToolRegistry();
  r.register(new MockSecurityAdapter());
  if (withConnectors) {
    const adapters = createProxyAdapters({
      instances: new InMemoryScannerInstanceProvider(FIXTURE_INSTANCES),
      endpoints: new MapEndpointResolver(FIXTURE_ENDPOINTS),
      secrets: new MapSecretResolver(FIXTURE_SECRETS),
      transport: createFixtureTransport(),
    });
    for (const a of adapters) r.register(a);
  }
  return r;
}

const EXECUTABLE = ["mock", "owasp-zap", "burp-suite-professional", "caido"];

function input(overrides: Record<string, unknown> = {}) {
  return {
    scanId: "scan-1", assessmentId: "a-1", targetId: "t-1", workspaceId: "w-1", organizationId: "org-1",
    targetType: "WEB_APPLICATION" as const, targetValue: "https://example.com", targetHost: "example.com",
    scope, targetVerified: true, assessmentApproved: true,
    selection: { executableSlugs: EXECUTABLE, healthBySlug: proxyHealthBySlug(FIXTURE_INSTANCES) },
    ...overrides,
  };
}

describe("Prompt 8 stage model (§37/§38/§39)", () => {
  it("web profiles include PASSIVE_SECURITY_ANALYSIS after the safe vuln scan; PASSIVE_RECON never does", () => {
    for (const profile of ["WEB_BASELINE", "WEB_COMPREHENSIVE", "API_ASSESSMENT"] as const) {
      const types = PROFILE_TEMPLATES[profile].map((s) => s.type);
      expect(types).toContain("PASSIVE_SECURITY_ANALYSIS");
      expect(types.indexOf("PASSIVE_SECURITY_ANALYSIS")).toBe(types.indexOf("SAFE_VULNERABILITY_SCAN") + 1);
    }
    expect(PROFILE_TEMPLATES.PASSIVE_RECON.map((s) => s.type)).not.toContain("PASSIVE_SECURITY_ANALYSIS");
  });

  it("ACTIVE_SECURITY_ANALYSIS exists in the library but in NO profile template (§38)", () => {
    expect(STAGE_LIBRARY.ACTIVE_SECURITY_ANALYSIS.requiredCapabilities).toEqual(["ACTIVE_WEB_SCANNING"]);
    expect(STAGE_LIBRARY.ACTIVE_SECURITY_ANALYSIS.simulationFallback).toBe(false);
    for (const stages of Object.values(PROFILE_TEMPLATES)) {
      expect(stages.map((s) => s.type)).not.toContain("ACTIVE_SECURITY_ANALYSIS");
    }
  });

  it("with configured healthy connectors, the passive stage selects all three — simulation never substitutes (§37)", () => {
    const { plan } = buildScanPlan(input({ profile: "WEB_COMPREHENSIVE", registry: registry(true) }) as never);
    const stage = plan.stages.find((s) => s.type === "PASSIVE_SECURITY_ANALYSIS");
    expect(stage).toBeDefined();
    expect(stage!.selectedAdapters.map((a) => a.slug).sort()).toEqual(["burp-suite-professional", "caido", "owasp-zap"]);
    expect(stage!.selectedAdapters.every((a) => !a.simulation)).toBe(true);
    expect(stage!.dependencies).toEqual(["SAFE_VULNERABILITY_SCAN"]);
    const norm = plan.stages.find((s) => s.type === "NORMALIZATION");
    expect(norm!.dependencies).toEqual(["PASSIVE_SECURITY_ANALYSIS"]);
  });

  it("with NO connectors configured, the stage has an EMPTY selection — no mock simulation of a scanner (§66)", () => {
    const { plan } = buildScanPlan(input({
      profile: "WEB_BASELINE",
      registry: registry(false),
      selection: { executableSlugs: EXECUTABLE, healthBySlug: proxyHealthBySlug([]) },
    }) as never);
    const stage = plan.stages.find((s) => s.type === "PASSIVE_SECURITY_ANALYSIS");
    expect(stage).toBeDefined();
    expect(stage!.selectedAdapters).toEqual([]);
  });

  it("NOT_CONFIGURED health rejects selection even when the adapters are registered (§66)", () => {
    const { plan } = buildScanPlan(input({
      profile: "WEB_COMPREHENSIVE",
      registry: registry(true),
      selection: { executableSlugs: EXECUTABLE, healthBySlug: proxyHealthBySlug([]) },
    }) as never);
    const stage = plan.stages.find((s) => s.type === "PASSIVE_SECURITY_ANALYSIS");
    expect(stage!.selectedAdapters).toEqual([]);
    const selection = selectAdaptersForStage(registry(true), STAGE_LIBRARY.PASSIVE_SECURITY_ANALYSIS, {
      executableSlugs: EXECUTABLE, healthBySlug: proxyHealthBySlug([]), targetType: "WEB_APPLICATION",
    });
    expect(selection.selected).toEqual([]);
    expect(selection.rejected.map((r) => r.slug).sort()).toEqual(["burp-suite-professional", "caido", "owasp-zap"]);
    expect(selection.rejected.every((r) => r.reason.includes("NOT_CONFIGURED"))).toBe(true);
  });
});
