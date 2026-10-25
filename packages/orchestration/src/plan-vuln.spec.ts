import { describe, expect, it } from "vitest";
import { FixtureToolRunner, LocalEchoAdapter, MockSecurityAdapter, ToolRegistry, createReconAdapters, createVulnAdapters, createWebDiscoveryAdapters } from "@zerosweep/security-sdk";
import { buildScanPlan } from "./plan";
import type { ScopeRules } from "@zerosweep/validation";

const SCOPE: ScopeRules = { includeHosts: ["example.com", "*.example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [80, 443], allowedPaths: [], excludedPaths: [] };

function registryWithAll(): ToolRegistry {
  const r = new ToolRegistry();
  r.register(new MockSecurityAdapter());
  r.register(new LocalEchoAdapter());
  const runner = new FixtureToolRunner();
  for (const a of [...createReconAdapters(runner), ...createWebDiscoveryAdapters(runner), ...createVulnAdapters(runner)]) r.register(a);
  return r;
}

function plan(profile: "WEB_BASELINE" | "WEB_COMPREHENSIVE") {
  return buildScanPlan({
    scanId: "s", assessmentId: "a", targetId: "t", workspaceId: "ws", organizationId: "org",
    profile, targetType: "WEB_APPLICATION", targetValue: "https://example.com", targetHost: "example.com",
    scope: SCOPE, targetVerified: true, assessmentApproved: true, registry: registryWithAll(),
    selection: { executableSlugs: ["mock", "local-echo", "nuclei", "nikto", "testssl", "sslyze", "subfinder", "dnsx", "httpx", "whatweb", "katana", "ffuf", "arjun"] },
  }).plan;
}

/**
 * Prompt 7 §14/§50: SAFE_VULNERABILITY_SCAN unions vulnerability scanners
 * and TLS assessors; WEB_BASELINE stays conservative (no Nikto),
 * WEB_COMPREHENSIVE runs all four adapters. Nothing intrusive is ever
 * selected — catalog-only tools like sqlmap are not even registered here.
 */
describe("Prompt 7 vuln stage planning", () => {
  it("WEB_BASELINE selects nuclei + testssl + sslyze, NOT nikto", () => {
    const p = plan("WEB_BASELINE");
    const stage = p.stages.find((s) => s.type === "SAFE_VULNERABILITY_SCAN")!;
    expect(stage.selectedAdapters.map((a) => a.slug).sort()).toEqual(["nuclei", "sslyze", "testssl"]);
    expect(stage.adapterAllowlist).toEqual(["nuclei", "testssl", "sslyze"]);
    expect(stage.capabilityGroups).toEqual([["VULNERABILITY_SCANNING"], ["TLS_ANALYSIS"]]);
    // Ordering: the vuln stage runs after endpoint discovery in baseline.
    expect(stage.dependencies).toEqual(["ENDPOINT_DISCOVERY"]);
  });

  it("WEB_COMPREHENSIVE selects all four adapters after web-surface normalization", () => {
    const p = plan("WEB_COMPREHENSIVE");
    const stage = p.stages.find((s) => s.type === "SAFE_VULNERABILITY_SCAN")!;
    expect(stage.selectedAdapters.map((a) => a.slug).sort()).toEqual(["nikto", "nuclei", "sslyze", "testssl"]);
    expect(stage.dependencies).toEqual(["WEB_SURFACE_NORMALIZATION"]);
    // Tail still exercised in order (§14).
    const types = p.stages.map((s) => s.type);
    expect(types.indexOf("NORMALIZATION")).toBeGreaterThan(types.indexOf("SAFE_VULNERABILITY_SCAN"));
    expect(types.indexOf("CORRELATION")).toBeGreaterThan(types.indexOf("NORMALIZATION"));
    expect(types.indexOf("RISK_ANALYSIS")).toBeGreaterThan(types.indexOf("CORRELATION"));
  });
});
