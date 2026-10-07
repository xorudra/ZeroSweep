import { describe, expect, it } from "vitest";
import {
  FixtureToolRunner, MockSecurityAdapter, ToolRegistry,
  registerReconAdapters, registerWebDiscoveryAdapters,
} from "@dsrclone/security-sdk";
import { buildScanPlan } from "./plan";
import { resolveTemplate } from "./profiles";

/**
 * Prompt 6 profile/stage wiring (§48–§49, §53): WEB_BASELINE gains a SMALL,
 * single-adapter content-discovery stage; WEB_COMPREHENSIVE and
 * API_ASSESSMENT gain content + parameter discovery and the platform
 * web-surface normalization stage. COMPREHENSIVE wordlists are never
 * auto-selected — templates carry stage bounds only.
 */
const scope = { includeHosts: ["example.com", "*.example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [80, 443], allowedPaths: [], excludedPaths: [] };

function registry(): ToolRegistry {
  const r = new ToolRegistry();
  r.register(new MockSecurityAdapter());
  registerReconAdapters(r, new FixtureToolRunner());
  registerWebDiscoveryAdapters(r, new FixtureToolRunner());
  return r;
}

const baseInput = {
  scanId: "scan-1", assessmentId: "a-1", targetId: "t-1", workspaceId: "w-1", organizationId: "org-1",
  targetType: "WEB_APPLICATION" as const, targetValue: "https://example.com", targetHost: "example.com",
  scope, targetVerified: true, assessmentApproved: true,
  selection: { executableSlugs: ["mock", "subfinder", "amass", "assetfinder", "findomain", "dnsx", "httpx", "whatweb", "gau", "waybackurls", "katana", "ffuf", "feroxbuster", "gobuster", "wfuzz", "arjun"] },
};

describe("Prompt 6 stages in profile templates (§48/§49)", () => {
  it("WEB_BASELINE: CONTENT_DISCOVERY sits between CRAWLING and ENDPOINT_DISCOVERY, capped at ONE adapter", () => {
    const { plan } = buildScanPlan({ ...baseInput, profile: "WEB_BASELINE", registry: registry() });
    const types = plan.stages.map((s) => s.type);
    expect(types.indexOf("CONTENT_DISCOVERY")).toBe(types.indexOf("CRAWLING") + 1);
    expect(types.indexOf("ENDPOINT_DISCOVERY")).toBe(types.indexOf("CONTENT_DISCOVERY") + 1);
    expect(types).not.toContain("PARAMETER_DISCOVERY"); // baseline: limited parameter fuzzing only (§48)
    expect(types).not.toContain("WEB_SURFACE_NORMALIZATION");
    const content = plan.stages.find((s) => s.type === "CONTENT_DISCOVERY")!;
    expect(content.dependencies).toEqual(["CRAWLING"]);
    expect(content.selectedAdapters).toHaveLength(1); // §48: small content discovery
    expect(content.selectedAdapters[0]!.simulation).toBe(false);
    expect(content.networkCapable).toBe(true);
    expect(content.failureStrategy).toBe("CONTINUE_WITH_PARTIAL_DATA");
  });

  it("WEB_COMPREHENSIVE: standard content + parameter discovery + normalization (§49)", () => {
    const { plan } = buildScanPlan({ ...baseInput, profile: "WEB_COMPREHENSIVE", registry: registry() });
    const types = plan.stages.map((s) => s.type);
    for (const t of ["CONTENT_DISCOVERY", "PARAMETER_DISCOVERY", "WEB_SURFACE_NORMALIZATION"]) expect(types).toContain(t);
    const content = plan.stages.find((s) => s.type === "CONTENT_DISCOVERY")!;
    expect(content.selectedAdapters.map((a) => a.slug).sort()).toEqual(["feroxbuster", "ffuf", "gobuster", "wfuzz"]); // all executable content adapters
    const params = plan.stages.find((s) => s.type === "PARAMETER_DISCOVERY")!;
    expect(params.selectedAdapters.map((a) => a.slug).sort()).toEqual(["arjun", "wfuzz"]);
    const norm = plan.stages.find((s) => s.type === "WEB_SURFACE_NORMALIZATION")!;
    expect(norm.selectedAdapters).toEqual([]); // platform stage — no tool
    expect(norm.dependencies).toEqual(["PARAMETER_DISCOVERY"]);
  });

  it("API_ASSESSMENT follows the Prompt 9 API pipeline, not the web chain", () => {
    // Prompt 9 §39 supersedes the Prompt 6 placeholder: API_ASSESSMENT is
    // the dedicated API pipeline now (full assertions in plan-api.spec.ts).
    const types = resolveTemplate("API_ASSESSMENT").map((d) => d.type);
    expect(types).toContain("API_DISCOVERY");
    expect(types).toContain("SAFE_SCHEMA_TESTING");
    expect(types).not.toContain("CONTENT_DISCOVERY");
    expect(types).not.toContain("WEB_SURFACE_NORMALIZATION");
  });

  it("PASSIVE_RECON stays passive — no active content discovery", () => {
    const types = resolveTemplate("PASSIVE_RECON").map((d) => d.type);
    expect(types).not.toContain("CONTENT_DISCOVERY");
    expect(types).not.toContain("PARAMETER_DISCOVERY");
  });

  it("stage library definitions are complete for the new stages (§53)", () => {
    const defs = resolveTemplate("WEB_COMPREHENSIVE");
    const content = defs.find((d) => d.type === "CONTENT_DISCOVERY")!;
    expect(content.requiredCapabilities).toEqual(["CONTENT_DISCOVERY"]);
    const norm = defs.find((d) => d.type === "NORMALIZATION")!;
    // Prompt 8: PASSIVE_SECURITY_ANALYSIS now sits between the vuln scan
    // and NORMALIZATION in web profiles, and the dependency-rewriting rule
    // (NORMALIZATION follows the last stage before it) points here.
    expect(norm.dependencies).toEqual(["PASSIVE_SECURITY_ANALYSIS"]);
  });
});
