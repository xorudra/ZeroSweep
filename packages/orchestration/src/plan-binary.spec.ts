/**
 * Prompt 18 §11 — binary profile → plan tests. Stage order, dependencies
 * and tool-stage allowlists are asserted so a profile edit can never
 * silently drop the intake gate, let a static adapter into the debug
 * stage, or route a binary profile through an executing stage that was
 * not designed for hostile artifacts.
 */
import { describe, expect, it } from "vitest";
import {
  FixtureToolRunner, LocalEchoAdapter, MockSecurityAdapter, ToolRegistry,
  createBinaryAdapters, BINARY_SLUGS,
} from "@dsrclone/security-sdk";
import { PROFILE_TEMPLATES } from "./profiles";
import { buildScanPlan } from "./plan";

function plan(profile: string) {
  const registry = new ToolRegistry();
  registry.register(new MockSecurityAdapter());
  registry.register(new LocalEchoAdapter());
  const binary = createBinaryAdapters(new FixtureToolRunner({
    checksec: { stdout: "{}", version: "2.6.0" },
    r2: { stdout: "[]", version: "5.9.0" },
    analyzeHeadless: { stdout: "{}", version: "11.3" },
  }));
  for (const a of binary) registry.register(a);
  const health: Record<string, string> = Object.fromEntries(binary.map((a) => [a.metadata.slug, "HEALTHY"]));
  return buildScanPlan({
    scanId: "scan-1", assessmentId: "a-1", targetId: "t-1", workspaceId: "ws-1", organizationId: "org-1",
    profile: profile as never,
    targetType: "BINARY" as never,
    targetValue: "artifact", targetHost: "artifact",
    scope: { includeHosts: ["artifact"], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
    targetVerified: true, assessmentApproved: true, registry,
    selection: { executableSlugs: ["mock", "local-echo", ...BINARY_SLUGS], healthBySlug: health },
  }).plan;
}

const HEAD = ["AUTHORIZATION_CHECK", "SCOPE_VALIDATION"];
const TAIL = ["NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"];

describe("Prompt 18 binary profile chains", () => {
  it("BINARY_METADATA_ONLY stops at platform extraction", () => {
    expect(plan("BINARY_METADATA_ONLY").stages.map((s) => s.type)).toEqual([
      ...HEAD, "BINARY_ARTIFACT_INTAKE", "BINARY_METADATA_EXTRACTION", ...TAIL,
    ]);
  });

  it("BINARY_BASELINE (and its BINARY_ASSESSMENT alias) add hardening + static tool stages", () => {
    const baseline = plan("BINARY_BASELINE").stages.map((s) => s.type);
    expect(baseline).toEqual([...HEAD, "BINARY_ARTIFACT_INTAKE", "BINARY_METADATA_EXTRACTION", "BINARY_HARDENING_ANALYSIS", "BINARY_STATIC_ANALYSIS", ...TAIL]);
    expect(plan("BINARY_ASSESSMENT").stages.map((s) => s.type)).toEqual(baseline);
  });

  it("BINARY_COMPREHENSIVE_STATIC adds dependency inventory + SBOM", () => {
    const t = plan("BINARY_COMPREHENSIVE_STATIC").stages.map((s) => s.type);
    expect(t.indexOf("DEPENDENCY_INVENTORY")).toBeGreaterThan(t.indexOf("BINARY_STATIC_ANALYSIS"));
    expect(t).toContain("SBOM_GENERATION");
  });

  it("BINARY_CONTROLLED_DEBUG appends ONLY the governed debug stage — never an adapter stage", () => {
    const p = plan("BINARY_CONTROLLED_DEBUG");
    expect(p.stages.map((s) => s.type)).toContain("BINARY_DEBUG_SESSION");
    const debug = p.stages.find((s) => s.type === "BINARY_DEBUG_SESSION")!;
    expect(debug.adapterAllowlist).toEqual([]);
    expect(debug.requiredCapabilities).toEqual(["DYNAMIC_DEBUGGING"]);
    expect(debug.selectedAdapters).toEqual([]);
  });

  it("tool stages carry the right allowlists + worker capabilities", () => {
    const p = plan("BINARY_BASELINE");
    expect(p.stages.find((s) => s.type === "BINARY_HARDENING_ANALYSIS")!.adapterAllowlist).toEqual(["checksec"]);
    const statik = p.stages.find((s) => s.type === "BINARY_STATIC_ANALYSIS")!;
    expect(statik.adapterAllowlist).toEqual(["ghidra", "radare2"]);
    expect(statik.capabilityGroups).toEqual([["BINARY_STATIC_ANALYSIS"], ["STATIC_BINARY_ANALYSIS"]]);
    const selected = p.stages.flatMap((s) => s.selectedAdapters ?? []);
    expect(selected.map((t) => t.slug)).toEqual(expect.arrayContaining(["checksec", "ghidra"]));
  });

  it("stage dependencies are consistent within every binary profile", () => {
    for (const profile of ["BINARY_METADATA_ONLY", "BINARY_BASELINE", "BINARY_ASSESSMENT", "BINARY_COMPREHENSIVE_STATIC", "BINARY_DEPENDENCY_ANALYSIS", "BINARY_CONTROLLED_DEBUG"]) {
      const p = plan(profile);
      const present = new Set(p.stages.map((s) => s.type));
      for (const stage of p.stages) {
        for (const dep of stage.dependencies) expect(present.has(dep)).toBe(true);
      }
      expect(PROFILE_TEMPLATES[profile as keyof typeof PROFILE_TEMPLATES].length).toBe(p.stages.length);
    }
  });
});
