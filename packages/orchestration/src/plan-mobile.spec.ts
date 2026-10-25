/**
 * Prompt 17 — mobile profile plan tests (§10–§12/§103): the six
 * mobile profiles resolve to the spec stage chain; platform stages
 * select no adapters; static stages select ONLY the governed static
 * family; dynamic stages exist only in the CONTROLLED profiles;
 * Frida/Objection are selectable by NO stage; mobile tool stages
 * never fall back to simulation.
 */
import { describe, expect, it } from "vitest";
import {
  FixtureToolRunner, LocalEchoAdapter, MockSecurityAdapter, ToolRegistry,
  createMobileAdapters, createFixtureMobileDeps, mobileHealthBySlug, MOBILE_SLUGS,
} from "@zerosweep/security-sdk";
import { PROFILE_TEMPLATES, STAGE_LIBRARY, resolveTemplate } from "./profiles";
import { buildScanPlan } from "./plan";

const FIXTURES = {
  jadx: { stdout: "{}", version: "1.5.1" },
  apktool: { stdout: "{}", version: "2.9.3" },
  analyzeHeadless: { stdout: "{}", version: "11.3" },
};

function registryWith() {
  const registry = new ToolRegistry();
  registry.register(new MockSecurityAdapter());
  registry.register(new LocalEchoAdapter());
  const deps = createFixtureMobileDeps();
  const mobile = createMobileAdapters(new FixtureToolRunner(FIXTURES), deps);
  for (const a of mobile) registry.register(a);
  const health = mobileHealthBySlug(mobile, deps);
  // Connectors/lab adapters resolve per-instance/per-session at
  // execute time; at plan time they are selectable when the store
  // will resolve the registered build/session (mirrors the P15
  // connector plan posture).
  health.mobsf = "HEALTHY";
  health.adb = "HEALTHY";
  health.mitmproxy = "HEALTHY";
  return { registry, health };
}

function plan(profile: string) {
  const { registry, health } = registryWith();
  return buildScanPlan({
    scanId: "scan-1", assessmentId: "a-1", targetId: "t-1", workspaceId: "ws-1", organizationId: "org-1",
    profile: profile as never,
    targetType: "MOBILE_APP" as never,
    targetValue: "com.example.app", targetHost: "com.example.app",
    scope: { includeHosts: ["com.example.app"], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
    targetVerified: true, assessmentApproved: true, registry,
    selection: {
      executableSlugs: ["mock", "local-echo", ...MOBILE_SLUGS],
      healthBySlug: health,
    },
  }).plan;
}

const HEAD = ["AUTHORIZATION_CHECK", "SCOPE_VALIDATION"];
const TAIL = ["NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"];
const STATIC_CORE = ["MOBILE_ARTIFACT_INTAKE", "MOBILE_METADATA_EXTRACTION", "MOBILE_MANIFEST_ANALYSIS", "MOBILE_STATIC_ANALYSIS"];

describe("Prompt 17 — mobile profiles (§12)", () => {
  it("MOBILE_STATIC_BASELINE resolves to the spec chain in order", () => {
    expect(plan("MOBILE_STATIC_BASELINE").stages.map((s) => s.type)).toEqual([...HEAD, ...STATIC_CORE, ...TAIL]);
  });

  it("the legacy MOBILE profile resolves to the baseline chain", () => {
    expect(plan("MOBILE").stages.map((s) => s.type)).toEqual(plan("MOBILE_STATIC_BASELINE").stages.map((s) => s.type));
  });

  it("comprehensive adds binary analysis + dependency inventory + SBOM", () => {
    const types = plan("MOBILE_STATIC_COMPREHENSIVE").stages.map((s) => s.type);
    expect(types).toEqual([...HEAD, ...STATIC_CORE, "MOBILE_BINARY_ANALYSIS", "DEPENDENCY_INVENTORY", "SBOM_GENERATION", ...TAIL]);
  });

  it("secrets-only and binary profiles resolve to their focused chains", () => {
    expect(plan("MOBILE_SECRETS_ONLY").stages.map((s) => s.type)).toEqual(
      [...HEAD, "MOBILE_ARTIFACT_INTAKE", "MOBILE_METADATA_EXTRACTION", "MOBILE_STATIC_ANALYSIS", ...TAIL]);
    expect(plan("MOBILE_BINARY_ANALYSIS").stages.map((s) => s.type)).toEqual(
      [...HEAD, "MOBILE_ARTIFACT_INTAKE", "MOBILE_METADATA_EXTRACTION", "MOBILE_MANIFEST_ANALYSIS", "MOBILE_BINARY_ANALYSIS", ...TAIL]);
  });

  it("dynamic stages exist ONLY in the CONTROLLED profiles", () => {
    for (const profile of ["MOBILE_STATIC_BASELINE", "MOBILE_STATIC_COMPREHENSIVE", "MOBILE_SECRETS_ONLY", "MOBILE_BINARY_ANALYSIS"]) {
      const types = plan(profile).stages.map((s) => s.type);
      expect(types, profile).not.toContain("MOBILE_DYNAMIC_SESSION");
      expect(types, profile).not.toContain("MOBILE_TRAFFIC_ANALYSIS");
    }
    expect(plan("MOBILE_DYNAMIC_CONTROLLED").stages.map((s) => s.type)).toEqual(
      [...HEAD, ...STATIC_CORE, "MOBILE_DYNAMIC_SESSION", "MOBILE_TRAFFIC_ANALYSIS", ...TAIL]);
    expect(plan("MOBILE_FULL_CONTROLLED").stages.map((s) => s.type)).toEqual(
      [...HEAD, ...STATIC_CORE, "MOBILE_BINARY_ANALYSIS", "MOBILE_DYNAMIC_SESSION", "MOBILE_TRAFFIC_ANALYSIS", ...TAIL]);
  });

  it("platform stages select no adapters; tool stages select only their governed family", () => {
    const p = plan("MOBILE_FULL_CONTROLLED");
    for (const type of ["MOBILE_ARTIFACT_INTAKE", "MOBILE_METADATA_EXTRACTION", "MOBILE_MANIFEST_ANALYSIS"]) {
      expect(p.stages.find((s) => s.type === type)?.selectedAdapters, type).toEqual([]);
    }
    const staticSlugs = p.stages.find((s) => s.type === "MOBILE_STATIC_ANALYSIS")!.selectedAdapters.map((a) => a.slug);
    expect(staticSlugs).toEqual(expect.arrayContaining(["mobsf", "jadx", "apktool"]));
    expect(staticSlugs.every((s) => ["mobsf", "jadx", "apktool"].includes(s))).toBe(true);
    expect(p.stages.find((s) => s.type === "MOBILE_BINARY_ANALYSIS")!.selectedAdapters.map((a) => a.slug)).toEqual(["ghidra"]);
    expect(p.stages.find((s) => s.type === "MOBILE_DYNAMIC_SESSION")!.selectedAdapters.map((a) => a.slug)).toEqual(["adb"]);
    expect(p.stages.find((s) => s.type === "MOBILE_TRAFFIC_ANALYSIS")!.selectedAdapters.map((a) => a.slug)).toEqual(["mitmproxy"]);
  });

  it("NO stage in ANY profile can select Frida/Objection or a simulation fallback (§69–§74)", () => {
    for (const profile of Object.keys(PROFILE_TEMPLATES)) {
      const p = plan(profile);
      for (const stage of p.stages) {
        for (const adapter of stage.selectedAdapters) {
          expect(["frida", "objection"], `${profile}/${stage.type}`).not.toContain(adapter.slug);
          expect(adapter.simulation, `${profile}/${stage.type}/${adapter.slug}`).toBe(false);
        }
      }
    }
    for (const type of ["MOBILE_STATIC_ANALYSIS", "MOBILE_BINARY_ANALYSIS", "MOBILE_DYNAMIC_SESSION", "MOBILE_TRAFFIC_ANALYSIS"] as const) {
      expect(STAGE_LIBRARY[type].simulationFallback).toBe(false);
      expect(resolveTemplate("MOBILE_FULL_CONTROLLED").find((d) => d.type === type)).toBeDefined();
    }
  });

  it("every mobile stage type exists in the stage library with sane weights", () => {
    for (const type of ["MOBILE_ARTIFACT_INTAKE", "MOBILE_METADATA_EXTRACTION", "MOBILE_MANIFEST_ANALYSIS", "MOBILE_STATIC_ANALYSIS", "MOBILE_BINARY_ANALYSIS", "MOBILE_DYNAMIC_SESSION", "MOBILE_TRAFFIC_ANALYSIS"] as const) {
      expect(STAGE_LIBRARY[type].weight).toBeGreaterThan(0);
      expect(STAGE_LIBRARY[type].timeoutSeconds).toBeGreaterThan(0);
    }
  });
});
