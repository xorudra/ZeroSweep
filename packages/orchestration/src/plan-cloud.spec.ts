/**
 * Prompt 14 — cloud profile plan tests (§12/§86/§88): the seven cloud
 * profiles resolve to the spec stage chain; the legacy CLOUD profile
 * resolves to CLOUD_BASELINE; Pacu is selectable by NO stage (§34);
 * cloud tool stages never fall back to simulation.
 */
import { describe, expect, it } from "vitest";
import {
  FixtureToolRunner, LocalEchoAdapter, MockSecurityAdapter, ToolRegistry,
  PACU_DESCRIPTOR, cloudSecHealthBySlug, createCloudSecAdapters,
} from "@dsrclone/security-sdk";
import { PROFILE_TEMPLATES, STAGE_LIBRARY, resolveTemplate } from "./profiles";
import { buildScanPlan } from "./plan";

function registryWith() {
  const registry = new ToolRegistry();
  registry.register(new MockSecurityAdapter());
  registry.register(new LocalEchoAdapter());
  const runner = new FixtureToolRunner({
    prowler: { stdout: "[]", version: "5.0.0" },
    scout: { stdout: "{}", version: "5.14.0" },
    steampipe: { stdout: "[]", version: "1.0.0" },
  });
  const cloud = createCloudSecAdapters(runner);
  for (const a of cloud) registry.register(a);
  const health = cloudSecHealthBySlug(cloud);
  // Per-account connectors report HEALTHY at plan time when the store
  // resolves a registered account for the scan (mirrors the K8s
  // connector plan posture, Prompt 13).
  health["aws-inventory"] = "HEALTHY";
  health["azure-inventory"] = "HEALTHY";
  health["gcp-inventory"] = "HEALTHY";
  return { registry, health };
}

function plan(profile: string) {
  const { registry, health } = registryWith();
  return buildScanPlan({
    scanId: "scan-1", assessmentId: "a-1", targetId: "t-1", workspaceId: "ws-1", organizationId: "org-1",
    profile: profile as never,
    targetType: "AWS" as never,
    targetValue: "123456789012", targetHost: "123456789012",
    scope: { includeHosts: ["123456789012"], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
    targetVerified: true, assessmentApproved: true, registry,
    selection: {
      executableSlugs: ["mock", "local-echo", "aws-inventory", "azure-inventory", "gcp-inventory", "prowler", "scoutsuite", "steampipe", "cloudmapper", "roadtools"],
      healthBySlug: health,
    },
  }).plan;
}

describe("Prompt 14 cloud profiles (§12)", () => {
  it("CLOUD_BASELINE resolves to the §86 stage chain", () => {
    const types = resolveTemplate("CLOUD_BASELINE").map((s) => s.type);
    expect(types).toEqual([
      "AUTHORIZATION_CHECK", "SCOPE_VALIDATION", "CLOUD_AUTH", "CLOUD_INVENTORY",
      "IAM_ANALYSIS", "NETWORK_ANALYSIS", "STORAGE_ANALYSIS", "ENCRYPTION_ANALYSIS",
      "LOGGING_ANALYSIS", "CLOUD_CSPM", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS",
      "CLOUD_COMPLIANCE", "QUALITY_GATE", "REPORT_GENERATION",
    ]);
  });

  it("legacy CLOUD resolves to the CLOUD_BASELINE chain", () => {
    expect(resolveTemplate("CLOUD").map((s) => s.type)).toEqual(resolveTemplate("CLOUD_BASELINE").map((s) => s.type));
  });

  it("CLOUD_INVENTORY is the minimal chain; COMPLIANCE_ASSESSMENT covers every analysis section", () => {
    expect(resolveTemplate("CLOUD_INVENTORY").map((s) => s.type)).toContain("CLOUD_AUTH");
    expect(resolveTemplate("CLOUD_INVENTORY").map((s) => s.type)).not.toContain("CLOUD_CSPM");
    const comp = resolveTemplate("COMPLIANCE_ASSESSMENT").map((s) => s.type);
    for (const s of ["IAM_ANALYSIS", "NETWORK_ANALYSIS", "STORAGE_ANALYSIS", "ENCRYPTION_ANALYSIS", "LOGGING_ANALYSIS", "CLOUD_CSPM", "CLOUD_COMPLIANCE"]) {
      expect(comp).toContain(s);
    }
    expect(resolveTemplate("CLOUD_COMPREHENSIVE").map((s) => s.type)).toContain("MANIFEST_SCAN");
    expect(resolveTemplate("IAC_TO_CLOUD_CORRELATION").map((s) => s.type)).toContain("MANIFEST_SCAN");
  });

  it("builds a valid CLOUD_BASELINE plan for a cloud-account (AWS) target", () => {
    const p = plan("CLOUD_BASELINE");
    const types = p.stages.map((s) => s.type);
    expect(types).toContain("CLOUD_INVENTORY");
    expect(types).toContain("CLOUD_CSPM");
    const inventory = p.stages.find((s) => s.type === "CLOUD_INVENTORY")!;
    // All three provider connectors are capability candidates; the
    // executor narrows to the account's provider. ROADtools (import
    // connector) honestly reports NOT_CONFIGURED at plan time and so
    // is not selected until an Entra export source is configured.
    expect(inventory.selectedAdapters.map((a) => a.slug)).toEqual(
      expect.arrayContaining(["aws-inventory", "azure-inventory", "gcp-inventory"]),
    );
    expect(inventory.selectedAdapters.map((a) => a.slug)).not.toContain("roadtools");
    const cspm = p.stages.find((s) => s.type === "CLOUD_CSPM")!;
    expect(cspm.selectedAdapters.map((a) => a.slug)).toEqual(expect.arrayContaining(["prowler", "scoutsuite"]));
    expect(cspm.selectedAdapters.map((a) => a.slug)).not.toContain("pacu");
  });

  it("Pacu is selectable by NO stage and NO profile (§34)", () => {
    for (const def of Object.values(STAGE_LIBRARY)) {
      expect(JSON.stringify(def)).not.toContain("pacu");
    }
    for (const stages of Object.values(PROFILE_TEMPLATES)) {
      expect(JSON.stringify(stages)).not.toContain("pacu");
    }
    expect(PACU_DESCRIPTOR.status).toBe("DISABLED");
    expect(createCloudSecAdapters().map((a) => a.metadata.slug)).not.toContain("pacu");
  });

  it("cloud tool stages never fall back to simulation", () => {
    expect(STAGE_LIBRARY.CLOUD_INVENTORY.simulationFallback).toBe(false);
    expect(STAGE_LIBRARY.CLOUD_CSPM.simulationFallback).toBe(false);
  });
});
