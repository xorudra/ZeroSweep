import { describe, expect, it } from "vitest";
import {
  FixtureToolRunner, LocalEchoAdapter, MockSecurityAdapter, ToolRegistry,
  cloudNativeHealthBySlug, createCloudNativeAdapters, createCodeAdapters, codeHealthBySlug,
} from "@zerosweep/security-sdk";
import { buildScanPlan } from "./plan";

/**
 * Prompt 13 plan tests (§80/§90): cloud-native profiles resolve to the
 * governed stage chains; adapter selection honors capabilities, target
 * types and health; nothing is ever simulated for these stages.
 */

function registryWith(fixtures: Record<string, { stdout: string; version?: string }>) {
  const registry = new ToolRegistry();
  registry.register(new MockSecurityAdapter());
  registry.register(new LocalEchoAdapter());
  const runner = new FixtureToolRunner(fixtures);
  const cloud = createCloudNativeAdapters(runner);
  for (const a of cloud) registry.register(a);
  const code = createCodeAdapters(runner);
  for (const a of code) registry.register(a);
  const health = { ...cloudNativeHealthBySlug(cloud), ...codeHealthBySlug(code) };
  // The connector is per-cluster: a registered cluster makes it healthy.
  health["kubernetes-connector"] = "HEALTHY";
  return { registry, health };
}

const ALL_FIXTURES = {
  trivy: { stdout: "{}", version: "0.58.0" },
  syft: { stdout: "{}", version: "1.18.0" },
  grype: { stdout: "{}", version: "0.92.0" },
  checkov: { stdout: "[]", version: "3.2.0" },
  kubescape: { stdout: "{}", version: "3.0.0" },
  "kube-bench": { stdout: "{}", version: "0.9.0" },
  "kube-hunter": { stdout: "{}", version: "0.6.8" },
  "docker-bench-security": { stdout: "{}", version: "1.6.0" },
};

function plan(profile: string, targetType: string, fixtures: Record<string, { stdout: string; version?: string }> = ALL_FIXTURES) {
  const { registry, health } = registryWith(fixtures);
  return buildScanPlan({
    scanId: "scan-1", assessmentId: "a-1", targetId: "t-1", workspaceId: "ws-1", organizationId: "org-1",
    profile: profile as never,
    targetType: targetType as never,
    targetValue: "registry.example.com/team/webapp:1.4.2", targetHost: "registry.example.com",
    scope: { includeHosts: ["registry.example.com", "fixture-cluster"], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
    targetVerified: true, assessmentApproved: true, registry,
    selection: {
      executableSlugs: ["mock", "local-echo", "trivy", "syft", "grype", "checkov", "kubescape", "kube-bench", "kube-hunter", "docker-bench-for-security", "kubernetes-connector"],
      healthBySlug: health,
    },
  }).plan;
}

describe("Prompt 13 profile plans", () => {
  it("CONTAINER_BASELINE: resolution → Syft SBOM → Trivy/Grype image scan → gate", () => {
    const p = plan("CONTAINER_BASELINE", "CONTAINER_IMAGE");
    const types = p.stages.map((s) => s.type);
    expect(types).toEqual([
      "AUTHORIZATION_CHECK", "SCOPE_VALIDATION", "IMAGE_RESOLUTION", "SBOM_GENERATION",
      "IMAGE_VULNERABILITY_SCAN", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS",
      "QUALITY_GATE", "REPORT_GENERATION",
    ]);
    const sbom = p.stages.find((s) => s.type === "SBOM_GENERATION")!;
    expect(sbom.selectedAdapters.map((a) => a.slug)).toEqual(["syft"]);
    const vuln = p.stages.find((s) => s.type === "IMAGE_VULNERABILITY_SCAN")!;
    expect(vuln.selectedAdapters.map((a) => a.slug).sort()).toEqual(["grype", "trivy"]);
    expect(vuln.selectedAdapters.every((a) => !a.simulation)).toBe(true);
    // IMAGE_RESOLUTION is a platform stage (digest resolution, §78).
    expect(p.stages.find((s) => s.type === "IMAGE_RESOLUTION")!.selectedAdapters).toEqual([]);
  });

  it("SBOM_ONLY selects Syft alone; IMAGE_VULNERABILITIES_ONLY skips SBOM tooling", () => {
    const sbomOnly = plan("SBOM_ONLY", "CONTAINER_IMAGE");
    expect(sbomOnly.stages.map((s) => s.type)).not.toContain("IMAGE_VULNERABILITY_SCAN");
    expect(sbomOnly.selectedTools).toContain("syft");
    const vulnOnly = plan("IMAGE_VULNERABILITIES_ONLY", "CONTAINER_IMAGE");
    expect(vulnOnly.selectedTools).not.toContain("syft");
    expect(vulnOnly.selectedTools.sort()).toEqual(expect.arrayContaining(["grype", "trivy"]));
  });

  it("KUBERNETES_BASELINE: connector inventory + posture without kube-hunter; COMPREHENSIVE adds it", () => {
    const base = plan("KUBERNETES_BASELINE", "KUBERNETES_CLUSTER");
    const inv = base.stages.find((s) => s.type === "CLUSTER_INVENTORY")!;
    expect(inv.selectedAdapters.map((a) => a.slug)).toEqual(["kubernetes-connector"]);
    const posture = base.stages.find((s) => s.type === "KUBERNETES_POSTURE")!;
    expect(posture.selectedAdapters.map((a) => a.slug)).not.toContain("kube-hunter");
    expect(posture.selectedAdapters.map((a) => a.slug)).toEqual(expect.arrayContaining(["kubernetes-connector", "kubescape", "kube-bench"]));
    const comp = plan("KUBERNETES_COMPREHENSIVE", "KUBERNETES_CLUSTER");
    expect(comp.stages.find((s) => s.type === "KUBERNETES_POSTURE")!.selectedAdapters.map((a) => a.slug)).toContain("kube-hunter");
  });

  it("DOCKER_HOST_BASELINE selects only Docker Bench for the posture stage", () => {
    const p = plan("DOCKER_HOST_BASELINE", "DOCKER_HOST");
    const stage = p.stages.find((s) => s.type === "DOCKER_POSTURE")!;
    expect(stage.selectedAdapters.map((a) => a.slug)).toEqual(["docker-bench-for-security"]);
  });

  it("absent binaries degrade honestly — stages select nothing, never simulation", () => {
    const p = plan("CONTAINER_BASELINE", "CONTAINER_IMAGE", {});
    const vuln = p.stages.find((s) => s.type === "IMAGE_VULNERABILITY_SCAN")!;
    expect(vuln.selectedAdapters).toEqual([]);
    expect(JSON.stringify(p)).not.toContain("\"simulation\":true");
  });

  it("legacy CONTAINER profile resolves to the baseline chain", () => {
    const legacy = plan("CONTAINER", "CONTAINER_IMAGE");
    const baseline = plan("CONTAINER_BASELINE", "CONTAINER_IMAGE");
    expect(legacy.stages.map((s) => s.type)).toEqual(baseline.stages.map((s) => s.type));
  });
});
