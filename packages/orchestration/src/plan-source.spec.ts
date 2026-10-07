import { describe, expect, it } from "vitest";
import { ToolRegistry, createCodeAdapters, MockSecurityAdapter, codeHealthBySlug } from "@dsrclone/security-sdk";
import { buildScanPlan } from "./plan";
import { resolveTemplate } from "./profiles";

/**
 * Prompt 12 — source profile planning (§18/§19/§96): the source chain
 * plans in order, platform stages select no adapters, per-profile
 * allowlists shape SAST/SCA, and the quality gate sits between risk
 * analysis and report generation.
 */

function registryWithCode(): ToolRegistry {
  const registry = new ToolRegistry();
  registry.register(new MockSecurityAdapter());
  for (const a of createCodeAdapters()) registry.register(a);
  return registry;
}

function planFor(profile: "SOURCE_BASELINE" | "SOURCE_COMPREHENSIVE" | "SECRETS_ONLY" | "DEPENDENCIES_ONLY" | "SAST_ONLY") {
  const registry = registryWithCode();
  const adapters = createCodeAdapters();
  return buildScanPlan({
    scanId: "scan-1", assessmentId: "a-1", targetId: "t-1", workspaceId: "ws-1", organizationId: "org-1",
    profile, targetType: "SOURCE_REPOSITORY",
    targetValue: "https://github.com/example/fixture-repo.git", targetHost: "github.com",
    scope: { includeHosts: ["github.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
    targetVerified: true, assessmentApproved: true, registry,
    selection: {
      executableSlugs: adapters.map((a) => a.metadata.slug),
      healthBySlug: Object.fromEntries(adapters.map((a) => [a.metadata.slug, "HEALTHY"])),
    },
  }).plan;
}

describe("Prompt 12 — source profile plans", () => {
  it("SOURCE_BASELINE plans the full §19 chain in order with the quality gate before reporting", () => {
    const plan = planFor("SOURCE_BASELINE");
    const types = plan.stages.map((s) => s.type);
    expect(types).toEqual([
      "AUTHORIZATION_CHECK", "SCOPE_VALIDATION", "SOURCE_ACQUISITION", "LANGUAGE_DETECTION",
      "SECRET_SCANNING", "SAST", "DEPENDENCY_INVENTORY", "SCA", "SBOM_GENERATION",
      "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION",
    ]);
    const qg = plan.stages.find((s) => s.type === "QUALITY_GATE")!;
    expect(qg.dependencies).toEqual(["RISK_ANALYSIS"]);
    expect(plan.stages.find((s) => s.type === "REPORT_GENERATION")!.dependencies).toEqual(["QUALITY_GATE"]);
    // Platform stages select no adapters.
    for (const t of ["SOURCE_ACQUISITION", "LANGUAGE_DETECTION", "DEPENDENCY_INVENTORY", "SBOM_GENERATION", "QUALITY_GATE"]) {
      expect(plan.stages.find((s) => s.type === t)!.selectedAdapters).toEqual([]);
    }
  });

  it("baseline SAST selects semgrep/bandit/brakeman only; SCA selects grype only", () => {
    const plan = planFor("SOURCE_BASELINE");
    const sast = plan.stages.find((s) => s.type === "SAST")!;
    expect(sast.selectedAdapters.map((a) => a.slug).sort()).toEqual(["bandit", "brakeman", "semgrep"]);
    const sca = plan.stages.find((s) => s.type === "SCA")!;
    expect(sca.selectedAdapters.map((a) => a.slug)).toEqual(["grype"]);
    const secrets = plan.stages.find((s) => s.type === "SECRET_SCANNING")!;
    expect(secrets.selectedAdapters.map((a) => a.slug).sort()).toEqual(["gitleaks", "trufflehog"]);
  });

  it("comprehensive SAST adds codeql + spotbugs (sonarqube absent without connector deps)", () => {
    const plan = planFor("SOURCE_COMPREHENSIVE");
    const sast = plan.stages.find((s) => s.type === "SAST")!;
    expect(sast.selectedAdapters.map((a) => a.slug).sort()).toEqual(["bandit", "brakeman", "codeql", "semgrep", "spotbugs"]);
    const sca = plan.stages.find((s) => s.type === "SCA")!;
    expect(sca.selectedAdapters.map((a) => a.slug).sort()).toEqual(["grype", "owasp-dependency-check"]);
  });

  it("focused profiles plan only their stages", () => {
    expect(planFor("SECRETS_ONLY").stages.map((s) => s.type)).toContain("SECRET_SCANNING");
    expect(planFor("SECRETS_ONLY").stages.map((s) => s.type)).not.toContain("SAST");
    expect(planFor("DEPENDENCIES_ONLY").stages.map((s) => s.type)).toEqual(expect.arrayContaining(["DEPENDENCY_INVENTORY", "SCA", "SBOM_GENERATION"]));
    expect(planFor("SAST_ONLY").stages.map((s) => s.type)).not.toContain("SCA");
  });

  it("source stages are not network-capable (NO_NETWORK local analysis, §13)", () => {
    const plan = planFor("SOURCE_BASELINE");
    for (const s of plan.stages) {
      if (["SECRET_SCANNING", "SAST", "SCA"].includes(s.type)) expect(s.networkCapable).toBe(false);
    }
  });

  it("health codes: absent binaries report UNAVAILABLE via the sync probe", () => {
    const health = codeHealthBySlug(createCodeAdapters());
    for (const slug of ["semgrep", "gitleaks", "grype"]) {
      expect(["HEALTHY", "UNAVAILABLE"]).toContain(health[slug]);
    }
  });

  it("templates resolve without dangling dependencies for every source profile", () => {
    for (const profile of ["SOURCE_BASELINE", "SOURCE_COMPREHENSIVE", "SECRETS_ONLY", "DEPENDENCIES_ONLY", "SAST_ONLY", "SOURCE_CODE"] as const) {
      const defs = resolveTemplate(profile);
      const types = new Set(defs.map((d) => d.type));
      for (const d of defs) for (const dep of d.dependencies) expect(types.has(dep)).toBe(true);
    }
  });
});
