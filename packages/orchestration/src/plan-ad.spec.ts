/**
 * Prompt 15 — AD profile plan tests (§85/§86/§103/§112): the seven AD
 * profiles resolve to the spec stage chain; platform stages select no
 * adapters; offensive tools are selectable by NO stage; AD tool
 * stages never fall back to simulation.
 */
import { describe, expect, it } from "vitest";
import {
  FixtureToolRunner, LocalEchoAdapter, MockSecurityAdapter, ToolRegistry,
  createDirectoryAdapters, directoryHealthBySlug, INERT_DIRECTORY_DEPS,
} from "@zerosweep/security-sdk";
import { PROFILE_TEMPLATES, STAGE_LIBRARY, resolveTemplate } from "./profiles";
import { buildScanPlan } from "./plan";

async function registryWith() {
  const registry = new ToolRegistry();
  registry.register(new MockSecurityAdapter());
  registry.register(new LocalEchoAdapter());
  const runner = new FixtureToolRunner({
    ldapsearch: { stdout: "", version: "2.6.0" },
    SharpHound: { stdout: "{}", version: "2.0.0" },
    PingCastle: { stdout: "", version: "3.0.0" },
    "enum4linux-ng": { stdout: "{}", version: "1.3.0" },
    smbmap: { stdout: "{}", version: "1.10.0" },
    certipy: { stdout: "{}", version: "4.0.0" },
  });
  const directory = createDirectoryAdapters(runner, INERT_DIRECTORY_DEPS);
  for (const a of directory) registry.register(a);
  const healthMap = await directoryHealthBySlug(directory, INERT_DIRECTORY_DEPS);
  const health: Record<string, string> = {};
  for (const [slug, h] of healthMap) health[slug] = h.status === "NOT_CONFIGURED" ? "HEALTHY" : h.status;
  // Connectors resolve per-domain at execute time; at plan time they
  // are selectable when the store will resolve a registered domain
  // (mirrors the P14 connector plan posture).
  health["ldap-directory-connector"] = "HEALTHY";
  health["bloodhound-connector"] = "HEALTHY";
  return { registry, health };
}

async function plan(profile: string) {
  const { registry, health } = await registryWith();
  return buildScanPlan({
    scanId: "scan-1", assessmentId: "a-1", targetId: "t-1", workspaceId: "ws-1", organizationId: "org-1",
    profile: profile as never,
    targetType: "ACTIVE_DIRECTORY_DOMAIN" as never,
    targetValue: "corp.example", targetHost: "corp.example",
    scope: { includeHosts: ["corp.example"], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
    targetVerified: true, assessmentApproved: true, registry,
    selection: {
      executableSlugs: ["mock", "local-echo", "ldap-directory-connector", "bloodhound-connector", "ldapsearch", "sharphound", "pingcastle", "enum4linux-ng", "smbmap", "certipy-posture"],
      healthBySlug: health,
    },
  }).plan;
}

const OFFENSIVE_SLUGS = ["netexec", "impacket", "kerbrute", "responder", "powerview", "adexplorer"];

describe("Prompt 15 — AD profiles (§85/§86)", () => {
  it("AD_BASELINE resolves to the spec chain in order", async () => {
    const p = await plan("AD_BASELINE");
    const types = p.stages.map((s) => s.type);
    expect(types).toEqual([
      "AUTHORIZATION_CHECK", "SCOPE_VALIDATION", "DOMAIN_DISCOVERY", "DIRECTORY_INVENTORY",
      "LDAP_POSTURE", "GRAPH_COLLECTION", "PINGCASTLE_POSTURE", "ADCS_POSTURE",
      "NORMALIZATION", "CORRELATION", "ATTACK_PATH_ANALYSIS", "RISK_ANALYSIS", "REPORT_GENERATION",
    ]);
  });

  it("the focused profiles resolve to their chains", async () => {
    expect((await plan("AD_INVENTORY")).stages.map((s) => s.type)).toEqual([
      "AUTHORIZATION_CHECK", "SCOPE_VALIDATION", "DOMAIN_DISCOVERY", "DIRECTORY_INVENTORY",
      "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "REPORT_GENERATION",
    ]);
    expect((await plan("ADCS_POSTURE")).stages.map((s) => s.type)).toContain("ADCS_POSTURE");
    expect((await plan("SMB_POSTURE")).stages.map((s) => s.type)).toContain("SMB_POSTURE");
    expect((await plan("AD_COMPREHENSIVE")).stages.map((s) => s.type)).toContain("SMB_POSTURE");
    expect((await plan("IDENTITY_GRAPH")).stages.map((s) => s.type)).not.toContain("PINGCASTLE_POSTURE");
  });

  it("attack-path analysis depends on graph + correlation; risk consumes it (§86)", () => {
    const defs = resolveTemplate("AD_BASELINE" as never);
    const apa = defs.find((d) => d.type === "ATTACK_PATH_ANALYSIS")!;
    expect(apa.dependencies).toEqual(expect.arrayContaining(["GRAPH_COLLECTION", "CORRELATION"]));
    const risk = defs.find((d) => d.type === "RISK_ANALYSIS")!;
    expect(risk.dependencies).toContain("ATTACK_PATH_ANALYSIS");
    // Non-AD profiles are untouched by the AD shaping.
    const web = resolveTemplate("WEB_BASELINE" as never);
    expect(web.find((d) => d.type === "RISK_ANALYSIS")!.dependencies).toEqual(["CORRELATION"]);
  });

  it("platform stages select no adapters; inventory selects the connectors", async () => {
    const p = await plan("AD_BASELINE");
    for (const type of ["DOMAIN_DISCOVERY", "LDAP_POSTURE", "GRAPH_COLLECTION", "ATTACK_PATH_ANALYSIS"]) {
      const stage = p.stages.find((s) => s.type === type)!;
      expect(stage.selectedAdapters).toEqual([]);
    }
    const inventory = p.stages.find((s) => s.type === "DIRECTORY_INVENTORY")!;
    const slugs = inventory.selectedAdapters.map((a) => a.slug);
    expect(slugs).toContain("ldap-directory-connector");
    expect(slugs).toContain("bloodhound-connector");
  });

  it("offensive tools are selectable by NO stage of ANY AD profile (§112)", async () => {
    for (const profile of ["AD_INVENTORY", "AD_BASELINE", "AD_COMPREHENSIVE", "ADCS_POSTURE", "SMB_POSTURE", "IDENTITY_GRAPH", "ATTACK_PATH_ANALYSIS"]) {
      const p = await plan(profile);
      for (const stage of p.stages) {
        for (const adapter of stage.selectedAdapters) {
          expect(OFFENSIVE_SLUGS).not.toContain(adapter.slug);
        }
      }
    }
    // And no stage definition anywhere allows them in.
    for (const def of Object.values(STAGE_LIBRARY)) {
      for (const slug of def.adapterAllowlist ?? []) expect(OFFENSIVE_SLUGS).not.toContain(slug);
    }
    expect(Object.keys(PROFILE_TEMPLATES)).toEqual(expect.arrayContaining([
      "AD_INVENTORY", "AD_BASELINE", "AD_COMPREHENSIVE", "ADCS_POSTURE", "SMB_POSTURE", "IDENTITY_GRAPH", "ATTACK_PATH_ANALYSIS",
    ]));
  });

  it("AD tool stages never use simulation fallback", () => {
    for (const type of ["DIRECTORY_INVENTORY", "SMB_POSTURE", "PINGCASTLE_POSTURE", "ADCS_POSTURE"] as const) {
      expect(STAGE_LIBRARY[type].simulationFallback).toBe(false);
    }
  });
});
