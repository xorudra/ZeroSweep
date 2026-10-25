/**
 * Prompt 19 §15/§64 — wireless profile → plan tests. Stage order,
 * allowlists and the ACTIVE-TOOL LOCK are asserted so a profile edit
 * can never route a baseline wireless profile through Wifite or
 * active hcxdumptool modes, drop the intake gate, or simulate
 * passive observations that never happened.
 */
import { describe, expect, it } from "vitest";
import {
  FixtureToolRunner, LocalEchoAdapter, MockSecurityAdapter, ToolRegistry,
  createWirelessAdapters, WIRELESS_SLUGS,
} from "@zerosweep/security-sdk";
import { buildScanPlan } from "./plan";

function plan(profile: string) {
  const registry = new ToolRegistry();
  registry.register(new MockSecurityAdapter());
  registry.register(new LocalEchoAdapter());
  const wireless = createWirelessAdapters(new FixtureToolRunner({
    kismet: { stdout: "[]", version: "2023.07.R1" },
    tshark: { stdout: "", version: "4.2.0" },
    hcxpcapngtool: { stdout: "", version: "6.3.4" },
    "aircrack-ng": { stdout: "", version: "1.7" },
  }));
  for (const a of wireless) registry.register(a);
  const health: Record<string, string> = Object.fromEntries(wireless.map((a) => [a.metadata.slug, "HEALTHY"]));
  return buildScanPlan({
    scanId: "scan-1", assessmentId: "a-1", targetId: "t-1", workspaceId: "ws-1", organizationId: "org-1",
    profile: profile as never,
    targetType: "WIRELESS_LAB" as never,
    targetValue: "example-corp-wifi", targetHost: "example-corp-wifi",
    scope: { includeHosts: ["example-corp-wifi"], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
    targetVerified: true, assessmentApproved: true, registry,
    selection: { executableSlugs: ["mock", "local-echo", ...WIRELESS_SLUGS], healthBySlug: health },
  }).plan;
}

const HEAD = ["AUTHORIZATION_CHECK", "SCOPE_VALIDATION"];
const TAIL = ["NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"];
const BASELINE = [...HEAD, "WIRELESS_CAPTURE_INTAKE", "WIRELESS_PASSIVE_DISCOVERY", "WIRELESS_POSTURE_ANALYSIS", ...TAIL];

describe("Prompt 19 — wireless profile plans (§15)", () => {
  it("WIRELESS_PASSIVE_BASELINE is intake → passive discovery → posture → tail", () => {
    expect(plan("WIRELESS_PASSIVE_BASELINE").stages.map((s) => s.type)).toEqual(BASELINE);
  });

  it("WIRELESS_PASSIVE_COMPREHENSIVE and WIRELESS_COMPLIANCE add offline PCAP analysis", () => {
    const expected = [...HEAD, "WIRELESS_CAPTURE_INTAKE", "WIRELESS_PASSIVE_DISCOVERY", "WIRELESS_PCAP_ANALYSIS", "WIRELESS_POSTURE_ANALYSIS", ...TAIL];
    expect(plan("WIRELESS_PASSIVE_COMPREHENSIVE").stages.map((s) => s.type)).toEqual(expected);
    expect(plan("WIRELESS_COMPLIANCE").stages.map((s) => s.type)).toEqual(expected);
  });

  it("PCAP_ANALYSIS_ONLY skips live discovery — captures only", () => {
    expect(plan("PCAP_ANALYSIS_ONLY").stages.map((s) => s.type)).toEqual(
      [...HEAD, "WIRELESS_CAPTURE_INTAKE", "WIRELESS_PCAP_ANALYSIS", "WIRELESS_POSTURE_ANALYSIS", ...TAIL],
    );
  });

  it("WIRELESS_LAB_VALIDATION runs the passive chain only (§65 architecture, no active stages)", () => {
    expect(plan("WIRELESS_LAB_VALIDATION").stages.map((s) => s.type)).toEqual(BASELINE);
  });

  it("discovery selects ONLY kismet; pcap analysis selects only the offline trio", () => {
    const p = plan("WIRELESS_PASSIVE_COMPREHENSIVE");
    expect(p.stages.find((s) => s.type === "WIRELESS_PASSIVE_DISCOVERY")!.selectedAdapters.map((a) => a.slug)).toEqual(["kismet"]);
    expect(p.stages.find((s) => s.type === "WIRELESS_PCAP_ANALYSIS")!.selectedAdapters.map((a) => a.slug).sort())
      .toEqual(["aircrack-ng", "hcxtools", "tshark-wireless"]);
    expect(p.stages.find((s) => s.type === "WIRELESS_CAPTURE_INTAKE")!.selectedAdapters).toEqual([]);
    expect(p.stages.find((s) => s.type === "WIRELESS_POSTURE_ANALYSIS")!.selectedAdapters).toEqual([]);
  });

  it("§64 ACTIVE-TOOL LOCK: no wireless profile ever selects wifite or hcxdumptool", () => {
    for (const profile of ["WIRELESS_PASSIVE_BASELINE", "WIRELESS_PASSIVE_COMPREHENSIVE", "PCAP_ANALYSIS_ONLY", "WIRELESS_COMPLIANCE", "WIRELESS_LAB_VALIDATION"]) {
      const p = plan(profile);
      const selected = p.stages.flatMap((s) => s.selectedAdapters.map((a) => a.slug));
      expect(selected).not.toContain("wifite");
      expect(selected).not.toContain("hcxdumptool");
      expect(selected).not.toContain("wireshark");
      expect(p.selectedTools).not.toContain("wifite");
      expect(p.selectedTools).not.toContain("hcxdumptool");
    }
  });
});
