import { describe, expect, it } from "vitest";
import { MockSecurityAdapter, ToolRegistry, LocalEchoAdapter } from "@zerosweep/security-sdk";
import { buildScanPlan } from "./plan";
import { evaluateAuthorizationGate } from "./policy-gate";

const scope = { includeHosts: ["example.com", "*.example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [80, 443], allowedPaths: [], excludedPaths: [] };

function registry(): ToolRegistry {
  const r = new ToolRegistry();
  r.register(new MockSecurityAdapter());
  r.register(new LocalEchoAdapter());
  return r;
}

const baseInput = {
  scanId: "scan-1", assessmentId: "a-1", targetId: "t-1", workspaceId: "w-1", organizationId: "org-1",
  targetType: "DOMAIN" as const, targetValue: "example.com", targetHost: "example.com",
  scope, targetVerified: true, assessmentApproved: true,
  selection: { executableSlugs: ["mock", "local-echo"] },
};

describe("profile → plan mapping (§7)", () => {
  it("PASSIVE_RECON plan has the spec stage chain and no vulnerability-scan stage", () => {
    const { plan } = buildScanPlan({ ...baseInput, profile: "PASSIVE_RECON", registry: registry() });
    const types = plan.stages.map((s) => s.type);
    // Prompt 5 §40: PASSIVE_RECON gains ENDPOINT_DISCOVERY (historical URL
    // sources) while staying free of active probing/crawling stages.
    expect(types).toEqual([
      "AUTHORIZATION_CHECK", "SCOPE_VALIDATION", "PASSIVE_RECON", "ASSET_DISCOVERY",
      "DNS_RESOLUTION", "ENDPOINT_DISCOVERY", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "REPORT_GENERATION",
    ]);
    const norm = plan.stages.find((s) => s.type === "NORMALIZATION");
    expect(norm!.dependencies).toEqual(["ENDPOINT_DISCOVERY"]);
    const endpoints = plan.stages.find((s) => s.type === "ENDPOINT_DISCOVERY");
    expect(endpoints!.dependencies).toEqual(["DNS_RESOLUTION"]); // crawl/tech deps substituted in this profile
  });

  it("WEB_BASELINE selects the mock (simulation) adapter for capability stages, honestly flagged", () => {
    const { plan } = buildScanPlan({ ...baseInput, profile: "WEB_BASELINE", registry: registry() });
    const crawl = plan.stages.find((s) => s.type === "CRAWLING");
    expect(crawl!.selectedAdapters).toHaveLength(1);
    expect(crawl!.selectedAdapters[0]!.slug).toBe("mock");
    expect(crawl!.selectedAdapters[0]!.simulation).toBe(true);
    expect(plan.policySnapshot.simulation).toBe(true);
    const auth = plan.stages.find((s) => s.type === "AUTHORIZATION_CHECK");
    expect(auth!.selectedAdapters).toEqual([]); // platform-internal stage, no tool
  });

  it("plan is rejected for an incompatible target/adapter combination at selection level", () => {
    const { plan } = buildScanPlan({ ...baseInput, profile: "WEB_BASELINE", targetType: "APK", registry: registry() });
    const recon = plan.stages.find((s) => s.type === "PASSIVE_RECON");
    expect(recon!.selectedAdapters).toEqual([]); // mock does not support APK — nothing selected, never forced
  });
});

describe("authorization + scope gate (§11–§12)", () => {
  const auth = {
    organizationId: "org-1", workspaceId: "w-1", targetId: "t-1", targetOrganizationId: "org-1",
    assessmentId: "a-1", scanId: "scan-1", verificationStatus: "VERIFIED" as const, approvalStatus: "APPROVED" as const, requestedBy: "u-1",
  };
  const gate = {
    auth, targetHost: "example.com", scopeRules: scope,
    targetExists: true, targetWorkspaceId: "w-1", workspaceId: "w-1",
    targetVerified: true, assessmentApproved: true, scopeValid: true,
    // Independent approval: creator u-2, approver u-3, requester u-1.
    assessmentCreatedBy: "u-2", assessmentApprovedBy: "u-3",
  };

  it("allows a verified, approved, in-scope target", () => {
    expect(evaluateAuthorizationGate(gate).allowed).toBe(true);
  });
  it("denies unverified targets, unapproved assessments and cross-org targets", () => {
    expect(evaluateAuthorizationGate({ ...gate, targetVerified: false }).reasonCode).toBe("TARGET_NOT_VERIFIED");
    expect(evaluateAuthorizationGate({ ...gate, assessmentApproved: false }).reasonCode).toBe("ASSESSMENT_NOT_APPROVED");
    expect(evaluateAuthorizationGate({ ...gate, targetWorkspaceId: "other" }).reasonCode).toBe("WORKSPACE_MISMATCH");
    expect(evaluateAuthorizationGate({ ...gate, auth: { ...auth, verificationStatus: "PENDING" as const } }).reasonCode).toBe("TARGET_NOT_VERIFIED");
  });
  it("denies self-approved and requester-approved assessments (run-2 independence)", () => {
    expect(evaluateAuthorizationGate({ ...gate, assessmentApprovedBy: "u-2" }).reasonCode).toBe("ASSESSMENT_NOT_APPROVED"); // approver == creator
    expect(evaluateAuthorizationGate({ ...gate, assessmentApprovedBy: "u-1" }).reasonCode).toBe("ASSESSMENT_NOT_APPROVED"); // approver == requester
    expect(evaluateAuthorizationGate({ ...gate, assessmentApprovedBy: null }).reasonCode).toBe("ASSESSMENT_NOT_APPROVED"); // no recorded approver
  });
  it("denies a target host outside the approved scope — discovered assets never expand it", () => {
    expect(evaluateAuthorizationGate({ ...gate, targetHost: "third-party-cdn.example.net" }).reasonCode).toBe("TARGET_OUT_OF_SCOPE");
    expect(evaluateAuthorizationGate({ ...gate, targetHost: "sub.example.com" }).allowed).toBe(true); // wildcard include
  });
});
