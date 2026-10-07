import { describe, expect, it } from "vitest";
import { evaluateToolPolicy, type PolicyInput } from "./policy.engine";
import type { ToolMetadata } from "../adapter/adapter.types";

const tool: ToolMetadata = {
  id: "t1", slug: "example-scanner", name: "Example", description: "d", category: "WEB",
  adapterVersion: "1.0.0", licenseType: "OPEN_SOURCE", executionMode: "CONTAINER",
  riskLevel: "LOW", supportedTargetTypes: ["WEB_APPLICATION"], supportedOutputFormats: ["JSON"],
  capabilities: ["VULNERABILITY_SCANNING"], requiresCredentials: [], requiresApproval: false,
  supportsContainerExecution: true, supportsCancellation: true, supportsProgress: false,
  defaultTimeoutSeconds: 600, maxTimeoutSeconds: 1800, resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 600 },
};

const base: PolicyInput = {
  tool, toolEnabled: true, adapterEnabled: true, toolHealthy: true,
  targetType: "WEB_APPLICATION", targetHost: "app.example.com",
  auth: {
    organizationId: "org1", workspaceId: "ws1", targetId: "tg1", targetOrganizationId: "org1",
    assessmentId: "a1", scanId: "s1", verificationStatus: "VERIFIED", approvalStatus: "APPROVED",
    requestedBy: "u1",
  },
  scopeRules: { includeHosts: ["*.example.com", "example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [443], allowedPaths: [], excludedPaths: [] },
  availableCredentialRefs: [], currentConcurrency: 0, maxConcurrency: 2,
};

describe("ToolExecutionPolicyEngine", () => {
  it("allows a verified, in-scope, healthy tool", () => {
    expect(evaluateToolPolicy(base).decision).toBe("ALLOW");
  });
  it("denies cross-organization targets (tenant isolation)", () => {
    const d = evaluateToolPolicy({ ...base, auth: { ...base.auth, targetOrganizationId: "org2" } });
    expect(d.decision).toBe("DENY");
    expect(d.reasonCode).toBe("ORGANIZATION_MISMATCH");
  });
  it("denies unverified targets for active tools", () => {
    const d = evaluateToolPolicy({ ...base, auth: { ...base.auth, verificationStatus: "PENDING" } });
    expect(d.reasonCode).toBe("TARGET_NOT_VERIFIED");
  });
  it("denies out-of-scope hosts and blocked internal targets", () => {
    expect(evaluateToolPolicy({ ...base, targetHost: "evil.com" }).reasonCode).toBe("TARGET_OUT_OF_SCOPE");
    expect(evaluateToolPolicy({ ...base, targetHost: "169.254.169.254", scopeRules: undefined }).reasonCode).toBe("TARGET_BLOCKED");
  });
  it("always denies RESTRICTED tools by default", () => {
    const d = evaluateToolPolicy({ ...base, tool: { ...tool, riskLevel: "RESTRICTED" } });
    expect(d.decision).toBe("DENY");
  });
  it("requires approval for intrusive tools without approval", () => {
    const d = evaluateToolPolicy({ ...base, tool: { ...tool, riskLevel: "INTRUSIVE" }, auth: { ...base.auth, approvalStatus: "PENDING" } });
    expect(d.decision).toBe("REQUIRE_APPROVAL");
  });
  it("denies when a required credential reference is missing", () => {
    const d = evaluateToolPolicy({ ...base, tool: { ...tool, requiresCredentials: ["EXAMPLE_API_KEY"] } });
    expect(d.reasonCode).toBe("CREDENTIAL_REQUIRED");
  });
});
