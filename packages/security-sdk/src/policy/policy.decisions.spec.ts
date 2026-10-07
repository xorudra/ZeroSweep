import { describe, expect, it } from "vitest";
import { evaluateToolPolicy, type PolicyInput } from "./policy.engine";
import type { ToolMetadata } from "../adapter/adapter.types";

const tool: ToolMetadata = {
  id: "t1", slug: "s", name: "S", description: "d", category: "WEB", adapterVersion: "1.0.0",
  licenseType: "OPEN_SOURCE", executionMode: "CONTAINER", riskLevel: "PASSIVE",
  supportedTargetTypes: ["DOMAIN"], supportedOutputFormats: ["JSON"], capabilities: [],
  requiresCredentials: [], requiresApproval: false, supportsContainerExecution: true,
  supportsCancellation: true, supportsProgress: false, defaultTimeoutSeconds: 60,
  maxTimeoutSeconds: 600, resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 60 },
};
const base: PolicyInput = {
  tool, toolEnabled: true, adapterEnabled: true, toolHealthy: true,
  targetType: "DOMAIN", targetHost: "example.com",
  auth: { organizationId: "o", workspaceId: "w", targetId: "t", targetOrganizationId: "o", assessmentId: "a", scanId: "s", verificationStatus: "VERIFIED", approvalStatus: "APPROVED", requestedBy: "u" },
  availableCredentialRefs: [], currentConcurrency: 0, maxConcurrency: 2,
};

describe("PolicyEngine — remaining reason codes", () => {
  it("TOOL_DISABLED / ADAPTER_DISABLED / TOOL_UNHEALTHY", () => {
    expect(evaluateToolPolicy({ ...base, toolEnabled: false }).reasonCode).toBe("TOOL_DISABLED");
    expect(evaluateToolPolicy({ ...base, adapterEnabled: false }).reasonCode).toBe("ADAPTER_DISABLED");
    expect(evaluateToolPolicy({ ...base, toolHealthy: false }).reasonCode).toBe("TOOL_UNHEALTHY");
  });
  it("TARGET_TYPE_UNSUPPORTED", () => {
    expect(evaluateToolPolicy({ ...base, targetType: "APK" }).reasonCode).toBe("TARGET_TYPE_UNSUPPORTED");
  });
  it("NETWORK_POLICY_DENIED when network posture forbids execution", () => {
    expect(evaluateToolPolicy({ ...base, networkPermitted: false }).reasonCode).toBe("NETWORK_POLICY_DENIED");
  });
  it("RATE_LIMIT_EXCEEDED when the window is full", () => {
    expect(evaluateToolPolicy({ ...base, requestsInWindow: 60, rateLimitPerMinute: 60 }).reasonCode).toBe("RATE_LIMIT_EXCEEDED");
    expect(evaluateToolPolicy({ ...base, requestsInWindow: 59, rateLimitPerMinute: 60 }).decision).toBe("ALLOW");
  });
  it("CONCURRENCY_LIMIT at capacity", () => {
    expect(evaluateToolPolicy({ ...base, currentConcurrency: 2, maxConcurrency: 2 }).reasonCode).toBe("CONCURRENCY_LIMIT");
  });
  it("PASSIVE tools may run on unverified targets; LOW may not", () => {
    const unverified = { ...base, auth: { ...base.auth, verificationStatus: "PENDING" as const } };
    expect(evaluateToolPolicy(unverified).decision).toBe("ALLOW");
    expect(evaluateToolPolicy({ ...unverified, tool: { ...tool, riskLevel: "LOW" as const } }).reasonCode).toBe("TARGET_NOT_VERIFIED");
  });
});
