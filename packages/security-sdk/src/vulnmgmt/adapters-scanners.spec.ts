import { describe, expect, it } from "vitest";
import { createVulnScannerAdapters } from "./adapters-scanners";
import { InMemoryScannerInstanceProvider, type ScannerInstanceRecord } from "../proxy/types";
import type { ScannerTransport } from "../proxy/connector";
import { NESSUS_FIXTURE } from "./fixtures";

/**
 * Prompt 11 §84 worker-adapter tests: the full connector task lifecycle
 * against a fixture transport — no scanner is contacted. Unconfigured
 * scanners report NOT_CONFIGURED and throw UNAVAILABLE at execution so
 * the stage degrades honestly (§85/§86).
 */

const instance: ScannerInstanceRecord = {
  id: "inst-nessus", organizationId: "org-1", toolSlug: "nessus-professional", product: "NESSUS",
  name: "lab", endpointReference: "NESSUS_LAB", deploymentType: "ADMIN_PROVIDED",
  declaredCapabilities: ["NETWORK_VULNERABILITY_ASSESSMENT"], detectedCapabilities: [], enabled: true,
  healthStatus: "NOT_CONFIGURED", createdBy: "admin", createdAt: new Date(0).toISOString(), updatedAt: new Date(0).toISOString(),
  licenseState: "LICENSED",
  config: { profiles: { NETWORK_BASELINE: "policy-42" }, approvedInternal: true },
} as unknown as ScannerInstanceRecord;

function deps(transport: ScannerTransport, withInstance = true) {
  return {
    instances: new InMemoryScannerInstanceProvider(withInstance ? [instance] : []),
    endpoints: { resolve: async (ref: string) => (ref === "NESSUS_LAB" ? { baseUrl: "https://scanner.lab.example:8834", approvedInternal: true } : undefined) },
    secrets: { resolve: async () => "fixture-secret" },
    transport,
  };
}

const happyTransport: ScannerTransport = {
  async request({ request }) {
    if (request.path === "/server/status") return { status: 200, body: JSON.stringify({ version: "10.8.0" }), latencyMs: 2 };
    if (request.path === "/scans" && request.method === "POST") return { status: 200, body: JSON.stringify({ id: "task-1" }), latencyMs: 2 };
    if (request.path === "/scans/task-1") return { status: 200, body: JSON.stringify({ status: "COMPLETED" }), latencyMs: 2 };
    if (request.path === "/scans/task-1/report") return { status: 200, body: NESSUS_FIXTURE, latencyMs: 2 };
    return { status: 404, body: "", latencyMs: 2 };
  },
};

describe("VulnScannerAdapter (§84)", () => {
  it("runs create → poll → fetch → parse → normalize with scope-derived targets", async () => {
    const [, nessus] = createVulnScannerAdapters(deps(happyTransport));
    expect(await nessus!.checkAvailability()).toBe(true);
    const target = { type: "CIDR", value: "192.0.2.0/24", host: "192.0.2.10" } as never;
    const config = {
      instanceId: "inst-nessus", workspaceId: "ws-1", scanId: "scan-1",
      scopeIncludeHosts: ["192.0.2.10"], scopeExcludeHosts: [], scopeAllowedPorts: [], scopeAllowedPaths: [], scopeExcludedPaths: [],
      scopeIncludeCidrs: ["192.0.2.0/24"], logicalProfile: "NETWORK_BASELINE",
    };
    const plan = await nessus!.buildExecutionPlan(target, config);
    const { rawOutput } = await nessus!.execute(plan);
    const parsed = await nessus!.parse(rawOutput!) as { findings: unknown[] };
    expect(parsed.findings).toHaveLength(2);
    const normalized = await nessus!.normalize(parsed);
    expect(normalized.findings).toHaveLength(2);
    expect(normalized.mock).toBe(false);
    expect(normalized.assets[0]?.host).toBe("192.0.2.10");
  });

  it("no instance → NOT_CONFIGURED health and UNAVAILABLE execution (§85)", async () => {
    const [, nessus] = createVulnScannerAdapters(deps(happyTransport, false));
    const health = await nessus!.healthCheck();
    expect(health.status).toBe("NOT_CONFIGURED");
    expect(health.detail).toContain("not a platform failure");
    await expect(nessus!.checkAvailability()).resolves.toBe(false);
  });

  it("unreachable scanner → execution degrades with AdapterUnavailableError (§86)", async () => {
    const down: ScannerTransport = { async request() { throw new Error("connect ECONNREFUSED"); } };
    const [, nessus] = createVulnScannerAdapters(deps(down));
    const config = { instanceId: "inst-nessus", scopeIncludeHosts: ["192.0.2.10"], scopeIncludeCidrs: [], logicalProfile: "NETWORK_BASELINE" };
    await nessus!.buildExecutionPlan({ type: "IP_ADDRESS", value: "192.0.2.10", host: "192.0.2.10" } as never, config);
    await expect(nessus!.execute({} as never)).rejects.toThrow(/UNAVAILABLE|MISCONFIGURED|scanner is/);
  });
});
