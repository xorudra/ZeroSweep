import { BaseSecurityToolAdapter } from "../adapter/adapter.base";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { ToolMetadata } from "../adapter/adapter.types";
import type { ExecutionPlan } from "../execution/execution.types";
import type { NormalizedSecurityResult } from "../findings/finding.types";

/**
 * SAFE MOCK ADAPTER — implements the full lifecycle but performs NO network
 * activity and NO security testing. Its output is deterministic fixture data
 * with `mock: true` and ZERO findings, so it can never be mistaken for a real
 * vulnerability result.
 */
export class MockSecurityAdapter extends BaseSecurityToolAdapter {
  readonly metadata: ToolMetadata = {
    id: "mock", slug: "mock", name: "Mock Security Adapter (TEST ONLY)",
    description: "Test adapter that exercises the pipeline without touching any target.",
    category: "REPORTING", adapterVersion: "1.0.0", licenseType: "OPEN_SOURCE",
    executionMode: "MOCK", riskLevel: "PASSIVE",
    supportedTargetTypes: ["DOMAIN", "WEB_APPLICATION"],
    supportedOutputFormats: ["JSON"], capabilities: [],
    requiresCredentials: [], requiresApproval: false,
    supportsContainerExecution: false, supportsCancellation: true, supportsProgress: false,
    defaultTimeoutSeconds: 5, maxTimeoutSeconds: 30,
    resources: { cpu: "0.1", memory: "64Mi", timeoutSeconds: 5 },
  };

  async checkAvailability(): Promise<boolean> { return true; }
  async healthCheck(): Promise<{ status: string; detail?: string }> {
    return { status: "HEALTHY", detail: "Mock adapter (test only)" };
  }
  async buildExecutionPlan(_target: AdapterTarget, _config: Record<string, unknown>): Promise<ExecutionPlan> {
    return {
      adapterId: this.metadata.id, toolId: this.metadata.id, executionMode: "MOCK",
      arguments: [], environmentReferences: [], timeoutSeconds: 5, cpuLimit: "0.1",
      memoryLimit: "64Mi", networkPolicy: "NO_NETWORK", expectedOutputFormat: "JSON", outputFiles: [],
    };
  }
  async execute(_plan: ExecutionPlan): Promise<{ rawOutputLocation?: string }> {
    await new Promise((r) => setTimeout(r, 10)); // brief deterministic wait; no I/O, no network
    return {};
  }
  async parse(_raw: string): Promise<unknown> {
    return { mock: true, label: "TEST / MOCK DATA" };
  }
  async normalize(_parsed: unknown): Promise<NormalizedSecurityResult> {
    return { assets: [], services: [], endpoints: [], technologies: [], findings: [], artifacts: [], metrics: { mockExecutions: 1 }, mock: true };
  }
}
