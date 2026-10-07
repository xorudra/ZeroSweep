import { BaseSecurityToolAdapter } from "../adapter/adapter.base";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { ToolMetadata } from "../adapter/adapter.types";
import { TargetValidationError } from "../adapter/adapter.errors";
import type { ExecutionPlan } from "../execution/execution.types";
import type { NormalizedSecurityResult } from "../findings/finding.types";

/**
 * LOCAL ECHO ADAPTER (TEST ONLY) — exercises argument handling, the process
 * lifecycle contract, timeouts and parsing WITHOUT connecting to any target
 * and WITHOUT spawning any process: the "execution" is an in-process echo of
 * the already-validated plan arguments. If any argument contains shell
 * metacharacters it is rejected — arguments are data, never a shell string.
 */
export class LocalEchoAdapter extends BaseSecurityToolAdapter {
  readonly metadata: ToolMetadata = {
    id: "local-echo", slug: "local-echo", name: "Local Echo Adapter (TEST ONLY)",
    description: "Echoes validated plan arguments back as fixture output. No network, no subprocess, no target contact.",
    category: "REPORTING", adapterVersion: "1.0.0", licenseType: "OPEN_SOURCE",
    executionMode: "MOCK", riskLevel: "PASSIVE",
    supportedTargetTypes: ["DOMAIN", "WEB_APPLICATION"],
    supportedOutputFormats: ["JSON"], capabilities: [],
    inputSchema: [{ name: "label", type: "string", required: false, description: "Label echoed into the fixture output" }],
    requiresCredentials: [], requiresApproval: false,
    supportsContainerExecution: false, supportsCancellation: true, supportsProgress: false,
    defaultTimeoutSeconds: 5, maxTimeoutSeconds: 30,
    resources: { cpu: "0.1", memory: "64Mi", timeoutSeconds: 5 },
  };

  async checkAvailability(): Promise<boolean> { return true; }
  async healthCheck(): Promise<{ status: string; detail?: string }> {
    return { status: "HEALTHY", detail: "Local echo adapter (test only)" };
  }
  async buildExecutionPlan(target: AdapterTarget, config: Record<string, unknown>): Promise<ExecutionPlan> {
    await this.validateConfiguration(config);
    const label = typeof config.label === "string" ? config.label : "echo";
    return {
      adapterId: this.metadata.id, toolId: this.metadata.id, executionMode: "MOCK",
      executable: "local-echo", // in-process handler name — NOT a shell binary
      arguments: ["--target", target.host, "--label", label],
      environmentReferences: [], timeoutSeconds: 5, cpuLimit: "0.1",
      memoryLimit: "64Mi", networkPolicy: "NO_NETWORK", expectedOutputFormat: "JSON", outputFiles: [],
    };
  }
  async execute(plan: ExecutionPlan): Promise<{ rawOutputLocation?: string }> {
    for (const arg of plan.arguments) {
      if (/[;&|`$<>()\n\r]/.test(arg)) throw new TargetValidationError(`Argument contains shell metacharacters: ${arg}`);
    }
    // Deliberately no I/O: the fixture is derived from the plan itself.
    return { rawOutputLocation: `memory://local-echo/${encodeURIComponent(plan.arguments.join(" "))}` };
  }
  async parse(raw: string): Promise<unknown> {
    return { mock: true, label: "TEST / MOCK DATA", echo: raw };
  }
  async normalize(_parsed: unknown): Promise<NormalizedSecurityResult> {
    return { assets: [], services: [], endpoints: [], technologies: [], findings: [], artifacts: [], metrics: { echoExecutions: 1 }, mock: true };
  }
}
