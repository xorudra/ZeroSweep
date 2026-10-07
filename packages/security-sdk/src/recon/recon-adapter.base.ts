import { BaseSecurityToolAdapter } from "../adapter/adapter.base";
import { AdapterUnavailableError, ExecutionTimeoutError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { ExecutionPlan } from "../execution/execution.types";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import { classifyToolOutcome, type ToolOutcome } from "./outcome";
import type { ParsedRecon, ReconParser } from "./parsers-common";
import { ProcessToolRunner, type ToolRunner } from "./runner";

export interface ReconPlanParts {
  args: string[];
  stdin?: string;
  outputFiles?: string[];
}

/**
 * Base class for the real Prompt 5 recon adapters. Lifecycle:
 * validateConfiguration (schema, from Base) → buildExecutionPlan (executable
 * + argument array ONLY, plus data-only stdin) → execute (through the
 * ToolRunner — no shell, availability first, exit behaviour classified per
 * §38) → parse (dedicated parser, malformed records become warnings) →
 * normalize (ParsedRecon → NormalizedSecurityResult, findings ALWAYS empty:
 * recon produces inventory, never vulnerabilities, §47).
 *
 * Execution mode is CONTAINER in production (per §3 the plan carries the
 * tool's official image); on hosts where an administrator installed the
 * trusted binary instead, the same plan's executable+args run via PATH.
 * The adapter never downloads anything.
 */
export abstract class ReconAdapterBase extends BaseSecurityToolAdapter {
  /** Binary name resolved on PATH (never a user-supplied path). */
  abstract readonly executable: string;
  /** Official container image for containerized execution (§3). */
  abstract readonly containerImage: string;
  /** Args that print the tool's version (for §4 version detection). */
  abstract readonly versionArgs: string[];
  protected abstract readonly parser: ReconParser;
  /** Exit codes that mean "ran fine" for this tool (§38). */
  protected readonly acceptableExitCodes: readonly number[] = [0];
  /** True when empty stdout is a legitimate "found nothing" (§38). */
  protected readonly emptyOutputIsSuccess = true;

  protected lastRaw = "";
  protected lastOutcome: ToolOutcome | undefined;
  protected lastWarnings: string[] = [];

  protected readonly runner: ToolRunner;
  constructor(runner: ToolRunner = new ProcessToolRunner()) {
    super();
    this.runner = runner;
  }

  /** Synchronous PATH presence — plan-time health without spawning (§39). */
  isExecutablePresent(): boolean {
    return this.runner.findExecutable(this.executable) !== null;
  }

  async checkAvailability(): Promise<boolean> {
    return (await this.runner.probe(this.executable, this.versionArgs)).available;
  }

  async healthCheck(): Promise<{ status: string; detail?: string }> {
    const probe = await this.runner.probe(this.executable, this.versionArgs);
    if (!probe.available) {
      return {
        status: "UNAVAILABLE",
        detail: `${this.executable} not found on PATH and no container runtime wired — adapter reports UNAVAILABLE rather than failing scans (§2)`,
      };
    }
    return {
      status: "HEALTHY",
      detail: probe.version ? `${this.metadata.name} ${probe.version} at ${probe.path ?? this.executable}` : `${this.metadata.name} available at ${probe.path ?? this.executable}`,
    };
  }

  async buildExecutionPlan(target: AdapterTarget, config: Record<string, unknown>): Promise<ExecutionPlan> {
    await this.validateConfiguration(config);
    const parts = this.planFor(target, config);
    const timeout = typeof config.timeoutSeconds === "number" ? config.timeoutSeconds : this.metadata.defaultTimeoutSeconds;
    return {
      adapterId: this.metadata.id,
      toolId: this.metadata.id,
      executionMode: this.metadata.executionMode,
      containerImage: this.containerImage,
      executable: this.executable,
      arguments: parts.args,
      ...(parts.stdin !== undefined ? { stdin: parts.stdin } : {}),
      environmentReferences: [...this.metadata.requiresCredentials],
      timeoutSeconds: Math.min(timeout, this.metadata.maxTimeoutSeconds),
      cpuLimit: this.metadata.resources.cpu,
      memoryLimit: this.metadata.resources.memory,
      networkPolicy: this.planNetworkPolicy(),
      expectedOutputFormat: this.metadata.supportedOutputFormats[0] ?? "TEXT",
      outputFiles: parts.outputFiles ?? [],
    };
  }

  protected planNetworkPolicy(): ExecutionPlan["networkPolicy"] {
    return "SCOPE_ONLY";
  }

  protected abstract planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts;

  async execute(plan: ExecutionPlan): Promise<{ rawOutputLocation?: string; rawOutput?: string }> {
    const probe = await this.runner.probe(this.executable, this.versionArgs);
    if (!probe.available) {
      throw new AdapterUnavailableError(`${this.metadata.slug}: executable "${this.executable}" is not available in this environment`);
    }
    const result = await this.runner.run({
      executable: this.executable,
      args: plan.arguments,
      stdin: plan.stdin,
      timeoutSeconds: plan.timeoutSeconds,
    });
    this.lastRaw = result.stdout;
    const classification = classifyToolOutcome({
      exitCode: result.exitCode,
      acceptableExitCodes: this.acceptableExitCodes,
      hasOutput: result.stdout.trim().length > 0,
      emptyOutputIsSuccess: this.emptyOutputIsSuccess,
      timedOut: result.timedOut,
    });
    this.lastOutcome = classification.outcome;
    if (classification.outcome === "TIMED_OUT") {
      throw new ExecutionTimeoutError(`${this.metadata.slug}: ${classification.reason}`);
    }
    if (classification.outcome === "FAILED" || classification.outcome === "CANCELLED") {
      const err = new Error(`${this.metadata.slug}: tool execution failed (${classification.reason})${result.stderr ? `: ${result.stderr.slice(0, 200)}` : ""}`);
      err.name = "ToolExecutionError";
      throw err;
    }
    return { rawOutput: result.stdout };
  }

  async parse(raw: string): Promise<unknown> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    const parsed = this.parser.parse(text);
    this.lastWarnings = parsed.warnings;
    return parsed;
  }

  async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedRecon;
    return {
      assets: p.assets ?? [],
      services: p.services ?? [],
      endpoints: p.endpoints ?? [],
      technologies: p.technologies ?? [],
      ...(p.parameters ? { parameters: p.parameters } : {}),
      ...(p.forms ? { forms: p.forms } : {}),
      findings: [], // recon NEVER fabricates findings (§47)
      artifacts: [],
      metrics: {
        ...(p.metrics ?? {}),
        parserWarnings: (p.warnings ?? []).length,
        ...(this.lastOutcome ? { outcomePartial: this.lastOutcome === "PARTIAL" ? 1 : 0 } : {}),
      },
      mock: false,
    };
  }
}

/** Shared optional config fields every recon adapter accepts. */
export const TIMEOUT_FIELD = { name: "timeoutSeconds", type: "number", min: 10, max: 3600, description: "Per-execution timeout in seconds (clamped to the adapter maximum)" } as const;
export const HOSTS_FIELD = { name: "hosts", type: "string[]", description: "Authorized hostnames produced by previous pipeline stages (scope-checked again before use)" } as const;
export const URLS_FIELD = { name: "urls", type: "string[]", description: "Authorized URLs produced by previous pipeline stages (scope-checked again before use)" } as const;
