/**
 * Prompt 18 — shared base for binary adapters (§8–§11/§72).
 *
 * Binary adapters analyze REGISTERED artifacts in the static
 * sandbox: artifact identity (id + SHA-256 + object-storage
 * reference) is worker-derived only, credential-looking keys are
 * rejected, and ANY script/shell/command key is rejected at
 * validation (§93) — an adapter's plan is composed from typed
 * platform constants, never from API input. The artifact itself is
 * passed to tools as DATA (a file argument); it is never the
 * executable (§8/§100).
 */
import { ReconAdapterBase, type ReconPlanParts } from "../recon/recon-adapter.base";
import { AdapterConfigurationError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import { emptyParsed, type ReconParser } from "../recon/parsers-common";
import type { BinaryParserContext } from "./parsers-binary";
import { emptyParsedBinary, type ParsedBinary } from "./types";

export function binConfigStr(config: Record<string, unknown>, key: string): string | undefined {
  const v = config[key];
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

/** §59/§68/§93 config discipline for ALL binary adapters. */
export function assertBinaryConfig(config: Record<string, unknown>): void {
  for (const key of Object.keys(config)) {
    if (/credential|secret|token|password|privatekey/i.test(key)) {
      throw new AdapterConfigurationError(`binary config key "${key}" is forbidden: credentials exist only as secret references (§7)`);
    }
    if (/^(script|scriptbody|shell|shellcommand|command|commands|args|exec|r2command|gdbcommand|idapython|python)$/i.test(key)) {
      throw new AdapterConfigurationError(`binary config key "${key}" is forbidden: no arbitrary commands, scripts or debugger input are expressible (§34/§68/§93)`);
    }
  }
}

export abstract class BinaryAdapterBase extends ReconAdapterBase {
  protected abstract parseBinary(text: string, ctx: BinaryParserContext): ParsedBinary;
  protected abstract binaryPlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts;

  protected readonly parser: ReconParser = { tool: "binary", parse: () => emptyParsed() };
  protected lastConfig: Record<string, unknown> = {};

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    assertBinaryConfig(config);
    await super.validateConfiguration(config);
    this.lastConfig = config;
  }

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    return this.binaryPlan(target, config);
  }

  protected override planNetworkPolicy(): "NO_NETWORK" | "CUSTOM_ALLOWLIST" {
    return "NO_NETWORK"; // §10: static sandbox is NO_NETWORK
  }

  protected parserContext(): BinaryParserContext {
    const c = this.lastConfig;
    return {
      toolSlug: this.metadata.slug,
      ...(binConfigStr(c, "binaryArtifactId") ? { artifactId: binConfigStr(c, "binaryArtifactId")! } : {}),
      artifactHash: binConfigStr(c, "binaryArtifactHash") ?? "unknown-artifact",
      artifactName: binConfigStr(c, "binaryArtifactName") ?? "artifact",
    };
  }

  override async parse(raw: string): Promise<ParsedBinary> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    return text ? this.parseBinary(text, this.parserContext()) : emptyParsedBinary();
  }

  override async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedBinary;
    const components = p.components ?? p.binary?.dependencies
      .filter((d) => d.version)
      .map((d) => ({
        name: d.library, version: d.version, ecosystem: "generic-binary",
        purl: d.purl ?? `pkg:generic/${d.library}@${d.version}`,
        sourceManifest: p.binary?.artifactName ?? "binary-artifact",
        scope: "UNKNOWN" as const, dependencyScope: "RUNTIME" as const, licenses: [] as string[],
      })) ?? [];
    return {
      assets: [], services: [], endpoints: [], technologies: [],
      findings: p.findings ?? [],
      ...(components.length > 0 ? { components } : {}),
      ...(p.binary ? { binary: p.binary } : {}),
      artifacts: [],
      metrics: { ...(p.metrics ?? {}) },
      mock: false,
    };
  }
}
