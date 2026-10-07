import { ReconAdapterBase, type ReconPlanParts } from "../recon/recon-adapter.base";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import { emptyParsed, type ReconParser } from "../recon/parsers-common";
import type { ParsedCode, ParserContext } from "./parsers-code";
import { emptyParsedCode } from "./parsers-code";

/**
 * Base class for source-code tool adapters (Prompt 12 §12/§13), built on
 * the recon lifecycle (plan = executable + argument array ONLY, executed
 * through the ToolRunner — no shell). Source analysis runs over an
 * isolated snapshot with network policy NO_NETWORK and the repository
 * execution policy DO_NOT_EXECUTE_SOURCE: adapters READ the snapshot —
 * they never build, install, or execute anything inside it (§14).
 *
 * The target VALUE for source scans is the snapshot workspace path (or
 * the registered repository reference the worker resolved to one).
 */
export abstract class CodeAdapterBase extends ReconAdapterBase {
  /** The family's dedicated parser (hostile-safe, see parsers-code). */
  protected abstract parseCode(text: string): ParsedCode;
  /** Argument array for this tool — built ONLY from validated fields. */
  protected abstract codePlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts;

  /** ReconParser shim: the lifecycle's parse() is overridden below to
   *  use parseCode; this exists to satisfy the base contract. */
  protected readonly parser: ReconParser = { tool: "code", parse: () => emptyParsed() };

  /** Config from the most recent validateConfiguration call — the
   *  lifecycle's parse step receives no config, so the repository
   *  identity is read from here (mirrors the connector pattern). */
  protected lastConfig: Record<string, unknown> = {};

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    this.lastConfig = config;
  }

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    return this.codePlan(target, config);
  }

  /** Source tools never need network access (§13): rule packs and
   *  vulnerability databases are provisioned on the worker out of band. */
  protected override planNetworkPolicy(): "NO_NETWORK" {
    return "NO_NETWORK";
  }

  /** The snapshot path this execution analyzes: worker-resolved from the
   *  target + the scan's immutable snapshot (§5/§12). */
  protected sourcePath(target: AdapterTarget, config: Record<string, unknown>): string {
    return typeof config.sourcePath === "string" && config.sourcePath.length > 0 ? config.sourcePath : target.value;
  }

  /** Repository identity for source fingerprints (§64). */
  protected repositoryKey(config: Record<string, unknown>): string {
    return typeof config.repositoryId === "string" && config.repositoryId.length > 0
      ? config.repositoryId
      : "repository";
  }

  protected parserContext(): ParserContext {
    return { repositoryKey: this.repositoryKey(this.lastConfig), sourceTool: this.metadata.slug };
  }

  override async parse(raw: string): Promise<ParsedCode> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    return text ? this.parseCode(text) : emptyParsedCode();
  }

  override async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedCode;
    return {
      assets: [], services: [], endpoints: [], technologies: [],
      findings: p.findings ?? [],
      components: p.components ?? [],
      artifacts: [],
      metrics: { ...(p.metrics ?? {}), parserWarnings: (p.warnings ?? []).length },
      mock: false,
    };
  }
}
