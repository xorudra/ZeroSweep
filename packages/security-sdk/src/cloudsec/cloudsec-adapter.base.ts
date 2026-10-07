/**
 * Prompt 14 — cloud-security adapter base (§6/§10/§11).
 *
 * Built on the recon lifecycle like the other families. The base adds
 * the cloud disciplines every adapter inherits:
 *  - configuration carries a registered account id + a credential
 *    REFERENCE name only — inline credential material (or a value
 *    that merely looks like one) is rejected at validation (§6/§100);
 *  - parser context (account id/ref, provider) is assembled from
 *    worker-derived config only, never client input;
 *  - network policy is CUSTOM_ALLOWLIST: the only egress a cloud
 *    adapter may ever need is the assessed provider's own APIs (§10).
 */
import { ReconAdapterBase, type ReconPlanParts } from "../recon/recon-adapter.base";
import { AdapterConfigurationError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import { emptyParsed, type ReconParser } from "../recon/parsers-common";
import { emptyParsedCloudSec, type CloudSecParserContext, type ParsedCloudSec } from "./parsers-cloudsec";
import { isValidCredentialReference } from "./guards";
import type { CloudProvider } from "./types";

export function configStr(config: Record<string, unknown>, key: string): string | undefined {
  const v = config[key];
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

export function configStrList(config: Record<string, unknown>, key: string): string[] {
  const v = config[key];
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

/** Shared cloud-config validation (§6): account id required by
 *  connectors at execute time; any credential-looking VALUE in config
 *  is a hard error — only reference names may travel in a plan. */
export function assertCloudConfig(config: Record<string, unknown>): void {
  for (const key of Object.keys(config)) {
    if (/credential|secret|token|password|privatekey/i.test(key) && key !== "credentialReference") {
      throw new AdapterConfigurationError(`cloud config key "${key}" is forbidden: credentials exist only as secret references (§6)`);
    }
  }
  const ref = config.credentialReference;
  if (ref !== undefined && (typeof ref !== "string" || !isValidCredentialReference(ref))) {
    throw new AdapterConfigurationError("credentialReference must be a secret-manager reference NAME — credential values never travel in scan configuration (§6/§100)");
  }
}

export abstract class CloudSecAdapterBase extends ReconAdapterBase {
  protected abstract parseCloudSec(text: string, ctx: CloudSecParserContext): ParsedCloudSec;
  protected abstract cloudSecPlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts;

  protected readonly parser: ReconParser = { tool: "cloudsec", parse: () => emptyParsed() };

  /** Config from the most recent validateConfiguration call — parser
   *  context (account identity) is read from here (§10). */
  protected lastConfig: Record<string, unknown> = {};

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    assertCloudConfig(config);
    this.lastConfig = config;
  }

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    return this.cloudSecPlan(target, config);
  }

  protected override planNetworkPolicy(): "CUSTOM_ALLOWLIST" {
    return "CUSTOM_ALLOWLIST";
  }

  protected parserContext(): CloudSecParserContext {
    const c = this.lastConfig;
    const provider = configStr(c, "cloudProvider");
    return {
      toolSlug: this.metadata.slug,
      ...(provider === "AWS" || provider === "AZURE" || provider === "GCP" ? { provider: provider as CloudProvider } : {}),
      ...(configStr(c, "cloudAccountId") ? { accountId: configStr(c, "cloudAccountId")! } : {}),
      ...(configStr(c, "cloudAccountRef") ? { accountRef: configStr(c, "cloudAccountRef")! } : {}),
    };
  }

  override async parse(raw: string): Promise<ParsedCloudSec> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    return text ? this.parseCloudSec(text, this.parserContext()) : emptyParsedCloudSec();
  }

  override async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedCloudSec;
    return {
      assets: [], services: [], endpoints: [], technologies: [],
      findings: p.findings ?? [],
      ...(p.cloud ? { cloud: p.cloud } : {}),
      artifacts: [],
      metrics: { ...(p.metrics ?? {}) },
      mock: false,
    };
  }
}
