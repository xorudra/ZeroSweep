/**
 * Prompt 17 — shared bases for mobile adapters (§8–§11/§59/§72).
 *
 * The disciplines every mobile adapter inherits:
 *  - configuration carries a registered application/build id + the
 *    build hash — worker-derived only; credential-looking keys and
 *    ANY script/shell/command key are REJECTED at validation (§59/§72:
 *    no generic shell, no arbitrary scripts, by construction);
 *  - static adapters run in the sandbox contract: no network except
 *    the configured MobSF instance, no app-code execution (§8);
 *  - dynamic adapters (ADB / mitmproxy) additionally require the
 *    approved-session fields the worker derives from the lab session
 *    record — without them they refuse (§58/§73).
 */
import { ReconAdapterBase, type ReconPlanParts } from "../recon/recon-adapter.base";
import { AdapterConfigurationError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import { emptyParsed, type ReconParser } from "../recon/parsers-common";
import { emptyParsedMobile, type ParsedMobile } from "./types";

export function mobConfigStr(config: Record<string, unknown>, key: string): string | undefined {
  const v = config[key];
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

export function mobConfigStrList(config: Record<string, unknown>, key: string): string[] {
  const v = config[key];
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

/** §59/§72/§75 config discipline for ALL mobile adapters. */
export function assertMobileConfig(config: Record<string, unknown>): void {
  for (const key of Object.keys(config)) {
    if (/credential|secret|token|password|privatekey|signingkey/i.test(key) && key !== "mobileScannerCredentialReference") {
      throw new AdapterConfigurationError(`mobile config key "${key}" is forbidden: credentials exist only as secret references (§7/§31)`);
    }
    if (/^(script|scriptbody|shell|shellcommand|command|args|exec|objectioncommand|fridascript)$/i.test(key)) {
      throw new AdapterConfigurationError(`mobile config key "${key}" is forbidden: no arbitrary scripts, shell commands or tool commands are expressible (§59/§72/§75)`);
    }
  }
}

export interface MobileAdapterParserContext {
  toolSlug: string;
  applicationId?: string;
  buildId?: string;
  buildHash: string;
  applicationRef: string;
  platform: "ANDROID" | "IOS";
}

export abstract class MobileAdapterBase extends ReconAdapterBase {
  protected abstract parseMobile(text: string, ctx: MobileAdapterParserContext): ParsedMobile;
  protected abstract mobilePlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts;

  protected readonly parser: ReconParser = { tool: "mobile", parse: () => emptyParsed() };

  protected lastConfig: Record<string, unknown> = {};

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    assertMobileConfig(config);
    await super.validateConfiguration(config);
    this.lastConfig = config;
  }

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    return this.mobilePlan(target, config);
  }

  protected override planNetworkPolicy(): "NO_NETWORK" | "CUSTOM_ALLOWLIST" {
    return "NO_NETWORK";
  }

  protected parserContext(): MobileAdapterParserContext {
    const c = this.lastConfig;
    return {
      toolSlug: this.metadata.slug,
      ...(mobConfigStr(c, "mobileApplicationId") ? { applicationId: mobConfigStr(c, "mobileApplicationId")! } : {}),
      ...(mobConfigStr(c, "mobileBuildId") ? { buildId: mobConfigStr(c, "mobileBuildId")! } : {}),
      buildHash: mobConfigStr(c, "mobileBuildHash") ?? "unknown-build",
      applicationRef: mobConfigStr(c, "mobileApplicationRef") ?? "unknown-app",
      platform: mobConfigStr(c, "mobilePlatform") === "IOS" ? "IOS" : "ANDROID",
    };
  }

  override async parse(raw: string): Promise<ParsedMobile> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    return text ? this.parseMobile(text, this.parserContext()) : emptyParsedMobile();
  }

  override async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedMobile;
    // §29: extracted endpoints ALSO feed the generic endpoint
    // inventory (the API asset model) — as discovered references
    // whose scope verdict the result processor computes; extraction
    // never promotes them to targets.
    const endpoints = (p.mobile?.endpoints ?? []).map((e) => ({
      url: e.url, method: "GET", source: this.metadata.slug, sources: [this.metadata.slug],
    }));
    const components = p.components ?? [];
    return {
      assets: [], services: [], endpoints, technologies: [],
      findings: p.findings ?? [],
      ...(components.length > 0 ? { components } : {}),
      ...(p.sbom ? { sbom: p.sbom } : {}),
      ...(p.mobile ? { mobile: p.mobile } : {}),
      artifacts: [],
      metrics: { ...(p.metrics ?? {}) },
      mock: false,
    };
  }
}
