/**
 * Prompt 19 — shared base for wireless adapters (§12/§78/§91).
 *
 * Wireless adapters work on REGISTERED sensors and APPROVED capture
 * artifacts only: sensor/capture identity is worker-derived,
 * credential-looking keys are rejected, and ANY command/argument/
 * filter key is rejected at validation (§78) — a plan is composed
 * from typed platform constants, never from API input. Observed
 * values (SSIDs, sensor names, capture metadata) are DATA and never
 * reach a command line (§91). Execution is NO_NETWORK and passive:
 * adapters read captures or query a governed sensor; nothing here
 * can transmit.
 */
import { ReconAdapterBase, type ReconPlanParts } from "../recon/recon-adapter.base";
import { AdapterConfigurationError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import { emptyParsed, type ReconParser } from "../recon/parsers-common";
import { assertWirelessConfigKeys, evaluateAircrackConfig } from "./policy";
import type { WirelessParserContext } from "./parsers-wireless";
import { emptyParsedWireless, type ParsedWireless } from "./types";

export function wlConfigStr(config: Record<string, unknown>, key: string): string | undefined {
  const v = config[key];
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

/** §78/§91 config discipline for ALL wireless adapters. */
export function assertWirelessConfig(config: Record<string, unknown>, opts: { aircrack?: boolean } = {}): void {
  const decision = assertWirelessConfigKeys(config);
  if (!decision.allowed) throw new AdapterConfigurationError(decision.reason ?? "wireless config refused");
  if (opts.aircrack) {
    const aircrack = evaluateAircrackConfig(config);
    if (!aircrack.allowed) throw new AdapterConfigurationError(aircrack.reason ?? "aircrack workflow disabled (§20)");
  }
}

export abstract class WirelessAdapterBase extends ReconAdapterBase {
  protected abstract parseWireless(text: string, ctx: WirelessParserContext): ParsedWireless;
  protected abstract wirelessPlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts;

  protected readonly parser: ReconParser = { tool: "wireless", parse: () => emptyParsed() };
  protected lastConfig: Record<string, unknown> = {};

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    assertWirelessConfig(config, { aircrack: this.metadata.slug === "aircrack-ng" });
    await super.validateConfiguration(config);
    this.lastConfig = config;
  }

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    return this.wirelessPlan(target, config);
  }

  protected override planNetworkPolicy(): "NO_NETWORK" | "CUSTOM_ALLOWLIST" {
    return "NO_NETWORK"; // passive/offline work never needs a network
  }

  protected parserContext(): WirelessParserContext {
    const c = this.lastConfig;
    return {
      toolSlug: this.metadata.slug,
      sensorRef: wlConfigStr(c, "wirelessSensorRef") ?? "sensor-unregistered",
      workspaceKey: wlConfigStr(c, "workspaceKey") ?? "workspace",
      ...(wlConfigStr(c, "observedAt") ? { observedAt: wlConfigStr(c, "observedAt") } : {}),
    };
  }

  override async parse(raw: string): Promise<ParsedWireless> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    return text ? this.parseWireless(text, this.parserContext()) : emptyParsedWireless();
  }

  override async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedWireless;
    return {
      assets: [], services: [], endpoints: [], technologies: [],
      findings: p.findings ?? [],
      ...(p.wireless ? { wireless: p.wireless } : {}),
      artifacts: [],
      metrics: { ...(p.metrics ?? {}) },
      mock: false,
    };
  }
}
