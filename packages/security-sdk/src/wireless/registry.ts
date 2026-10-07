/**
 * Prompt 19 — wireless adapter registry (§10-family/§80).
 *
 * createWirelessAdapters returns the FOUR executing passive/offline
 * adapters (kismet, tshark-wireless, hcxtools, aircrack-ng metadata).
 * Wifite, active hcxdumptool and the Wireshark GUI are NOT adapters:
 * they surface in health as DISABLED / ANALYST_TOOL descriptor
 * entries (WIRELESS_DISABLED_REGISTRATIONS) — never as executable
 * pipeline tools (§21/§22/§25/§64). The Kismet instance connector
 * reports NOT_CONFIGURED until an administrator registers an
 * instance (§17).
 */
import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import type { ToolRegistry } from "../registry/registry";
import { ProcessToolRunner, type ToolRunner } from "../recon/runner";
import { AircrackMetadataAdapter, HcxToolsAdapter, KismetAdapter, TsharkWirelessAdapter } from "./adapters-wireless";
import { INERT_KISMET_DEPS, WIRELESS_DISABLED_REGISTRATIONS, type KismetInstanceDeps } from "./types";

export const WIRELESS_SLUGS = ["kismet", "tshark-wireless", "hcxtools", "aircrack-ng"] as const;
/** Tool stages the wireless adapters may run in (§15 profiles). */
export const WIRELESS_TOOL_STAGES = ["WIRELESS_PASSIVE_DISCOVERY", "WIRELESS_PCAP_ANALYSIS"] as const;

export function createWirelessAdapters(runner: ToolRunner = new ProcessToolRunner()): SecurityToolAdapter[] {
  return [
    new KismetAdapter(runner), new TsharkWirelessAdapter(runner),
    new HcxToolsAdapter(runner), new AircrackMetadataAdapter(runner),
  ];
}

export function registerWirelessAdapters(registry: ToolRegistry, runner: ToolRunner = new ProcessToolRunner()): string[] {
  const registered: string[] = [];
  for (const adapter of createWirelessAdapters(runner)) {
    if (registry.resolve(adapter.metadata.slug)) continue;
    registry.register(adapter);
    registered.push(adapter.metadata.slug);
  }
  return registered;
}

/** §17: administrator-managed Kismet instance connector. Server
 *  authentication is a secret REFERENCE only. The production
 *  transport is deliberately unwired in this build: an instance
 *  reports NOT_CONFIGURED honestly rather than fabricating a feed. */
export class KismetInstanceConnector {
  constructor(private readonly deps: KismetInstanceDeps = INERT_KISMET_DEPS) {}

  async healthCheck(): Promise<{ status: string; detail?: string }> {
    if (!this.deps.instanceConfigured) {
      return {
        status: "NOT_CONFIGURED",
        detail: "no administrator-managed Kismet instance is registered (§17) — passive discovery runs through sensor-local adapters instead",
      };
    }
    return {
      status: "NOT_CONFIGURED",
      detail: `Kismet instance "${this.deps.instanceRef ?? "unnamed"}" is registered but its transport is not provisioned in this build — no observations are fabricated`,
    };
  }
}

/** Plan-time health record (synchronous): executing adapters report
 *  their PATH probe; the Kismet instance reports NOT_CONFIGURED at
 *  plan time; governed descriptors report their non-executing state
 *  verbatim. */
export function wirelessHealthRecord(adapters: SecurityToolAdapter[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const adapter of adapters) {
    if ((WIRELESS_SLUGS as readonly string[]).includes(adapter.metadata.slug)) {
      const probe = (adapter as { isExecutablePresent?: () => boolean }).isExecutablePresent?.();
      out[adapter.metadata.slug] = probe ? "HEALTHY" : "UNAVAILABLE";
    }
  }
  out["kismet-instance"] = "NOT_CONFIGURED";
  for (const reg of WIRELESS_DISABLED_REGISTRATIONS) {
    out[reg.slug] = reg.executionState;
  }
  return out;
}

/** §80 health surface: executing adapters probe their binary; the
 *  instance connector reports its honest state; descriptors report
 *  their governed non-executing state. Nothing fabricates readiness. */
export async function wirelessHealthBySlug(
  adapters: SecurityToolAdapter[],
  deps: KismetInstanceDeps = INERT_KISMET_DEPS,
): Promise<Record<string, { status: string; detail?: string }>> {
  const out: Record<string, { status: string; detail?: string }> = {};
  for (const adapter of adapters) {
    if ((WIRELESS_SLUGS as readonly string[]).includes(adapter.metadata.slug)) {
      out[adapter.metadata.slug] = await adapter.healthCheck();
    }
  }
  out["kismet-instance"] = await new KismetInstanceConnector(deps).healthCheck();
  for (const reg of WIRELESS_DISABLED_REGISTRATIONS) {
    out[reg.slug] = { status: reg.executionState, detail: reg.reason };
  }
  return out;
}
