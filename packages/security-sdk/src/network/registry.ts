import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import type { ToolRegistry } from "../registry/registry";
import type { ToolRunner } from "../recon/runner";
import {
  ArpScanAdapter, MasscanAdapter, NaabuAdapter, NetdiscoverAdapter, NmapAdapter,
  RustScanAdapter, TcpdumpCaptureAdapter, TsharkAnalysisAdapter,
} from "./adapters-network";
import { NetworkAdapterBase } from "./network-adapter.base";

/**
 * Network adapter registration (Prompt 10 §2/§10). Same deployment-time,
 * code-installed registry discipline as Prompts 5–9: workers and the API
 * build the registry through this one helper so they can never drift
 * apart. Wireshark (§46) is intentionally NOT an adapter — it is a
 * manual analyst/desktop tool; only its capture exports flow in.
 */
export const NETWORK_SLUGS = [
  "nmap", "naabu", "rustscan", "masscan", "netdiscover", "arp-scan", "tcpdump", "tshark",
] as const;
export type NetworkSlug = (typeof NETWORK_SLUGS)[number];

export function createNetworkAdapters(runner?: ToolRunner): SecurityToolAdapter[] {
  return [
    new NmapAdapter(runner), new NaabuAdapter(runner), new RustScanAdapter(runner),
    new MasscanAdapter(runner), new NetdiscoverAdapter(runner), new ArpScanAdapter(runner),
    new TcpdumpCaptureAdapter(runner), new TsharkAnalysisAdapter(runner),
  ];
}

export function registerNetworkAdapters(registry: ToolRegistry, runner?: ToolRunner): SecurityToolAdapter[] {
  const adapters = createNetworkAdapters(runner);
  for (const adapter of adapters) registry.register(adapter);
  return adapters;
}

/** Plan-time health for network adapters (§86): synchronous PATH probe —
 *  HEALTHY when the trusted binary is present, UNAVAILABLE when it is
 *  not. Absence is reported, never faked. */
export function networkHealthBySlug(adapters: SecurityToolAdapter[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const adapter of adapters) {
    if (adapter instanceof NetworkAdapterBase) {
      out[adapter.metadata.slug] = adapter.isExecutablePresent() ? "HEALTHY" : "UNAVAILABLE";
    }
  }
  return out;
}
