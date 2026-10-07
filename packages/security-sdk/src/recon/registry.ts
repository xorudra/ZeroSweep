import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import type { ToolRegistry } from "../registry/registry";
import {
  AmassAdapter, AssetfinderAdapter, DnsxAdapter, FindomainAdapter, SubfinderAdapter,
} from "./adapters-discovery";
import {
  GauAdapter, HttpxAdapter, KatanaAdapter, WaybackurlsAdapter, WhatWebAdapter,
} from "./adapters-web";
import { ReconAdapterBase } from "./recon-adapter.base";
import type { ToolRunner } from "./runner";

/**
 * Recon adapter registration (Prompt 5 §2). The registry stays a
 * deployment-time list of trusted, code-installed adapters — workers and the
 * API build it through this one helper so they can never drift apart.
 */
export const RECON_SLUGS = [
  "subfinder", "amass", "assetfinder", "findomain", "dnsx",
  "httpx", "whatweb", "gau", "waybackurls", "katana",
] as const;
export type ReconSlug = (typeof RECON_SLUGS)[number];

export function createReconAdapters(runner?: ToolRunner): SecurityToolAdapter[] {
  return [
    new SubfinderAdapter(runner), new AmassAdapter(runner), new AssetfinderAdapter(runner),
    new FindomainAdapter(runner), new DnsxAdapter(runner),
    new HttpxAdapter(runner), new WhatWebAdapter(runner),
    new GauAdapter(runner), new WaybackurlsAdapter(runner), new KatanaAdapter(runner),
  ];
}

export function registerReconAdapters(registry: ToolRegistry, runner?: ToolRunner): SecurityToolAdapter[] {
  const adapters = createReconAdapters(runner);
  for (const adapter of adapters) registry.register(adapter);
  return adapters;
}

/**
 * Plan-time health for recon adapters (Prompt 5 §39): a synchronous PATH
 * probe — HEALTHY when the trusted binary is present, UNAVAILABLE when it
 * is not. Adapters that are not recon adapters are omitted (callers keep
 * their existing defaults for them).
 */
export function reconHealthBySlug(adapters: SecurityToolAdapter[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const adapter of adapters) {
    if (adapter instanceof ReconAdapterBase) {
      out[adapter.metadata.slug] = adapter.isExecutablePresent() ? "HEALTHY" : "UNAVAILABLE";
    }
  }
  return out;
}
