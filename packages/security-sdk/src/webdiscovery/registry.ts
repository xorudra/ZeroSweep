import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import type { ToolRegistry } from "../registry/registry";
import {
  ArjunAdapter, FeroxbusterAdapter, FfufAdapter, GobusterAdapter, WfuzzAdapter,
} from "./adapters-webdiscovery";
import type { ToolRunner } from "../recon/runner";

/**
 * Web-discovery adapter registration (Prompt 6 §2). Same deployment-time,
 * code-installed registry discipline as the recon adapters — the API and
 * the worker build their registries through these helpers so plan-time
 * selection and execution-time resolution can never drift apart.
 */
export const WEB_DISCOVERY_SLUGS = ["ffuf", "feroxbuster", "gobuster", "wfuzz", "arjun"] as const;
export type WebDiscoverySlug = (typeof WEB_DISCOVERY_SLUGS)[number];

export function createWebDiscoveryAdapters(runner?: ToolRunner): SecurityToolAdapter[] {
  return [
    new FfufAdapter(runner), new FeroxbusterAdapter(runner), new GobusterAdapter(runner),
    new WfuzzAdapter(runner), new ArjunAdapter(runner),
  ];
}

export function registerWebDiscoveryAdapters(registry: ToolRegistry, runner?: ToolRunner): SecurityToolAdapter[] {
  const adapters = createWebDiscoveryAdapters(runner);
  for (const adapter of adapters) registry.register(adapter);
  return adapters;
}
