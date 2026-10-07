import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import type { ToolRegistry } from "../registry/registry";
import type { ToolRunner } from "../recon/runner";
import { NiktoAdapter, NucleiAdapter, SslyzeAdapter, TestsslAdapter } from "./adapters-vuln";
import { VulnAdapterBase } from "./vuln-adapter.base";

/**
 * Vulnerability/TLS adapter registration (Prompt 7 §2). Same
 * deployment-time, code-installed registry discipline as Prompts 5–6.
 */
export const VULN_SLUGS = ["nuclei", "nikto", "testssl", "sslyze"] as const;
export type VulnSlug = (typeof VULN_SLUGS)[number];

export function createVulnAdapters(runner?: ToolRunner): SecurityToolAdapter[] {
  return [
    new NucleiAdapter(runner), new NiktoAdapter(runner),
    new TestsslAdapter(runner), new SslyzeAdapter(runner),
  ];
}

export function registerVulnAdapters(registry: ToolRegistry, runner?: ToolRunner): SecurityToolAdapter[] {
  const adapters = createVulnAdapters(runner);
  for (const adapter of adapters) registry.register(adapter);
  return adapters;
}

/** Plan-time health for vuln adapters: synchronous PATH probe, HEALTHY /
 *  UNAVAILABLE — an absent binary is reported, never faked (§49). */
export function vulnHealthBySlug(adapters: SecurityToolAdapter[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const adapter of adapters) {
    if (adapter instanceof VulnAdapterBase) {
      out[adapter.metadata.slug] = adapter.isExecutablePresent() ? "HEALTHY" : "UNAVAILABLE";
    }
  }
  return out;
}
