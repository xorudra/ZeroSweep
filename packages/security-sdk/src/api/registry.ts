import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import type { ToolRegistry } from "../registry/registry";
import type { ToolRunner } from "../recon/runner";
import { ApiAdapterBase } from "./api-adapter.base";
import { createApiAdapters } from "./adapters-api";

/**
 * API adapter registration (Prompt 9). Same deployment-time pattern as
 * the other families: workers and the API build the registry through
 * this one helper so they can never drift apart. jwt-tool is registered
 * for capability/policy description; the executor's allowlist decides
 * which slugs actually run in scan stages (jwt-tool never does — JWT
 * analysis is a platform hook over captured/provided tokens, §22).
 */
export const API_SLUGS = ["kiterunner", "schemathesis", "inql", "graphqlmap"] as const;
export type ApiSlug = (typeof API_SLUGS)[number];

export function createApiAdapterSet(runner?: ToolRunner): SecurityToolAdapter[] {
  return createApiAdapters(runner);
}

export function registerApiAdapters(registry: ToolRegistry, runner?: ToolRunner): SecurityToolAdapter[] {
  const adapters = createApiAdapterSet(runner);
  for (const adapter of adapters) registry.register(adapter);
  return adapters;
}

/** Plan-time health, same contract as the other families: HEALTHY when
 *  the trusted binary is present, UNAVAILABLE when it is not. jwt-tool
 *  reports HEALTHY when its in-process inspector is available (it is
 *  platform code, not an external binary). Importers (postman/insomnia)
 *  are platform code too and are reported by the API layer. */
export function apiHealthBySlug(adapters: SecurityToolAdapter[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const adapter of adapters) {
    if (adapter instanceof ApiAdapterBase) {
      out[adapter.metadata.slug] = adapter.metadata.slug === "jwt-tool" ? "HEALTHY" : adapter.isExecutablePresent() ? "HEALTHY" : "UNAVAILABLE";
    }
  }
  return out;
}
