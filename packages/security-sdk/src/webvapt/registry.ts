import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import type { ToolRegistry } from "../registry/registry";
import type { ToolRunner } from "../recon/runner";
import { CommixAdapter, DalfoxAdapter, SqlmapAdapter, SstimapAdapter, WpscanAdapter, XsstrikeAdapter } from "./adapters-injection";

/**
 * Web/API V2 adapter registration (Prompt 32 §2/§3). Same
 * deployment-time, code-installed registry discipline as every other
 * adapter family — the API and the worker build their registries
 * through these helpers so plan-time selection and execution-time
 * resolution can never drift apart.
 */
export const WEB_VAPT_SLUGS = ["dalfox", "xsstrike", "sqlmap", "commix", "sstimap", "wpscan"] as const;
export type WebVaptSlug = (typeof WEB_VAPT_SLUGS)[number];

export function createWebVaptAdapters(runner?: ToolRunner): SecurityToolAdapter[] {
  return [
    new DalfoxAdapter(runner), new XsstrikeAdapter(runner), new SqlmapAdapter(runner),
    new CommixAdapter(runner), new SstimapAdapter(runner), new WpscanAdapter(runner),
  ];
}

export function registerWebVaptAdapters(registry: ToolRegistry, runner?: ToolRunner): SecurityToolAdapter[] {
  const adapters = createWebVaptAdapters(runner);
  for (const adapter of adapters) registry.register(adapter);
  return adapters;
}
