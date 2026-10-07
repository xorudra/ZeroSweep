import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import type { ToolRegistry } from "../registry/registry";
import { EnvEndpointResolver, EnvSecretResolver, InMemoryScannerInstanceProvider } from "./types";
import type { ScannerInstanceRecord } from "./types";
import { createProxyAdapters, type ScannerConnectorAdapter } from "./adapters-proxy";
import { HttpScannerTransport, type ConnectorDeps } from "./connector";

/**
 * Proxy connector registration (Prompt 8 §2/§16). Same deployment-time,
 * code-installed discipline as the earlier adapter families. Default deps
 * describe THIS host honestly: instances come from an empty in-memory
 * provider unless the host wires a real one (API/worker inject Prisma-
 * backed providers), endpoints resolve from server configuration, and the
 * transport is the SSRF-guarded HTTP transport. With no instances
 * registered, every connector health-reports NOT_CONFIGURED (§66).
 */
export const PROXY_SLUGS = ["owasp-zap", "burp-suite-professional", "caido"] as const;
export type ProxySlug = (typeof PROXY_SLUGS)[number];

export function defaultConnectorDeps(): ConnectorDeps {
  return {
    instances: new InMemoryScannerInstanceProvider(),
    endpoints: new EnvEndpointResolver(),
    secrets: new EnvSecretResolver(),
    transport: new HttpScannerTransport(),
  };
}

export function registerProxyAdapters(registry: ToolRegistry, deps: ConnectorDeps = defaultConnectorDeps()): ScannerConnectorAdapter[] {
  const adapters = createProxyAdapters(deps);
  for (const adapter of adapters) registry.register(adapter);
  return adapters;
}

/**
 * Plan-time health for connectors (§53/§66): derived from the registered
 * instance snapshot — a product with no enabled instance is NOT_CONFIGURED
 * (the selector rejects it and the passive stage stays honestly idle);
 * otherwise the first enabled instance's last known health wins. The
 * worker re-probes live at execution time on its own host.
 */
export function proxyHealthBySlug(instances: ScannerInstanceRecord[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const slug of PROXY_SLUGS) {
    const enabled = instances.filter((i) => i.toolSlug === slug && i.enabled);
    out[slug] = enabled.length === 0 ? "NOT_CONFIGURED" : enabled[0]!.healthStatus;
  }
  return out;
}

export type { ScannerConnectorAdapter };
export type _ProxyAdapterMarker = SecurityToolAdapter;
