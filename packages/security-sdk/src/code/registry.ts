import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import type { ToolRegistry } from "../registry/registry";
import type { ConnectorDeps } from "../proxy/connector";
import type { ToolRunner } from "../recon/runner";

/** Inert connector deps for plan-time registration (API): no instances
 *  are visible, so SonarQube reports NOT_CONFIGURED and can only be
 *  selected when the caller's registered ScannerInstance rows say so
 *  (the same discipline as the proxy connectors, §53/§66). The worker
 *  always passes REAL deps. */
export const INERT_CONNECTOR_DEPS: ConnectorDeps = {
  instances: {
    listEnabled: async () => [],
    getById: async () => null,
    snapshot: () => [],
  },
  endpoints: { resolve: async () => undefined },
  secrets: { resolve: async () => undefined },
  transport: {
    request: async () => {
      throw new Error("sonarqube: no transport configured on this host (NOT_CONFIGURED)");
    },
  },
};
import {
  BanditAdapter, BrakemanAdapter, CodeqlAdapter, DependencyCheckAdapter,
  GitleaksAdapter, GrypeAdapter, SemgrepAdapter, SonarQubeAdapter,
  SpotbugsAdapter, TrufflehogAdapter,
} from "./adapters-code";
import { CodeAdapterBase } from "./code-adapter.base";

/**
 * Source-code adapter registration (Prompt 12 §53). Deployment-time,
 * code-installed — the same helper builds the registry for the API
 * (plan time) and the worker (execution time) so they can never drift.
 */
export const CODE_SLUGS = [
  "semgrep", "codeql", "bandit", "brakeman", "spotbugs",
  "gitleaks", "trufflehog", "owasp-dependency-check", "grype", "sonarqube",
] as const;
export type CodeSlug = (typeof CODE_SLUGS)[number];

export function createCodeAdapters(runner?: ToolRunner, deps?: ConnectorDeps): SecurityToolAdapter[] {
  const adapters: SecurityToolAdapter[] = [
    new SemgrepAdapter(runner), new CodeqlAdapter(runner), new BanditAdapter(runner),
    new BrakemanAdapter(runner), new SpotbugsAdapter(runner),
    new GitleaksAdapter(runner), new TrufflehogAdapter(runner),
    new DependencyCheckAdapter(runner), new GrypeAdapter(runner),
  ];
  // The SonarQube connector exists only when connector deps are wired
  // (worker: real deps; API plan-time: INERT_CONNECTOR_DEPS so instance
  // rows drive its health). Without deps it is honestly absent (§23).
  if (deps) adapters.push(new SonarQubeAdapter(deps));
  return adapters;
}

export function registerCodeAdapters(registry: ToolRegistry, runner?: ToolRunner, deps?: ConnectorDeps): SecurityToolAdapter[] {
  const adapters = createCodeAdapters(runner, deps);
  for (const adapter of adapters) registry.register(adapter);
  return adapters;
}

/** Plan-time health for code adapters: synchronous PATH probe for CLI
 *  tools; the SonarQube connector reports NOT_CONFIGURED synchronously
 *  (its instance resolution is async — plan time treats an unprobed
 *  connector as NOT_CONFIGURED until the worker resolves it). */
export function codeHealthBySlug(adapters: SecurityToolAdapter[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const adapter of adapters) {
    if (adapter instanceof CodeAdapterBase) {
      out[adapter.metadata.slug] = adapter.isExecutablePresent() ? "HEALTHY" : "UNAVAILABLE";
    } else if (adapter instanceof SonarQubeAdapter) {
      out[adapter.metadata.slug] = "NOT_CONFIGURED";
    }
  }
  return out;
}
