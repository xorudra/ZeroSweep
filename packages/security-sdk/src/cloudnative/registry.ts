/**
 * Prompt 13 — cloud-native adapter registry (§10/§93).
 * Grype is deliberately NOT here: it lives in the code family
 * (CODE_SLUGS) and was EXTENDED for image/SBOM inputs (§19) rather
 * than duplicated. FALCO is an ingestion connector, not a scan
 * adapter — it has no slug in the executable set.
 */
import type { ToolRegistry } from "../registry/registry";
import type { ToolRunner } from "../recon/runner";
import { ProcessToolRunner } from "../recon/runner";
import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import {
  CheckovAdapter, DockerBenchAdapter, FalcoConnector, INERT_KUBERNETES_DEPS, KubeBenchAdapter,
  KubeHunterAdapter, KubernetesConnector, KubescapeAdapter, SyftAdapter, TrivyAdapter,
  type KubernetesConnectorDeps,
} from "./adapters-cloud";

/** Executable cloud-native adapter slugs (tool stages). */
export const CLOUD_NATIVE_SLUGS = [
  "trivy", "syft", "docker-bench-for-security", "kube-bench", "kube-hunter",
  "kubescape", "checkov", "kubernetes-connector",
] as const;

/** INTERNAL_PRIVILEGED adapters (§28/§39): the executor additionally
 *  requires the PRIVILEGED_HOST_ASSESSMENT worker capability AND an
 *  approved host/cluster — plan selection alone never runs them. */
export const PRIVILEGED_CLOUD_SLUGS = ["docker-bench-for-security", "kube-bench"] as const;

/** The §93 tool-health surface: the nine governed tools of this phase. */
export const CLOUD_NATIVE_TOOL_SLUGS = [
  "trivy", "grype", "syft", "docker-bench-for-security", "kube-bench",
  "kube-hunter", "kubescape", "falco", "checkov",
] as const;

export function createCloudNativeAdapters(
  runner: ToolRunner = new ProcessToolRunner(),
  connectorDeps: KubernetesConnectorDeps = INERT_KUBERNETES_DEPS,
): SecurityToolAdapter[] {
  return [
    new SyftAdapter(runner),
    new TrivyAdapter(runner),
    new DockerBenchAdapter(runner),
    new KubeBenchAdapter(runner),
    new KubeHunterAdapter(runner),
    new KubescapeAdapter(runner),
    new CheckovAdapter(runner),
    new KubernetesConnector(connectorDeps),
  ];
}

export function registerCloudNativeAdapters(
  registry: ToolRegistry,
  runner: ToolRunner = new ProcessToolRunner(),
  connectorDeps: KubernetesConnectorDeps = INERT_KUBERNETES_DEPS,
): SecurityToolAdapter[] {
  const adapters = createCloudNativeAdapters(runner, connectorDeps);
  for (const adapter of adapters) registry.register(adapter);
  return adapters;
}

/** Plan-time health (§93): synchronous PATH probe per adapter. Falco
 *  is an ingestion path, so its health describes the INGESTION
 *  configuration, never a binary. The Kubernetes connector is
 *  per-cluster NOT_CONFIGURED until a cluster is registered. */
export function cloudNativeHealthBySlug(adapters: SecurityToolAdapter[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const a of adapters) {
    if (a instanceof KubernetesConnector) { out[a.metadata.slug] = "NOT_CONFIGURED"; continue; }
    const probe = (a as { isExecutablePresent?: () => boolean }).isExecutablePresent?.();
    out[a.metadata.slug] = probe ? "HEALTHY" : "UNAVAILABLE";
  }
  out["falco"] = "NOT_CONFIGURED"; // ingestion endpoint is configured per deployment (§57)
  return out;
}

export { FalcoConnector };
