/**
 * Prompt 14 — cloud-security adapter registry (§88/§89).
 *
 * Factory + health surface mirroring the earlier families. Pacu is
 * NOT in the executable set: it is exposed as a DISABLED registry
 * descriptor only (§34/§89), so the Tools GUI can show its governed
 * state and policy can name it — no stage can ever select it.
 * "checkov" stays shared with the cloud-native family (§33): one
 * adapter serves IaC correlation here.
 */
import type { ToolRegistry } from "../registry/registry";
import type { ToolRunner } from "../recon/runner";
import { ProcessToolRunner } from "../recon/runner";
import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import {
  AwsInventoryConnector, AzureInventoryConnector, CloudMapperConnector, GcpInventoryConnector,
  ProwlerAdapter, RoadtoolsConnector, ScoutSuiteAdapter, SteampipeAdapter,
} from "./adapters-cloudsec";
import { INERT_CLOUD_DEPS, type CloudConnectorDeps } from "./inventory";
import { PACU_REGISTRATION } from "./types";

/** Executable cloud-security adapter slugs. "pacu" is deliberately
 *  ABSENT (§34) — offensive tooling never executes in this phase. */
export const CLOUD_SEC_SLUGS = [
  "aws-inventory", "azure-inventory", "gcp-inventory",
  "prowler", "scoutsuite", "cloudmapper", "steampipe", "roadtools",
] as const;
export type CloudSecSlug = (typeof CLOUD_SEC_SLUGS)[number];

/** The §88 tool surface for this phase (incl. the shared Checkov). */
export const CLOUD_SEC_TOOL_SLUGS = [...CLOUD_SEC_SLUGS, "checkov", "pacu"] as const;

/** The Pacu registry descriptor (§89): visible in the Tools surface as
 *  DISABLED / APPROVAL REQUIRED, with NO adapter behind it. */
export const PACU_DESCRIPTOR = {
  slug: PACU_REGISTRATION.slug,
  name: "Pacu",
  classification: PACU_REGISTRATION.classification,
  riskLevel: PACU_REGISTRATION.riskLevel,
  status: PACU_REGISTRATION.status,
  requiresApproval: PACU_REGISTRATION.requiresApproval,
  note: PACU_REGISTRATION.note,
};

export function createCloudSecAdapters(
  runner: ToolRunner = new ProcessToolRunner(),
  cloudDeps: CloudConnectorDeps = INERT_CLOUD_DEPS,
): SecurityToolAdapter[] {
  return [
    new AwsInventoryConnector(cloudDeps),
    new AzureInventoryConnector(cloudDeps),
    new GcpInventoryConnector(cloudDeps),
    new ProwlerAdapter(runner),
    new ScoutSuiteAdapter(runner),
    new CloudMapperConnector(),
    new SteampipeAdapter(runner),
    new RoadtoolsConnector(),
  ];
}

export function registerCloudSecAdapters(
  registry: ToolRegistry,
  runner: ToolRunner = new ProcessToolRunner(),
  cloudDeps: CloudConnectorDeps = INERT_CLOUD_DEPS,
): SecurityToolAdapter[] {
  const adapters = createCloudSecAdapters(runner, cloudDeps);
  for (const adapter of adapters) registry.register(adapter);
  return adapters;
}

/** Plan-time health (§89): binary probes for the CLI tools,
 *  NOT_CONFIGURED for per-account/import connectors, and a governed
 *  DISABLED constant for Pacu — never a probe. */
export function cloudSecHealthBySlug(adapters: SecurityToolAdapter[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const a of adapters) {
    const slug = a.metadata.slug;
    if (slug.endsWith("-inventory") || slug === "cloudmapper" || slug === "roadtools") {
      out[slug] = "NOT_CONFIGURED";
      continue;
    }
    const probe = (a as { isExecutablePresent?: () => boolean }).isExecutablePresent?.();
    out[slug] = probe ? "HEALTHY" : "UNAVAILABLE";
  }
  out[PACU_REGISTRATION.slug] = "DISABLED";
  return out;
}
