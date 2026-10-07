import { ReconAdapterBase, type ReconPlanParts } from "../recon/recon-adapter.base";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import { emptyParsed, type ReconParser } from "../recon/parsers-common";
import { emptyParsedCloud, type CloudParserContext, type ParsedCloud } from "./parsers-cloud";

/**
 * Base class for cloud-native tool adapters (Prompt 13 §10/§13), built
 * on the recon lifecycle (plan = executable + argument array ONLY, run
 * through the ToolRunner — no shell).
 *
 * Analysis is STATIC (§9): adapters read image layers/config, manifest
 * files or benchmark data. No adapter in this family can run an image,
 * apply a manifest, exec into a pod or talk to a Docker socket — those
 * operations do not exist in any plan this base can produce. Network
 * policy is NO_NETWORK: vulnerability databases and rule packs are
 * provisioned on the CONTAINER_ANALYSIS worker out of band, and image
 * content reaches the worker as a cached artifact, never pulled by a
 * scan-stage tool invocation.
 */
export abstract class CloudAdapterBase extends ReconAdapterBase {
  protected abstract parseCloud(text: string, ctx: CloudParserContext): ParsedCloud;
  protected abstract cloudPlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts;

  protected readonly parser: ReconParser = { tool: "cloudnative", parse: () => emptyParsed() };

  /** Config from the most recent validateConfiguration call — the
   *  lifecycle's parse step receives no config, so worker-derived
   *  identity (image digest, cluster ref) is read from here. */
  protected lastConfig: Record<string, unknown> = {};

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    this.lastConfig = config;
  }

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    return this.cloudPlan(target, config);
  }

  protected override planNetworkPolicy(): "NO_NETWORK" {
    return "NO_NETWORK";
  }

  /** Parser context assembled from worker-derived config ONLY (§12):
   *  the image reference/digest and cluster/host references resolved
   *  by the store from registered assets — never client input. */
  protected parserContext(origin?: CloudParserContext["origin"]): CloudParserContext {
    const c = this.lastConfig;
    return {
      toolSlug: this.metadata.slug,
      ...(typeof c.imageRef === "string" ? { imageRef: c.imageRef } : {}),
      ...(typeof c.imageDigest === "string" ? { imageDigest: c.imageDigest } : {}),
      ...(typeof c.clusterRef === "string" ? { clusterRef: c.clusterRef } : {}),
      ...(typeof c.hostRef === "string" ? { hostRef: c.hostRef } : {}),
      ...(Array.isArray(c.scanKinds) ? { scanKinds: c.scanKinds.map(String) } : {}),
      ...(origin ? { origin } : {}),
    };
  }

  override async parse(raw: string): Promise<ParsedCloud> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    return text ? this.parseCloud(text, this.parserContext()) : emptyParsedCloud();
  }

  override async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedCloud;
    return {
      assets: [], services: [], endpoints: [], technologies: [],
      findings: p.findings ?? [],
      components: p.components ?? [],
      ...(p.sbom ? { sbom: p.sbom } : {}),
      cloudNative: {
        images: p.images ?? [],
        workloads: p.workloads ?? [],
        controlAssessments: p.controlAssessments ?? [],
        manifests: [],
        runtimeEvents: p.runtimeEvents ?? [],
      },
      artifacts: [],
      metrics: { ...(p.metrics ?? {}) },
      mock: false,
    };
  }
}
