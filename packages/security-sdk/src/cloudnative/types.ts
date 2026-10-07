/**
 * Prompt 13 — Container, Docker & Kubernetes security: shared domain
 * types (§4–§90).
 *
 * The platform analyzes containers STATICALLY: image layers, image
 * configuration, Dockerfiles, Kubernetes manifests and read-only
 * cluster inventory. Target images and workloads are NEVER executed
 * (§9), no Docker socket is mounted into any general worker (§30/§106),
 * and credentials exist only as secret REFERENCES (§7/§33).
 */
import type {
  NormalizedCloudNativeData, NormalizedContainerImage, NormalizedControlAssessment,
  NormalizedInfrastructureManifest, NormalizedKubernetesWorkload, NormalizedRuntimeEvent,
} from "../findings/finding.types";

export type {
  NormalizedCloudNativeData, NormalizedContainerImage, NormalizedControlAssessment,
  NormalizedInfrastructureManifest, NormalizedKubernetesWorkload, NormalizedRuntimeEvent,
};

export const CLOUD_NATIVE_PROFILES = [
  "CONTAINER_BASELINE", "CONTAINER_COMPREHENSIVE", "SBOM_ONLY", "IMAGE_VULNERABILITIES_ONLY",
  "CONTAINER_MISCONFIG_ONLY", "KUBERNETES_BASELINE", "KUBERNETES_COMPREHENSIVE",
  "DOCKER_HOST_BASELINE", "CLOUD_NATIVE_FULL",
] as const;
export type CloudNativeProfile = (typeof CLOUD_NATIVE_PROFILES)[number];

/** Finding origins (§51/§103): static configuration analysis and live
 *  cluster observation are DIFFERENT evidence kinds; correlation keeps
 *  both observations instead of collapsing them. */
export const FINDING_ORIGINS = [
  "STATIC_CONFIGURATION_FINDING", "LIVE_CLUSTER_FINDING", "IMAGE_FINDING",
  "DOCKER_HOST_FINDING", "RUNTIME_CORRELATED",
] as const;
export type FindingOrigin = (typeof FINDING_ORIGINS)[number];

/** Scan budget for cloud-native work (§81). Every limit is bounded by a
 *  hard cap; there is no unbounded mode. */
export interface CloudNativeBudget {
  maxImages: number;
  maxImageSizeMb: number;
  maxPackagesPerImage: number;
  maxManifestFiles: number;
  maxKubernetesResources: number;
  maxNamespaces: number;
  maxClusterRequests: number;
  maxRuntimeEvents: number;
  maxScanDurationSeconds: number;
}

export const DEFAULT_CLOUD_NATIVE_BUDGET: CloudNativeBudget = {
  maxImages: 25,
  maxImageSizeMb: 2048,
  maxPackagesPerImage: 5000,
  maxManifestFiles: 500,
  maxKubernetesResources: 5000,
  maxNamespaces: 200,
  maxClusterRequests: 500,
  maxRuntimeEvents: 10000,
  maxScanDurationSeconds: 3600,
};

/** Hard caps (§81): budgets may be tightened per engagement, never
 *  raised past these values. */
export const CLOUD_NATIVE_BUDGET_CAPS: CloudNativeBudget = {
  maxImages: 250,
  maxImageSizeMb: 10240,
  maxPackagesPerImage: 20000,
  maxManifestFiles: 5000,
  maxKubernetesResources: 50000,
  maxNamespaces: 2000,
  maxClusterRequests: 5000,
  maxRuntimeEvents: 100000,
  maxScanDurationSeconds: 14400,
};

export function clampCloudNativeBudget(input: Partial<CloudNativeBudget> = {}): CloudNativeBudget {
  const out = { ...DEFAULT_CLOUD_NATIVE_BUDGET };
  for (const key of Object.keys(out) as (keyof CloudNativeBudget)[]) {
    const v = input[key];
    if (typeof v === "number" && Number.isFinite(v) && v > 0) {
      out[key] = Math.min(Math.floor(v), CLOUD_NATIVE_BUDGET_CAPS[key]);
    }
  }
  return out;
}

/** Adapters in this family classify (§28/§39). Only STATIC_ANALYSIS runs
 *  on general workers; INTERNAL_PRIVILEGED benchmark tools additionally
 *  require an explicitly approved host AND a dedicated privileged
 *  worker — the executor enforces both, the plan alone never suffices. */
export type CloudAdapterClassification = "STATIC_ANALYSIS" | "INTERNAL_PRIVILEGED" | "CONNECTOR";

/** kube-hunter check classification (§42). Automated platform behavior:
 *  SAFE checks may run under an approved assessment; REVIEW_REQUIRED
 *  needs explicit per-assessment approval; INTRUSIVE and DISABLED
 *  checks can never be produced by automation. */
export type KubeHunterCheckClass = "SAFE" | "REVIEW_REQUIRED" | "INTRUSIVE" | "DISABLED";

/** Exposure classes for workloads (§64). Internal exposure lowers
 *  priority; it never makes a finding disappear. */
export type WorkloadExposure = NormalizedKubernetesWorkload["exposure"];

/** A parsed container image reference (§5). */
export interface ImageReference {
  registry: string;
  repository: string;
  tag?: string;
  digest?: string;
  /** Canonical display form: registry/repository[:tag][@digest]. */
  reference: string;
}

/** Kubernetes API access discipline (§82): bounded concurrency,
 *  pagination and backoff — never an unbounded list/watch storm. */
export interface ClusterAccessPolicy {
  maxConcurrency: number;
  pageSize: number;
  maxRequests: number;
  backoffBaseMs: number;
  readOnly: true;
}

export const DEFAULT_CLUSTER_ACCESS_POLICY: ClusterAccessPolicy = {
  maxConcurrency: 4,
  pageSize: 100,
  maxRequests: 500,
  backoffBaseMs: 250,
  readOnly: true,
};

/** Compliance frameworks the platform maps controls for (§55). Mapping
 *  supports reporting structure ONLY — never a certification claim. */
export const COMPLIANCE_FRAMEWORKS = [
  { key: "CIS_DOCKER", name: "CIS Docker Benchmark", version: "1.6" },
  { key: "CIS_KUBERNETES", name: "CIS Kubernetes Benchmark", version: "1.8" },
  { key: "NSA_CISA_KUBERNETES", name: "NSA/CISA Kubernetes Hardening Guide", version: "1.2" },
] as const;
export type ComplianceFrameworkKey = (typeof COMPLIANCE_FRAMEWORKS)[number]["key"];
