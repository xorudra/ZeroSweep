/**
 * Prompt 13 — cloud-native adapters (§12–§47).
 *
 * Syft (SBOM), Trivy (image vulnerabilities + misconfiguration +
 * secrets), Docker Bench and kube-bench (INTERNAL_PRIVILEGED CIS
 * benchmarks), kube-hunter (policy-governed discovery), Kubescape
 * (posture), Checkov (IaC/manifest static analysis) — plus the
 * KubernetesConnector (read-only cluster inventory + posture) and the
 * FalcoConnector (runtime event ingestion; NOT a scan adapter).
 *
 * Nothing here executes an image, applies a manifest, renders a Helm
 * chart, execs into a pod or mounts a Docker socket (§9/§47/§50/§106).
 */
import { BaseSecurityToolAdapter } from "../adapter/adapter.base";
import { AdapterConfigurationError, AdapterUnavailableError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { ExecutionPlan } from "../execution/execution.types";
import type { ToolMetadata } from "../adapter/adapter.types";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import type { ReconPlanParts } from "../recon/recon-adapter.base";
import { CloudAdapterBase } from "./cloud-adapter.base";
import {
  parseCheckov, parseDockerBench, parseFalcoEvents, parseKubeBench, parseKubeHunter,
  parseKubescape, parseSyft, parseTrivy, emptyParsedCloud, type ParsedCloud,
} from "./parsers-cloud";
import { assessKubernetesPosture, type PostureInventory } from "./posture";
import { kubeHunterCheckAllowed } from "./correlation";
import { sanitizeCloudText } from "./sanitize";
import type { NormalizedKubernetesWorkload, NormalizedRuntimeEvent } from "./types";

function cloudMeta(partial: Partial<ToolMetadata> & Pick<ToolMetadata, "id" | "slug" | "name" | "description" | "homepage" | "licenseType" | "capabilities">): ToolMetadata {
  return {
    adapterVersion: "1.0.0",
    category: "CONTAINER",
    executionMode: "CONTAINER",
    riskLevel: "LOW",
    requiresApproval: false,
    supportedTargetTypes: ["CONTAINER_IMAGE"],
    supportedOutputFormats: ["JSON"],
    requiresCredentials: [],
    supportsContainerExecution: true,
    supportsCancellation: true,
    supportsProgress: false,
    defaultTimeoutSeconds: 1200, maxTimeoutSeconds: 3600,
    resources: { cpu: "2", memory: "2Gi", timeoutSeconds: 1200 },
    inputSchema: [
      { name: "imageRef", type: "string", description: "Image reference resolved by the worker from the registered image asset — never client-supplied" },
      { name: "imageDigest", type: "string", description: "Digest the IMAGE_RESOLUTION stage resolved for this scan (strongest identity, §5)" },
    ],
    ...partial,
  } as ToolMetadata;
}

function str(config: Record<string, unknown>, key: string): string | undefined {
  const v = config[key];
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

// ── Syft (§12) ───────────────────────────────────────────────────────

export class SyftAdapter extends CloudAdapterBase {
  readonly metadata = cloudMeta({
    id: "syft", slug: "syft", name: "Syft",
    description: "SBOM generation for container images (§12): produces the package inventory in CycloneDX/SPDX form that feeds the existing SBOM models. Static analysis only — the image is never run.",
    homepage: "https://github.com/anchore/syft", licenseType: "OPEN_SOURCE",
    capabilities: ["SBOM_GENERATION", "IMAGE_ANALYSIS"],
    inputSchema: [
      { name: "imageRef", type: "string", description: "Image reference resolved by the worker from the registered image asset" },
      { name: "imageDigest", type: "string", description: "Resolved digest for this scan (§5)" },
      { name: "sbomRef", type: "string", description: "Optional SBOM artifact to inventory instead of an image" },
    ],
  });
  readonly executable = "syft";
  readonly containerImage = "anchore/syft:latest";
  readonly versionArgs = ["version"];

  protected cloudPlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const source = str(config, "sbomRef") ? `sbom:${str(config, "sbomRef")}`
      : str(config, "imageRef") ?? target.value;
    return { args: ["packages", source, "-o", "syft-json"] };
  }
  protected parseCloud(text: string, ctx: Parameters<CloudAdapterBase["parseCloud"]>[1]): ParsedCloud {
    return parseSyft(text, ctx);
  }
}

// ── Trivy (§13–§18) ──────────────────────────────────────────────────

export class TrivyAdapter extends CloudAdapterBase {
  readonly metadata = cloudMeta({
    id: "trivy", slug: "trivy", name: "Trivy",
    description: "Image vulnerability, misconfiguration and secret scanning (§15–§18). Modes are separate result kinds: CVEs never borrow config identity, config findings map to controls, secrets are metadata-only. Vulnerability DB is worker-provisioned; scans run offline.",
    homepage: "https://github.com/aquasecurity/trivy", licenseType: "OPEN_SOURCE",
    capabilities: ["IMAGE_VULNERABILITY_SCANNING", "MISCONFIGURATION_SCANNING", "SECRET_SCANNING", "IMAGE_ANALYSIS"],
    inputSchema: [
      { name: "imageRef", type: "string", description: "Image reference resolved by the worker" },
      { name: "imageDigest", type: "string", description: "Resolved digest for this scan (§5)" },
      { name: "scanKinds", type: "string[]", description: "Worker-derived scanner kinds for the profile: vuln | config | secret (§16)" },
      { name: "scanTarget", type: "string", description: "image | fs — worker-derived from the profile (§11)" },
      { name: "sourcePath", type: "string", description: "Snapshot path for filesystem (misconfiguration) scans" },
    ],
  });
  readonly executable = "trivy";
  readonly containerImage = "aquasec/trivy:latest";
  readonly versionArgs = ["version"];

  protected cloudPlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const kinds = Array.isArray(config.scanKinds) && config.scanKinds.length > 0
      ? (config.scanKinds as string[]).filter((k) => ["vuln", "config", "secret"].includes(k))
      : ["vuln", "config", "secret"];
    // Offline discipline: DBs are provisioned on the worker out of band
    // (same rule as Grype §13) — a scan never downloads a database.
    const common = ["--format", "json", "--scanners", kinds.join(","), "--skip-db-update", "--skip-java-db-update", "--offline-scan"];
    if (str(config, "scanTarget") === "fs") {
      return { args: ["fs", ...common, str(config, "sourcePath") ?? target.value] };
    }
    return { args: ["image", ...common, str(config, "imageRef") ?? target.value] };
  }
  protected parseCloud(text: string, ctx: Parameters<CloudAdapterBase["parseCloud"]>[1]): ParsedCloud {
    return parseTrivy(text, ctx);
  }
}

// ── Docker Bench (§28–§31) — INTERNAL_PRIVILEGED ─────────────────────

export class DockerBenchAdapter extends CloudAdapterBase {
  readonly metadata = cloudMeta({
    id: "docker-bench-for-security", slug: "docker-bench-for-security", name: "Docker Bench for Security",
    description: "CIS Docker Benchmark checks against an APPROVED Docker host (§28). Classified INTERNAL_PRIVILEGED: runs only from the dedicated privileged worker against an explicitly approved host in an approved assessment.",
    homepage: "https://github.com/docker/docker-bench-security", licenseType: "OPEN_SOURCE",
    riskLevel: "MODERATE",
    requiresApproval: true,
    supportedTargetTypes: ["DOCKER_HOST", "DOCKER"],
    capabilities: ["DOCKER_CIS_ASSESSMENT", "DOCKER_HOST_CONFIGURATION", "COMPLIANCE_ASSESSMENT"],
    inputSchema: [
      { name: "hostRef", type: "string", description: "Approved Docker host reference resolved by the worker from the registered asset" },
    ],
  });
  readonly executable = "docker-bench-security";
  readonly containerImage = "docker/docker-bench-security:latest";
  readonly versionArgs = ["-v"];
  /** §28 classification marker the executor gates on. */
  readonly classification = "INTERNAL_PRIVILEGED" as const;

  protected cloudPlan(_target: AdapterTarget, _config: Record<string, unknown>): ReconPlanParts {
    // The governed wrapper on the privileged worker runs the benchmark
    // on the approved host and captures its JSON report; no host, port
    // or socket path is ever an argument (§28/§30).
    return { args: [] };
  }
  protected parseCloud(text: string, ctx: Parameters<CloudAdapterBase["parseCloud"]>[1]): ParsedCloud {
    return parseDockerBench(text, ctx);
  }
}

// ── kube-bench (§39–§41) — INTERNAL_PRIVILEGED ───────────────────────

export class KubeBenchAdapter extends CloudAdapterBase {
  readonly metadata = cloudMeta({
    id: "kube-bench", slug: "kube-bench", name: "kube-bench",
    description: "CIS Kubernetes Benchmark checks (§39). Classified INTERNAL_PRIVILEGED: node-level checks run only from the dedicated privileged worker against an explicitly approved cluster.",
    homepage: "https://github.com/aquasecurity/kube-bench", licenseType: "OPEN_SOURCE",
    riskLevel: "MODERATE",
    requiresApproval: true,
    supportedTargetTypes: ["KUBERNETES_CLUSTER", "KUBERNETES"],
    capabilities: ["KUBERNETES_CIS_ASSESSMENT", "COMPLIANCE_ASSESSMENT"],
    inputSchema: [
      { name: "clusterRef", type: "string", description: "Approved cluster reference resolved by the worker" },
    ],
  });
  readonly executable = "kube-bench";
  readonly containerImage = "aquasec/kube-bench:latest";
  readonly versionArgs = ["--version"];
  readonly classification = "INTERNAL_PRIVILEGED" as const;

  protected cloudPlan(_target: AdapterTarget, _config: Record<string, unknown>): ReconPlanParts {
    return { args: ["--json"] };
  }
  protected parseCloud(text: string, ctx: Parameters<CloudAdapterBase["parseCloud"]>[1]): ParsedCloud {
    return parseKubeBench(text, ctx);
  }
}

// ── kube-hunter (§42/§43) ────────────────────────────────────────────

export class KubeHunterAdapter extends CloudAdapterBase {
  readonly metadata = cloudMeta({
    id: "kube-hunter", slug: "kube-hunter", name: "kube-hunter",
    description: "Kubernetes exposure discovery (§42). Governed by the check policy: automated runs use the least-intrusive passive mode ONLY; active hunting is never built into a plan (§43/§114).",
    homepage: "https://github.com/aquasecurity/kube-hunter", licenseType: "OPEN_SOURCE",
    riskLevel: "MODERATE",
    requiresApproval: true,
    supportedTargetTypes: ["KUBERNETES_CLUSTER", "KUBERNETES"],
    capabilities: ["KUBERNETES_SECURITY_DISCOVERY", "KUBERNETES_POSTURE_TESTING"],
    inputSchema: [
      { name: "clusterRef", type: "string", description: "Approved cluster reference resolved by the worker" },
      { name: "hunterMode", type: "string", description: "PASSIVE_DISCOVERY only — any other value is refused at plan time (§43)" },
    ],
  });
  readonly executable = "kube-hunter";
  readonly containerImage = "aquasec/kube-hunter:latest";
  readonly versionArgs = ["--version"];

  /** The plan builder is the policy enforcement point (§43): only the
   *  passive discovery mode exists. `--active` can never appear. */
  protected cloudPlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const mode = str(config, "hunterMode") ?? "PASSIVE_DISCOVERY";
    if (mode !== "PASSIVE_DISCOVERY") {
      throw new AdapterConfigurationError(`kube-hunter: mode ${mode} is not automatable — automated runs are limited to the least-intrusive passive discovery (§43)`);
    }
    if (!kubeHunterCheckAllowed("api-server")) throw new AdapterConfigurationError("kube-hunter: policy denies the discovery check set");
    return { args: ["--remote", target.value, "--report", "json", "--dispatch", "stdout"] };
  }
  protected parseCloud(text: string, ctx: Parameters<CloudAdapterBase["parseCloud"]>[1]): ParsedCloud {
    return parseKubeHunter(text, ctx);
  }
}

// ── Kubescape (§44/§45) ──────────────────────────────────────────────

export class KubescapeAdapter extends CloudAdapterBase {
  readonly metadata = cloudMeta({
    id: "kubescape", slug: "kubescape", name: "Kubescape",
    description: "Kubernetes posture + manifest compliance (§44): NSA/CISA and MITRE control evaluation over cluster inventory or static manifests. Duplicate configuration findings dedupe via the shared §54 fingerprint (§45).",
    homepage: "https://github.com/kubescape/kubescape", licenseType: "OPEN_SOURCE",
    supportedTargetTypes: ["KUBERNETES_CLUSTER", "KUBERNETES", "KUBERNETES_MANIFEST", "SOURCE_REPOSITORY"],
    capabilities: ["KUBERNETES_POSTURE", "MANIFEST_ANALYSIS", "COMPLIANCE_ASSESSMENT"],
    inputSchema: [
      { name: "clusterRef", type: "string", description: "Cluster reference for live posture scans (worker-resolved)" },
      { name: "scanMode", type: "string", description: "cluster | manifests — worker-derived from the stage/profile" },
      { name: "sourcePath", type: "string", description: "Snapshot path for manifest scans" },
    ],
  });
  readonly executable = "kubescape";
  readonly containerImage = "kubescape/kubescape:latest";
  readonly versionArgs = ["version"];

  protected cloudPlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    if (str(config, "scanMode") === "manifests") {
      return { args: ["scan", str(config, "sourcePath") ?? target.value, "--format", "json"] };
    }
    return { args: ["scan", "--format", "json"] };
  }
  protected override parserContext() {
    return super.parserContext(this.lastConfig.scanMode === "manifests" ? "STATIC_CONFIGURATION_FINDING" : "LIVE_CLUSTER_FINDING");
  }
  protected parseCloud(text: string, ctx: Parameters<CloudAdapterBase["parseCloud"]>[1]): ParsedCloud {
    return parseKubescape(text, ctx);
  }
}

// ── Checkov (§46/§47) ────────────────────────────────────────────────

export class CheckovAdapter extends CloudAdapterBase {
  readonly metadata = cloudMeta({
    id: "checkov", slug: "checkov", name: "Checkov",
    description: "Static IaC analysis (§46): Dockerfiles, Kubernetes manifests, Helm charts and Terraform over the source snapshot. Nothing is executed, applied or rendered — Helm hooks and templates are never run (§47/§50).",
    homepage: "https://www.checkov.io", licenseType: "OPEN_SOURCE",
    supportedTargetTypes: ["SOURCE_REPOSITORY", "KUBERNETES_MANIFEST", "HELM_CHART", "CONTAINER_IMAGE", "KUBERNETES_CLUSTER"],
    capabilities: ["IAC_SECURITY", "KUBERNETES_MANIFEST_SECURITY", "DOCKERFILE_SECURITY", "HELM_SECURITY"],
    inputSchema: [
      { name: "sourcePath", type: "string", description: "Snapshot workspace path resolved by the worker — never client-supplied" },
    ],
  });
  readonly executable = "checkov";
  readonly containerImage = "bridgecrew/checkov:latest";
  readonly versionArgs = ["--version"];

  protected cloudPlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const path = str(config, "sourcePath") ?? target.value;
    // --skip-download: no external policy packs are fetched at scan
    // time; --soft-fail=false default keeps exit semantics honest.
    return { args: ["-d", path, "--output", "json", "--quiet", "--skip-download"] };
  }
  protected parseCloud(text: string, ctx: Parameters<CloudAdapterBase["parseCloud"]>[1]): ParsedCloud {
    return parseCheckov(text, ctx);
  }
}

// ── Kubernetes connector (§32–§38) ──────────────────────────────────

/** Cluster record as the store resolves it — reference + credential
 *  REFERENCE only (§33). */
export interface KubernetesClusterRecord {
  id: string;
  name: string;
  apiServerReference: string;
  credentialReference?: string;
  version?: string;
}

/** Read-only cluster transport (§34/§82). Implementations list
 *  inventory through the bounded access policy; there is deliberately
 *  NO write/apply/exec/watch-forever method on this interface. Secret
 *  objects come back as METADATA stubs only (name/namespace/type) —
 *  the transport contract forbids returning data/stringData values. */
export interface KubernetesTransport {
  inventory(cluster: KubernetesClusterRecord): Promise<{
    version?: string;
    namespaces: string[];
    workloads: NormalizedKubernetesWorkload[];
    roleBindings?: PostureInventory["roleBindings"];
    namespacesWithNetworkPolicy?: string[];
    ingresses?: PostureInventory["ingresses"];
    secretMetadataCount: number;
  }>;
}

export interface KubernetesConnectorDeps {
  clusters: { getById(id: string): Promise<KubernetesClusterRecord | null> };
  transport: KubernetesTransport;
}

/** Inert deps for plan-time registration (API): no cluster can resolve,
 *  so the connector honestly reports NOT_CONFIGURED (§34). */
export const INERT_KUBERNETES_DEPS: KubernetesConnectorDeps = {
  clusters: { async getById() { return null; } },
  transport: {
    async inventory() { throw new AdapterUnavailableError("kubernetes: no cluster transport is wired in this process"); },
  },
};

/**
 * The KubernetesConnector (§34): CLUSTER_INVENTORY and
 * POSTURE_ASSESSMENT over read-only inventory. It never retrieves
 * Secret values (§36/§105), never uses service-account tokens (§67),
 * and never mutates the cluster — the transport interface has no
 * write surface at all.
 */
export class KubernetesConnector extends BaseSecurityToolAdapter {
  readonly metadata = cloudMeta({
    id: "kubernetes-connector", slug: "kubernetes-connector", name: "Kubernetes Connector",
    description: "Read-only cluster inventory + posture assessment (§34–§38) over a registered cluster connection (secret-reference credentials, least-privilege service account). Secret values are never retrieved; no cluster mutation exists in this connector.",
    homepage: "https://kubernetes.io", licenseType: "OPEN_SOURCE",
    executionMode: "EXTERNAL_API",
    supportsContainerExecution: false,
    supportedTargetTypes: ["KUBERNETES_CLUSTER", "KUBERNETES"],
    capabilities: ["CLUSTER_INVENTORY", "RESOURCE_INVENTORY", "POSTURE_ASSESSMENT"],
    inputSchema: [
      { name: "clusterId", type: "string", description: "Registered cluster id resolved by the worker from the scan's target — never client-supplied" },
      { name: "inventoryMode", type: "string", description: "CLUSTER_INVENTORY | POSTURE_ASSESSMENT — worker-derived from the stage" },
    ],
  });

  private lastRaw = "";
  private pendingConfig: Record<string, unknown> | undefined;

  constructor(private readonly deps: KubernetesConnectorDeps) { super(); }

  async checkAvailability(): Promise<boolean> {
    return true; // availability is per-cluster (NOT_CONFIGURED when unregistered), resolved at execute time
  }

  async healthCheck(): Promise<{ status: string; detail?: string }> {
    return { status: "UNKNOWN", detail: "Kubernetes connector health is per-cluster: NOT_CONFIGURED until a cluster is registered for the workspace (§34)" };
  }

  async buildExecutionPlan(_target: AdapterTarget, config: Record<string, unknown>): Promise<ExecutionPlan> {
    await this.validateConfiguration(config);
    return {
      adapterId: this.metadata.id, toolId: this.metadata.id, executionMode: "EXTERNAL_API",
      arguments: [], environmentReferences: [],
      timeoutSeconds: this.metadata.defaultTimeoutSeconds,
      cpuLimit: this.metadata.resources.cpu, memoryLimit: this.metadata.resources.memory,
      networkPolicy: "CUSTOM_ALLOWLIST", expectedOutputFormat: "JSON", outputFiles: [],
    };
  }

  async execute(_plan: ExecutionPlan): Promise<{ rawOutputLocation?: string; rawOutput?: string }> {
    const config = this.pendingConfig;
    if (!config) throw new AdapterConfigurationError("kubernetes: execute() called without buildExecutionPlan()");
    const clusterId = str(config, "clusterId");
    if (!clusterId) throw new AdapterUnavailableError("kubernetes: no cluster is registered for this scan — connector reports NOT_CONFIGURED (§34)");
    const cluster = await this.deps.clusters.getById(clusterId);
    if (!cluster) throw new AdapterUnavailableError(`kubernetes: cluster ${clusterId} no longer exists`);
    const inventory = await this.deps.transport.inventory(cluster);
    const mode = str(config, "inventoryMode") ?? "POSTURE_ASSESSMENT";
    const posture = mode === "POSTURE_ASSESSMENT"
      ? assessKubernetesPosture({
          workloads: inventory.workloads,
          roleBindings: inventory.roleBindings,
          namespacesWithNetworkPolicy: inventory.namespacesWithNetworkPolicy,
          namespaces: inventory.namespaces,
          ingresses: inventory.ingresses,
          kubernetesVersion: inventory.version,
        }, { clusterRef: cluster.name, origin: "LIVE_CLUSTER_FINDING", toolSlug: this.metadata.slug })
      : { findings: [], controlAssessments: [], metrics: {} as Record<string, number> };
    const payload: ParsedCloud = {
      ...emptyParsedCloud(),
      findings: posture.findings,
      workloads: inventory.workloads,
      controlAssessments: posture.controlAssessments,
      metrics: {
        namespaces: inventory.namespaces.length,
        workloads: inventory.workloads.length,
        // §36/§105: proves by count that Secrets were inventoried as
        // metadata only — values were never in the payload.
        secretsMetadataOnly: inventory.secretMetadataCount,
        ...posture.metrics,
      },
    };
    this.lastRaw = JSON.stringify(payload);
    return { rawOutput: this.lastRaw };
  }

  async parse(raw: string): Promise<ParsedCloud> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    if (!text) return emptyParsedCloud();
    return JSON.parse(text) as ParsedCloud;
  }

  async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedCloud;
    return {
      assets: [], services: [], endpoints: [], technologies: [],
      findings: p.findings ?? [], components: [],
      cloudNative: {
        images: [], workloads: p.workloads ?? [], controlAssessments: p.controlAssessments ?? [],
        manifests: [], runtimeEvents: [],
      },
      artifacts: [], metrics: { ...(p.metrics ?? {}) }, mock: false,
    };
  }

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    this.pendingConfig = config;
  }
}

/** Structural check used by the worker's stage executor (confinement). */
export function isKubernetesConnector(adapter: BaseSecurityToolAdapter): adapter is KubernetesConnector {
  return adapter instanceof KubernetesConnector;
}

// ── Falco connector (§57–§63) ────────────────────────────────────────

/**
 * FalcoConnector: runtime events arrive through a DEDICATED ingestion
 * path — never through scan workers (§57). Events are validated,
 * sanitized (§60) and normalized; user-authored rules are never
 * accepted here (§61) — `rule` is the sensor's rule name only.
 * Correlation with workload posture raises CONTEXT around an event
 * (§63); it never claims exploitation occurred.
 */
export class FalcoConnector {
  readonly slug = "falco";

  ingest(text: string, ctx: { clusterRef?: string; maxEvents?: number } = {}): { events: NormalizedRuntimeEvent[]; rejected: number } {
    const parsed = parseFalcoEvents(text, { toolSlug: this.slug, clusterRef: ctx.clusterRef });
    const max = ctx.maxEvents ?? 10000;
    const events = parsed.runtimeEvents.slice(0, max);
    return { events, rejected: parsed.runtimeEvents.length - events.length };
  }

  /** §63 contextual correlation: an event on a workload that also has
   *  posture findings gets context flags (privileged, exposed) — the
   *  event itself stays a detection, not a vulnerability. */
  correlate(
    event: NormalizedRuntimeEvent,
    workloads: NormalizedKubernetesWorkload[],
  ): { contextFlags: string[]; note: string } {
    const workload = workloads.find((w) => w.namespace === event.namespace && (!event.pod || event.pod.startsWith(w.name)));
    if (!workload) return { contextFlags: [], note: "No workload posture context matched this event." };
    const flags: string[] = [];
    if (workload.securityContext.privileged) flags.push("WORKLOAD_PRIVILEGED");
    if (workload.exposure === "PUBLIC_INTERNET") flags.push("WORKLOAD_PUBLICLY_EXPOSED");
    if (workload.securityContext.runAsRoot !== false) flags.push("WORKLOAD_MAY_RUN_AS_ROOT");
    return {
      contextFlags: flags,
      note: sanitizeCloudText(`Event observed on ${workload.kind} ${workload.namespace}/${workload.name}. Context raises triage priority only — a runtime event is a detection, not proof of exploitation (§63).`, 500),
    };
  }
}
