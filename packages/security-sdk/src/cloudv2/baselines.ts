/**
 * Prompt 34 — versioned security baselines (§97–§100), coverage
 * builders (§111–§115), orchestrator/tool-job governance (§106–§109)
 * and verification planning (§121–§125).
 *
 * Baselines are declarative expectations over observable posture
 * facts. Drift is a DEVIATION record — it never triggers a provider
 * change: auto-remediation of cloud/IAM/network/cluster state is
 * refused by design (§124), and any future action framework stays
 * disabled-by-default, approval-gated and audited (§125).
 */
import { createHash } from "node:crypto";
import type {
  CloudV2BaselineDeviation, CloudV2BaselineRule, CloudV2CoverageGap,
} from "./types";
import { completionForGaps } from "./types";

/* ------------------------------ Baselines (§97–§100) ------------------------------ */

/** Canonical hash of a baseline rule set — a changed rule set is a
 *  new VERSION, never an in-place edit (§97). */
export function hashBaselineRules(rules: CloudV2BaselineRule[]): string {
  const canonical = [...rules]
    .sort((a, b) => a.ruleId.localeCompare(b.ruleId))
    .map((r) => `${r.ruleId}|${r.expectation}|${r.severity}`)
    .join("\n");
  return createHash("sha256").update(canonical).digest("hex");
}

/** Default governed baseline rule sets (§97–§99): expectations the
 *  platform can verify from collected evidence only. */
export const DEFAULT_CLOUD_BASELINE_RULES: CloudV2BaselineRule[] = [
  { ruleId: "storage-public-access", expectation: "ABSENT", severity: "CRITICAL" },
  { ruleId: "database-public-access", expectation: "ABSENT", severity: "CRITICAL" },
  { ruleId: "audit-logging-disabled", expectation: "ABSENT", severity: "HIGH" },
  { ruleId: "storage-encryption", expectation: "ABSENT", severity: "HIGH" },
  { ruleId: "iam-admin-equivalent", expectation: "REVIEWED", severity: "HIGH" },
  { ruleId: "kms-rotation-disabled", expectation: "ABSENT", severity: "MEDIUM" },
];

export const DEFAULT_CONTAINER_BASELINE_RULES: CloudV2BaselineRule[] = [
  { ruleId: "kev-in-image", expectation: "ABSENT", severity: "CRITICAL" },
  { ruleId: "latest-tag", expectation: "ABSENT", severity: "MEDIUM" },
  { ruleId: "root-user", expectation: "ABSENT", severity: "HIGH" },
  { ruleId: "unapproved-registry", expectation: "ABSENT", severity: "HIGH" },
];

export const DEFAULT_KUBERNETES_BASELINE_RULES: CloudV2BaselineRule[] = [
  { ruleId: "privileged-workload", expectation: "ABSENT", severity: "CRITICAL" },
  { ruleId: "cluster-admin-binding", expectation: "REVIEWED", severity: "CRITICAL" },
  { ruleId: "wildcard-permissions", expectation: "ABSENT", severity: "HIGH" },
  { ruleId: "host-network-workload", expectation: "ABSENT", severity: "HIGH" },
];

/**
 * §100: deviations of current posture facts from an approved
 * baseline. `facts` maps ruleId → observed state ("PRESENT" when the
 * governed check currently produces the finding, "ABSENT" when it
 * does not, "REVIEWED" when a human reviewed exception exists).
 * Rules whose fact is unknown produce NO deviation — unknown is a
 * coverage gap, not drift.
 */
export function evaluateBaselineDeviations(
  rules: CloudV2BaselineRule[],
  facts: Record<string, string>,
): CloudV2BaselineDeviation[] {
  const deviations: CloudV2BaselineDeviation[] = [];
  for (const rule of rules) {
    const observed = facts[rule.ruleId];
    if (observed === undefined) continue;
    if (observed !== rule.expectation) {
      deviations.push({ ruleId: rule.ruleId, expectation: rule.expectation, observed, severity: rule.severity });
    }
  }
  return deviations;
}

/* ------------------------------ Coverage (§111–§115) ------------------------------ */

export interface CloudCoverageInput {
  accountsCovered: number;
  regionsCovered: number;
  regionsAuthorized: number;
  servicesCovered: number;
  resourcesCovered: number;
  iamIdentities: number;
  postureChecks: number;
  connectionResult: string;
  missingPermissions: string[];
  transportConfigured: boolean;
}

/** §112: cloud coverage + gaps. A partial inventory (§110) is
 *  COMPLETED_WITH_GAPS — the environment is never reported clean. */
export function buildCloudCoverage(input: CloudCoverageInput): { coverage: Omit<CloudCoverageInput, "connectionResult" | "missingPermissions" | "transportConfigured">; gaps: CloudV2CoverageGap[]; completion: string } {
  const gaps: CloudV2CoverageGap[] = [];
  if (!input.transportConfigured) {
    gaps.push({ area: "INVENTORY", reason: "TOOL_UNAVAILABLE", detail: "Provider transport NOT_CONFIGURED in this deployment — inventory reflects previously recorded data only." });
  }
  if (input.regionsCovered < input.regionsAuthorized) {
    gaps.push({ area: "REGIONS", reason: "MISSING_PERMISSION", detail: `${input.regionsAuthorized - input.regionsCovered} authorized region(s) could not be inventoried (§110/§144).` });
  }
  for (const perm of input.missingPermissions) {
    gaps.push({ area: "PERMISSIONS", reason: "MISSING_PERMISSION", detail: `Missing read permission: ${perm} (§13).` });
  }
  if (input.connectionResult === "AUTH_FAILED" || input.connectionResult === "EXPIRED") {
    gaps.push({ area: "CONNECTION", reason: "SECRET_UNAVAILABLE", detail: `Connection test result: ${input.connectionResult} — live collection is blocked (§12).` });
  }
  const coverage = {
    accountsCovered: input.accountsCovered, regionsCovered: input.regionsCovered,
    regionsAuthorized: input.regionsAuthorized, servicesCovered: input.servicesCovered,
    resourcesCovered: input.resourcesCovered, iamIdentities: input.iamIdentities,
    postureChecks: input.postureChecks,
  };
  return { coverage, gaps, completion: completionForGaps(gaps) };
}

export interface ContainerCoverageInput {
  registriesCovered: number;
  repositoriesCovered: number;
  imagesCovered: number;
  imagesWithSbom: number;
  imagesScanned: number;
  deploymentCorrelated: number;
  transportConfigured: boolean;
}

/** §113: container coverage — SBOM/vulnerability coverage are ratios
 *  of OBSERVED counts, null when nothing was observed (never 100%
 *  by assumption). */
export function buildContainerCoverage(input: ContainerCoverageInput): {
  coverage: { registriesCovered: number; repositoriesCovered: number; imagesCovered: number; sbomCoverage: number | null; vulnerabilityCoverage: number | null; deploymentCorrelated: number };
  gaps: CloudV2CoverageGap[]; completion: string;
} {
  const gaps: CloudV2CoverageGap[] = [];
  const ratio = (n: number, d: number) => (d > 0 ? Math.round((n / d) * 1000) / 1000 : null);
  if (!input.transportConfigured) gaps.push({ area: "SCANNERS", reason: "TOOL_UNAVAILABLE", detail: "Scanner transports (Trivy/Grype/Syft) report UNAVAILABLE/NOT_CONFIGURED — coverage reflects recorded results only." });
  if (input.imagesCovered > 0 && input.imagesWithSbom < input.imagesCovered) {
    gaps.push({ area: "SBOM", reason: "UNSUPPORTED", detail: `${input.imagesCovered - input.imagesWithSbom} image(s) have no SBOM (§113).` });
  }
  if (input.imagesCovered > 0 && input.imagesScanned < input.imagesCovered) {
    gaps.push({ area: "VULNERABILITY", reason: "TOOL_UNAVAILABLE", detail: `${input.imagesCovered - input.imagesScanned} image(s) have no vulnerability scan result (§113).` });
  }
  return {
    coverage: {
      registriesCovered: input.registriesCovered, repositoriesCovered: input.repositoriesCovered,
      imagesCovered: input.imagesCovered, sbomCoverage: ratio(input.imagesWithSbom, input.imagesCovered),
      vulnerabilityCoverage: ratio(input.imagesScanned, input.imagesCovered),
      deploymentCorrelated: input.deploymentCorrelated,
    },
    gaps, completion: completionForGaps(gaps),
  };
}

export interface KubernetesCoverageInput {
  namespacesCovered: number;
  workloadsCovered: number;
  rbacSubjects: number;
  benchmarkChecks: number;
  imagesCorrelated: number;
  workloadsTotal: number;
  runtimeTelemetry: boolean;
  transportConfigured: boolean;
}

/** §114: Kubernetes coverage. */
export function buildKubernetesCoverage(input: KubernetesCoverageInput): {
  coverage: Omit<KubernetesCoverageInput, "workloadsTotal" | "transportConfigured">;
  gaps: CloudV2CoverageGap[]; completion: string;
} {
  const gaps: CloudV2CoverageGap[] = [];
  if (!input.transportConfigured) gaps.push({ area: "CLUSTER_CONNECTION", reason: "TOOL_UNAVAILABLE", detail: "Live cluster transport NOT_CONFIGURED — assessment reflects recorded inventory only." });
  if (input.workloadsTotal > 0 && input.imagesCorrelated < input.workloadsTotal) {
    gaps.push({ area: "IMAGE_CORRELATION", reason: "UNSUPPORTED", detail: `${input.workloadsTotal - input.imagesCorrelated} workload(s) have images not correlated to SBOM/vulnerability records (§86/§114).` });
  }
  if (!input.runtimeTelemetry) gaps.push({ area: "RUNTIME", reason: "TOOL_UNAVAILABLE", detail: "No Falco runtime telemetry recorded for this cluster (§114)." });
  if (input.benchmarkChecks === 0) gaps.push({ area: "BENCHMARK", reason: "TOOL_UNAVAILABLE", detail: "No kube-bench/Kubescape benchmark results recorded (§114)." });
  const coverage = {
    namespacesCovered: input.namespacesCovered, workloadsCovered: input.workloadsCovered,
    rbacSubjects: input.rbacSubjects, benchmarkChecks: input.benchmarkChecks,
    imagesCorrelated: input.imagesCorrelated, runtimeTelemetry: input.runtimeTelemetry,
  };
  return { coverage, gaps, completion: completionForGaps(gaps) };
}

/* --------------------- Tool-job governance (§106–§109) --------------------- */

export interface ToolJobConstraints {
  isolation: "SCANNER_WORKER";
  timeoutSeconds: number;
  cpuLimit: number;
  memoryMb: number;
  outputLimitBytes: number;
  /** §109: bounded concurrency + backoff for provider APIs. */
  maxConcurrency: number;
  backoffBaseMs: number;
}

const DEFAULT_JOB: ToolJobConstraints = {
  isolation: "SCANNER_WORKER", timeoutSeconds: 1800, cpuLimit: 2,
  memoryMb: 2048, outputLimitBytes: 64 * 1024 * 1024, maxConcurrency: 4, backoffBaseMs: 500,
};

const JOB_OVERRIDES: Record<string, Partial<ToolJobConstraints>> = {
  prowler: { timeoutSeconds: 3600, memoryMb: 4096 },
  scoutsuite: { timeoutSeconds: 3600, memoryMb: 4096 },
  trivy: { timeoutSeconds: 2400 },
  "kube-bench": { timeoutSeconds: 900 },
  kubescape: { timeoutSeconds: 1800 },
  checkov: { timeoutSeconds: 1800 },
};

/** §106–§109: every cloud/container/Kubernetes tool job runs in an
 *  isolated scanner worker with hard resource bounds. */
export function toolJobConstraints(slug: string): ToolJobConstraints {
  return { ...DEFAULT_JOB, ...(JOB_OVERRIDES[slug] ?? {}) };
}

const SHELL_META_RE = /[;|&$`\\<>(){}\n\r]|\$\(|&&|\|\|/;

/**
 * §107/§161: command safety. Account ids, projects, subscriptions,
 * image references, registry names, cluster names, namespaces and
 * file paths are DATA — they are passed as validated argument-array
 * elements, never concatenated into a shell string. A value carrying
 * shell syntax is rejected outright.
 */
export function validateToolArgument(value: string, what = "argument"): { ok: boolean; reason?: string } {
  if (typeof value !== "string" || value.length === 0) return { ok: false, reason: `${what} must be a non-empty string` };
  if (value.length > 1024) return { ok: false, reason: `${what} exceeds the length bound (§107)` };
  if (SHELL_META_RE.test(value)) return { ok: false, reason: `${what} contains shell syntax — treated as data and rejected, never executed (§107/§161)` };
  if (value.startsWith("-") && value.length > 1 && !/^-[a-z0-9]$/i.test(value)) {
    // A leading-dash value could be mistaken for a flag; single-dash refs are data too.
    return { ok: false, reason: `${what} looks like a command flag — refused as an argument value (§107)` };
  }
  return { ok: true };
}

/** Build a validated argv array (§107) — the only way tool arguments
 *  are constructed in V2 planning. Throws on the first unsafe value. */
export function buildToolArgv(parts: string[]): string[] {
  for (const part of parts) {
    const verdict = validateToolArgument(part);
    if (!verdict.ok) throw new Error(verdict.reason);
  }
  return [...parts];
}

/* --------------------- Verification planning (§121–§125) --------------------- */

export type CloudVerificationMethod =
  | "CONFIGURATION_REREAD" | "PROVIDER_STATE_CHECK" | "TARGETED_PROWLER_CHECK" | "TARGETED_STEAMPIPE_CHECK";
export type ContainerVerificationMethod =
  | "NEW_IMAGE_DIGEST" | "NEW_SBOM" | "TRIVY_GRYPE_RESCAN" | "FIXED_VERSION_VERIFICATION";
export type KubernetesVerificationMethod =
  | "MANIFEST_REREAD" | "WORKLOAD_REEVALUATION" | "RBAC_REEVALUATION" | "TARGETED_BENCHMARK_CHECK" | "IMAGE_REEVALUATION";

export interface CloudV2VerificationPlan {
  domain: "CLOUD" | "CONTAINER" | "KUBERNETES";
  methods: string[];
  /** Verification observes state — it never changes it (§121–§124). */
  mutatesTarget: false;
  detail: string;
}

/** §121: cloud fix verification — re-read configuration and compare. */
export function planCloudVerification(ruleId: string): CloudV2VerificationPlan {
  const methods: CloudVerificationMethod[] = ["CONFIGURATION_REREAD", "PROVIDER_STATE_CHECK"];
  if (ruleId.startsWith("iam-") || ruleId.startsWith("storage-") || ruleId.startsWith("database-")) methods.push("TARGETED_PROWLER_CHECK");
  methods.push("TARGETED_STEAMPIPE_CHECK");
  return { domain: "CLOUD", methods, mutatesTarget: false, detail: "Verification re-reads provider configuration and re-runs the targeted governed check; it never modifies the resource (§121)." };
}

/** §122: container fix verification — a fix is a NEW digest + NEW SBOM. */
export function planContainerVerification(): CloudV2VerificationPlan {
  const methods: ContainerVerificationMethod[] = ["NEW_IMAGE_DIGEST", "NEW_SBOM", "TRIVY_GRYPE_RESCAN", "FIXED_VERSION_VERIFICATION"];
  return { domain: "CONTAINER", methods, mutatesTarget: false, detail: "A fixed image is verified by its new digest, a regenerated SBOM and a rescan confirming the fixed package version (§122/§150)." };
}

/** §123: Kubernetes fix verification. */
export function planKubernetesVerification(kind: "WORKLOAD" | "RBAC" | "BENCHMARK" | "IMAGE"): CloudV2VerificationPlan {
  const byKind: Record<string, KubernetesVerificationMethod[]> = {
    WORKLOAD: ["MANIFEST_REREAD", "WORKLOAD_REEVALUATION", "IMAGE_REEVALUATION"],
    RBAC: ["MANIFEST_REREAD", "RBAC_REEVALUATION"],
    BENCHMARK: ["TARGETED_BENCHMARK_CHECK", "WORKLOAD_REEVALUATION"],
    IMAGE: ["IMAGE_REEVALUATION"],
  };
  return { domain: "KUBERNETES", methods: byKind[kind], mutatesTarget: false, detail: "Verification re-reads manifests and re-evaluates the workload/RBAC/benchmark state (§123)." };
}

/** §124: actions the platform will NEVER perform automatically. */
export const FORBIDDEN_AUTO_REMEDIATION_ACTIONS = [
  "CHANGE_IAM", "MODIFY_SECURITY_GROUP", "MAKE_BUCKET_PRIVATE", "ROTATE_CREDENTIALS",
  "DELETE_RESOURCE", "PATCH_CLUSTER", "RESTART_WORKLOAD", "DELETE_POD", "KILL_WORKLOAD",
  "DISABLE_LOGGING", "OPEN_SECURITY_GROUP", "ESCALATE_PRIVILEGE",
] as const;

/** §124/§125: auto-remediation evaluation — always refused in V2.
 *  The output is evidence-backed remediation GUIDANCE, not action. */
export function evaluateAutoRemediationRequest(action: string): { allowed: false; reason: string } {
  return {
    allowed: false,
    reason: `Auto-remediation action "${action}" is refused: the platform never changes IAM, security groups, storage exposure, credentials, resources or workloads automatically (§124). Any future action framework remains disabled by default, approval-gated, provider-specific and fully audited (§125) — this platform produces evidence-backed remediation guidance instead.`,
  };
}
