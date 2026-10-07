/**
 * Prompt 13 — deterministic Kubernetes posture assessment (§38, §64–
 * §73). These checks run over INVENTORY data (connector output or
 * parsed manifests) — they are configuration analysis, not probing.
 * Each failed check produces a configuration finding bound to the
 * §54 fingerprint and a CIS/NSA-CISA control mapping; passing checks
 * produce control assessments only (§56).
 *
 * Discipline notes:
 *  - absent NetworkPolicy is CONTEXT, not an automatic vulnerability
 *    (§66) — it only becomes a finding combined with exposure;
 *  - service-account TOKENS are never retrieved or used (§67) — only
 *    the automount flag is posture;
 *  - an end-of-life Kubernetes version is POTENTIAL_EXPOSURE signal
 *    (§73), never a confirmed vulnerability.
 */
import type { NormalizedControlAssessment, NormalizedFinding, NormalizedKubernetesWorkload } from "../findings/finding.types";
import { configurationFingerprint } from "./correlation";
import { isValidKubernetesName } from "./sanitize";

export interface PostureInventory {
  workloads: NormalizedKubernetesWorkload[];
  /** RBAC objects (§65): role bindings summarized by the connector. */
  roleBindings?: {
    namespace?: string; name: string; roleKind: string; roleName: string;
    subjects: { kind: string; name: string; namespace?: string }[];
    verbs?: string[]; resources?: string[];
  }[];
  /** Namespaces that carry at least one NetworkPolicy (§66). */
  namespacesWithNetworkPolicy?: string[];
  namespaces?: string[];
  /** Ingresses with their exposure (§37/§64). */
  ingresses?: { namespace: string; name: string; hosts: string[]; tls: boolean }[];
  kubernetesVersion?: string;
}

export interface PostureResult {
  findings: NormalizedFinding[];
  controlAssessments: NormalizedControlAssessment[];
  metrics: Record<string, number>;
}

interface CheckDef {
  controlId: string;
  frameworkKey: string;
  title: string;
  severity: NormalizedFinding["severity"];
  fails: (w: NormalizedKubernetesWorkload) => boolean;
  evidence: (w: NormalizedKubernetesWorkload) => string;
  remediation: string;
}

const WORKLOAD_CHECKS: CheckDef[] = [
  {
    controlId: "KSV-0014", frameworkKey: "NSA_CISA_KUBERNETES", title: "Privileged container",
    severity: "CRITICAL",
    fails: (w) => w.securityContext.privileged === true,
    evidence: (w) => `${w.kind} ${w.namespace}/${w.name} runs a privileged container.`,
    remediation: "Remove privileged mode; grant only the specific capabilities the workload needs.",
  },
  {
    controlId: "CIS-5.2.9", frameworkKey: "CIS_KUBERNETES", title: "Host filesystem (hostPath) volume mounted",
    severity: "HIGH",
    fails: (w) => w.securityContext.hostPaths.length > 0,
    evidence: (w) => `${w.kind} ${w.namespace}/${w.name} mounts hostPath volumes: ${w.securityContext.hostPaths.join(", ")}.`,
    remediation: "Replace hostPath volumes with projected volumes, config maps or dedicated storage classes.",
  },
  {
    controlId: "CIS-5.2.5", frameworkKey: "CIS_KUBERNETES", title: "Dangerous Linux capabilities added",
    severity: "HIGH",
    fails: (w) => w.securityContext.addedCapabilities.some((c) => ["ALL", "SYS_ADMIN", "NET_ADMIN"].includes(c.toUpperCase())),
    evidence: (w) => `${w.kind} ${w.namespace}/${w.name} adds dangerous capabilities: ${w.securityContext.addedCapabilities.join(", ")}.`,
    remediation: "Drop ALL capabilities and add back only the minimum required.",
  },
  {
    controlId: "CIS-5.2.6", frameworkKey: "CIS_KUBERNETES", title: "Container may run as root",
    severity: "MEDIUM",
    fails: (w) => w.securityContext.runAsRoot !== false,
    evidence: (w) => `${w.kind} ${w.namespace}/${w.name} does not enforce runAsNonRoot.`,
    remediation: "Set runAsNonRoot: true and runAsUser to a non-root UID in the security context.",
  },
  {
    controlId: "KSV-0012", frameworkKey: "NSA_CISA_KUBERNETES", title: "Writable root filesystem",
    severity: "MEDIUM",
    fails: (w) => w.securityContext.readOnlyRootFilesystem !== true,
    evidence: (w) => `${w.kind} ${w.namespace}/${w.name} allows a writable root filesystem.`,
    remediation: "Set readOnlyRootFilesystem: true and mount tmpfs/emptyDir for scratch paths.",
  },
  {
    controlId: "CIS-5.2.2", frameworkKey: "CIS_KUBERNETES", title: "Host network namespace shared",
    severity: "HIGH",
    fails: (w) => w.securityContext.hostNetwork === true,
    evidence: (w) => `${w.kind} ${w.namespace}/${w.name} shares the host network namespace.`,
    remediation: "Remove hostNetwork unless the workload is a governed node-level agent.",
  },
  {
    controlId: "CIS-5.2.3", frameworkKey: "CIS_KUBERNETES", title: "Host PID namespace shared",
    severity: "HIGH",
    fails: (w) => w.securityContext.hostPid === true,
    evidence: (w) => `${w.kind} ${w.namespace}/${w.name} shares the host PID namespace.`,
    remediation: "Remove hostPID unless the workload is a governed node-level agent.",
  },
  {
    controlId: "CIS-5.7.3", frameworkKey: "CIS_KUBERNETES", title: "Service account token automount not disabled",
    severity: "LOW",
    fails: (w) => w.securityContext.automountServiceAccountToken === true,
    evidence: (w) => `${w.kind} ${w.namespace}/${w.name} automounts the service account token it may not need.`,
    remediation: "Set automountServiceAccountToken: false unless the workload calls the Kubernetes API.",
  },
  {
    controlId: "CIS-5.4.5", frameworkKey: "CIS_KUBERNETES", title: "Default service account in use",
    severity: "LOW",
    fails: (w) => !w.serviceAccount || w.serviceAccount === "default",
    evidence: (w) => `${w.kind} ${w.namespace}/${w.name} uses the default service account.`,
    remediation: "Give the workload a dedicated, least-privilege service account.",
  },
  {
    controlId: "KSV-0015", frameworkKey: "NSA_CISA_KUBERNETES", title: "Image not pinned by digest",
    severity: "MEDIUM",
    fails: (w) => w.images.some((i) => !i.digestPinned),
    evidence: (w) => `${w.kind} ${w.namespace}/${w.name} references an image by tag only: ${w.images.filter((i) => !i.digestPinned).map((i) => i.image).join(", ")}.`,
    remediation: "Pin images by digest (image@sha256:...) so the analyzed artifact is the deployed artifact.",
  },
  {
    controlId: "KSV-0013", frameworkKey: "NSA_CISA_KUBERNETES", title: "Image pull policy allows mutable tags (Always / latest)",
    severity: "LOW",
    fails: (w) => w.images.some((i) => /(^|:)latest$/.test(i.image) || i.image.endsWith(":latest")),
    evidence: (w) => `${w.kind} ${w.namespace}/${w.name} uses the mutable 'latest' tag.`,
    remediation: "Use immutable, versioned tags or digests instead of 'latest'.",
  },
  {
    controlId: "CIS-5.4.1", frameworkKey: "CIS_KUBERNETES", title: "Resource limits not declared",
    severity: "LOW",
    fails: (w) => w.securityContext.resourceLimitsDeclared === false,
    evidence: (w) => `${w.kind} ${w.namespace}/${w.name} declares no CPU/memory limits.`,
    remediation: "Declare resource requests and limits for every container.",
  },
];

/** Dangerous RBAC grants (§65): cluster-admin bindings and wildcard
 *  verbs/resources bound broadly. Analysis of inventory only — the
 *  platform never exercises the permissions. */
function assessRbac(inventory: PostureInventory, ctx: { clusterRef: string; origin: NormalizedFinding["origin"] }): PostureResult {
  const findings: NormalizedFinding[] = [];
  const assessments: NormalizedControlAssessment[] = [];
  for (const binding of inventory.roleBindings ?? []) {
    const dangerous = binding.roleName === "cluster-admin"
      || (binding.verbs ?? []).includes("*") || (binding.resources ?? []).includes("*");
    const status = dangerous ? "FAIL" : "PASS";
    assessments.push({
      frameworkKey: "CIS_KUBERNETES", controlId: "CIS-5.1.1",
      subjectRef: `RoleBinding ${binding.namespace ?? "cluster-wide"}/${binding.name}`,
      status, evidence: dangerous ? `Binding grants ${binding.roleName} (verbs: ${(binding.verbs ?? []).join(",") || "role-defined"})` : `Binding to ${binding.roleName} reviewed — no wildcard/cluster-admin grant.`,
    });
    if (dangerous) {
      findings.push({
        title: `Excessive RBAC grant via ${binding.name} (${binding.roleName})`,
        description: "A role binding grants cluster-admin or wildcard permissions. RBAC analysis is inventory-only; the platform never exercises these permissions.",
        severity: binding.roleName === "cluster-admin" ? "CRITICAL" : "HIGH",
        confidence: 0.9,
        references: [],
        sourceTool: "kubernetes-posture",
        sourceFingerprint: configurationFingerprint({ namespace: binding.namespace, resourceKind: "RoleBinding", resourceName: binding.name, controlId: "CIS-5.1.1" }),
        origin: ctx.origin,
        clusterRef: ctx.clusterRef,
        ...(binding.namespace ? { namespace: binding.namespace } : {}),
        resourceKind: "RoleBinding", resourceName: binding.name, controlId: "CIS-5.1.1", ruleId: "CIS-5.1.1",
        evidence: `Binding ${binding.name} → ${binding.roleKind}/${binding.roleName} for subjects: ${binding.subjects.map((s) => `${s.kind}/${s.name}`).join(", ")}.`,
        remediation: "Scope the binding to the smallest namespace/verbs/resources the subject needs; reserve cluster-admin for break-glass identities.",
      });
    }
  }
  return { findings, controlAssessments: assessments, metrics: { rbacBindings: (inventory.roleBindings ?? []).length } };
}

/** Assess a full inventory (connector or manifest-derived) into
 *  findings + control assessments (§38/§65–§73). */
export function assessKubernetesPosture(
  inventory: PostureInventory,
  ctx: { clusterRef: string; origin: NormalizedFinding["origin"]; toolSlug?: string },
): PostureResult {
  const findings: NormalizedFinding[] = [];
  const controlAssessments: NormalizedControlAssessment[] = [];
  const tool = ctx.toolSlug ?? "kubernetes-posture";
  let checksRun = 0;
  for (const workload of inventory.workloads) {
    if (!isValidKubernetesName(workload.name) || !isValidKubernetesName(workload.namespace)) continue; // hostile identity — never assessed into a fake resource (§109)
    for (const check of WORKLOAD_CHECKS) {
      checksRun++;
      const subjectRef = `${workload.kind} ${workload.namespace}/${workload.name}`;
      const failed = check.fails(workload);
      controlAssessments.push({
        frameworkKey: check.frameworkKey, controlId: check.controlId, subjectRef,
        status: failed ? "FAIL" : "PASS",
        evidence: failed ? check.evidence(workload) : `${subjectRef}: ${check.title} — control satisfied.`,
      });
      if (!failed) continue;
      for (const image of workload.images.length > 0 ? workload.images : [{ container: workload.name, image: "", digestPinned: true, tagPinned: true }]) {
        void image;
      }
      findings.push({
        title: `${check.title} — ${workload.namespace}/${workload.name}`,
        description: check.evidence(workload),
        severity: check.severity,
        confidence: 0.9,
        references: [],
        sourceTool: tool,
        sourceFingerprint: configurationFingerprint({
          namespace: workload.namespace, resourceKind: workload.kind, resourceName: workload.name,
          ...(workload.images[0]?.container ? { containerName: workload.images[0].container } : {}),
          controlId: check.controlId,
        }),
        origin: ctx.origin,
        clusterRef: ctx.clusterRef,
        namespace: workload.namespace,
        resourceKind: workload.kind,
        resourceName: workload.name,
        ...(workload.images[0]?.container ? { containerName: workload.images[0].container } : {}),
        ...(workload.images[0]?.digest ? { imageDigest: workload.images[0].digest } : {}),
        ...(workload.images[0]?.image ? { imageRef: workload.images[0].image } : {}),
        ruleId: check.controlId, controlId: check.controlId,
        evidence: check.evidence(workload),
        remediation: check.remediation,
      });
    }
  }
  // §66: missing NetworkPolicy is context — a finding only when the
  // namespace also carries externally exposed workloads/ingresses.
  const withPolicy = new Set(inventory.namespacesWithNetworkPolicy ?? []);
  const exposedNamespaces = new Set<string>();
  for (const w of inventory.workloads) {
    if (w.exposure === "PUBLIC_INTERNET" || w.exposure === "EXTERNAL_NETWORK") exposedNamespaces.add(w.namespace);
  }
  for (const ing of inventory.ingresses ?? []) exposedNamespaces.add(ing.namespace);
  for (const ns of inventory.namespaces ?? [...new Set(inventory.workloads.map((w) => w.namespace))]) {
    const exposed = exposedNamespaces.has(ns);
    const hasPolicy = withPolicy.has(ns);
    controlAssessments.push({
      frameworkKey: "CIS_KUBERNETES", controlId: "CIS-5.3.2",
      subjectRef: `Namespace ${ns}`,
      status: hasPolicy ? "PASS" : exposed ? "FAIL" : "WARN",
      evidence: hasPolicy
        ? `Namespace ${ns} carries at least one NetworkPolicy.`
        : exposed
          ? `Namespace ${ns} is externally exposed and carries no NetworkPolicy.`
          : `Namespace ${ns} carries no NetworkPolicy (internal only — context, not a vulnerability).`,
    });
    if (!hasPolicy && exposed) {
      findings.push({
        title: `Exposed namespace without NetworkPolicy — ${ns}`,
        description: "The namespace is reachable from outside the cluster and has no NetworkPolicy restricting pod-to-pod or ingress traffic.",
        severity: "MEDIUM", confidence: 0.8, references: [], sourceTool: tool,
        sourceFingerprint: configurationFingerprint({ namespace: ns, resourceKind: "Namespace", resourceName: ns, controlId: "CIS-5.3.2" }),
        origin: ctx.origin, clusterRef: ctx.clusterRef, namespace: ns,
        resourceKind: "Namespace", resourceName: ns, controlId: "CIS-5.3.2", ruleId: "CIS-5.3.2",
        evidence: `Namespace ${ns} has externally exposed workloads/ingresses and zero NetworkPolicies.`,
        remediation: "Add a default-deny NetworkPolicy and allow only the flows the workloads need.",
      });
    }
  }
  // §73: cluster version support state is exposure context only.
  if (inventory.kubernetesVersion) {
    const eol = isEndOfLifeKubernetes(inventory.kubernetesVersion);
    controlAssessments.push({
      frameworkKey: "CIS_KUBERNETES", controlId: "VERSION-SUPPORT",
      subjectRef: `Cluster ${ctx.clusterRef}`,
      status: eol ? "WARN" : "PASS",
      evidence: eol
        ? `Kubernetes ${inventory.kubernetesVersion} is outside upstream support windows — recorded as POTENTIAL_EXPOSURE context, not a detected vulnerability.`
        : `Kubernetes ${inventory.kubernetesVersion} is within known support windows.`,
    });
  }
  const rbac = assessRbac(inventory, ctx);
  findings.push(...rbac.findings);
  controlAssessments.push(...rbac.controlAssessments);
  return {
    findings, controlAssessments,
    metrics: {
      postureChecks: checksRun, workloadsAssessed: inventory.workloads.length,
      ...rbac.metrics,
    },
  };
}

/** Conservative EOL table (§73): minor versions whose upstream support
 *  ended before 2026. Anything newer/unknown is NOT flagged. */
const KUBERNETES_EOL_MAX_MINOR = 28; // 1.28 and older: EOL by 2026
export function isEndOfLifeKubernetes(version: string): boolean {
  const m = version.replace(/^v/, "").match(/^(\d+)\.(\d+)/);
  if (!m) return false;
  const major = Number(m[1]);
  const minor = Number(m[2]);
  if (major < 1) return true;
  if (major === 1) return minor <= KUBERNETES_EOL_MAX_MINOR;
  return false;
}

/** Convert parsed manifest objects (hostile YAML already safely
 *  parsed, §49) into workload inventory for posture analysis (§47/§52).
 *  Secrets objects contribute METADATA ONLY — data values are never
 *  read into inventory (§36/§105). */
export function workloadsFromManifests(docs: Record<string, unknown>[], clusterRef = "static-manifests"): { workloads: NormalizedKubernetesWorkload[]; secretsMetadataOnly: number } {
  const workloads: NormalizedKubernetesWorkload[] = [];
  let secretsMetadataOnly = 0;
  for (const doc of docs) {
    const kind = String(doc.kind ?? "");
    if (kind === "Secret") { secretsMetadataOnly++; continue; } // name/namespace only via caller metrics — values dropped here
    const template = workloadTemplate(doc);
    if (!template) continue;
    const meta = (doc.metadata ?? {}) as Record<string, unknown>;
    const spec = (template.spec ?? {}) as Record<string, unknown>;
    const containers = Array.isArray(spec.containers) ? (spec.containers as Record<string, unknown>[]) : [];
    const volumes = Array.isArray(spec.volumes) ? (spec.volumes as Record<string, unknown>[]) : [];
    const images = containers.map((c) => {
      const image = String(c.image ?? "");
      const digestPinned = image.includes("@sha256:");
      return {
        container: String(c.name ?? "container"),
        image,
        ...(digestPinned ? { digest: image.split("@")[1] } : {}),
        tagPinned: /:[A-Za-z0-9_.-]+$/.test(image.split("@")[0] ?? "") && !image.endsWith(":latest"),
        digestPinned,
      };
    });
    const podSc = (spec.securityContext ?? {}) as Record<string, unknown>;
    const firstContainerSc = (containers[0]?.securityContext ?? {}) as Record<string, unknown>;
    const caps = ((firstContainerSc.capabilities as Record<string, unknown> | undefined)?.add ?? []) as unknown[];
    workloads.push({
      clusterRef,
      kind,
      namespace: String(meta.namespace ?? "default"),
      name: String(meta.name ?? "unnamed"),
      ...(typeof (doc.spec as Record<string, unknown> | undefined)?.replicas === "number" ? { replicas: (doc.spec as Record<string, unknown>).replicas as number } : {}),
      ...(typeof spec.serviceAccountName === "string" ? { serviceAccount: spec.serviceAccountName } : {}),
      images,
      securityContext: {
        privileged: firstContainerSc.privileged === true,
        runAsRoot: podSc.runAsNonRoot === false || firstContainerSc.runAsNonRoot === false ? true : podSc.runAsNonRoot === true || firstContainerSc.runAsNonRoot === true ? false : undefined,
        allowPrivilegeEscalation: firstContainerSc.allowPrivilegeEscalation === true,
        readOnlyRootFilesystem: firstContainerSc.readOnlyRootFilesystem === true,
        hostNetwork: spec.hostNetwork === true,
        hostPid: spec.hostPID === true,
        hostIpc: spec.hostIPC === true,
        hostPaths: volumes.filter((v) => v.hostPath).map((v) => String(((v.hostPath as Record<string, unknown>)?.path ?? "hostPath"))),
        addedCapabilities: caps.map(String),
        automountServiceAccountToken: spec.automountServiceAccountToken !== false,
        resourceLimitsDeclared: containers.every((c) => !!((c.resources as Record<string, unknown> | undefined)?.limits)),
      },
      exposure: "UNKNOWN",
      labels: {},
    });
  }
  return { workloads, secretsMetadataOnly };
}

function workloadTemplate(doc: Record<string, unknown>): { spec?: Record<string, unknown> } | null {
  const kind = String(doc.kind ?? "");
  const spec = (doc.spec ?? {}) as Record<string, unknown>;
  if (kind === "Pod") return { spec: doc.spec as Record<string, unknown> };
  if (["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"].includes(kind)) {
    const template = (spec.template ?? {}) as Record<string, unknown>;
    return { spec: template.spec as Record<string, unknown> };
  }
  if (kind === "CronJob") {
    const jobTemplate = (spec.jobTemplate ?? {}) as Record<string, unknown>;
    const jobSpec = (jobTemplate.spec ?? {}) as Record<string, unknown>;
    const template = (jobSpec.template ?? {}) as Record<string, unknown>;
    return { spec: template.spec as Record<string, unknown> };
  }
  return null;
}
