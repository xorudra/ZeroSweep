/**
 * Prompt 13 — cloud-native fingerprints + correlation (§20/§51/§54/§95).
 *
 * Deterministic identities are what make correlation honest:
 *  - image vulnerabilities: CVE + package + version + IMAGE DIGEST
 *    (§20) — Trivy and Grype reporting the same CVE in the same
 *    package of the same image produce ONE canonical finding with
 *    multiple observations, never two findings;
 *  - configuration findings: cluster/namespace/kind/name/container/
 *    control (§54), shared by static manifest analysis and live cluster
 *    observation so the two evidence kinds correlate while BOTH
 *    observations are preserved (§51/§103);
 *  - benchmark checks: host/cluster + check id (§31/§41).
 */
import { createHash } from "node:crypto";
import type { KubeHunterCheckClass } from "./types";

function hash(parts: string[]): string {
  return createHash("sha256").update(parts.map((p) => p.trim().toLowerCase()).join("|")).digest("hex");
}

export function imageVulnerabilityFingerprint(input: {
  imageDigest?: string; imageRef: string; cve: string; packageName: string; packageVersion: string;
}): string {
  return `imgvuln:${hash([input.imageDigest ?? input.imageRef, input.cve, input.packageName, input.packageVersion])}`;
}

export function configurationFingerprint(input: {
  namespace?: string; resourceKind: string; resourceName: string; containerName?: string; controlId: string;
}): string {
  return `k8scfg:${hash([input.namespace ?? "", input.resourceKind, input.resourceName, input.containerName ?? "", input.controlId])}`;
}

export function dockerBenchmarkFingerprint(input: { hostRef: string; checkId: string }): string {
  return `dockerbench:${hash([input.hostRef, input.checkId])}`;
}

export function kubernetesBenchmarkFingerprint(input: { clusterRef: string; checkId: string }): string {
  return `kubebench:${hash([input.clusterRef, input.checkId])}`;
}

export function imageSecretFingerprint(input: { imageDigest?: string; imageRef: string; secretType: string; location: string }): string {
  return `imgsecret:${hash([input.imageDigest ?? input.imageRef, input.secretType, input.location])}`;
}

/** Two findings describe the same configuration issue when their
 *  configuration identity matches — regardless of whether one came
 *  from a static manifest and the other from a live cluster (§51). */
export function sameConfigurationIdentity(
  a: { namespace?: string; resourceKind?: string; resourceName?: string; containerName?: string; controlId?: string },
  b: { namespace?: string; resourceKind?: string; resourceName?: string; containerName?: string; controlId?: string },
): boolean {
  if (!a.controlId || !b.controlId || !a.resourceKind || !b.resourceKind || !a.resourceName || !b.resourceName) return false;
  return a.controlId === b.controlId
    && a.resourceKind.toLowerCase() === b.resourceKind.toLowerCase()
    && a.resourceName.toLowerCase() === b.resourceName.toLowerCase()
    && (a.namespace ?? "").toLowerCase() === (b.namespace ?? "").toLowerCase()
    && (a.containerName ?? "").toLowerCase() === (b.containerName ?? "").toLowerCase();
}

/**
 * kube-hunter check policy (§42/§43). The catalog classifies KNOWN
 * kube-hunter checks; anything unrecognized defaults to
 * REVIEW_REQUIRED (fail closed). INTRUSIVE checks (pod execution,
 * privilege probing, exploitation paths) can never be automated —
 * the adapter refuses to build a plan that would enable them.
 */
export const KUBE_HUNTER_CHECK_POLICY: Record<string, KubeHunterCheckClass> = {
  // Passive discovery of exposed surfaces (default automated mode).
  "api-server": "SAFE",
  "kubelet-readonly": "SAFE",
  "kubelet-authenticated": "SAFE",
  "dashboard-exposure": "SAFE",
  "etcd-exposure": "SAFE",
  "exposed-pods": "SAFE",
  // Checks that probe behavior beyond passive reading.
  "kubelet-readwrite": "REVIEW_REQUIRED",
  "anonymous-auth": "REVIEW_REQUIRED",
  "token-scope-probing": "REVIEW_REQUIRED",
  // Intrusive / exploitation-adjacent: never automated (§114).
  "pod-execution": "DISABLED",
  "privilege-escalation": "DISABLED",
  "container-escape": "DISABLED",
  "credential-access": "DISABLED",
};

export function classifyKubeHunterCheck(checkId: string): KubeHunterCheckClass {
  return KUBE_HUNTER_CHECK_POLICY[checkId.trim().toLowerCase()] ?? "REVIEW_REQUIRED";
}

/** Whether an automated (approved-assessment) run may include a check.
 *  `approvedReview` carries the per-assessment REVIEW_REQUIRED approval
 *  (§43); SAFE never needs it; INTRUSIVE/DISABLED are never allowed. */
export function kubeHunterCheckAllowed(checkId: string, opts: { approvedReview?: boolean } = {}): boolean {
  const cls = classifyKubeHunterCheck(checkId);
  if (cls === "SAFE") return true;
  if (cls === "REVIEW_REQUIRED") return opts.approvedReview === true;
  return false;
}
