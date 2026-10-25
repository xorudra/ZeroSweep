/**
 * Prompt 13 — container quality gate + deployment security gate
 * (§75/§76) and cluster risk signals (§74).
 *
 * The DeploymentSecurityGate is an ARCHITECTURE artifact: it evaluates
 * a policy over scan results and returns PASSED / FAILED / WARNING.
 * It does NOT deploy, block or mutate any production system — callers
 * (CI, platform workflows) decide what to do with the verdict.
 */
import type { NormalizedFinding } from "../findings/finding.types";

export interface ContainerGateInput {
  findings: Pick<NormalizedFinding, "severity" | "cve" | "origin" | "secret" | "controlId" | "resourceKind">[];
  /** KEV membership comes from the Phase 11 intelligence dataset —
   *  attached by enrichment, never assumed (§74). */
  kevCves?: string[];
  criticalControlIds?: string[];
}

export interface ContainerGateResult {
  status: "PASSED" | "FAILED" | "WARNING";
  failedRules: string[];
  warningRules: string[];
  summary: Record<string, number>;
}

export const CONTAINER_GATE_POLICY_VERSION = "container-gate/1.0.0";

const CRITICAL_POSTURE_CONTROLS = new Set(["KSV-0014", "CIS-5.2.9", "CIS-5.1.1"]);

/** §75 default rules: no KEV-listed image vulnerabilities, no critical
 *  image CVEs, no verified image secrets, no privileged containers,
 *  no critical Kubernetes misconfigurations. */
export function evaluateContainerQualityGate(input: ContainerGateInput): ContainerGateResult {
  const failed: string[] = [];
  const warnings: string[] = [];
  const kev = new Set(input.kevCves ?? []);
  const imageFindings = input.findings.filter((f) => f.origin === "IMAGE_FINDING");
  const kevHits = imageFindings.filter((f) => f.cve && kev.has(f.cve));
  if (kevHits.length > 0) failed.push(`KEV_IMAGE_VULNERABILITIES:${kevHits.length}`);
  const criticalCves = imageFindings.filter((f) => f.severity === "CRITICAL" && f.cve);
  if (criticalCves.length > 0) failed.push(`CRITICAL_IMAGE_CVES:${criticalCves.length}`);
  const secrets = input.findings.filter((f) => f.secret);
  if (secrets.length > 0) failed.push(`IMAGE_SECRETS:${secrets.length}`);
  const privileged = input.findings.filter((f) => f.controlId === "KSV-0014");
  if (privileged.length > 0) failed.push(`PRIVILEGED_CONTAINERS:${privileged.length}`);
  const criticalControls = new Set(input.criticalControlIds ?? [...CRITICAL_POSTURE_CONTROLS]);
  const criticalMisconfigs = input.findings.filter((f) => f.controlId && criticalControls.has(f.controlId) && f.controlId !== "KSV-0014");
  if (criticalMisconfigs.length > 0) failed.push(`CRITICAL_KUBERNETES_MISCONFIGURATIONS:${criticalMisconfigs.length}`);
  const highFindings = input.findings.filter((f) => f.severity === "HIGH");
  if (failed.length === 0 && highFindings.length > 0) warnings.push(`HIGH_SEVERITY_FINDINGS:${highFindings.length}`);
  return {
    status: failed.length > 0 ? "FAILED" : warnings.length > 0 ? "WARNING" : "PASSED",
    failedRules: failed,
    warningRules: warnings,
    summary: {
      findings: input.findings.length,
      kevImageVulnerabilities: kevHits.length,
      criticalImageCves: criticalCves.length,
      imageSecrets: secrets.length,
      privilegedContainers: privileged.length,
      criticalMisconfigurations: criticalMisconfigs.length,
    },
  };
}

/** §76: the deployment gate wraps the container gate verdict for a
 *  candidate image/workload set. Pure evaluation — no side effects. */
export function evaluateDeploymentSecurityGate(input: ContainerGateInput & { candidate: string }): ContainerGateResult & { candidate: string; advisory: string } {
  const result = evaluateContainerQualityGate(input);
  return {
    ...result,
    candidate: input.candidate,
    advisory: result.status === "FAILED"
      ? "Deployment gate FAILED: remediate the failed rules before promoting this artifact. ZeroSweep reports this verdict only — it does not deploy or block production systems itself."
      : result.status === "WARNING"
        ? "Deployment gate WARNING: high-severity findings remain; promotion is a human decision with this report attached. ZeroSweep reports this verdict only — it does not deploy or block production systems itself."
        : "Deployment gate PASSED under the container gate policy. ZeroSweep reports this verdict only — it does not deploy or block production systems itself.",
  };
}

/** §74 cluster risk signals feeding Risk Engine V2: contextual factors
 *  only (exposure, internet reachability, KEV/EPSS come from the
 *  finding/intel layer). Deterministic and explainable. */
export function clusterRiskSignals(input: {
  exposure: string; privileged: boolean; publicIngress: boolean;
  defaultServiceAccount: boolean; imageDigestPinned: boolean;
}): { factor: string; detail: string }[] {
  const signals: { factor: string; detail: string }[] = [];
  if (input.exposure === "PUBLIC_INTERNET") signals.push({ factor: "WORKLOAD_PUBLICLY_EXPOSED", detail: "Workload is reachable from the public internet." });
  else if (input.exposure === "EXTERNAL_NETWORK") signals.push({ factor: "WORKLOAD_EXTERNALLY_EXPOSED", detail: "Workload is reachable from external networks." });
  if (input.privileged) signals.push({ factor: "PRIVILEGED_WORKLOAD", detail: "Workload runs privileged — finding impact is amplified." });
  if (input.publicIngress) signals.push({ factor: "PUBLIC_INGRESS", detail: "An ingress exposes this workload publicly." });
  if (input.defaultServiceAccount) signals.push({ factor: "DEFAULT_SERVICE_ACCOUNT", detail: "Workload uses the default service account." });
  if (!input.imageDigestPinned) signals.push({ factor: "IMAGE_NOT_DIGEST_PINNED", detail: "Image is referenced by mutable tag — analyzed artifact may differ from deployed artifact." });
  return signals;
}
