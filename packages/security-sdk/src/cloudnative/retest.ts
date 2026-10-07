/**
 * Prompt 13 — retest extensions (§77). A cloud-native finding is
 * retested by re-running its ORIGINAL detection kind against the same
 * governed target: image findings → image rescan, static manifest
 * findings → manifest rescan, live posture findings → posture
 * reassessment, Docker host findings → benchmark rerun. The retest
 * child scan re-passes every gate (authorization, verified target,
 * approved assessment, scope, policy) exactly like the original scan —
 * this helper only chooses the stage; it grants nothing.
 */
export interface CloudNativeRetestPlan {
  stageType: "IMAGE_VULNERABILITY_SCAN" | "MANIFEST_SCAN" | "KUBERNETES_POSTURE" | "DOCKER_POSTURE" | "SBOM_GENERATION";
  rationale: string;
}

export function planCloudNativeRetest(finding: {
  origin?: string;
  sourceTool?: string;
  controlId?: string;
}): CloudNativeRetestPlan | null {
  const tool = finding.sourceTool ?? "";
  switch (finding.origin) {
    case "IMAGE_FINDING":
      return { stageType: "IMAGE_VULNERABILITY_SCAN", rationale: `image rescan via original tool ${tool || "(recorded tool)"} against the same digest-bound image (§77)` };
    case "DOCKER_HOST_FINDING":
      return { stageType: "DOCKER_POSTURE", rationale: "Docker benchmark rerun on the approved host via the privileged worker (§77)" };
    case "LIVE_CLUSTER_FINDING":
      return tool === "kube-bench"
        ? { stageType: "KUBERNETES_POSTURE", rationale: "CIS benchmark rerun via the privileged worker (§77)" }
        : { stageType: "KUBERNETES_POSTURE", rationale: `cluster posture reassessment via original tool ${tool || "(recorded tool)"} (§77)` };
    case "STATIC_CONFIGURATION_FINDING":
      return { stageType: "MANIFEST_SCAN", rationale: `manifest/IaC rescan via original tool ${tool || "(recorded tool)"} (§77)` };
    default:
      return null;
  }
}
