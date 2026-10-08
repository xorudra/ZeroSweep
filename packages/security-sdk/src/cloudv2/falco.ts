/**
 * Prompt 34 — Falco runtime correlation (§91–§95) and SOC linkage
 * (§141).
 *
 * Falco is DETECTION (§92): events are runtime signals ingested into
 * the existing RuntimeSecurityEvent / SOC architecture (§93 — the
 * parser lives in cloudnative/parsers-cloud). This module correlates
 * an event with the workload, image and known vulnerabilities the
 * platform already holds (§94/§158). Correlation raises CONTEXTUAL
 * risk only — the original scanner severity is never altered (§95) —
 * and no response action is ever taken against a workload (§96).
 */
export interface RuntimeEventFacts {
  namespace?: string;
  pod?: string;
  container?: string;
  rule: string;
  priority: string; // EMERGENCY | ALERT | CRITICAL | ERROR | WARNING | NOTICE | INFORMATIONAL | DEBUG
}

export interface RuntimeWorkloadFacts {
  namespace: string;
  kind: string;
  name: string;
  pods?: string[];
  images: Array<{ container?: string; image: string; digest?: string }>;
}

export interface RuntimeImageFacts {
  id: string;
  repository: string;
  digest?: string | null;
}

export interface RuntimeFindingFacts {
  id: string;
  imageDigest?: string | null;
  imageRepository?: string | null;
  cve?: string | null;
  severity: string;
}

export interface RuntimeCorrelation {
  workloadRef?: string;
  imageRef?: string;
  imageId?: string;
  findingIds: string[];
  confidence: "LOW" | "MEDIUM" | "HIGH";
  /** §141: high-confidence, high-priority signals link a SOC alert —
   *  the alert service dedupes; correlation itself never duplicates. */
  socAlertRecommended: boolean;
  /** §95: contextual signal only — original severity untouched. */
  contextualRiskSignal: "NONE" | "ELEVATED";
  detail: string;
}

const HIGH_PRIORITIES = new Set(["EMERGENCY", "ALERT", "CRITICAL"]);

function imageMatches(event: RuntimeEventFacts, workload: RuntimeWorkloadFacts): { image: string; digest?: string } | undefined {
  if (!workload.images.length) return undefined;
  if (event.container) {
    const byContainer = workload.images.find((i) => i.container === event.container);
    if (byContainer) return byContainer;
  }
  return workload.images[0];
}

/** §94/§158: link a runtime event to pod → workload → image → known
 *  vulnerability, using only recorded platform data. */
export function correlateRuntimeEvent(
  event: RuntimeEventFacts,
  context: { workloads: RuntimeWorkloadFacts[]; images: RuntimeImageFacts[]; findings: RuntimeFindingFacts[] },
): RuntimeCorrelation {
  const notes: string[] = [];
  const workload = context.workloads.find((w) =>
    w.namespace === event.namespace && (event.pod ? (w.pods ?? []).includes(event.pod) || event.pod.startsWith(`${w.name}-`) : false),
  ) ?? context.workloads.find((w) => w.namespace === event.namespace && event.pod?.startsWith(w.name));
  if (!workload) {
    return {
      findingIds: [], confidence: "LOW", socAlertRecommended: false, contextualRiskSignal: "NONE",
      detail: "Runtime event could not be linked to a recorded workload — retained as an uncorrelated SOC signal (§94).",
    };
  }
  const workloadRef = `${workload.namespace}/${workload.kind}/${workload.name}`;
  notes.push(`workload ${workloadRef}`);
  const img = imageMatches(event, workload);
  let imageId: string | undefined;
  let imageRef: string | undefined;
  if (img) {
    imageRef = img.digest ? `${img.image.split("@")[0]}@${img.digest}` : img.image;
    const known = context.images.find((i) => (img.digest && i.digest === img.digest) || i.repository === img.image.split("@")[0]);
    if (known) { imageId = known.id; notes.push(`image ${known.repository}@${known.digest ?? "unknown-digest"}`); }
  }
  const findingIds = context.findings
    .filter((f) => (img?.digest && f.imageDigest === img.digest) || (img && f.imageRepository === img.image.split("@")[0]))
    .map((f) => f.id);
  if (findingIds.length) notes.push(`${findingIds.length} known vulnerabilit(ies) on the image`);

  const confidence: RuntimeCorrelation["confidence"] =
    imageId && findingIds.length > 0 ? "HIGH" : workload && imageRef ? "MEDIUM" : "LOW";
  const highPriority = HIGH_PRIORITIES.has(event.priority);
  return {
    workloadRef,
    ...(imageRef ? { imageRef } : {}),
    ...(imageId ? { imageId } : {}),
    findingIds,
    confidence,
    socAlertRecommended: confidence === "HIGH" && highPriority,
    contextualRiskSignal: highPriority && confidence !== "LOW" ? "ELEVATED" : "NONE",
    detail: `Correlated to ${notes.join("; ")}. Contextual risk only — scanner severity unchanged (§95); no workload action taken (§96).`,
  };
}
