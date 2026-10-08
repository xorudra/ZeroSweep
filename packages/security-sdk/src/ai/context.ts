import { createHash } from "node:crypto";
import type {
  AiBuiltContext, AiContextRecord, AiDataClassification, AiFindingContextInput, AiTaskType,
} from "./types";
import { classificationRank } from "./types";

/**
 * Security context builder (Prompt 21 §9/§10/§33). Builds the MINIMAL
 * task-specific context from normalized platform records. The API
 * layer is responsible for fetching these records with tenant
 * filtering (§12) and RBAC (§11) BEFORE calling this builder — the
 * builder never sees records the requester cannot access, and it
 * never pulls a whole workspace when one finding is being analyzed
 * (least-context, §10).
 *
 * Classification (§13): finding/evidence content defaults to
 * CONFIDENTIAL (scanner data is target-influenced), intel records are
 * PUBLIC reference data, code snippets are CONFIDENTIAL, and anything
 * the caller marks SECRET stays SECRET so policy can refuse it (§14).
 */

function maxClass(records: AiContextRecord[]): AiDataClassification {
  let out: AiDataClassification = "PUBLIC";
  for (const r of records) if (classificationRank(r.classification) > classificationRank(out)) out = r.classification;
  return out;
}

export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

/** §106: trim lowest-priority records so mandatory policy context always fits. */
export function trimContext(records: AiContextRecord[], maxTokens: number): AiContextRecord[] {
  // Priority: TRUSTED structured records first, then UNTRUSTED evidence.
  const ordered = [...records].sort((a, b) => (a.trust === b.trust ? 0 : a.trust === "TRUSTED" ? -1 : 1));
  const kept: AiContextRecord[] = [];
  let used = 0;
  for (const r of ordered) {
    const cost = estimateTokens(JSON.stringify(r.fields));
    if (used + cost > maxTokens && kept.length > 0) continue;
    kept.push(r);
    used += cost;
  }
  return kept;
}

export function buildFindingContext(
  finding: AiFindingContextInput,
  task: AiTaskType,
  options: { maxTokens?: number } = {},
): AiBuiltContext {
  const records: AiContextRecord[] = [];
  const core: Record<string, string> = {
    title: finding.title,
    severity: finding.severity,
    status: finding.lifecycleStatus ?? finding.status,
    verificationStatus: finding.verificationStatus ?? "UNVERIFIED",
  };
  if (finding.cvssScore != null) core.cvssScore = String(finding.cvssScore);
  if (finding.cve) core.cve = finding.cve;
  if (finding.cwe) core.cwe = finding.cwe;
  if (finding.sourceDomain) core.domain = finding.sourceDomain;
  if (finding.category) core.category = finding.category;
  if (finding.fixedVersion) core.knownFixedVersion = finding.fixedVersion;
  if (finding.filePath) core.filePath = finding.filePath;
  if (finding.riskScore != null) core.riskScore = String(finding.riskScore);
  if (finding.riskBand) core.riskBand = finding.riskBand;
  records.push({ sourceType: "FINDING", sourceId: finding.id, classification: "INTERNAL", trust: "TRUSTED", fields: core });

  // Description is scanner-authored text → UNTRUSTED (§18).
  records.push({
    sourceType: "FINDING", sourceId: finding.id, classification: "CONFIDENTIAL", trust: "UNTRUSTED",
    fields: { description: finding.description },
  });

  if (finding.riskExplanation && (task === "RISK_EXPLANATION" || task === "FINDING_EXPLANATION" || task === "COPILOT_CHAT")) {
    const signals = [
      ...(finding.riskExplanation.factors ?? []),
      ...(finding.riskExplanation.adjustments ?? []).map((a) => `${a.delta >= 0 ? "+" : ""}${a.delta} ${a.signal}: ${a.rationale}`),
    ];
    records.push({
      sourceType: "FINDING", sourceId: finding.id, classification: "INTERNAL", trust: "TRUSTED",
      fields: { riskEngineVersion: "risk-v3.0", riskSignals: signals.join("; "), missingInformation: (finding.riskExplanation.missingInformation ?? []).join("; ") },
    });
  }

  if (finding.asset) {
    records.push({
      sourceType: "ASSET", sourceId: finding.asset.id, classification: "INTERNAL", trust: "TRUSTED",
      fields: {
        name: finding.asset.name,
        ...(finding.asset.type ? { type: finding.asset.type } : {}),
        ...(finding.asset.environment ? { environment: finding.asset.environment } : {}),
        ...(finding.asset.exposure ? { exposure: finding.asset.exposure } : {}),
      },
    });
  }

  for (const obs of (finding.observations ?? []).slice(0, 10)) {
    records.push({ sourceType: "OBSERVATION", sourceId: obs.id, classification: "CONFIDENTIAL", trust: "UNTRUSTED", fields: { summary: obs.summary } });
  }
  for (const ev of (finding.evidence ?? []).slice(0, 10)) {
    records.push({
      sourceType: "EVIDENCE", sourceId: ev.id, classification: "CONFIDENTIAL", trust: "UNTRUSTED",
      fields: { sourceTool: ev.sourceTool, summary: ev.summary, ...(ev.fingerprint ? { fingerprint: ev.fingerprint } : {}) },
    });
  }

  if (finding.intel) {
    if (finding.cve && finding.intel.cveDescription) {
      records.push({ sourceType: "CVE", sourceId: finding.cve, classification: "PUBLIC", trust: "TRUSTED", fields: { description: finding.intel.cveDescription, ...(finding.intel.cvssScore != null ? { cvssScore: String(finding.intel.cvssScore) } : {}) } });
    }
    if (finding.cwe && finding.intel.cweName) {
      records.push({ sourceType: "CWE", sourceId: finding.cwe, classification: "PUBLIC", trust: "TRUSTED", fields: { name: finding.intel.cweName } });
    }
    if (finding.cve && finding.intel.epssScore != null) {
      records.push({ sourceType: "EPSS", sourceId: finding.cve, classification: "PUBLIC", trust: "TRUSTED", fields: { epssScore: String(finding.intel.epssScore), ...(finding.intel.epssPercentile != null ? { percentile: String(finding.intel.epssPercentile) } : {}) } });
    }
    if (finding.cve && finding.intel.kevListed) {
      records.push({ sourceType: "KEV", sourceId: finding.cve, classification: "PUBLIC", trust: "TRUSTED", fields: { kevListed: "true", ...(finding.intel.kevRequiredAction ? { requiredAction: finding.intel.kevRequiredAction } : {}) } });
    }
  }

  for (const c of finding.complianceControls ?? []) {
    records.push({ sourceType: "COMPLIANCE_CONTROL", sourceId: c.id, classification: "INTERNAL", trust: "TRUSTED", fields: { framework: c.framework, title: c.title, status: c.status } });
  }

  if (finding.attackPath && task === "ATTACK_PATH_EXPLANATION") {
    records.push({
      sourceType: "GRAPH_RELATIONSHIP", sourceId: finding.attackPath.id, classification: "CONFIDENTIAL", trust: "TRUSTED",
      fields: { summary: finding.attackPath.summary, steps: finding.attackPath.steps.join(" -> ") },
    });
  }

  let includesSourceCode = false;
  if (finding.codeSnippet && (task === "SECURE_CODE_GUIDANCE" || task === "FINDING_EXPLANATION" || task === "REMEDIATION_GUIDANCE")) {
    includesSourceCode = true;
    records.push({
      sourceType: "FINDING", sourceId: finding.id, classification: "CONFIDENTIAL", trust: "UNTRUSTED",
      fields: { codeSnippet: finding.codeSnippet.slice(0, 2000) }, // §33: minimal snippet only
    });
  }
  if (finding.remediation && (task === "REMEDIATION_GUIDANCE" || task === "FINDING_EXPLANATION")) {
    records.push({ sourceType: "FINDING", sourceId: finding.id, classification: "INTERNAL", trust: "UNTRUSTED", fields: { existingRemediationNote: finding.remediation } });
  }

  const trimmed = options.maxTokens ? trimContext(records, options.maxTokens) : records;
  const serialized = JSON.stringify(trimmed);
  return {
    records: trimmed,
    maxClassification: maxClass(trimmed),
    includesSourceCode,
    includesRawEvidence: (finding.evidence ?? []).length > 0,
    estimatedTokens: estimateTokens(serialized),
    contextHash: createHash("sha256").update(serialized).digest("hex"),
  };
}

/** §75: cache key — tenant + task + context hash + model + policy + data version. */
export function aiCacheKey(parts: {
  workspaceId: string; task: AiTaskType; contextHash: string; modelName: string; policyVersion: string; dataVersion: string;
}): string {
  return createHash("sha256")
    .update([parts.workspaceId, parts.task, parts.contextHash, parts.modelName, parts.policyVersion, parts.dataVersion].join("|"))
    .digest("hex");
}
