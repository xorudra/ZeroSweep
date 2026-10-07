import { SEVERITY_ORDER } from "../findings/severity";
import { assessConfidence, canonicalFindingFingerprint, computeRisk, sourceFindingFingerprint } from "./analysis";
import { vulnClassFamily } from "./taxonomy";
import type { CorrelatedFinding, CorrelationStats, NormalizedVulnFinding } from "./types";

/**
 * Deduplication + cross-tool correlation (Prompt 7 §19–§21).
 *
 * FindingDeduplicationService semantics:
 * - DUPLICATE — same canonical fingerprint (asset + service + endpoint +
 *   parameter + vulnerability class + CVE/CWE): merged into ONE canonical
 *   finding; the duplicate's evidence is PRESERVED as an additional
 *   source — evidence is never deleted (§20).
 * - POSSIBLE_DUPLICATE — same asset+endpoint and the same vulnerability
 *   class FAMILY, but a different exact fingerprint: findings stay
 *   separate, cross-linked for an analyst to judge.
 * - UNIQUE — everything else.
 *
 * The canonical finding keeps the highest severity, the strongest
 * CVSS/CVE/CWE any source actually provided, corroborated confidence
 * (§22) and a fresh deterministic risk score (§34).
 */

export function fingerprintOfFinding(f: NormalizedVulnFinding): string {
  return canonicalFindingFingerprint({
    host: f.host ?? "", port: f.port, endpoint: f.endpoint, parameter: f.parameter,
    vulnClass: f.vulnClass, cve: f.cve, cwe: f.cwe,
  });
}

export function correlateFindings(
  inputs: NormalizedVulnFinding[],
  opts: { maxFindings?: number } = {},
): { findings: CorrelatedFinding[]; stats: CorrelationStats } {
  const byFingerprint = new Map<string, NormalizedVulnFinding[]>();
  for (const f of inputs) {
    const fp = fingerprintOfFinding(f);
    byFingerprint.set(fp, [...(byFingerprint.get(fp) ?? []), f]);
  }

  const correlated: CorrelatedFinding[] = [];
  for (const [fp, group] of byFingerprint) {
    const sorted = [...group].sort((a, b) =>
      (SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]) || (b.sourceConfidence - a.sourceConfidence));
    const primary = sorted[0]!;
    // Merge fields conservatively: a field is filled from another source
    // ONLY when the primary lacks it and that source actually provided it.
    const merged: NormalizedVulnFinding = { ...primary };
    for (const other of sorted.slice(1)) {
      merged.cvssScore ??= other.cvssScore;
      merged.cvssVector ??= other.cvssVector;
      merged.cvssVersion ??= other.cvssVersion;
      merged.cve ??= other.cve;
      merged.cwe ??= other.cwe;
      merged.remediation ??= other.remediation;
      merged.technicalImpact ??= (other as NormalizedVulnFinding & { technicalImpact?: string }).technicalImpact;
      if (other.referencesDetailed.length + merged.referencesDetailed.length > 0) {
        const seen = new Set(merged.referencesDetailed.map((r) => r.url));
        merged.referencesDetailed = [...merged.referencesDetailed, ...other.referencesDetailed.filter((r) => !seen.has(r.url))];
        merged.references = [...new Set([...merged.references, ...other.references])];
      }
    }
    const sources = group.map((f) => ({
      tool: f.sourceTool,
      summary: f.evidence ?? f.description,
      ...(f.evidenceDetail ? { evidence: f.evidenceDetail } : {}),
      sourceFingerprint: f.sourceFingerprint || sourceFindingFingerprint({
        host: f.host ?? "", port: f.port, endpoint: f.endpoint, parameter: f.parameter,
        vulnClass: f.vulnClass, cve: f.cve, cwe: f.cwe, sourceTool: f.sourceTool, checkId: f.templateId,
      }),
      ...(f.templateId ? { templateId: f.templateId } : {}),
      ...(f.signatureFamily ?? f.evidenceDetail?.signatureFamily ? { signatureFamily: f.signatureFamily ?? f.evidenceDetail?.signatureFamily } : {}),
      confidence: f.sourceConfidence,
    }));
    const confidence = assessConfidence({
      sources: sources.map((s) => ({ tool: s.tool, confidence: s.confidence, ...(s.signatureFamily ? { signatureFamily: s.signatureFamily } : {}) })),
    });
    const risk = computeRisk({
      severity: merged.severity, cvssScore: merged.cvssScore, confidence: confidence.score,
      assetCriticality: merged.assetCriticality, internetExposed: merged.internetExposed,
      verificationStatus: confidence.verificationStatus,
    });
    correlated.push({
      finding: merged,
      canonicalFingerprint: fp,
      sources,
      dedupState: group.length > 1 ? "DUPLICATE" : "UNIQUE",
      possibleDuplicates: [],
      confidenceScore: confidence.score,
      confidenceBand: confidence.band,
      verificationStatus: merged.verificationStatus === "CONFIRMED" ? "CONFIRMED" : confidence.verificationStatus,
      confidenceRationale: confidence.rationale,
      riskScore: risk.score,
      riskBand: risk.band,
      riskExplanation: risk.explanation,
    });
  }

  // POSSIBLE_DUPLICATE links (§20): same asset+endpoint, same class family,
  // different fingerprint — linked, never merged.
  for (const a of correlated) {
    for (const b of correlated) {
      if (a === b) continue;
      const fa = a.finding; const fb = b.finding;
      if ((fa.host ?? "") === (fb.host ?? "")
        && (fa.endpoint ?? "") === (fb.endpoint ?? "")
        && vulnClassFamily(fa.vulnClass) === vulnClassFamily(fb.vulnClass)
        && fa.vulnClass !== fb.vulnClass) {
        a.possibleDuplicates.push(b.canonicalFingerprint);
        a.dedupState = a.dedupState === "DUPLICATE" ? "DUPLICATE" : "POSSIBLE_DUPLICATE";
      }
    }
  }

  // Deterministic order: risk desc, then fingerprint (§64 batch stability).
  correlated.sort((x, y) => (y.riskScore - x.riskScore) || x.canonicalFingerprint.localeCompare(y.canonicalFingerprint));

  const stats: CorrelationStats = {
    total: inputs.length,
    unique: correlated.length,
    duplicatesMerged: inputs.length - correlated.length,
    corroborated: correlated.filter((c) => new Set(c.sources.map((s) => s.tool)).size >= 2).length,
    byTool: {},
  };
  for (const f of inputs) {
    stats.byTool[f.sourceTool] ??= { total: 0, unique: 0, corroborated: 0 };
    stats.byTool[f.sourceTool]!.total++;
  }
  for (const c of correlated) {
    const tools = [...new Set(c.sources.map((s) => s.tool))];
    for (const t of tools) {
      stats.byTool[t] ??= { total: 0, unique: 0, corroborated: 0 };
      if (c.sources[0]?.tool === t || tools.length === 1) stats.byTool[t]!.unique++;
      if (tools.length >= 2) stats.byTool[t]!.corroborated++;
    }
  }

  // maxFindings (§51): keep the highest-risk canonical findings; the rest
  // are a RECORDED limit event, never a silent discard.
  if (opts.maxFindings !== undefined && correlated.length > opts.maxFindings) {
    const kept = correlated.slice(0, opts.maxFindings);
    stats.limitEvent = { type: "MAX_FINDINGS_REACHED", kept: kept.length, dropped: correlated.length - kept.length };
    stats.unique = kept.length;
    return { findings: kept, stats };
  }
  return { findings: correlated, stats };
}
