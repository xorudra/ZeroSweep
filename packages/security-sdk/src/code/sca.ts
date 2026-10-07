import type { NormalizedFinding, NormalizedSoftwareComponent } from "../findings/finding.types";
import type { IntelligenceDataset } from "../vulnmgmt/intelligence";
import { componentToCpe } from "./components";

/**
 * SCA correlation (Prompt 12 §49–§58). Two governed sources of truth:
 *
 *  1. Scanner tools (Dependency-Check, Grype) report vulnerabilities
 *     from THEIR governed databases (managed outside scans, §50) —
 *     their findings normalize like any other tool output and merge by
 *     (component, CVE) so two tools reporting the same issue produce ONE
 *     canonical finding with multiple observations (§58).
 *  2. The Phase 11 LOCAL intelligence dataset: components are matched
 *     through governed CPE records ONLY. A match is POTENTIAL_EXPOSURE
 *     (§33 discipline) — presence in a dependency graph is not proof of
 *     exploitation or even of reachability. An empty dataset produces
 *     ZERO matches, honestly.
 */

export interface DependencyFindingDraft extends NormalizedFinding {
  sources: string[];
}

/** Identity used to merge multi-tool dependency observations (§58). */
export function dependencyFindingKey(f: NormalizedFinding): string | null {
  if (!f.cve || !f.componentPurl) return null;
  return `${f.componentPurl}|${f.cve.toUpperCase()}`;
}

/**
 * Merge dependency findings from multiple tools (§58): same component +
 * same CVE = one canonical finding, all tools recorded as observations,
 * the highest severity/CVSS kept, fixed version kept when ANY trusted
 * source provides it (§74).
 */
export function mergeDependencyObservations(findings: NormalizedFinding[]): DependencyFindingDraft[] {
  const byKey = new Map<string, DependencyFindingDraft>();
  const passthrough: DependencyFindingDraft[] = [];
  const severityRank: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFORMATIONAL: 1 };
  for (const f of findings) {
    const key = dependencyFindingKey(f);
    if (!key) { passthrough.push({ ...f, sources: [f.sourceTool] }); continue; }
    const existing = byKey.get(key);
    if (!existing) { byKey.set(key, { ...f, sources: [f.sourceTool] }); continue; }
    existing.sources = [...new Set([...existing.sources, f.sourceTool])].sort();
    if ((severityRank[f.severity] ?? 0) > (severityRank[existing.severity] ?? 0)) existing.severity = f.severity;
    if ((f.cvssScore ?? 0) > (existing.cvssScore ?? 0)) { existing.cvssScore = f.cvssScore; existing.cvssVector = f.cvssVector ?? existing.cvssVector; }
    existing.fixedVersion ??= f.fixedVersion;
    existing.confidence = Math.max(existing.confidence, f.confidence);
    existing.references = [...new Set([...existing.references, ...f.references])];
  }
  return [...byKey.values(), ...passthrough];
}

/**
 * Match the component inventory against the local intelligence dataset
 * (§52–§56). Reads ONLY the governed dataset (Phase 11) — no public
 * service is consulted per component (§87 discipline carried over).
 * Empty dataset ⇒ zero drafts.
 */
export function matchComponentsAgainstIntel(
  components: NormalizedSoftwareComponent[],
  dataset: IntelligenceDataset,
): DependencyFindingDraft[] {
  const drafts: DependencyFindingDraft[] = [];
  for (const component of components) {
    const cpe = componentToCpe(component);
    if (!cpe) continue;
    const record = dataset.lookupCpe(cpe);
    if (!record) continue;
    for (const cveId of record.cveIds) {
      const cve = dataset.getCve(cveId);
      if (!cve) continue;
      const epss = dataset.getEpss(cveId);
      const kev = dataset.getKev(cveId);
      drafts.push({
        title: `${cveId} potentially affects ${component.name} ${component.version ?? ""}`.trim(),
        description: `Component ${component.purl} matches governed CPE record ${record.canonical}, which a trusted source associates with ${cveId}. This is a POTENTIAL EXPOSURE (§33/§56): dependency presence alone does not prove the vulnerable code path is reachable or exploitable.`,
        severity: cve.cvss ? (cve.cvss.baseScore >= 9 ? "CRITICAL" : cve.cvss.baseScore >= 7 ? "HIGH" : cve.cvss.baseScore >= 4 ? "MEDIUM" : "LOW") : "MEDIUM",
        confidence: 0.5,
        cve: cveId,
        cwe: cve.cweIds[0],
        cvssScore: cve.cvss?.baseScore,
        cvssVector: cve.cvss?.vector,
        references: cve.references.map((r) => r.url),
        sourceTool: "intelligence-correlation",
        sourceFingerprint: `dep|${component.purl}|${cveId}`,
        componentName: component.name,
        componentVersion: component.version,
        componentPurl: component.purl,
        dependencyScope: component.dependencyScope,
        reachability: "POTENTIAL_EXPOSURE",
        sources: ["intelligence-correlation"],
        ...(epss ? { evidence: `EPSS ${epss.score} (percentile ${epss.percentile})${kev ? "; listed in CISA KEV" : ""} — from the local intelligence dataset snapshot ${dataset.snapshotId()}` } : {}),
      });
    }
  }
  return drafts;
}

/**
 * Enrich tool-reported dependency findings with local intelligence
 * (§55/§57): EPSS/KEV/CVSS attach ONLY when the dataset actually holds
 * the CVE — absence stays absence, never an invented value.
 */
export function enrichDependencyFindings(
  findings: NormalizedFinding[],
  dataset: IntelligenceDataset,
): NormalizedFinding[] {
  return findings.map((f) => {
    if (!f.cve) return f;
    const cve = dataset.getCve(f.cve);
    if (!cve) return f;
    const epss = dataset.getEpss(f.cve);
    const kev = dataset.getKev(f.cve);
    const notes: string[] = [];
    if (epss) notes.push(`EPSS ${epss.score}`);
    if (kev) notes.push("CISA KEV listed");
    return {
      ...f,
      cvssScore: f.cvssScore ?? cve.cvss?.baseScore,
      cvssVector: f.cvssVector ?? cve.cvss?.vector,
      cwe: f.cwe ?? cve.cweIds[0],
      evidence: [f.evidence, notes.length > 0 ? `Intelligence: ${notes.join("; ")} (snapshot ${dataset.snapshotId()})` : undefined].filter(Boolean).join(" — ") || undefined,
    };
  });
}
