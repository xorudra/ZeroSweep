import type { IntelligenceDataset, KevRecordData, EpssRecordData } from "./intelligence";
import { resolveCvssTrust, type CvssTrustResolution } from "./intelligence";
import { extractCveIds, normalizeCveId, normalizeCweId, parseCpe, formatCpe } from "./normalize";

/**
 * Finding enrichment (Prompt 11 §35–§36) + CPE correlation (§33–§34).
 *
 * Pipeline: extract CVE/CWE/CPE → normalize → read the LOCAL intelligence
 * cache → attach CVSS/EPSS/KEV → record exploit-reference presence →
 * hand the result to Risk Engine V2. Enrichment is IDEMPOTENT (§36):
 * every attachment is keyed, so re-running produces the same link set,
 * never duplicates.
 *
 * A finding gains intelligence ONLY for identifiers it actually carries
 * and ONLY when the local dataset actually contains a record. Absent
 * data is reported as absent — enrichment never fills gaps with
 * plausible-looking values.
 */

export interface EnrichableFinding {
  cve?: string;
  cwe?: string;
  cpe?: string;
  description?: string;
  cvssScore?: number; // scanner-provided
  vulnClass?: string;
}

export interface FindingEnrichment {
  cveId?: string;
  cweId?: string;
  cpeCanonical?: string;
  /** CVSS trust resolution (§32): scanner / intelligence / effective. */
  cvss: CvssTrustResolution;
  epss?: EpssRecordData;
  kev?: KevRecordData;
  kevListed: boolean;
  /** Link keys for idempotent persistence (§36): stable per finding+type+id. */
  linkKeys: string[];
  /** Human-readable account of exactly what was attached and what was not. */
  notes: string[];
  /** Intelligence snapshot used (§31). */
  snapshotId: string;
}

export function enrichFinding(finding: EnrichableFinding, dataset: IntelligenceDataset): FindingEnrichment {
  const notes: string[] = [];
  const linkKeys: string[] = [];
  const cveId = normalizeCveId(finding.cve) ?? extractCveIds(finding.description)[0];
  const cweId = normalizeCweId(finding.cwe);
  const cpeParts = parseCpe(finding.cpe);
  const cpeCanonical = cpeParts ? formatCpe(cpeParts) : undefined;

  let intelCvss: number | undefined;
  if (cveId) {
    const record = dataset.getCve(cveId);
    if (record) {
      linkKeys.push(`cve:${cveId}`);
      intelCvss = record.cvss?.baseScore;
      notes.push(`CVE record ${cveId} found in local intelligence (source ${record.source})`);
      for (const linkedCwe of record.cweIds) linkKeys.push(`cve-cwe:${cveId}:${linkedCwe}`);
    } else {
      notes.push(`no local intelligence record for ${cveId} — enrichment leaves the finding exactly as its scanner reported it`);
    }
  } else {
    notes.push("finding carries no CVE identifier — CVE/EPSS/KEV enrichment not applicable");
  }
  if (cweId) linkKeys.push(`cwe:${cweId}`);
  if (cpeCanonical) linkKeys.push(`cpe:${cpeCanonical}`);

  const epss = cveId ? dataset.getEpss(cveId) : undefined;
  if (epss) { linkKeys.push(`epss:${cveId}:${epss.date}`); notes.push(`EPSS ${epss.score} (percentile ${epss.percentile}, ${epss.date}) attached`); }
  const kev = cveId ? dataset.getKev(cveId) : undefined;
  if (kev) { linkKeys.push(`kev:${cveId}`); notes.push(`CISA KEV: ${cveId} is listed (added ${kev.dateAdded ?? "unknown date"})`); }

  return {
    ...(cveId ? { cveId } : {}),
    ...(cweId ? { cweId } : {}),
    ...(cpeCanonical ? { cpeCanonical } : {}),
    cvss: resolveCvssTrust({ scannerScore: finding.cvssScore, intelligenceScore: intelCvss }),
    ...(epss ? { epss } : {}),
    ...(kev ? { kev } : {}),
    kevListed: !!kev,
    linkKeys: [...new Set(linkKeys)].sort(),
    notes,
    snapshotId: dataset.snapshotId(),
  };
}

// ------------------------------- CPE → CVE correlation (§33/§34) -------------------------------

export interface PotentialExposure {
  cpeCanonical: string;
  cveId: string;
  detectionKind: "POTENTIAL_EXPOSURE";
  reason: string;
}

/**
 * CpeCveCorrelationService (§33): a software version matching a CPE that
 * a governed source associates with CVEs produces POTENTIAL_EXPOSURE
 * candidates ONLY. A CPE match is never a detection: without scanner /
 * evidence confirmation the issue is not a confirmed vulnerability and
 * must not enter the findings pipeline as one (§34, §96).
 */
export class CpeCveCorrelationService {
  constructor(private readonly dataset: IntelligenceDataset) {}

  correlate(input: { cpe?: string }): PotentialExposure[] {
    if (!input.cpe) return [];
    const parts = parseCpe(input.cpe);
    if (!parts) return [];
    const record = this.dataset.lookupCpe(formatCpe(parts));
    if (!record) return [];
    return record.cveIds.map((cveId) => ({
      cpeCanonical: record.canonical, cveId, detectionKind: "POTENTIAL_EXPOSURE" as const,
      reason: `governed intelligence associates ${record.canonical} with ${cveId}; no scanner detection exists — potential exposure only (§33)`,
    }));
  }
}
