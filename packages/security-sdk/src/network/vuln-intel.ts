/**
 * Vulnerability intelligence — PREPARED, not yet ingesting (Prompt 10
 * §55). A normalized service/product/version/CPE may LATER be enriched
 * with CVE / CVSS / EPSS / KEV data through dedicated feed adapters
 * (Prompt 11/30). This phase defines ONLY the boundary: a local dataset
 * interface, an empty default dataset, and a lookup that can never
 * invent data — when the dataset has no entry, the lookup returns
 * nothing and the finding keeps exactly the evidence its source
 * produced. No uncontrolled feed ingestion happens here.
 */

export interface VulnerabilityIntelRecord {
  cveId: string;
  cpe?: string;
  product?: string;
  affectedVersions?: string[];
  cvssScore?: number;
  cvssVector?: string;
  epssScore?: number;
  kevListed?: boolean;
  summary?: string;
}

export interface VulnerabilityDataset {
  lookupByCpe(cpe: string): VulnerabilityIntelRecord[];
  lookupByProduct(product: string, version?: string): VulnerabilityIntelRecord[];
}

/** The shipped dataset is EMPTY by design (§55 prepared-only). */
export const EMPTY_VULNERABILITY_DATASET: VulnerabilityDataset = {
  lookupByCpe: () => [],
  lookupByProduct: () => [],
};

export class VulnerabilityIntelligenceService {
  constructor(private readonly dataset: VulnerabilityDataset = EMPTY_VULNERABILITY_DATASET) {}

  enrichService(service: { name?: string; product?: string; version?: string; cpe?: string }): VulnerabilityIntelRecord[] {
    const out: VulnerabilityIntelRecord[] = [];
    if (service.cpe) out.push(...this.dataset.lookupByCpe(service.cpe));
    if (service.product) out.push(...this.dataset.lookupByProduct(service.product, service.version));
    const seen = new Set<string>();
    return out.filter((r) => (seen.has(r.cveId) ? false : (seen.add(r.cveId), true)));
  }

  /** Always false in this phase: no feed is connected, so nothing may
   *  claim live intelligence. Callers surface this honestly. */
  get feedsConnected(): boolean {
    return false;
  }
}

export const vulnerabilityIntelligence = new VulnerabilityIntelligenceService();
