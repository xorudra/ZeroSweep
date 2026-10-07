import { createHash } from "node:crypto";
import type { CvssRecord } from "./normalize";
import { normalizeCveId, normalizeCweId, normalizeCvss } from "./normalize";

/**
 * Vulnerability intelligence (Prompt 11 §22–§32, §87–§89). Trusted
 * vulnerability metadata is cached LOCALLY in normalized records; scans
 * and enrichment read the local dataset only — never a public service
 * per finding (§87). Providers are pluggable (§29): each knows how to
 * parse its source's payload into records, and the sync engine handles
 * incremental state, checksums, retry/backoff and last-success tracking
 * (§30) without any business logic in download jobs.
 *
 * The production dataset starts EMPTY and every source starts
 * NEVER_SYNCED. Nothing in this module can invent a record: enrichment
 * finds a CVE only when a synced record actually contains it.
 */

export interface CveRecordData {
  cveId: string;
  description: string;
  publishedAt?: string;
  modifiedAt?: string;
  cvss?: CvssRecord;
  cweIds: string[];
  references: { label: string; url: string }[];
  source: string;
  lastSyncedAt?: string;
}

export interface CweRecordData {
  cweId: string;
  name: string;
  description: string;
  category?: string;
  source: string;
}

export interface CpeRecordData {
  canonical: string;
  part: string;
  vendor: string;
  product: string;
  version?: string;
  /** CVEs a governed source associates with this CPE (exact record data,
   *  used only for POTENTIAL_EXPOSURE correlation, §33). */
  cveIds: string[];
  source: string;
}

export interface EpssRecordData {
  cveId: string;
  score: number; // probability 0..1 (§27 — context, not severity)
  percentile: number; // 0..1
  date: string; // ISO date of the EPSS snapshot
  source: string;
}

export interface KevRecordData {
  cveId: string;
  dateAdded?: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  requiredAction?: string;
  dueDate?: string;
  knownRansomwareUse?: string;
  source: string;
  lastSyncedAt?: string;
}

export type IntelligenceSourceId = "NVD" | "FIRST_EPSS" | "CISA_KEV" | "CURATED_CWE";

export interface SyncState {
  source: IntelligenceSourceId;
  status: "NEVER_SYNCED" | "SYNCED" | "FAILED";
  lastAttemptAt?: string;
  lastSuccessAt?: string;
  checksum?: string;
  recordCount: number;
  detail?: string;
}

export interface IntelligenceDataset {
  getCve(cveId: string): CveRecordData | undefined;
  getCwe(cweId: string): CweRecordData | undefined;
  getEpss(cveId: string): EpssRecordData | undefined;
  getKev(cveId: string): KevRecordData | undefined;
  lookupCpe(canonical: string): CpeRecordData | undefined;
  /** CVEs whose records reference this CWE. */
  cvesForCwe(cweId: string): string[];
  syncState(source: IntelligenceSourceId): SyncState;
  /** A stable fingerprint of what the dataset currently holds — the
   *  intelligence snapshot recorded with every risk calculation (§31). */
  snapshotId(): string;
}

/** In-memory dataset — the fixture/lab implementation and the shape the
 *  Prisma-backed API dataset mirrors. Starts empty (§93). */
export class InMemoryIntelligenceDataset implements IntelligenceDataset {
  private readonly cves = new Map<string, CveRecordData>();
  private readonly cwes = new Map<string, CweRecordData>();
  private readonly cpes = new Map<string, CpeRecordData>();
  private readonly epss = new Map<string, EpssRecordData>();
  private readonly kev = new Map<string, KevRecordData>();
  private readonly sync = new Map<IntelligenceSourceId, SyncState>();

  constructor() {
    for (const source of ["NVD", "FIRST_EPSS", "CISA_KEV", "CURATED_CWE"] as IntelligenceSourceId[]) {
      this.sync.set(source, { source, status: "NEVER_SYNCED", recordCount: 0 });
    }
  }

  upsertCve(record: CveRecordData): void { this.cves.set(record.cveId, record); }
  upsertCwe(record: CweRecordData): void { this.cwes.set(record.cweId, record); }
  upsertCpe(record: CpeRecordData): void { this.cpes.set(record.canonical, record); }
  upsertEpss(record: EpssRecordData): void {
    const existing = this.epss.get(record.cveId);
    if (!existing || existing.date <= record.date) this.epss.set(record.cveId, record);
  }
  upsertKev(record: KevRecordData): void { this.kev.set(record.cveId, record); }
  setSyncState(state: SyncState): void { this.sync.set(state.source, state); }

  getCve(cveId: string): CveRecordData | undefined { return this.cves.get(cveId); }
  getCwe(cweId: string): CweRecordData | undefined { return this.cwes.get(cweId); }
  getEpss(cveId: string): EpssRecordData | undefined { return this.epss.get(cveId); }
  getKev(cveId: string): KevRecordData | undefined { return this.kev.get(cveId); }
  lookupCpe(canonical: string): CpeRecordData | undefined { return this.cpes.get(canonical); }
  cvesForCwe(cweId: string): string[] {
    return [...this.cves.values()].filter((c) => c.cweIds.includes(cweId)).map((c) => c.cveId);
  }
  syncState(source: IntelligenceSourceId): SyncState {
    return this.sync.get(source) ?? { source, status: "NEVER_SYNCED", recordCount: 0 };
  }
  snapshotId(): string {
    const basis = [
      this.cves.size, this.cwes.size, this.cpes.size, this.epss.size, this.kev.size,
      ...[...this.sync.values()].map((s) => `${s.source}:${s.checksum ?? "none"}:${s.lastSuccessAt ?? "never"}`),
    ].join("|");
    return `intel-${createHash("sha256").update(basis).digest("hex").slice(0, 16)}`;
  }
}

// ------------------------------- Providers (§29) -------------------------------

export interface ProviderPayload {
  records: {
    cves: CveRecordData[];
    cwes: CweRecordData[];
    cpes: CpeRecordData[];
    epss: EpssRecordData[];
    kev: KevRecordData[];
  };
  /** Upstream checksum/ETag for incremental sync (§30), when the source offers one. */
  checksum?: string;
  warnings: string[];
}

export interface IntelligenceProvider {
  readonly source: IntelligenceSourceId;
  /** Parse ONE source payload (already fetched by the caller) into
   *  normalized records. Pure: no I/O, no fetching, fully fixture-testable. */
  parse(raw: string): ProviderPayload;
}

const emptyRecords = (): ProviderPayload["records"] => ({ cves: [], cwes: [], cpes: [], epss: [], kev: [] });

function parseJson(raw: string, source: string): unknown {
  try { return JSON.parse(raw); } catch { throw new Error(`${source} payload is not valid JSON`); }
}

/** NVD 2.0 API shape (vulnerabilities[].cve). CVSS versions are preserved
 *  as published (§26); CWE mappings come only from the record itself. */
export class NvdIntelligenceProvider implements IntelligenceProvider {
  readonly source = "NVD" as const;
  parse(raw: string): ProviderPayload {
    const doc = parseJson(raw, "NVD") as { vulnerabilities?: unknown[] };
    const out: ProviderPayload = { records: emptyRecords(), warnings: [] };
    for (const entry of doc.vulnerabilities ?? []) {
      const cve = (entry as { cve?: Record<string, unknown> }).cve;
      if (!cve) { out.warnings.push("NVD entry without cve object skipped"); continue; }
      const cveId = normalizeCveId(String(cve.id ?? ""));
      if (!cveId) { out.warnings.push("NVD entry with unparseable CVE id skipped"); continue; }
      const descriptions = (cve.descriptions as { lang: string; value: string }[] | undefined) ?? [];
      const description = descriptions.find((d) => d.lang === "en")?.value ?? descriptions[0]?.value ?? "";
      const metrics = (cve.metrics as Record<string, { cvssData?: { version?: string; baseScore?: number; vectorString?: string } }[]> | undefined) ?? {};
      const cvssData = metrics.cvssMetricV40?.[0]?.cvssData ?? metrics.cvssMetricV31?.[0]?.cvssData
        ?? metrics.cvssMetricV30?.[0]?.cvssData ?? metrics.cvssMetricV2?.[0]?.cvssData;
      const cvss = cvssData ? normalizeCvss({ score: cvssData.baseScore, vector: cvssData.vectorString, version: cvssData.version, source: "NVD" }) : undefined;
      const cweIds = new Set<string>();
      for (const w of (cve.weaknesses as { description?: { lang: string; value: string }[] }[] | undefined) ?? []) {
        for (const d of w.description ?? []) {
          const id = normalizeCweId(d.value);
          if (id) cweIds.add(id);
        }
      }
      const references = ((cve.references as { url?: string; source?: string }[] | undefined) ?? [])
        .filter((r) => typeof r.url === "string" && /^https?:\/\//.test(r.url))
        .map((r) => ({ label: r.source ?? "reference", url: r.url as string }));
      out.records.cves.push({
        cveId, description,
        ...(typeof cve.published === "string" ? { publishedAt: cve.published } : {}),
        ...(typeof cve.lastModified === "string" ? { modifiedAt: cve.lastModified } : {}),
        ...(cvss ? { cvss } : {}),
        cweIds: [...cweIds], references, source: "NVD",
      });
    }
    return out;
  }
}

/** FIRST EPSS API shape (data[].{cve,epss,percentile,date}). EPSS is a
 *  probability + percentile pair (§27/§98) — the two are never conflated. */
export class EpssIntelligenceProvider implements IntelligenceProvider {
  readonly source = "FIRST_EPSS" as const;
  parse(raw: string): ProviderPayload {
    const doc = parseJson(raw, "EPSS") as { data?: Record<string, unknown>[] };
    const out: ProviderPayload = { records: emptyRecords(), warnings: [] };
    for (const row of doc.data ?? []) {
      const cveId = normalizeCveId(String(row.cve ?? ""));
      const score = Number(row.epss);
      const percentile = Number(row.percentile);
      if (!cveId || !Number.isFinite(score) || !Number.isFinite(percentile)) {
        out.warnings.push("EPSS row with unparseable cve/score skipped");
        continue;
      }
      out.records.epss.push({
        cveId, score, percentile,
        date: typeof row.date === "string" ? row.date : "",
        source: "FIRST_EPSS",
      });
    }
    return out;
  }
}

/** CISA KEV catalog shape (vulnerabilities[]). KEV presence is a
 *  prioritization signal (§28) — the record keeps the source's own fields. */
export class KevIntelligenceProvider implements IntelligenceProvider {
  readonly source = "CISA_KEV" as const;
  parse(raw: string): ProviderPayload {
    const doc = parseJson(raw, "KEV") as { vulnerabilities?: Record<string, unknown>[] };
    const out: ProviderPayload = { records: emptyRecords(), warnings: [] };
    for (const row of doc.vulnerabilities ?? []) {
      const cveId = normalizeCveId(String(row.cveID ?? ""));
      if (!cveId) { out.warnings.push("KEV row with unparseable cveID skipped"); continue; }
      const str = (k: string) => (typeof row[k] === "string" && row[k] !== "" ? (row[k] as string) : undefined);
      out.records.kev.push({
        cveId,
        ...(str("dateAdded") ? { dateAdded: str("dateAdded") } : {}),
        ...(str("vendorProject") ? { vendorProject: str("vendorProject") } : {}),
        ...(str("product") ? { product: str("product") } : {}),
        ...(str("vulnerabilityName") ? { vulnerabilityName: str("vulnerabilityName") } : {}),
        ...(str("requiredAction") ? { requiredAction: str("requiredAction") } : {}),
        ...(str("dueDate") ? { dueDate: str("dueDate") } : {}),
        ...(str("knownRansomwareCampaignUse") ? { knownRansomwareUse: str("knownRansomwareCampaignUse") } : {}),
        source: "CISA_KEV",
      });
    }
    return out;
  }
}

// ------------------------------- Sync engine (§30) -------------------------------

export interface SyncOutcome {
  source: IntelligenceSourceId;
  status: "SYNCED" | "FAILED" | "UNCHANGED";
  recordCount: number;
  checksum?: string;
  attempts: number;
  detail?: string;
}

/**
 * IntelligenceSyncEngine (§30): incremental by checksum (an unchanged
 * payload is a no-op), bounded retry with exponential backoff, and
 * last-success tracking on the dataset. Fetching is INJECTED — the engine
 * never performs network I/O itself, which keeps builds/tests offline
 * and lets deployments wire their own approved egress. A failed sync
 * never blocks scanning (§30): callers read whatever the local dataset
 * already holds.
 */
export class IntelligenceSyncEngine {
  constructor(
    private readonly dataset: InMemoryIntelligenceDataset,
    private readonly fetchPayload: (source: IntelligenceSourceId) => Promise<string>,
    private readonly options: { maxAttempts?: number; baseBackoffMs?: number; sleep?: (ms: number) => Promise<void>; now?: () => Date } = {},
  ) {}

  async sync(provider: IntelligenceProvider): Promise<SyncOutcome> {
    const maxAttempts = this.options.maxAttempts ?? 3;
    const sleep = this.options.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
    const now = this.options.now ?? (() => new Date());
    const previous = this.dataset.syncState(provider.source);
    let lastError = "";
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const raw = await this.fetchPayload(provider.source);
        const checksum = createHash("sha256").update(raw).digest("hex");
        if (previous.checksum === checksum && previous.status === "SYNCED") {
          this.dataset.setSyncState({ ...previous, lastAttemptAt: now().toISOString() });
          return { source: provider.source, status: "UNCHANGED", recordCount: previous.recordCount, checksum, attempts: attempt };
        }
        const parsed = provider.parse(raw);
        for (const r of parsed.records.cves) this.dataset.upsertCve({ ...r, lastSyncedAt: now().toISOString() });
        for (const r of parsed.records.cwes) this.dataset.upsertCwe(r);
        for (const r of parsed.records.cpes) this.dataset.upsertCpe(r);
        for (const r of parsed.records.epss) this.dataset.upsertEpss(r);
        for (const r of parsed.records.kev) this.dataset.upsertKev({ ...r, lastSyncedAt: now().toISOString() });
        const count = parsed.records.cves.length + parsed.records.cwes.length + parsed.records.cpes.length
          + parsed.records.epss.length + parsed.records.kev.length;
        this.dataset.setSyncState({
          source: provider.source, status: "SYNCED",
          lastAttemptAt: now().toISOString(), lastSuccessAt: now().toISOString(),
          checksum: parsed.checksum ?? checksum, recordCount: count,
          ...(parsed.warnings.length ? { detail: parsed.warnings.join("; ") } : {}),
        });
        return { source: provider.source, status: "SYNCED", recordCount: count, checksum: parsed.checksum ?? checksum, attempts: attempt };
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        if (attempt < maxAttempts) await sleep((this.options.baseBackoffMs ?? 250) * 2 ** (attempt - 1));
      }
    }
    this.dataset.setSyncState({
      ...previous, status: "FAILED", lastAttemptAt: now().toISOString(),
      detail: `sync failed after ${maxAttempts} attempts: ${lastError}`,
    });
    return { source: provider.source, status: "FAILED", recordCount: previous.recordCount, attempts: maxAttempts, detail: lastError };
  }
}

// ------------------------------- Source trust (§32) -------------------------------

export interface CvssTrustResolution {
  scannerScore?: number;
  intelligenceScore?: number;
  effectiveScore?: number;
  reason: string;
}

/**
 * Source precedence (§32): scanner-provided CVSS and authoritative
 * intelligence CVSS may differ. Neither silently overwrites the other —
 * all three values are preserved with the reason the effective score was
 * chosen. Rule: a finding keeps its SCANNER score as effective when the
 * scanner provided one (it describes what the scanner measured);
 * intelligence fills the gap only when the scanner provided none.
 */
export function resolveCvssTrust(input: { scannerScore?: number; intelligenceScore?: number }): CvssTrustResolution {
  const { scannerScore, intelligenceScore } = input;
  if (scannerScore !== undefined && intelligenceScore !== undefined) {
    return {
      scannerScore, intelligenceScore, effectiveScore: scannerScore,
      reason: scannerScore === intelligenceScore
        ? "scanner and intelligence CVSS agree"
        : `scanner CVSS ${scannerScore} kept as effective; intelligence CVSS ${intelligenceScore} preserved separately (§32)`,
    };
  }
  if (scannerScore !== undefined) return { scannerScore, effectiveScore: scannerScore, reason: "scanner-provided CVSS; no intelligence record" };
  if (intelligenceScore !== undefined) return { intelligenceScore, effectiveScore: intelligenceScore, reason: "no scanner CVSS; intelligence CVSS applied (§32)" };
  return { reason: "no CVSS from scanner or intelligence — score stays unset" };
}

/** The VulnerabilityIntelligenceService (§22): the read facade every
 *  consumer uses. Lookups hit the LOCAL dataset only (§87). */
export class VulnerabilityIntelligenceServiceV2 {
  constructor(private readonly dataset: IntelligenceDataset) {}
  cve(cveId: string): CveRecordData | undefined { const id = normalizeCveId(cveId); return id ? this.dataset.getCve(id) : undefined; }
  cwe(cweId: string): CweRecordData | undefined { const id = normalizeCweId(cweId); return id ? this.dataset.getCwe(id) : undefined; }
  epss(cveId: string): EpssRecordData | undefined { const id = normalizeCveId(cveId); return id ? this.dataset.getEpss(id) : undefined; }
  kev(cveId: string): KevRecordData | undefined { const id = normalizeCveId(cveId); return id ? this.dataset.getKev(id) : undefined; }
  snapshotId(): string { return this.dataset.snapshotId(); }
  syncState(source: IntelligenceSourceId): SyncState { return this.dataset.syncState(source); }
}
