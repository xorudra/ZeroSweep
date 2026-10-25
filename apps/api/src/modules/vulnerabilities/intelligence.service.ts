import { Inject, Injectable } from "@nestjs/common";
import {
  CpeCveCorrelationService, EpssIntelligenceProvider, InMemoryIntelligenceDataset, IntelligenceSyncEngine,
  KevIntelligenceProvider, NvdIntelligenceProvider, VulnerabilityIntelligenceServiceV2,
  enrichFinding, normalizeCveId, type IntelligenceDataset, type IntelligenceSourceId,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";

/**
 * Vulnerability intelligence over the GOVERNED LOCAL DATASET (Prompt 11
 * §22–§36, §87): CVE/CWE/CPE/EPSS/KEV records live in local tables,
 * synchronized by the sync engine from public sources. Nothing is ever
 * fetched per-request and nothing is invented — a CVE with no local
 * record has NO intelligence data, and the API says exactly that.
 *
 * The sync fetcher is injected: production wires an egress fetcher in a
 * deployment phase; in this build NO fetcher is configured, so a sync
 * attempt honestly records FAILED with that reason and every state stays
 * NEVER_SYNCED until real records exist (§30/§87).
 */
export const INTELLIGENCE_FETCHER = Symbol("INTELLIGENCE_FETCHER");
export type IntelligenceFetcher = (source: IntelligenceSourceId) => Promise<string>;

@Injectable()
export class IntelligenceService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    @Inject(INTELLIGENCE_FETCHER) private readonly fetcher: IntelligenceFetcher | null,
  ) {}

  /** Load a dataset slice for the given CVE ids from local tables. */
  async loadDataset(cveIds: string[] = []): Promise<InMemoryIntelligenceDataset> {
    const ds = new InMemoryIntelligenceDataset();
    const [states, cves, epss, kevs, cpes] = await Promise.all([
      this.prisma.intelligenceSyncState.findMany(),
      cveIds.length ? this.prisma.cveRecord.findMany({ where: { cveId: { in: cveIds } } }) : Promise.resolve([]),
      cveIds.length ? this.prisma.epssRecord.findMany({ where: { cveId: { in: cveIds } }, orderBy: { date: "desc" } }) : Promise.resolve([]),
      cveIds.length ? this.prisma.kevRecord.findMany({ where: { cveId: { in: cveIds } } }) : Promise.resolve([]),
      this.prisma.cpeRecord.findMany({ take: 5000 }),
    ]);
    for (const s of states) {
      ds.setSyncState({
        source: s.source as IntelligenceSourceId,
        status: s.status as "NEVER_SYNCED" | "SYNCED" | "FAILED", recordCount: s.recordCount,
        ...(s.lastAttemptAt ? { lastAttemptAt: s.lastAttemptAt.toISOString() } : {}),
        ...(s.lastSuccessAt ? { lastSuccessAt: s.lastSuccessAt.toISOString() } : {}),
        ...(s.checksum ? { checksum: s.checksum } : {}),
        ...(s.detail ? { detail: s.detail } : {}),
      });
    }
    for (const c of cves) {
      const record: Parameters<InMemoryIntelligenceDataset["upsertCve"]>[0] = {
        cveId: c.cveId, description: c.description,
        cweIds: c.cweIds, publishedAt: c.publishedAt?.toISOString(), modifiedAt: c.modifiedAt?.toISOString(),
        references: (c.references as Array<{ label: string; url: string }> | null) ?? [], source: c.source,
      };
      if (c.cvssScore != null) {
        record.cvss = {
          baseScore: c.cvssScore, version: (c.cvssVersion ?? "3.1") as "3.1", source: c.source,
          ...(c.cvssVector ? { vector: c.cvssVector } : {}),
        } as typeof record.cvss;
      }
      ds.upsertCve(record);
    }
    const seenEpss = new Set<string>();
    for (const e of epss) {
      if (seenEpss.has(e.cveId)) continue; // latest only (ordered desc)
      seenEpss.add(e.cveId);
      ds.upsertEpss({ cveId: e.cveId, score: e.score, percentile: e.percentile, date: e.date.toISOString().slice(0, 10), source: e.source });
    }
    for (const k of kevs) {
      ds.upsertKev({ cveId: k.cveId, vendorProject: k.vendorProject ?? undefined, product: k.product ?? undefined, ...(k.dateAdded ? { dateAdded: k.dateAdded.toISOString().slice(0, 10) } : {}), requiredAction: k.requiredAction ?? undefined, dueDate: k.dueDate?.toISOString().slice(0, 10), knownRansomwareUse: k.knownRansomwareUse ?? undefined, source: k.source });
    }
    for (const c of cpes) {
      ds.upsertCpe({ canonical: c.canonical, part: c.part, vendor: c.vendor, product: c.product, version: c.version ?? undefined, cveIds: c.cveIds, source: c.source });
    }
    return ds;
  }

  async syncStates() {
    const rows = await this.prisma.intelligenceSyncState.findMany({ orderBy: { source: "asc" } });
    const known: IntelligenceSourceId[] = ["NVD", "FIRST_EPSS", "CISA_KEV"];
    return known.map((source) => {
      const row = rows.find((r) => r.source === source);
      return row
        ? { source, status: row.status, records: row.recordCount, lastSuccessAt: row.lastSuccessAt, detail: row.detail }
        : { source, status: "NEVER_SYNCED", records: 0, lastSuccessAt: null, detail: "no sync has run for this source" };
    });
  }

  /** §69/§80: full intelligence view for one CVE (record may be absent). */
  async cveDetail(rawCveId: string, workspaceId?: string) {
    const cveId = normalizeCveId(rawCveId) ?? rawCveId.toUpperCase();
    const ds = await this.loadDataset([cveId]);
    const svc = new VulnerabilityIntelligenceServiceV2(ds);
    const view = {
      cve: svc.cve(cveId), epss: svc.epss(cveId), kev: svc.kev(cveId),
      hasData: Boolean(svc.cve(cveId) ?? svc.epss(cveId) ?? svc.kev(cveId)),
    };
    const affectedAssets = workspaceId
      ? await this.prisma.finding.groupBy({
          by: ["host"],
          where: { workspaceId, cve: cveId, duplicateOfId: null },
          _count: { _all: true },
        })
      : [];
    const affectedFindings = workspaceId
      ? await this.prisma.finding.findMany({
          where: { workspaceId, cve: cveId, duplicateOfId: null },
          select: { id: true, title: true, severity: true, lifecycleStatus: true, priority: true, host: true, port: true, firstSeen: true, lastSeen: true },
          orderBy: { riskScore: "desc" }, take: 200,
        })
      : [];
    return {
      cveId,
      hasIntelligenceData: view.hasData,
      cve: view.cve ?? null,
      epss: view.epss ?? null,
      kev: view.kev ?? null,
      exploitReferencesNote: "Exploit references are recorded per finding from the governed reference dataset (§20) — a reference existing is NOT confirmation of exploitability.",
      affectedAssets: affectedAssets.map((a) => ({ host: a.host, findings: a._count._all })),
      affectedFindings,
      syncStates: await this.syncStates(),
    };
  }

  /** Enrich one finding's identifiers against the local dataset (§35). */
  async enrich(input: { cve?: string | null; cwe?: string | null; cpe?: string | null; cvssScore?: number | null }) {
    const cveId = input.cve ? normalizeCveId(input.cve) : undefined;
    const ds = await this.loadDataset(cveId ? [cveId] : []);
    return { enrichment: enrichFinding({ cve: input.cve ?? undefined, cwe: input.cwe ?? undefined, cpe: input.cpe ?? undefined, cvssScore: input.cvssScore ?? undefined }, ds), dataset: ds as IntelligenceDataset };
  }

  /** CPE → potential exposure candidates (§33/§34). */
  async potentialExposures(cpe: string) {
    const ds = await this.loadDataset();
    return new CpeCveCorrelationService(ds).correlate({ cpe });
  }

  /**
   * Run one source sync (§29/§30). With no egress fetcher configured the
   * attempt fails honestly and is recorded — scans are never blocked.
   */
  async runSync(source: "NVD" | "FIRST_EPSS" | "CISA_KEV") {
    const fetcher: IntelligenceFetcher = this.fetcher ?? (async () => { throw new Error("no intelligence egress fetcher is configured on this host — sync cannot run (state remains honest)"); });
    const providers = { NVD: new NvdIntelligenceProvider(), FIRST_EPSS: new EpssIntelligenceProvider(), CISA_KEV: new KevIntelligenceProvider() };
    const provider = providers[source];
    const persisting = new PersistingDataset(this.prisma);
    const engine = new IntelligenceSyncEngine(persisting, fetcher, { sleep: async () => {} });
    const outcome = await engine.sync(provider);
    await persisting.flush();
    await this.prisma.intelligenceSyncState.upsert({
      where: { source },
      create: { source, status: outcome.status === "SYNCED" || outcome.status === "UNCHANGED" ? "SYNCED" : outcome.status, recordCount: outcome.recordCount, lastAttemptAt: new Date(), ...(outcome.status !== "FAILED" ? { lastSuccessAt: new Date() } : {}), checksum: outcome.checksum, detail: outcome.detail },
      update: { status: outcome.status === "UNCHANGED" ? "SYNCED" : outcome.status, recordCount: outcome.recordCount, lastAttemptAt: new Date(), ...(outcome.status !== "FAILED" ? { lastSuccessAt: new Date() } : {}), checksum: outcome.checksum, detail: outcome.detail },
    });
    return outcome;
  }
}

/** Dataset facade that persists provider records into the local tables. */
class PersistingDataset extends InMemoryIntelligenceDataset {
  private readonly pending: Promise<unknown>[] = [];
  constructor(private readonly prisma: PrismaClientLike) { super(); }
  /** Await every fire-and-forget table write the sync produced. */
  async flush(): Promise<void> { await Promise.allSettled(this.pending); }
  private track<T>(p: Promise<T>): void { this.pending.push(p.catch(() => undefined)); }

  override upsertCve(record: Parameters<InMemoryIntelligenceDataset["upsertCve"]>[0]): void {
    super.upsertCve(record);
    this.track(this.prisma.cveRecord.upsert({
      where: { cveId: record.cveId },
      create: {
        cveId: record.cveId, description: record.description ?? "",
        cvssScore: record.cvss?.baseScore, cvssVector: record.cvss?.vector, cvssVersion: record.cvss?.version,
        cweIds: record.cweIds, references: (record.references ?? []) as never,
        publishedAt: record.publishedAt ? new Date(record.publishedAt) : undefined,
        modifiedAt: record.modifiedAt ? new Date(record.modifiedAt) : undefined, source: record.source,
      },
      update: {
        description: record.description ?? "",
        cvssScore: record.cvss?.baseScore, cvssVector: record.cvss?.vector, cvssVersion: record.cvss?.version,
        cweIds: record.cweIds, references: (record.references ?? []) as never,
        publishedAt: record.publishedAt ? new Date(record.publishedAt) : undefined,
        modifiedAt: record.modifiedAt ? new Date(record.modifiedAt) : undefined, source: record.source,
      },
    }));
  }

  override upsertEpss(record: Parameters<InMemoryIntelligenceDataset["upsertEpss"]>[0]): void {
    super.upsertEpss(record);
    this.track(this.prisma.epssRecord.upsert({
      where: { cveId_date: { cveId: record.cveId, date: new Date(record.date) } },
      create: { cveId: record.cveId, score: record.score, percentile: record.percentile, date: new Date(record.date), source: record.source },
      update: { score: record.score, percentile: record.percentile, source: record.source },
    }));
  }

  override upsertKev(record: Parameters<InMemoryIntelligenceDataset["upsertKev"]>[0]): void {
    super.upsertKev(record);
    this.track(this.prisma.kevRecord.upsert({
      where: { cveId: record.cveId },
      create: {
        cveId: record.cveId, vendorProject: record.vendorProject, product: record.product,
        dateAdded: record.dateAdded ? new Date(record.dateAdded) : undefined, requiredAction: record.requiredAction,
        dueDate: record.dueDate ? new Date(record.dueDate) : undefined,
        knownRansomwareUse: record.knownRansomwareUse, source: record.source,
      },
      update: {
        vendorProject: record.vendorProject, product: record.product,
        dateAdded: record.dateAdded ? new Date(record.dateAdded) : undefined, requiredAction: record.requiredAction,
        dueDate: record.dueDate ? new Date(record.dueDate) : undefined,
        knownRansomwareUse: record.knownRansomwareUse, source: record.source,
      },
    }));
  }
}
