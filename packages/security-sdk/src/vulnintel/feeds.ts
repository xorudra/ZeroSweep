import { createHash } from "node:crypto";
import { normalizeCveId, normalizeCweId } from "../vulnmgmt/normalize";
import type {
  AdvisoryData, AffectedRangeData, CvssAssessmentData, CveStatus, EpssPoint, KevEntryData,
} from "./types";

/**
 * Provider feeds (Prompt 30 §8–§15, §64–§71, §125–§130, §152–§154).
 *
 * Provider data is UNTRUSTED EXTERNAL INPUT (§127): every parser caps
 * sizes, drops control characters / HTML from text fields, validates
 * reference URLs (http/https only) and NEVER fetches anything (§129) —
 * a URL inside provider data is stored as a reference string, period.
 *
 * The live fetch transport is deliberately NOT wired in this build:
 * providers expose parse() + health semantics, and the API layer's
 * fetch path reports NOT_CONFIGURED (the P11 honesty rule). Governed
 * snapshot IMPORT (an operator supplies a recorded feed document) is
 * the supported ingestion path here.
 */

// ------------------------------ input hardening (§127) ------------------------------

export const MAX_FEED_BYTES = 25_000_000; // 25 MB hard cap per snapshot document
export const MAX_FEED_RECORDS = 50_000;

/** Strip control characters + neutralize HTML in provider text (§153). */
export function sanitizeProviderText(raw: unknown, maxLen = 20_000): string {
  if (typeof raw !== "string") return "";
  return raw
    .slice(0, maxLen)
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .replace(/</g, "‹")
    .replace(/>/g, "›")
    .replace(/\r\n?/g, "\n")
    .trim();
}

/** §128: only http/https references survive; everything else is dropped,
 *  never fetched (§129/§154). */
export function validateReferenceUrl(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const value = raw.trim();
  if (value.length > 2048) return undefined;
  let url: URL;
  try { url = new URL(value); } catch { return undefined; }
  if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
  if (url.username || url.password) return undefined;
  return url.toString();
}

export function sanitizeReferences(raw: unknown): { label: string; url: string }[] {
  if (!Array.isArray(raw)) return [];
  const out: { label: string; url: string }[] = [];
  for (const item of raw.slice(0, 50)) {
    if (typeof item === "string") {
      const url = validateReferenceUrl(item);
      if (url) out.push({ label: "reference", url });
    } else if (item && typeof item === "object") {
      const rec = item as Record<string, unknown>;
      const url = validateReferenceUrl(rec.url ?? rec.href);
      if (url) out.push({ label: sanitizeProviderText(rec.label ?? rec.name ?? "reference", 200) || "reference", url });
    }
  }
  return out;
}

/** SHA-256 over the canonical snapshot document — provenance anchor (§6). */
export function snapshotChecksum(document: string): string {
  return createHash("sha256").update(document).digest("hex");
}

// ------------------------------ source priority (§7) ------------------------------

/**
 * Deterministic source priority (§7/§71). Higher wins for the PREFERRED
 * view of a field; lower-priority values are preserved, never deleted.
 * Authoritative registries outrank aggregators; scanner observations
 * rank lowest for intelligence fields (they are evidence, not intel).
 */
export const SOURCE_PRIORITY: Record<string, number> = {
  NVD: 90,
  CNA: 85,
  CISA_KEV: 95, // for KEV facts, the catalog itself is authoritative
  FIRST_EPSS: 95, // for EPSS facts
  GHSA: 80,
  OSV: 75,
  VENDOR: 85,
  CURATED: 60,
  SCANNER: 40,
  FIXTURE: 10, // recorded test excerpts — lowest, and labelled
};

export function sourcePriority(source: string): number {
  const key = source.toUpperCase();
  for (const [k, v] of Object.entries(SOURCE_PRIORITY)) if (key.includes(k)) return v;
  return 50;
}

/** §14: deterministic preferred CVSS — highest source priority, then
 *  newest CVSS version, then highest baseScore as final tiebreak. All
 *  assessments are preserved; this only SELECTS the preferred view. */
export function selectPreferredCvss(assessments: CvssAssessmentData[]): CvssAssessmentData | undefined {
  if (!assessments.length) return undefined;
  const versionRank = (v: string) => ({ "4.0": 4, "3.1": 3.1, "3.0": 3.0, "2.0": 2 }[v] ?? 0);
  return [...assessments].sort((a, b) =>
    sourcePriority(b.source) - sourcePriority(a.source)
    || versionRank(b.version) - versionRank(a.version)
    || b.baseScore - a.baseScore
    || a.source.localeCompare(b.source),
  )[0];
}

export function cvssSeverityForScore(score: number, version: string): string {
  if (version === "2.0") return score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : "LOW";
  if (score === 0) return "NONE";
  if (score < 4) return "LOW";
  if (score < 7) return "MEDIUM";
  if (score < 9) return "HIGH";
  return "CRITICAL";
}

// ------------------------------ provider interface (§8/§9) ------------------------------

export interface ProviderParseResult<T> {
  records: T[];
  rejected: { reason: string; sample?: string }[];
}

export interface CveIntelligenceProvider {
  readonly id: string;
  /** Live fetch is transport-dependent; in this build it is NOT wired. */
  fetchCve(cveId: string): Promise<never>;
  fetchModifiedSince(since: Date): Promise<never>;
  healthCheck(): { provider: string; status: "NOT_CONFIGURED"; detail: string };
}

export function unconfiguredProvider(id: string): CveIntelligenceProvider {
  const fail = (): Promise<never> => Promise.reject(new Error(`provider ${id}: live fetch transport is not configured in this deployment — governed snapshot import is the supported ingestion path`));
  return {
    id,
    fetchCve: fail,
    fetchModifiedSince: fail,
    healthCheck: () => ({ provider: id, status: "NOT_CONFIGURED", detail: "no egress fetcher wired; dataset updates arrive via governed snapshot import only" }),
  };
}

// ------------------------------ NVD 2.0 parser ------------------------------

export interface NvdParseOutput {
  cve: {
    cveId: string; status: CveStatus; description: string; publishedAt?: string; modifiedAt?: string;
    cweIds: string[]; references: { label: string; url: string }[];
  };
  cvss: CvssAssessmentData[];
  ranges: AffectedRangeData[];
  affectedProducts: { vendor: string; product: string; identifier: string; identifierType: "CPE" }[];
}

function mapNvdStatus(raw: unknown): CveStatus {
  const s = typeof raw === "string" ? raw.toUpperCase() : "";
  if (s.includes("REJECT")) return "REJECTED";
  if (s.includes("WITHDRAW")) return "WITHDRAWN";
  if (s === "PUBLISHED") return "PUBLISHED";
  if (s === "MODIFIED") return "MODIFIED";
  return "UNKNOWN";
}

/** Parse one NVD 2.0 vulnerability object (untrusted input, §127). */
export function parseNvdVulnerability(raw: unknown, observedAt: string, source = "NVD"): NvdParseOutput | null {
  if (!raw || typeof raw !== "object") return null;
  const cve = (raw as Record<string, unknown>).cve as Record<string, unknown> | undefined;
  if (!cve) return null;
  const cveId = normalizeCveId(typeof cve.id === "string" ? cve.id : undefined);
  if (!cveId) return null; // §131: malformed identifiers are rejected, never repaired
  const status = mapNvdStatus(cve.vulnStatus);
  const descriptions = Array.isArray(cve.descriptions) ? cve.descriptions : [];
  const en = descriptions.find((d) => (d as Record<string, unknown>)?.lang === "en") ?? descriptions[0];
  const description = sanitizeProviderText((en as Record<string, unknown> | undefined)?.value);
  const cweIds = new Set<string>();
  if (Array.isArray(cve.weaknesses)) {
    for (const w of cve.weaknesses as Record<string, unknown>[]) {
      const descs = Array.isArray(w?.description) ? w.description : [];
      for (const d of descs as Record<string, unknown>[]) {
        const id = normalizeCweId(typeof d?.value === "string" ? d.value : undefined);
        if (id) cweIds.add(id);
      }
    }
  }
  const references = sanitizeReferences(
    Array.isArray(cve.references) ? cve.references.map((r) => ({ label: (r as Record<string, unknown>)?.source, url: (r as Record<string, unknown>)?.url })) : [],
  );
  const cvss: CvssAssessmentData[] = [];
  const metrics = (cve.metrics ?? {}) as Record<string, unknown>;
  const metricMap: [string, CvssAssessmentData["version"]][] = [
    ["cvssMetricV40", "4.0"], ["cvssMetricV31", "3.1"], ["cvssMetricV30", "3.0"], ["cvssMetricV2", "2.0"],
  ];
  for (const [key, version] of metricMap) {
    const entries = metrics[key];
    if (!Array.isArray(entries)) continue;
    for (const entry of entries as Record<string, unknown>[]) {
      const data = (entry?.cvssData ?? {}) as Record<string, unknown>;
      const score = typeof data.baseScore === "number" ? data.baseScore : Number(data.baseScore);
      if (!Number.isFinite(score) || score < 0 || score > 10) continue;
      const src = typeof entry?.source === "string" ? entry.source : source;
      cvss.push({
        cveId, version,
        ...(typeof data.vectorString === "string" ? { vector: data.vectorString.slice(0, 200) } : {}),
        baseScore: score,
        severity: typeof data.baseSeverity === "string" ? data.baseSeverity : cvssSeverityForScore(score, version),
        source: src === "nvd@nist.gov" ? "NVD" : source,
        observedAt,
      });
    }
  }
  const ranges: AffectedRangeData[] = [];
  const affectedProducts: NvdParseOutput["affectedProducts"] = [];
  const configurations = Array.isArray(cve.configurations) ? cve.configurations : [];
  for (const cfg of configurations as Record<string, unknown>[]) {
    const nodes = Array.isArray(cfg?.nodes) ? cfg.nodes : [];
    for (const node of nodes as Record<string, unknown>[]) {
      const matches = Array.isArray(node?.cpeMatch) ? node.cpeMatch : [];
      for (const match of matches as Record<string, unknown>[]) {
        if (match?.vulnerable === false) continue;
        const criteria = typeof match?.criteria === "string" ? match.criteria : "";
        const fields = criteria.split(":");
        if (fields.length < 5 || fields[0] !== "cpe") continue;
        const vendor = (fields[3] ?? "").replace(/\\/g, "");
        const product = (fields[4] ?? "").replace(/\\/g, "");
        if (!vendor || !product || vendor === "*" || product === "*") continue;
        affectedProducts.push({ vendor, product, identifier: criteria, identifierType: "CPE" });
        ranges.push({
          cveId, vendor, product, ecosystem: "generic",
          ...(typeof match.versionStartIncluding === "string" ? { introducedVersion: match.versionStartIncluding } : {}),
          ...(typeof match.versionEndExcluding === "string" ? { fixedVersion: match.versionEndExcluding } : {}),
          ...(typeof match.versionEndIncluding === "string" ? { lastAffectedVersion: match.versionEndIncluding } : {}),
          rangeExpression: criteria.slice(0, 500),
          confidence: "HIGH",
          source,
        });
      }
    }
  }
  return {
    cve: {
      cveId, status, description,
      ...(typeof cve.published === "string" ? { publishedAt: cve.published } : {}),
      ...(typeof cve.lastModified === "string" ? { modifiedAt: cve.lastModified } : {}),
      cweIds: [...cweIds], references,
    },
    cvss, ranges, affectedProducts,
  };
}

/** Parse a full NVD 2.0 feed document (bounded, §127). */
export function parseNvdFeed(document: string, observedAt: string, source = "NVD"): ProviderParseResult<NvdParseOutput> {
  const rejected: ProviderParseResult<NvdParseOutput>["rejected"] = [];
  if (Buffer.byteLength(document) > MAX_FEED_BYTES) return { records: [], rejected: [{ reason: `document exceeds ${MAX_FEED_BYTES} bytes` }] };
  let parsed: unknown;
  try { parsed = JSON.parse(document); } catch { return { records: [], rejected: [{ reason: "document is not valid JSON" }] }; }
  const vulns = (parsed as Record<string, unknown>)?.vulnerabilities;
  if (!Array.isArray(vulns)) return { records: [], rejected: [{ reason: "NVD document has no vulnerabilities array" }] };
  if (vulns.length > MAX_FEED_RECORDS) return { records: [], rejected: [{ reason: `document exceeds ${MAX_FEED_RECORDS} records` }] };
  const records: NvdParseOutput[] = [];
  for (const v of vulns) {
    const out = parseNvdVulnerability(v, observedAt, source);
    if (out) records.push(out);
    else rejected.push({ reason: "vulnerability entry rejected (malformed CVE id or shape)" });
  }
  return { records, rejected };
}

// ------------------------------ EPSS parser (§19–§22) ------------------------------

/** Parse an EPSS CSV document (header `#model_version:...` or plain).
 *  Every row is one dated point — history is preserved by the caller
 *  keying on (cveId, date); this parser never collapses dates (§20). */
export function parseEpssCsv(document: string, source = "FIRST_EPSS"): ProviderParseResult<EpssPoint> {
  const rejected: ProviderParseResult<EpssPoint>["rejected"] = [];
  if (Buffer.byteLength(document) > MAX_FEED_BYTES) return { records: [], rejected: [{ reason: "document exceeds size cap" }] };
  const lines = document.split(/\r?\n/).filter((l) => l.trim().length > 0);
  let date = "";
  const records: EpssPoint[] = [];
  for (const line of lines) {
    if (line.startsWith("#")) {
      const m = line.match(/score_date[:=]([0-9]{4}-[0-9]{2}-[0-9]{2})/);
      if (m) date = m[1]!;
      continue;
    }
    if (/^cve,/.test(line)) continue; // header row
    const [cveRaw, scoreRaw, percentileRaw, dateRaw] = line.split(",").map((s) => s?.trim());
    const cveId = normalizeCveId(cveRaw);
    const score = Number(scoreRaw);
    const percentile = Number(percentileRaw);
    const rowDate = dateRaw && /^[0-9]{4}-[0-9]{2}-[0-9]{2}/.test(dateRaw) ? dateRaw.slice(0, 10) : date;
    if (!cveId || !Number.isFinite(score) || score < 0 || score > 1 || !Number.isFinite(percentile) || !rowDate) {
      rejected.push({ reason: "EPSS row rejected (malformed CVE, score out of 0..1, or missing date)", sample: line.slice(0, 120) });
      continue;
    }
    records.push({ cveId, score, percentile, date: rowDate, source });
    if (records.length > MAX_FEED_RECORDS) { rejected.push({ reason: "record cap reached" }); break; }
  }
  return { records, rejected };
}

// ------------------------------ KEV parser (§23–§25) ------------------------------

export function parseKevCatalog(document: string, observedAt: string, source = "CISA_KEV"): ProviderParseResult<KevEntryData> {
  void observedAt;
  const rejected: ProviderParseResult<KevEntryData>["rejected"] = [];
  if (Buffer.byteLength(document) > MAX_FEED_BYTES) return { records: [], rejected: [{ reason: "document exceeds size cap" }] };
  let parsed: unknown;
  try { parsed = JSON.parse(document); } catch { return { records: [], rejected: [{ reason: "document is not valid JSON" }] }; }
  const vulns = (parsed as Record<string, unknown>)?.vulnerabilities;
  if (!Array.isArray(vulns)) return { records: [], rejected: [{ reason: "KEV document has no vulnerabilities array" }] };
  const records: KevEntryData[] = [];
  for (const v of vulns as Record<string, unknown>[]) {
    const cveId = normalizeCveId(typeof v?.cveID === "string" ? v.cveID : undefined);
    if (!cveId) { rejected.push({ reason: "KEV entry rejected (malformed CVE id)" }); continue; }
    records.push({
      cveId, catalogSource: source,
      ...(typeof v.dateAdded === "string" ? { dateAdded: v.dateAdded.slice(0, 10) } : {}),
      ...(typeof v.requiredAction === "string" ? { requiredAction: sanitizeProviderText(v.requiredAction, 2000) } : {}),
      ...(typeof v.dueDate === "string" ? { dueDate: v.dueDate.slice(0, 10) } : {}),
      ...(typeof v.knownRansomwareCampaignUse === "string" ? { ransomwareAssociation: v.knownRansomwareCampaignUse } : {}),
      ...(typeof v.notes === "string" ? { notes: sanitizeProviderText(v.notes, 2000) } : {}),
      ...(typeof v.vendorProject === "string" ? { vendorProject: sanitizeProviderText(v.vendorProject, 300) } : {}),
      ...(typeof v.product === "string" ? { product: sanitizeProviderText(v.product, 300) } : {}),
      status: "ACTIVE",
      source,
    });
  }
  return { records, rejected };
}

// ------------------------------ Advisory parser (§44) ------------------------------

/** Parse OSV/GHSA-shaped advisory records (bounded, untrusted). */
export function parseAdvisories(document: string, provider: string, source: string): ProviderParseResult<AdvisoryData> {
  const rejected: ProviderParseResult<AdvisoryData>["rejected"] = [];
  if (Buffer.byteLength(document) > MAX_FEED_BYTES) return { records: [], rejected: [{ reason: "document exceeds size cap" }] };
  let parsed: unknown;
  try { parsed = JSON.parse(document); } catch { return { records: [], rejected: [{ reason: "document is not valid JSON" }] }; }
  const list = Array.isArray(parsed) ? parsed : [parsed];
  const records: AdvisoryData[] = [];
  for (const item of list.slice(0, MAX_FEED_RECORDS)) {
    const rec = item as Record<string, unknown>;
    const advisoryId = typeof rec?.id === "string" ? rec.id.slice(0, 200) : "";
    if (!advisoryId) { rejected.push({ reason: "advisory without id rejected" }); continue; }
    const aliases = Array.isArray(rec.aliases) ? rec.aliases : [];
    const cveIds = new Set<string>();
    for (const a of aliases) { const id = normalizeCveId(typeof a === "string" ? a : undefined); if (id) cveIds.add(id); }
    const selfId = normalizeCveId(advisoryId); if (selfId) cveIds.add(selfId);
    const fixedVersions: Record<string, string[]> = {};
    const mitigations: AdvisoryData["mitigations"] = [];
    const affected = Array.isArray(rec.affected) ? rec.affected : [];
    for (const aff of affected as Record<string, unknown>[]) {
      const pkg = (aff?.package ?? {}) as Record<string, unknown>;
      const name = typeof pkg.name === "string" ? pkg.name : "";
      const ecosystem = typeof pkg.ecosystem === "string" ? pkg.ecosystem : "";
      if (!name) continue;
      const key = `${ecosystem.toLowerCase()}:${name.toLowerCase()}`;
      const ranges = Array.isArray(aff.ranges) ? aff.ranges : [];
      for (const range of ranges as Record<string, unknown>[]) {
        const events = Array.isArray(range?.events) ? range.events : [];
        for (const ev of events as Record<string, unknown>[]) {
          if (typeof ev?.fixed === "string") {
            (fixedVersions[key] ??= []).push(ev.fixed.slice(0, 100));
          }
        }
      }
    }
    const refs = sanitizeReferences(Array.isArray(rec.references) ? rec.references.map((r) => ({ label: (r as Record<string, unknown>)?.type, url: (r as Record<string, unknown>)?.url })) : []);
    if (typeof rec.details === "string" && /mitigat/i.test(rec.details)) {
      mitigations.push({ productKey: "*", text: sanitizeProviderText(rec.details, 2000) });
    }
    records.push({
      provider, advisoryId,
      title: sanitizeProviderText(rec.summary ?? rec.title ?? advisoryId, 500),
      ...(typeof rec.published === "string" ? { publishedAt: rec.published } : {}),
      ...(typeof rec.modified === "string" ? { updatedAt: rec.modified } : {}),
      references: refs,
      cveIds: [...cveIds],
      fixedVersions,
      mitigations,
      source,
    });
  }
  return { records, rejected };
}

// ------------------------------ conflicts (§69–§71) ------------------------------

export type ConflictType = "CVSS_MISMATCH" | "VERSION_RANGE_MISMATCH" | "FIXED_VERSION_MISMATCH" | "CWE_MISMATCH" | "STATUS_MISMATCH";

export interface IntelConflict {
  cveId: string;
  conflictType: ConflictType;
  detail: Record<string, unknown>;
}

/**
 * Detect material disagreement between trusted sources (§69). Minor
 * rounding (≤0.1 CVSS) is not material. Conflicts are REPORTED with all
 * values preserved — resolution happens by source priority at read
 * time, never by deleting the losing record (§71).
 */
export function detectConflicts(input: {
  cveId: string;
  cvssBySource: { source: string; score: number; version: string }[];
  fixedVersionsBySource: { source: string; productKey: string; fixedVersion: string }[];
  cweBySource: { source: string; cweIds: string[] }[];
  statusBySource: { source: string; status: CveStatus }[];
}): IntelConflict[] {
  const out: IntelConflict[] = [];
  const { cveId } = input;
  const scores = input.cvssBySource.filter((c) => sourcePriority(c.source) >= 60);
  if (scores.length > 1) {
    const max = Math.max(...scores.map((s) => s.score));
    const min = Math.min(...scores.map((s) => s.score));
    if (max - min > 0.1 + 1e-9) {
      out.push({ cveId, conflictType: "CVSS_MISMATCH", detail: { bySource: scores, spread: Number((max - min).toFixed(2)) } });
    }
  }
  const fixedByProduct = new Map<string, { source: string; fixedVersion: string }[]>();
  for (const f of input.fixedVersionsBySource) {
    (fixedByProduct.get(f.productKey) ?? fixedByProduct.set(f.productKey, []).get(f.productKey)!).push(f);
  }
  for (const [productKey, entries] of fixedByProduct) {
    const distinct = new Set(entries.map((e) => e.fixedVersion));
    if (entries.length > 1 && distinct.size > 1) {
      out.push({ cveId, conflictType: "FIXED_VERSION_MISMATCH", detail: { productKey, bySource: entries } });
    }
  }
  const cweSets = input.cweBySource.filter((c) => c.cweIds.length > 0);
  if (cweSets.length > 1) {
    const first = new Set(cweSets[0]!.cweIds);
    const disagree = cweSets.some((c) => c.cweIds.length !== first.size || c.cweIds.some((id) => !first.has(id)));
    if (disagree) out.push({ cveId, conflictType: "CWE_MISMATCH", detail: { bySource: cweSets } });
  }
  const statuses = new Set(input.statusBySource.map((s) => s.status));
  if (statuses.size > 1) {
    out.push({ cveId, conflictType: "STATUS_MISMATCH", detail: { bySource: input.statusBySource } });
  }
  return out;
}

// ------------------------------ EPSS trend / staleness (§21/§22) ------------------------------

export interface EpssTrend {
  current: EpssPoint;
  previous?: EpssPoint;
  change?: number; // current - previous score (signed)
  history: EpssPoint[]; // ascending by date
}

/** Build the trend from the FULL dated history (§20/§21). The latest
 *  point is current; history is never collapsed or overwritten. */
export function epssTrend(points: EpssPoint[]): EpssTrend | undefined {
  if (!points.length) return undefined;
  const history = [...points].sort((a, b) => a.date.localeCompare(b.date));
  const current = history[history.length - 1]!;
  const previous = history.length > 1 ? history[history.length - 2] : undefined;
  return {
    current,
    ...(previous ? { previous, change: Number((current.score - previous.score).toFixed(6)) } : {}),
    history,
  };
}

/** §22: freshness policy — EPSS older than the threshold is STALE and
 *  must be marked wherever it is displayed or used. */
export const EPSS_STALE_DAYS = 7;
export function epssFreshness(point: EpssPoint | undefined, now: Date): "CURRENT" | "STALE" | "ABSENT" {
  if (!point) return "ABSENT";
  const ageDays = (now.getTime() - new Date(`${point.date}T00:00:00Z`).getTime()) / 86_400_000;
  return ageDays > EPSS_STALE_DAYS ? "STALE" : "CURRENT";
}

/** Material EPSS change (§89): absolute move ≥ 0.1 or crossing the 0.5
 *  exploitation-probability line. */
export function epssMateriallyChanged(trend: EpssTrend): boolean {
  if (!trend.previous || trend.change === undefined) return false;
  if (Math.abs(trend.change) >= 0.1) return true;
  return (trend.previous.score < 0.5) !== (trend.current.score < 0.5);
}

// ------------------------------ provider health / cache (§67/§68/§125/§126) ------------------------------

export type ProviderHealthStatus = "OK" | "DEGRADED" | "DOWN" | "NOT_CONFIGURED";

export interface ProviderHealthView {
  provider: string;
  status: ProviderHealthStatus;
  lastSuccessAt?: string;
  lastFailureAt?: string;
  latencyMs?: number;
  rateLimitState: string;
  freshness: string;
  detail?: string;
}

/** §67: a failed sync marks health/freshness — existing intelligence is
 *  retained untouched. This function only computes the health view. */
export function providerHealthAfterFailure(prev: ProviderHealthView, now: Date, error: string): ProviderHealthView {
  return {
    ...prev,
    status: prev.lastSuccessAt ? "DEGRADED" : "DOWN",
    lastFailureAt: now.toISOString(),
    freshness: prev.lastSuccessAt ? `STALE_SINCE_${prev.lastSuccessAt}` : "NEVER_SYNCED",
    detail: error.slice(0, 500),
  };
}

/** §125: cache key includes provider + identifier + provider context. */
export function intelCacheKey(provider: string, identifier: string, context = "v1"): string {
  return `intel:${provider.toLowerCase()}:${context}:${identifier}`;
}

/** §126: source-appropriate TTLs (seconds). Dynamic intelligence is
 *  never cached indefinitely. */
export const INTEL_CACHE_TTL_SECONDS: Record<string, number> = {
  NVD: 6 * 3600,
  FIRST_EPSS: 12 * 3600,
  CISA_KEV: 6 * 3600,
  GHSA: 6 * 3600,
  OSV: 6 * 3600,
};

/** §66: bounded retry/backoff plan for a provider sync attempt. */
export function syncBackoffDelays(attempts: number, baseMs = 1000, capMs = 60_000): number[] {
  const out: number[] = [];
  for (let i = 0; i < attempts; i++) out.push(Math.min(capMs, baseMs * 2 ** i));
  return out;
}
