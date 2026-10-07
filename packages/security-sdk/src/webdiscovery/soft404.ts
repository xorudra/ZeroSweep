/**
 * Soft-404 detection, response fingerprinting and wildcard routes
 * (Prompt 6 §17–§19). Content discovery against an application that answers
 * every path with the same "200 + page not found" (or the same SPA shell)
 * would otherwise invent thousands of fake endpoints. Calibration is done
 * from CONTROLLED BASELINE OBSERVATIONS — responses recorded for paths
 * that certainly do not exist — and candidates are compared by fingerprint
 * built ONLY from safe metadata (status, length, word/line counts, a body
 * hash when a tool provides one). No response body is ever stored here.
 */

export interface ResponseObservation {
  statusCode?: number;
  contentLength?: number;
  wordCount?: number;
  lineCount?: number;
  /** Hash of the response body when a tool recorded one (never the body). */
  bodyHash?: string;
  contentType?: string;
}

/** Deterministic fingerprint from safe response metadata (§18). Length is
 *  bucketed coarsely when no body hash exists: templated error pages often
 *  echo the requested path, so exact lengths jitter by a few bytes while
 *  word/line counts stay stable. */
export function responseFingerprint(obs: ResponseObservation): string {
  const parts = [
    `s=${obs.statusCode ?? "?"}`,
    obs.bodyHash ? `h=${obs.bodyHash}` : `l=${bucket(obs.contentLength)}`,
    `w=${bucket(obs.wordCount)}`,
    `n=${bucket(obs.lineCount)}`,
    `t=${normalizeContentType(obs.contentType)}`,
  ];
  return parts.join("|");
}

function bucket(v: number | undefined): string {
  if (v === undefined || !Number.isFinite(v)) return "?";
  if (v === 0) return "0";
  // ~5% buckets: 100 and 104 are the same page; 100 and 900 are not.
  return String(Math.round(Math.log2(Math.max(1, v)) * 4));
}

export function normalizeContentType(ct: string | undefined): string {
  if (!ct) return "?";
  return ct.split(";")[0]!.trim().toLowerCase();
}

export interface Soft404Verdict {
  isSoft404: boolean;
  /** The baseline fingerprint matched, when any. */
  matchedFingerprint?: string;
  reason?: string;
}

/**
 * Soft404Detector (§17): calibrated with baseline observations of
 * certainly-nonexistent paths. A candidate whose fingerprint matches a
 * baseline fingerprint AND whose recorded status was not a real 404 is a
 * soft-404 — the application claims success for missing content.
 */
export class Soft404Detector {
  private readonly baselineFingerprints = new Map<string, number>();

  constructor(baselines: readonly ResponseObservation[] = []) {
    for (const b of baselines) this.addBaseline(b);
  }

  addBaseline(obs: ResponseObservation): void {
    const fp = responseFingerprint(obs);
    this.baselineFingerprints.set(fp, (this.baselineFingerprints.get(fp) ?? 0) + 1);
  }

  get calibrated(): boolean {
    return this.baselineFingerprints.size > 0;
  }

  /** True when a precomputed response fingerprint (as stored on a
   *  normalized endpoint) matches a calibrated baseline. */
  matchesBaseline(fingerprint: string | undefined): boolean {
    return fingerprint !== undefined && this.baselineFingerprints.has(fingerprint);
  }

  classify(obs: ResponseObservation): Soft404Verdict {
    if (obs.statusCode === 404) return { isSoft404: false, reason: "real 404 status" };
    const fp = responseFingerprint(obs);
    const hits = this.baselineFingerprints.get(fp);
    if (hits !== undefined) {
      return { isSoft404: true, matchedFingerprint: fp, reason: `fingerprint matches ${hits} baseline (nonexistent-path) observation(s)` };
    }
    return { isSoft404: false, reason: "no baseline fingerprint match" };
  }
}

/**
 * Wildcard-route behaviour (§19): when ≥ `minPaths` DISTINCT paths return
 * the identical fingerprint with a success status, the application serves
 * the same shell for arbitrary paths. The group collapses to ONE
 * representative endpoint flagged WILDCARD_ROUTE_BEHAVIOR instead of an
 * inventory of fakes. Groups are computed per origin by the caller.
 */
export interface WildcardGroup<T> {
  fingerprint: string;
  representative: T;
  collapsed: T[];
  behavior: "WILDCARD_ROUTE_BEHAVIOR";
}

export function detectWildcardGroups<T extends { url: string; statusCode?: number; fingerprint?: string }>(
  items: readonly T[],
  minPaths = 3,
): { kept: T[]; groups: WildcardGroup<T>[] } {
  const byFingerprint = new Map<string, T[]>();
  for (const item of items) {
    if (!item.fingerprint || item.statusCode === undefined || item.statusCode >= 400) continue;
    const key = item.fingerprint;
    byFingerprint.set(key, [...(byFingerprint.get(key) ?? []), item]);
  }
  const collapsedUrls = new Set<string>();
  const groups: WildcardGroup<T>[] = [];
  for (const [fingerprint, members] of byFingerprint) {
    const distinctPaths = new Set(members.map((m) => safePath(m.url)));
    if (distinctPaths.size < minPaths) continue;
    const [representative, ...rest] = members;
    groups.push({ fingerprint, representative: representative!, collapsed: rest, behavior: "WILDCARD_ROUTE_BEHAVIOR" });
    for (const m of rest) collapsedUrls.add(m.url);
  }
  return { kept: items.filter((i) => !collapsedUrls.has(i.url)), groups };
}

function safePath(url: string): string {
  try { return new URL(url).pathname; } catch { return url; }
}
