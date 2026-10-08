import type { EasmDriftType } from "./types";
import { driftSeverity } from "./exposure";

/**
 * Exposure drift engine (Prompt 29 §80–§85) + lifecycle confirmation
 * (§92–§93). Drift compares a current snapshot against a previous
 * TRUSTED snapshot (a baseline when one exists). Comparison is pure
 * and deterministic; persistence and alerting live in the API layer.
 * Flapping protection: a change must be observed in N consecutive
 * snapshots (confirmation window) before it is alertable drift —
 * a single-snapshot blip is recorded as pending, not as drift.
 */

export interface EasmSnapshotAsset {
  /** Canonical candidate identity (normalized value). */
  identity: string;
  services: Array<{ port: number; transport: string; service?: string | null }>;
  ips: string[];
  httpStatus?: number | null;
  httpTitle?: string | null;
  certificateFingerprint?: string | null;
  technologies: string[];
  exposureState: string;
  ownershipStatus: string;
}

export interface EasmSnapshot {
  capturedAt: string;
  assets: EasmSnapshotAsset[];
}

export interface DriftCandidate {
  type: EasmDriftType;
  assetIdentity: string;
  before: unknown;
  after: unknown;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  /** Correlation fingerprint (§79): stable per asset+type+detail so
   *  repeated identical drift dedupes through the P27 architecture. */
  fingerprint: string;
  sensitiveServiceClass?: string | null;
}

function serviceKey(s: { port: number; transport: string }): string {
  return `${s.port}/${s.transport}`;
}

export function compareSnapshots(before: EasmSnapshot, after: EasmSnapshot, sensitiveClassifier: (s: { port: number; service?: string | null }) => string | null): DriftCandidate[] {
  const out: DriftCandidate[] = [];
  const bMap = new Map(before.assets.map((a) => [a.identity, a]));
  const aMap = new Map(after.assets.map((a) => [a.identity, a]));
  const push = (d: Omit<DriftCandidate, "severity" | "fingerprint"> & { detail: string }) => {
    const severity = driftSeverity({
      type: d.type, sensitiveServiceClass: d.sensitiveServiceClass,
      exposureBefore: bMap.get(d.assetIdentity)?.exposureState, exposureAfter: aMap.get(d.assetIdentity)?.exposureState,
      ownershipBefore: bMap.get(d.assetIdentity)?.ownershipStatus, ownershipAfter: aMap.get(d.assetIdentity)?.ownershipStatus,
    });
    out.push({
      type: d.type, assetIdentity: d.assetIdentity, before: d.before, after: d.after, severity,
      sensitiveServiceClass: d.sensitiveServiceClass ?? null,
      fingerprint: `easm-drift:${d.assetIdentity}:${d.type}:${d.detail}`,
    });
  };

  for (const [identity, a] of aMap) {
    const b = bMap.get(identity);
    if (!b) {
      push({ type: "ASSET_ADDED", assetIdentity: identity, before: null, after: { exposureState: a.exposureState }, detail: "added" });
      continue;
    }
    const bSvc = new Map(b.services.map((s) => [serviceKey(s), s]));
    const aSvc = new Map(a.services.map((s) => [serviceKey(s), s]));
    for (const [k, s] of aSvc) if (!bSvc.has(k)) {
      push({ type: "SERVICE_ADDED", assetIdentity: identity, before: null, after: s, detail: `svc:${k}`, sensitiveServiceClass: sensitiveClassifier(s) });
    }
    for (const [k, s] of bSvc) if (!aSvc.has(k)) {
      push({ type: "SERVICE_REMOVED", assetIdentity: identity, before: s, after: null, detail: `svc:${k}` });
    }
    const bIps = [...b.ips].sort().join(",");
    const aIps = [...a.ips].sort().join(",");
    if (bIps !== aIps) push({ type: "IP_CHANGED", assetIdentity: identity, before: b.ips, after: a.ips, detail: "ips" });
    if ((b.httpStatus ?? null) !== (a.httpStatus ?? null) || (b.httpTitle ?? null) !== (a.httpTitle ?? null)) {
      push({ type: "HTTP_CHANGED", assetIdentity: identity, before: { status: b.httpStatus ?? null, title: b.httpTitle ?? null }, after: { status: a.httpStatus ?? null, title: a.httpTitle ?? null }, detail: "http" });
    }
    if ((b.certificateFingerprint ?? null) !== (a.certificateFingerprint ?? null)) {
      push({ type: "CERTIFICATE_CHANGED", assetIdentity: identity, before: b.certificateFingerprint ?? null, after: a.certificateFingerprint ?? null, detail: "cert" });
    }
    const bTech = [...b.technologies].sort().join(",");
    const aTech = [...a.technologies].sort().join(",");
    if (bTech !== aTech) push({ type: "TECHNOLOGY_CHANGED", assetIdentity: identity, before: b.technologies, after: a.technologies, detail: "tech" });
    if (b.exposureState !== a.exposureState) {
      push({ type: "EXPOSURE_CHANGED", assetIdentity: identity, before: b.exposureState, after: a.exposureState, detail: "exposure" });
    }
    if (b.ownershipStatus !== a.ownershipStatus) {
      push({ type: "OWNERSHIP_CHANGED", assetIdentity: identity, before: b.ownershipStatus, after: a.ownershipStatus, detail: "ownership" });
    }
  }
  for (const [identity, b] of bMap) {
    if (!aMap.has(identity)) {
      push({ type: "ASSET_REMOVED", assetIdentity: identity, before: { exposureState: b.exposureState }, after: null, detail: "removed" });
    }
  }
  return out.sort((x, y) => x.fingerprint.localeCompare(y.fingerprint));
}

/**
 * §93 flapping filter: split drift candidates into CONFIRMED (seen
 * in at least `confirmations` consecutive comparisons, tracked by
 * fingerprint occurrence count supplied by the caller) and PENDING.
 */
export function applyFlappingFilter(
  candidates: DriftCandidate[],
  consecutiveCounts: Map<string, number>,
  confirmations = 2,
): { confirmed: DriftCandidate[]; pending: DriftCandidate[] } {
  const confirmed: DriftCandidate[] = [];
  const pending: DriftCandidate[] = [];
  for (const c of candidates) {
    const seen = (consecutiveCounts.get(c.fingerprint) ?? 0) + 1;
    consecutiveCounts.set(c.fingerprint, seen);
    (seen >= confirmations ? confirmed : pending).push(c);
  }
  return { confirmed, pending };
}

/**
 * §92/§143 disappearance policy: an asset is DISAPPEARED only after
 * `missThreshold` consecutive absences. One absence changes nothing.
 */
export function nextLifecycleOnObservation(input: {
  currentLifecycle: string;
  observedNow: boolean;
  missCount: number;
  missThreshold?: number;
}): { lifecycle: string; missCount: number } {
  const threshold = input.missThreshold ?? 3;
  if (input.observedNow) return { lifecycle: "ACTIVE", missCount: 0 };
  const misses = input.missCount + 1;
  if (misses >= threshold) return { lifecycle: "DISAPPEARED", missCount: misses };
  return { lifecycle: input.currentLifecycle === "DISCOVERED" ? "DISCOVERED" : "STALE", missCount: misses };
}
