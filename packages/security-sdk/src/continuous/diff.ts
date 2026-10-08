import type { AssetSnapshotEntry, FindingSnapshotEntry } from "./snapshots";

/**
 * Drift engines (Prompt 22 §33–§48). All diffs compare two IMMUTABLE
 * snapshots — never live state — so every drift event is reproducible
 * from stored evidence. New discovered assets are DISCOVERED, never
 * automatically AUTHORIZED_FOR_INTRUSIVE_TESTING (§35): drift output
 * carries no authorization side effects at all.
 */

export type AssetDriftType = "NEW" | "REMOVED" | "CHANGED" | "REAPPEARED";

export interface AssetDriftEvent {
  type: AssetDriftType;
  assetKey: string;
  host: string;
  assetType: string;
  changes: Array<{ field: string; from: unknown; to: unknown }>;
}

export type AttackSurfaceChangeType =
  | "NEW_DOMAIN" | "NEW_SUBDOMAIN" | "NEW_HOST" | "NEW_PORT" | "NEW_SERVICE"
  | "NEW_WEB_APP" | "NEW_API" | "NEW_CLOUD_RESOURCE" | "NEW_PUBLIC_RESOURCE"
  | "NEW_REPOSITORY" | "NEW_CONTAINER_IMAGE" | "EXPOSURE_CHANGED" | "SERVICE_CHANGED"
  | "ENDPOINT_CHANGED" | "ASSET_REMOVED";

export interface AttackSurfaceChange {
  type: AttackSurfaceChangeType;
  assetKey: string;
  host: string;
  /** HIGH for private → public exposure transitions (§108). */
  priority: "HIGH" | "NORMAL";
  detail: string;
}

function newAssetSurfaceType(entry: AssetSnapshotEntry): AttackSurfaceChangeType {
  const t = entry.type.toUpperCase();
  if (t.includes("DOMAIN")) return entry.host.split(".").length > 2 ? "NEW_SUBDOMAIN" : "NEW_DOMAIN";
  if (t.includes("WEB")) return "NEW_WEB_APP";
  if (t.includes("API")) return "NEW_API";
  if (t.includes("CLOUD")) return "NEW_CLOUD_RESOURCE";
  if (t.includes("REPO")) return "NEW_REPOSITORY";
  if (t.includes("IMAGE") || t.includes("CONTAINER")) return "NEW_CONTAINER_IMAGE";
  return "NEW_HOST";
}

export function diffAssetSnapshots(input: {
  previous: AssetSnapshotEntry[];
  current: AssetSnapshotEntry[];
  /** Keys seen in any snapshot BEFORE `previous` — distinguishes
   *  REAPPEARED from NEW (§33). */
  knownBefore?: Set<string>;
}): { assetDrift: AssetDriftEvent[]; surfaceChanges: AttackSurfaceChange[] } {
  const prev = new Map(input.previous.map((e) => [e.assetKey, e]));
  const curr = new Map(input.current.map((e) => [e.assetKey, e]));
  const assetDrift: AssetDriftEvent[] = [];
  const surfaceChanges: AttackSurfaceChange[] = [];

  for (const [key, entry] of curr) {
    const before = prev.get(key);
    if (!before) {
      const reappeared = input.knownBefore?.has(key) ?? false;
      assetDrift.push({ type: reappeared ? "REAPPEARED" : "NEW", assetKey: key, host: entry.host, assetType: entry.type, changes: [] });
      surfaceChanges.push({
        type: newAssetSurfaceType(entry), assetKey: key, host: entry.host, priority: "NORMAL",
        detail: reappeared ? "asset reappeared after being absent from the previous snapshot" : "new asset observed — status DISCOVERED, not authorized for intrusive testing (§35)",
      });
      continue;
    }
    if (before.stateHash === entry.stateHash) continue;
    const changes: AssetDriftEvent["changes"] = [];
    if (before.exposure !== entry.exposure) {
      changes.push({ field: "exposure", from: before.exposure, to: entry.exposure });
      const becamePublic = before.exposure !== "INTERNET_FACING" && entry.exposure === "INTERNET_FACING";
      surfaceChanges.push({
        type: "EXPOSURE_CHANGED", assetKey: key, host: entry.host,
        priority: becamePublic ? "HIGH" : "NORMAL",
        detail: `exposure changed ${before.exposure} → ${entry.exposure}`,
      });
      if (becamePublic) {
        surfaceChanges.push({
          type: "NEW_PUBLIC_RESOURCE", assetKey: key, host: entry.host, priority: "HIGH",
          detail: "asset became internet-facing (§36)",
        });
      }
    }
    const newPorts = entry.ports.filter((p) => !before.ports.includes(p));
    const closedPorts = before.ports.filter((p) => !entry.ports.includes(p));
    if (newPorts.length > 0) {
      changes.push({ field: "ports.opened", from: before.ports, to: entry.ports });
      for (const p of newPorts) {
        surfaceChanges.push({ type: "NEW_PORT", assetKey: key, host: entry.host, priority: "NORMAL", detail: `port ${p} opened (§37)` });
      }
    }
    if (closedPorts.length > 0) changes.push({ field: "ports.closed", from: before.ports, to: entry.ports });
    const newServices = entry.services.filter((s) => !before.services.includes(s));
    if (newServices.length > 0) {
      changes.push({ field: "services.added", from: before.services, to: entry.services });
      for (const s of newServices) {
        surfaceChanges.push({ type: "NEW_SERVICE", assetKey: key, host: entry.host, priority: "NORMAL", detail: `new service ${s} (§37)` });
      }
    } else if (before.services.join() !== entry.services.join()) {
      changes.push({ field: "services", from: before.services, to: entry.services });
      surfaceChanges.push({ type: "SERVICE_CHANGED", assetKey: key, host: entry.host, priority: "NORMAL", detail: "service set changed (§37)" });
    }
    if (before.endpointCount !== entry.endpointCount) {
      changes.push({ field: "endpointCount", from: before.endpointCount, to: entry.endpointCount });
      surfaceChanges.push({ type: "ENDPOINT_CHANGED", assetKey: key, host: entry.host, priority: "NORMAL", detail: `endpoint count ${before.endpointCount} → ${entry.endpointCount} (§38)` });
    }
    if (before.criticality !== entry.criticality) changes.push({ field: "criticality", from: before.criticality, to: entry.criticality });
    if (before.scopeStatus !== entry.scopeStatus) changes.push({ field: "scopeStatus", from: before.scopeStatus, to: entry.scopeStatus });
    if (changes.length > 0) {
      assetDrift.push({ type: "CHANGED", assetKey: key, host: entry.host, assetType: entry.type, changes });
    }
  }
  for (const [key, entry] of prev) {
    if (!curr.has(key)) {
      assetDrift.push({ type: "REMOVED", assetKey: key, host: entry.host, assetType: entry.type, changes: [] });
      surfaceChanges.push({ type: "ASSET_REMOVED", assetKey: key, host: entry.host, priority: "NORMAL", detail: "asset absent from the latest snapshot" });
    }
  }
  return { assetDrift, surfaceChanges };
}

export type FindingDriftType =
  | "NEW" | "RESOLVED" | "REOPENED" | "SEVERITY_CHANGED" | "PRIORITY_CHANGED" | "VERIFICATION_CHANGED" | "RISK_CHANGED";

export interface FindingDriftEvent {
  type: FindingDriftType;
  fingerprint: string;
  findingId?: string;
  detail: string;
  from?: unknown;
  to?: unknown;
}

const OPEN_LIFECYCLES = new Set(["NEW", "TRIAGED", "IN_PROGRESS", "REOPENED", "RETEST_PENDING"]);
const RESOLVED_LIFECYCLES = new Set(["RESOLVED", "CLOSED", "FIXED", "REMEDIATED"]);

/** Minimum absolute risk-score movement that counts as RISK_CHANGED. */
export const RISK_DRIFT_THRESHOLD = 10;

export function diffFindingSnapshots(input: {
  previous: FindingSnapshotEntry[];
  current: FindingSnapshotEntry[];
}): FindingDriftEvent[] {
  const prev = new Map(input.previous.map((e) => [e.fingerprint, e]));
  const curr = new Map(input.current.map((e) => [e.fingerprint, e]));
  const out: FindingDriftEvent[] = [];
  for (const [fp, entry] of curr) {
    const before = prev.get(fp);
    if (!before) {
      out.push({ type: "NEW", fingerprint: fp, ...(entry.findingId ? { findingId: entry.findingId } : {}), detail: "finding first observed in this snapshot" });
      continue;
    }
    const wasOpen = OPEN_LIFECYCLES.has(before.lifecycleStatus) || before.status === "OPEN";
    const isResolved = RESOLVED_LIFECYCLES.has(entry.lifecycleStatus);
    const wasResolved = RESOLVED_LIFECYCLES.has(before.lifecycleStatus);
    const isOpen = OPEN_LIFECYCLES.has(entry.lifecycleStatus) || entry.status === "OPEN";
    if (wasResolved && isOpen) {
      out.push({ type: "REOPENED", fingerprint: fp, ...(entry.findingId ? { findingId: entry.findingId } : {}), detail: `previously resolved finding observed again (${before.lifecycleStatus} → ${entry.lifecycleStatus}) (§109)`, from: before.lifecycleStatus, to: entry.lifecycleStatus });
    } else if (wasOpen && isResolved) {
      out.push({ type: "RESOLVED", fingerprint: fp, ...(entry.findingId ? { findingId: entry.findingId } : {}), detail: `finding resolved (${before.lifecycleStatus} → ${entry.lifecycleStatus})`, from: before.lifecycleStatus, to: entry.lifecycleStatus });
    }
    if (before.severity !== entry.severity) {
      out.push({ type: "SEVERITY_CHANGED", fingerprint: fp, detail: `severity ${before.severity} → ${entry.severity}`, from: before.severity, to: entry.severity });
    }
    if ((before.priority ?? null) !== (entry.priority ?? null)) {
      out.push({ type: "PRIORITY_CHANGED", fingerprint: fp, detail: `priority ${before.priority ?? "—"} → ${entry.priority ?? "—"}`, from: before.priority, to: entry.priority });
    }
    if (before.verificationStatus !== entry.verificationStatus) {
      out.push({ type: "VERIFICATION_CHANGED", fingerprint: fp, detail: `verification ${before.verificationStatus} → ${entry.verificationStatus}`, from: before.verificationStatus, to: entry.verificationStatus });
    }
    if (before.riskScore != null && entry.riskScore != null && Math.abs(entry.riskScore - before.riskScore) >= RISK_DRIFT_THRESHOLD) {
      out.push({ type: "RISK_CHANGED", fingerprint: fp, detail: `risk score ${before.riskScore} → ${entry.riskScore}`, from: before.riskScore, to: entry.riskScore });
    }
  }
  for (const [fp, entry] of prev) {
    if (!curr.has(fp) && !RESOLVED_LIFECYCLES.has(entry.lifecycleStatus)) {
      out.push({ type: "RESOLVED", fingerprint: fp, ...(entry.findingId ? { findingId: entry.findingId } : {}), detail: "finding absent from the latest snapshot without an explicit resolution record" });
    }
  }
  return out;
}

export type RiskDriftType = "KEV_ADDED" | "EPSS_INCREASED" | "CVSS_CHANGED" | "ASSET_BECAME_PUBLIC" | "CRITICALITY_CHANGED" | "VERIFICATION_CHANGED";

export interface RiskDriftEvent {
  type: RiskDriftType;
  findingId?: string;
  cve?: string;
  detail: string;
  from?: unknown;
  to?: unknown;
}

export interface IntelView {
  cve: string;
  kevListed: boolean;
  epssScore?: number | null;
  cvssScore?: number | null;
}

/** §48/§110: intelligence movement that changes risk without any new
 *  scan — a CVE entering KEV or a material EPSS rise. */
export const EPSS_DRIFT_THRESHOLD = 0.1;

export function diffIntelSnapshots(input: {
  previous: IntelView[];
  current: IntelView[];
  findingsByCve: Map<string, string[]>;
}): RiskDriftEvent[] {
  const prev = new Map(input.previous.map((i) => [i.cve, i]));
  const out: RiskDriftEvent[] = [];
  for (const now of input.current) {
    const before = prev.get(now.cve);
    const findingIds = input.findingsByCve.get(now.cve) ?? [];
    if (now.kevListed && !(before?.kevListed ?? false)) {
      for (const findingId of findingIds) {
        out.push({ type: "KEV_ADDED", findingId, cve: now.cve, detail: `${now.cve} newly listed in CISA KEV — risk recalculation required (§110)`, from: false, to: true });
      }
      if (findingIds.length === 0) {
        out.push({ type: "KEV_ADDED", cve: now.cve, detail: `${now.cve} newly listed in CISA KEV`, from: false, to: true });
      }
    }
    if (before?.epssScore != null && now.epssScore != null && now.epssScore - before.epssScore >= EPSS_DRIFT_THRESHOLD) {
      for (const findingId of findingIds) {
        out.push({ type: "EPSS_INCREASED", findingId, cve: now.cve, detail: `EPSS for ${now.cve} rose ${before.epssScore} → ${now.epssScore}`, from: before.epssScore, to: now.epssScore });
      }
    }
    if (before?.cvssScore != null && now.cvssScore != null && before.cvssScore !== now.cvssScore) {
      for (const findingId of findingIds) {
        out.push({ type: "CVSS_CHANGED", findingId, cve: now.cve, detail: `CVSS for ${now.cve} changed ${before.cvssScore} → ${now.cvssScore}`, from: before.cvssScore, to: now.cvssScore });
      }
    }
  }
  return out;
}
