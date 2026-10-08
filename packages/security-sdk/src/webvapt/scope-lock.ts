import { createHash } from "node:crypto";

/**
 * Scope lock (Prompt 32 §136–§141).
 *
 * At scan start the authorized scope is frozen into an immutable
 * ScanScopeSnapshot with a content hash. Everything the scan later
 * meets — a redirect, a newly discovered host, an OpenAPI `servers`
 * entry, a Postman/Insomnia collection host — is judged against the
 * SNAPSHOT, never against live scope records: an administrator editing
 * scope mid-run does not silently expand a running scan (§137), and a
 * discovered host is a candidate only (§138).
 */

export interface ScopeSnapshotInput {
  workspaceId: string;
  /** Authorized origins, e.g. "https://staging.example.com". */
  origins: string[];
  /** Extra authorized hosts (host[:port]) not covered by origins. */
  hosts?: string[];
  /** Path prefixes explicitly excluded from automatic interaction. */
  exclusions?: string[];
}

export interface ScopeSnapshot {
  workspaceId: string;
  origins: string[];
  hosts: string[];
  exclusions: string[];
  hash: string;
}

export function normalizeOrigin(raw: string): string | null {
  try {
    const u = new URL(raw.includes("://") ? raw : `https://${raw}`);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return `${u.protocol}//${u.host.toLowerCase()}`;
  } catch {
    return null;
  }
}

export function buildScopeSnapshot(input: ScopeSnapshotInput): ScopeSnapshot {
  const origins = [...new Set(input.origins.map(normalizeOrigin).filter((o): o is string => o !== null))].sort();
  const hosts = [...new Set((input.hosts ?? []).map((h) => h.toLowerCase()))].sort();
  const exclusions = [...new Set(input.exclusions ?? [])].sort();
  const hash = createHash("sha256")
    .update(JSON.stringify({ workspaceId: input.workspaceId, origins, hosts, exclusions }))
    .digest("hex");
  return { workspaceId: input.workspaceId, origins, hosts, exclusions, hash };
}

export type ScopeVerdict = "IN_SCOPE" | "OUT_OF_SCOPE" | "EXCLUDED" | "INVALID";

/** Judge a URL against the frozen snapshot. */
export function judgeUrlAgainstSnapshot(snapshot: ScopeSnapshot, rawUrl: string): ScopeVerdict {
  const origin = normalizeOrigin(rawUrl);
  if (!origin) return "INVALID";
  let path = "/";
  try { path = new URL(rawUrl).pathname; } catch { return "INVALID"; }
  if (snapshot.exclusions.some((ex) => path.startsWith(ex))) return "EXCLUDED";
  if (snapshot.origins.includes(origin)) return "IN_SCOPE";
  try {
    const host = new URL(rawUrl).host.toLowerCase();
    if (snapshot.hosts.includes(host)) return "IN_SCOPE";
  } catch { return "INVALID"; }
  return "OUT_OF_SCOPE";
}

/** §138: a host discovered mid-scan is a candidate, never auto-included. */
export function classifyDiscoveredHost(snapshot: ScopeSnapshot, host: string): "IN_SCOPE" | "CANDIDATE_ONLY" {
  const h = host.toLowerCase();
  if (snapshot.hosts.includes(h)) return "IN_SCOPE";
  if (snapshot.origins.some((o) => { try { return new URL(o).host.toLowerCase() === h; } catch { return false; } })) return "IN_SCOPE";
  return "CANDIDATE_ONLY";
}

/**
 * §139/§140: hosts referenced by an imported specification or
 * collection are NOT trusted. Each referenced host is validated
 * against the snapshot; unvalidated hosts are skipped, never fetched.
 */
export function validateReferencedHosts(snapshot: ScopeSnapshot, referencedHosts: string[]): { accepted: string[]; rejected: string[] } {
  const accepted: string[] = [];
  const rejected: string[] = [];
  for (const host of referencedHosts) {
    (classifyDiscoveredHost(snapshot, host) === "IN_SCOPE" ? accepted : rejected).push(host);
  }
  return { accepted, rejected };
}

/**
 * §133–§135: internal-target policy. Private/loopback/link-local and
 * cloud-metadata destinations require an explicit internal-scope
 * authorization; metadata endpoints are blocked even then unless the
 * caller records an approved isolated test (§134).
 */
const METADATA_HOSTS = new Set(["169.254.169.254", "metadata.google.internal", "metadata", "100.100.100.200"]);

export function isMetadataDestination(host: string): boolean {
  return METADATA_HOSTS.has(host.toLowerCase());
}

export function isPrivateOrLoopback(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".local") || h.endsWith(".internal")) return true;
  const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [a, b] = [Number(ipv4[1]), Number(ipv4[2])];
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  if (h === "::1" || h.startsWith("fe80:") || h.startsWith("fc") || h.startsWith("fd")) return true;
  return false;
}

export interface InternalTargetDecision {
  allowed: boolean;
  reason: string;
}

export function judgeInternalTarget(host: string, opts: { internalScopeAuthorized: boolean; approvedIsolatedMetadataTest?: boolean }): InternalTargetDecision {
  if (isMetadataDestination(host)) {
    if (opts.approvedIsolatedMetadataTest) return { allowed: true, reason: "metadata endpoint covered by an approved isolated test (§134)" };
    return { allowed: false, reason: "cloud metadata endpoints are blocked (§134)" };
  }
  if (isPrivateOrLoopback(host)) {
    if (!opts.internalScopeAuthorized) return { allowed: false, reason: "private/internal target requires explicit internal scope authorization (§133)" };
    return { allowed: true, reason: "internal target covered by internal scope authorization" };
  }
  return { allowed: true, reason: "public target" };
}
