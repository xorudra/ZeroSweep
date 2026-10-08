import { createHash } from "node:crypto";
import { cidrContainsCidr, ipInCidr, isCidr, parseIp } from "../network/cidr";

/**
 * Immutable network scope snapshot + discovered-host policy
 * (Prompt 33 §11/§12/§21, §141).
 *
 * A snapshot is frozen at run start (hosts, CIDRs, exclusions, and the
 * exact target values it came from) and hashed; a running scan cannot
 * expand beyond it. Hosts observed OUTSIDE the snapshot — from ARP,
 * routing tables, DNS or adjacent ranges — are recorded as CANDIDATES
 * when policy permits and are NEVER scanned (§12/§21): observation is
 * not authorization, in this package or anywhere downstream.
 */

export interface NetworkScopeSnapshotData {
  hosts: string[];
  cidrs: string[];
  exclusions: string[];
  hash: string;
}

export function buildNetworkScopeSnapshot(input: {
  hosts?: string[];
  cidrs?: string[];
  exclusions?: string[];
}): NetworkScopeSnapshotData {
  const hosts = [...new Set((input.hosts ?? []).map((h) => h.trim().toLowerCase()).filter(Boolean))].sort();
  const cidrs = [...new Set((input.cidrs ?? []).map((c) => c.trim()).filter(Boolean))].sort();
  const exclusions = [...new Set((input.exclusions ?? []).map((e) => e.trim().toLowerCase()).filter(Boolean))].sort();
  const hash = createHash("sha256").update(JSON.stringify({ hosts, cidrs, exclusions })).digest("hex");
  return { hosts, cidrs, exclusions, hash };
}

export type ScopeMembership = "IN_SCOPE" | "EXCLUDED" | "OUT_OF_SCOPE" | "INVALID";

/** Membership verdict for one observed IP against a frozen snapshot. */
export function judgeIpAgainstSnapshot(snapshot: NetworkScopeSnapshotData, ip: string): ScopeMembership {
  if (!parseIp(ip)) return "INVALID";
  for (const ex of snapshot.exclusions) {
    if (isCidr(ex) ? ipInCidr(ip, ex) : ex === ip.toLowerCase()) return "EXCLUDED";
  }
  if (snapshot.hosts.includes(ip.toLowerCase())) return "IN_SCOPE";
  for (const cidr of snapshot.cidrs) {
    if (isCidr(cidr) && ipInCidr(ip, cidr)) return "IN_SCOPE";
  }
  return "OUT_OF_SCOPE";
}

/** Is one CIDR fully contained in the snapshot's authorized ranges?
 *  Used to refuse plans whose targets outgrow the authorization (§11). */
export function cidrCoveredBySnapshot(snapshot: NetworkScopeSnapshotData, cidr: string): boolean {
  return snapshot.cidrs.some((c) => isCidr(c) && cidrContainsCidr(c, cidr));
}

export interface DiscoveredHostDecision {
  ip: string;
  membership: ScopeMembership;
  /** true only for IN_SCOPE — the ONLY state that may be scanned. */
  scannable: boolean;
  /** OUT_OF_SCOPE hosts become candidates when policy permits (§12). */
  recordCandidate: boolean;
  reason: string;
}

/**
 * The discovered-host policy (§12/§21/§141): a host discovered outside
 * the frozen scope is recorded as a candidate if policy permits, and is
 * NEVER scanned — regardless of how it was observed (ARP, DNS, routing,
 * certificate SANs or a scanner's own expansion).
 */
export function decideDiscoveredHost(
  snapshot: NetworkScopeSnapshotData,
  ip: string,
  opts: { recordCandidates?: boolean } = {},
): DiscoveredHostDecision {
  const membership = judgeIpAgainstSnapshot(snapshot, ip);
  if (membership === "IN_SCOPE") {
    return { ip, membership, scannable: true, recordCandidate: false, reason: "Inside the immutable scope snapshot — scannable (§11)" };
  }
  if (membership === "EXCLUDED") {
    return { ip, membership, scannable: false, recordCandidate: false, reason: "Explicitly excluded by the scope snapshot — not scanned, not recorded (§11)" };
  }
  if (membership === "INVALID") {
    return { ip, membership, scannable: false, recordCandidate: false, reason: "Not a valid IP literal — discarded as data (§138)" };
  }
  return {
    ip, membership, scannable: false,
    recordCandidate: opts.recordCandidates ?? true,
    reason: "Discovered outside the frozen scope: recorded as a candidate only — observation never authorizes scanning (§12/§21)",
  };
}
