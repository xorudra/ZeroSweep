/**
 * Network scope + CIDR safety (Prompt 10 §3–§7).
 *
 * All network scope is canonicalized BEFORE execution, target counts are
 * calculated BEFORE expansion, and expansion is BOUNDED: a large CIDR is
 * represented as ranges/chunks, never materialized into millions of rows
 * (§5). Protected destinations (loopback, link-local, cloud metadata,
 * platform infrastructure networks) are always rejected for external
 * workers; private/internal destinations require an explicitly approved
 * internal engagement — the same rule the Phase 3 target validator and
 * ScopeMatcher enforce, extended here to full CIDR arithmetic (§6).
 */

// ---------------------------------------------------------------------------
// IP parsing / formatting (IPv4 + IPv6, bigint-based, no dependencies)
// ---------------------------------------------------------------------------

export function parseIpv4(ip: string): bigint | null {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = (value << 8n) | BigInt(n);
  }
  return value;
}

export function formatIpv4(value: bigint): string {
  const parts: string[] = [];
  for (let shift = 24n; shift >= 0n; shift -= 8n) parts.push(String((value >> shift) & 0xffn));
  return parts.join(".");
}

export function parseIpv6(ip: string): bigint | null {
  let input = ip.trim().toLowerCase();
  if (input.includes(".")) {
    // Embedded IPv4 tail (e.g. ::ffff:192.0.2.1) — expand it to two groups.
    const lastColon = input.lastIndexOf(":");
    if (lastColon < 0) return null;
    const v4 = parseIpv4(input.slice(lastColon + 1));
    if (v4 === null) return null;
    const hi = Number((v4 >> 16n) & 0xffffn).toString(16);
    const lo = Number(v4 & 0xffffn).toString(16);
    input = `${input.slice(0, lastColon + 1)}${hi}:${lo}`;
  }
  const halves = input.split("::");
  if (halves.length > 2) return null;
  const parseGroups = (s: string): number[] | null => {
    if (s === "") return [];
    const out: number[] = [];
    for (const g of s.split(":")) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const left = parseGroups(halves[0]!);
  if (left === null) return null;
  let groups: number[];
  if (halves.length === 2) {
    const right = parseGroups(halves[1]!);
    if (right === null) return null;
    const missing = 8 - left.length - right.length;
    if (missing < 1) return null;
    groups = [...left, ...Array<number>(missing).fill(0), ...right];
  } else {
    if (left.length !== 8) return null;
    groups = left;
  }
  let value = 0n;
  for (const g of groups) value = (value << 16n) | BigInt(g);
  return value;
}

export function formatIpv6(value: bigint): string {
  const groups: string[] = [];
  for (let shift = 112n; shift >= 0n; shift -= 16n) groups.push(((value >> shift) & 0xffffn).toString(16));
  // Compress the longest run of zero groups (>= 2) per RFC 5952.
  let bestStart = -1; let bestLen = 0; let curStart = -1; let curLen = 0;
  groups.forEach((g, i) => {
    if (g === "0") { if (curStart < 0) curStart = i; curLen++; if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; } }
    else { curStart = -1; curLen = 0; }
  });
  if (bestLen < 2) return groups.join(":");
  const head = groups.slice(0, bestStart).join(":");
  const tail = groups.slice(bestStart + bestLen).join(":");
  return `${head}::${tail}`;
}

export type IpFamily = 4 | 6;

/** Parse any IP literal; returns family + value, or null when malformed. */
export function parseIp(ip: string): { family: IpFamily; value: bigint } | null {
  const v4 = parseIpv4(ip);
  if (v4 !== null) return { family: 4, value: v4 };
  const v6 = parseIpv6(ip);
  if (v6 !== null) return { family: 6, value: v6 };
  return null;
}

export function isIpLiteral(value: string): boolean {
  return parseIp(value) !== null;
}

// ---------------------------------------------------------------------------
// CIDR arithmetic (§4)
// ---------------------------------------------------------------------------

export interface CidrInfo {
  /** Canonical CIDR text (network address + prefix). */
  canonical: string;
  family: IpFamily;
  prefixLength: number;
  networkAddress: string;
  /** IPv4 only — IPv6 has no broadcast concept. */
  broadcastAddress?: string;
  /** Total addresses in the range (capped at MAX_COUNT for huge IPv6). */
  addressCount: number;
  /** Effective scan targets: excludes network/broadcast for IPv4 blocks
   *  of /30 or larger; equals addressCount for /31, /32 and all IPv6. */
  hostCount: number;
  firstHost: string;
  lastHost: string;
}

const MAX_COUNT = Number.MAX_SAFE_INTEGER;

export function parseCidr(raw: string): CidrInfo | null {
  const input = raw.trim();
  const slash = input.lastIndexOf("/");
  if (slash < 0) return null;
  const addr = input.slice(0, slash);
  const prefixRaw = input.slice(slash + 1);
  if (!/^\d{1,3}$/.test(prefixRaw)) return null;
  const prefix = Number(prefixRaw);
  const parsed = parseIp(addr);
  if (!parsed) return null;
  const bits = parsed.family === 4 ? 32 : 128;
  if (prefix > bits) return null;
  const hostBits = BigInt(bits - prefix);
  const mask = hostBits === 0n ? (1n << BigInt(bits)) - 1n : ((1n << BigInt(prefix)) - 1n) << hostBits;
  const network = parsed.value & mask;
  const last = network + ((1n << hostBits) - 1n);
  const fmt = parsed.family === 4 ? formatIpv4 : formatIpv6;
  const total = hostBits > 53n ? MAX_COUNT : Number(1n << hostBits);
  let first = network;
  let lastHost = last;
  let hosts = total;
  if (parsed.family === 4 && prefix <= 30) {
    first = network + 1n;
    lastHost = last - 1n;
    hosts = total - 2;
  }
  return {
    canonical: `${fmt(network)}/${prefix}`,
    family: parsed.family,
    prefixLength: prefix,
    networkAddress: fmt(network),
    ...(parsed.family === 4 ? { broadcastAddress: fmt(last) } : {}),
    addressCount: total,
    hostCount: hosts,
    firstHost: fmt(first),
    lastHost: fmt(lastHost),
  };
}

export function isCidr(value: string): boolean {
  return parseCidr(value) !== null;
}

/** Canonical form of a CIDR, or null when invalid. */
export function canonicalizeCidr(raw: string): string | null {
  return parseCidr(raw)?.canonical ?? null;
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const parsedIp = parseIp(ip);
  const info = parseCidr(cidr);
  if (!parsedIp || !info || parsedIp.family !== info.family) return false;
  const bits = info.family === 4 ? 32 : 128;
  const hostBits = BigInt(bits - info.prefixLength);
  const network = parseIp(info.networkAddress);
  if (!network) return false;
  return (parsedIp.value >> hostBits) === (network.value >> hostBits);
}

export function cidrContainsCidr(outer: string, inner: string): boolean {
  const o = parseCidr(outer);
  const i = parseCidr(inner);
  if (!o || !i || o.family !== i.family || i.prefixLength < o.prefixLength) return false;
  return ipInCidr(i.networkAddress, o.canonical) && ipInCidr(i.lastHost, o.canonical);
}

// ---------------------------------------------------------------------------
// Destination classification + protected policy (§6)
// ---------------------------------------------------------------------------

export type DestinationClass = "PUBLIC" | "PRIVATE_INTERNAL" | "PROTECTED";

const PROTECTED_CIDRS: Array<{ cidr: string; reason: string }> = [
  { cidr: "127.0.0.0/8", reason: "loopback range is blocked" },
  { cidr: "::1/128", reason: "IPv6 loopback is blocked" },
  { cidr: "169.254.0.0/16", reason: "link-local / cloud metadata range is blocked" },
  { cidr: "fe80::/10", reason: "IPv6 link-local range is blocked" },
  { cidr: "0.0.0.0/8", reason: "unspecified range is blocked" },
  { cidr: "::/128", reason: "IPv6 unspecified address is blocked" },
];

const PRIVATE_CIDRS = [
  "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC 1918
  "100.64.0.0/10", // CGNAT shared address space
  "fc00::/7", // IPv6 unique-local
];

export const PROTECTED_HOSTNAMES = ["localhost", "metadata.google.internal"] as const;

export function classifyDestination(ip: string): DestinationClass {
  for (const p of PROTECTED_CIDRS) if (ipInCidr(ip, p.cidr)) return "PROTECTED";
  for (const c of PRIVATE_CIDRS) if (ipInCidr(ip, c)) return "PRIVATE_INTERNAL";
  return "PUBLIC";
}

export function protectedDestinationReason(ip: string): string | null {
  for (const p of PROTECTED_CIDRS) if (ipInCidr(ip, p.cidr)) return p.reason;
  return null;
}

/**
 * Worker-side destination evaluation (§6/§7): every resolved address is
 * checked immediately before execution. PROTECTED destinations are denied
 * unconditionally (even an approved internal engagement never covers
 * loopback/metadata/platform-control networks); PRIVATE_INTERNAL requires
 * the approved internal engagement; extra platform-infrastructure CIDRs
 * configured by the deployment are protected as well.
 */
export function evaluateDestination(
  ip: string,
  opts: { internalEngagementApproved?: boolean; extraProtectedCidrs?: string[] } = {},
): { allowed: boolean; destinationClass: DestinationClass; reason?: string } {
  for (const c of opts.extraProtectedCidrs ?? []) {
    if (ipInCidr(ip, c)) return { allowed: false, destinationClass: "PROTECTED", reason: "platform infrastructure network is protected" };
  }
  const cls = classifyDestination(ip);
  if (cls === "PROTECTED") return { allowed: false, destinationClass: cls, reason: protectedDestinationReason(ip) ?? "protected destination" };
  if (cls === "PRIVATE_INTERNAL" && !opts.internalEngagementApproved) {
    return { allowed: false, destinationClass: cls, reason: "private range requires an approved internal engagement" };
  }
  return { allowed: true, destinationClass: cls };
}

// ---------------------------------------------------------------------------
// CIDR size policy (§4)
// ---------------------------------------------------------------------------

export type CidrSizeTier = "SINGLE_HOST" | "SMALL" | "LARGE" | "VERY_LARGE";
export type CidrApproval = "NORMAL" | "ELEVATED" | "ADMINISTRATOR" | "DENY";

export interface CidrPolicyThresholds {
  /** hostCount up to this = SMALL (normal approval). */
  smallMaxHosts: number;
  /** hostCount up to this = LARGE (elevated approval). */
  largeMaxHosts: number;
  /** Hard ceiling: above this a CIDR is denied outright. */
  denyAboveHosts: number;
}

export const DEFAULT_CIDR_THRESHOLDS: CidrPolicyThresholds = {
  smallMaxHosts: 256,
  largeMaxHosts: 4096,
  denyAboveHosts: 65536,
};

export interface CidrPolicyVerdict {
  cidr: string;
  family: IpFamily;
  hostCount: number;
  tier: CidrSizeTier;
  approval: CidrApproval;
  allowed: boolean;
  reason?: string;
}

/**
 * CidrPolicyService (§4): classifies a CIDR by effective target count.
 * Thresholds are configurable; the defaults keep a /24 a normal scan, a
 * /20 elevated, and anything beyond a /16 denied — an enormous network
 * is never silently allowed.
 */
export class CidrPolicyService {
  constructor(private readonly thresholds: CidrPolicyThresholds = DEFAULT_CIDR_THRESHOLDS) {}

  evaluate(rawCidr: string, opts: { administratorApproved?: boolean } = {}): CidrPolicyVerdict | null {
    const info = parseCidr(rawCidr);
    if (!info) return null;
    const hosts = info.hostCount;
    let tier: CidrSizeTier;
    let approval: CidrApproval;
    if (hosts <= 1) { tier = "SINGLE_HOST"; approval = "NORMAL"; }
    else if (hosts <= this.thresholds.smallMaxHosts) { tier = "SMALL"; approval = "NORMAL"; }
    else if (hosts <= this.thresholds.largeMaxHosts) { tier = "LARGE"; approval = "ELEVATED"; }
    else { tier = "VERY_LARGE"; approval = "ADMINISTRATOR"; }
    if (hosts > this.thresholds.denyAboveHosts) approval = "DENY";
    const allowed = approval === "NORMAL" || approval === "ELEVATED"
      || (approval === "ADMINISTRATOR" && opts.administratorApproved === true);
    return {
      cidr: info.canonical, family: info.family, hostCount: hosts, tier, approval, allowed,
      ...(allowed ? {} : { reason: approval === "DENY" ? `CIDR spans ${hosts} hosts — above the platform hard ceiling of ${this.thresholds.denyAboveHosts}` : `CIDR spans ${hosts} hosts — ${approval.toLowerCase()} approval required` }),
    };
  }
}

// ---------------------------------------------------------------------------
// Bounded expansion + chunking (§5/§62)
// ---------------------------------------------------------------------------

export interface TargetChunk {
  chunkId: string;
  /** First host of the chunk (canonical IP). */
  rangeStart: string;
  /** Last host of the chunk (canonical IP). */
  rangeEnd: string;
  hostCount: number;
}

export type ExpansionResult =
  | { kind: "LIST"; cidr: string; hosts: string[]; chunks: TargetChunk[] }
  | { kind: "RANGES"; cidr: string; totalHosts: number; chunks: TargetChunk[] };

/**
 * Bounded target expansion (§5): when the effective host count fits the
 * caller's materialization cap, a concrete host list is returned; beyond
 * it, the caller gets RANGE chunks only — the platform never expands an
 * enormous CIDR into database rows. Chunks are always produced (bounded
 * size) so large approved scans can be distributed and checkpointed (§62).
 */
export function expandCidrTargets(
  rawCidr: string,
  opts: { maxMaterializedHosts?: number; chunkSize?: number } = {},
): ExpansionResult | null {
  const info = parseCidr(rawCidr);
  if (!info) return null;
  const maxList = opts.maxMaterializedHosts ?? 1024;
  const chunkSize = Math.max(1, Math.min(opts.chunkSize ?? 256, 4096));
  const fmt = info.family === 4 ? formatIpv4 : formatIpv6;
  const first = parseIp(info.firstHost);
  const last = parseIp(info.lastHost);
  if (!first || !last) return null;

  const chunks: TargetChunk[] = [];
  let cursor = first.value;
  let index = 0;
  while (cursor <= last.value) {
    const remaining = last.value - cursor + 1n;
    const size = remaining > BigInt(chunkSize) ? chunkSize : Number(remaining);
    const end = cursor + BigInt(size - 1);
    chunks.push({ chunkId: `chunk-${index}`, rangeStart: fmt(cursor), rangeEnd: fmt(end), hostCount: size });
    cursor = end + 1n;
    index++;
    if (chunks.length > 100000) break; // absolute sanity bound; policy denies such sizes earlier
  }

  if (info.hostCount <= maxList) {
    const hosts: string[] = [];
    for (let v = first.value; v <= last.value; v++) hosts.push(fmt(v));
    return { kind: "LIST", cidr: info.canonical, hosts, chunks };
  }
  return { kind: "RANGES", cidr: info.canonical, totalHosts: info.hostCount, chunks };
}

/** Lazily iterate host addresses of a CIDR with a hard iteration cap —
 *  streaming representation for workers (§5); never used to pre-build
 *  huge arrays. */
export function* iterateCidrHosts(rawCidr: string, maxIterations = 100000): Generator<string> {
  const info = parseCidr(rawCidr);
  if (!info) return;
  const fmt = info.family === 4 ? formatIpv4 : formatIpv6;
  const first = parseIp(info.firstHost);
  const last = parseIp(info.lastHost);
  if (!first || !last) return;
  let n = 0;
  for (let v = first.value; v <= last.value && n < maxIterations; v++, n++) yield fmt(v);
}
