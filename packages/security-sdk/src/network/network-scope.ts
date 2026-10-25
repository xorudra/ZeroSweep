import type { ScopeRules } from "@zerosweep/validation";
import { canonicalizeCidr, ipInCidr, isCidr, isIpLiteral, parseIp } from "./cidr";
import { evaluateDestination } from "./cidr";

/**
 * NetworkScope (Prompt 10 §3): the canonicalized network view of a scan's
 * approved ScopeRules — individual IPv4/IPv6 addresses, CIDR ranges,
 * explicit hostnames, excluded addresses and excluded CIDRs. Everything
 * is canonicalized at construction; membership checks run against the
 * canonical form only, and exclusions always win (§3).
 */
export interface NetworkScope {
  includeIps: string[];
  includeCidrs: string[];
  includeHosts: string[];
  excludeIps: string[];
  excludeCidrs: string[];
  allowedPorts: number[];
}

export function buildNetworkScope(rules: ScopeRules): NetworkScope {
  const includeIps: string[] = [];
  const includeCidrs: string[] = [];
  const includeHosts: string[] = [];
  const excludeIps: string[] = [];
  const excludeCidrs: string[] = [];
  for (const raw of rules.includeCidrs) {
    const canonical = canonicalizeCidr(raw);
    if (canonical) includeCidrs.push(canonical);
  }
  for (const host of rules.includeHosts) {
    const h = host.toLowerCase().replace(/\.$/, "");
    if (isIpLiteral(h)) includeIps.push(h);
    else if (isCidr(h)) { const c = canonicalizeCidr(h); if (c) includeCidrs.push(c); }
    else includeHosts.push(h);
  }
  for (const host of rules.excludeHosts) {
    const h = host.toLowerCase().replace(/\.$/, "");
    if (isIpLiteral(h)) excludeIps.push(h);
    else if (isCidr(h)) { const c = canonicalizeCidr(h); if (c) excludeCidrs.push(c); }
  }
  return {
    includeIps: [...new Set(includeIps)],
    includeCidrs: [...new Set(includeCidrs)],
    includeHosts: [...new Set(includeHosts)],
    excludeIps: [...new Set(excludeIps)],
    excludeCidrs: [...new Set(excludeCidrs)],
    allowedPorts: [...rules.allowedPorts],
  };
}

/** Hostname pattern match: "*.example.com" covers any subdomain depth but
 *  not the apex (same semantics as ScopeMatcher, Prompt 3). */
function hostMatches(patterns: string[], host: string): boolean {
  const h = host.toLowerCase();
  return patterns.some((p) => {
    const pat = p.toLowerCase();
    if (pat.startsWith("*.")) {
      const suffix = pat.slice(1);
      return h.endsWith(suffix) && h.length > suffix.length;
    }
    return h === pat;
  });
}

export function networkScopeContainsIp(scope: NetworkScope, ip: string): { allowed: boolean; reason?: string } {
  if (!parseIp(ip)) return { allowed: false, reason: "not a valid IP address" };
  if (scope.excludeIps.includes(ip)) return { allowed: false, reason: "address is explicitly excluded" };
  for (const c of scope.excludeCidrs) if (ipInCidr(ip, c)) return { allowed: false, reason: "address is inside an excluded CIDR" };
  if (scope.includeIps.includes(ip)) return { allowed: true };
  for (const c of scope.includeCidrs) if (ipInCidr(ip, c)) return { allowed: true };
  return { allowed: false, reason: "address is outside the approved network scope" };
}

export function networkScopeContainsHost(scope: NetworkScope, host: string): boolean {
  if (isIpLiteral(host)) return networkScopeContainsIp(scope, host).allowed;
  return hostMatches(scope.includeHosts, host);
}

/**
 * DNS revalidation (§7): hostname targets are resolved IMMEDIATELY before
 * execution and EVERY resolved address is validated against scope,
 * protected ranges and the internal-engagement rule. Stale resolutions
 * are never trusted — the caller supplies the resolver (the worker uses
 * live DNS at execution time; tests inject recorded answers). One bad
 * address fails the whole validation: a hostname that now resolves into
 * a protected or out-of-scope address must not be scanned at all.
 */
export interface DnsRevalidationResult {
  host: string;
  resolvedAddresses: string[];
  allowed: boolean;
  blockedAddresses: Array<{ ip: string; reason: string }>;
  reason?: string;
}

export async function revalidateHostname(
  scope: NetworkScope,
  host: string,
  resolve: (hostname: string) => Promise<string[]>,
  opts: { internalEngagementApproved?: boolean; extraProtectedCidrs?: string[] } = {},
): Promise<DnsRevalidationResult> {
  const addresses = await resolve(host);
  const blocked: Array<{ ip: string; reason: string }> = [];
  for (const ip of addresses) {
    const dest = evaluateDestination(ip, opts);
    if (!dest.allowed) { blocked.push({ ip, reason: dest.reason ?? "destination not allowed" }); continue; }
    const inScope = networkScopeContainsIp(scope, ip);
    if (!inScope.allowed && !networkScopeContainsHost(scope, host)) {
      blocked.push({ ip, reason: inScope.reason ?? "resolved address is outside the approved scope" });
    }
  }
  const allowed = addresses.length > 0 && blocked.length === 0;
  return {
    host, resolvedAddresses: addresses, allowed, blockedAddresses: blocked,
    ...(allowed ? {} : { reason: addresses.length === 0 ? "hostname did not resolve" : "one or more resolved addresses are not scannable" }),
  };
}
