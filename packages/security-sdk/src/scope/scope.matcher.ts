import type { ScopeRules } from "@dsrclone/validation";

/**
 * Reusable scope matcher. Wildcard host rules: "*.example.com" matches any
 * subdomain depth of example.com but NOT example.com itself unless listed.
 */
export class ScopeMatcher {
  constructor(private readonly rules: ScopeRules) {}

  isHostAllowed(host: string): boolean {
    const h = host.toLowerCase();
    if (this.matchesAny(this.rules.excludeHosts, h)) return false;
    if (this.rules.includeHosts.length === 0 && this.rules.includeCidrs.length === 0) return false;
    if (this.matchesAny(this.rules.includeHosts, h)) return true;
    // CIDR inclusion applies to IPs; hostnames are checked again at execution
    // time after DNS resolution (DNS-rebinding protection lives in the worker).
    return this.rules.includeCidrs.length > 0 && /^[0-9.]+$/.test(h) && this.ipInAnyCidr(h);
  }

  isPortAllowed(port: number): boolean {
    return this.rules.allowedPorts.length === 0 || this.rules.allowedPorts.includes(port);
  }

  isPathAllowed(path: string): boolean {
    if (this.rules.excludedPaths.some((p) => path.startsWith(p))) return false;
    if (this.rules.allowedPaths.length === 0) return true;
    return this.rules.allowedPaths.some((p) => path.startsWith(p));
  }

  isUrlAllowed(rawUrl: string): boolean {
    let u: URL;
    try { u = new URL(rawUrl); } catch { return false; }
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    const port = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
    return this.isHostAllowed(u.hostname) && this.isPortAllowed(port) && this.isPathAllowed(u.pathname);
  }

  private matchesAny(patterns: string[], host: string): boolean {
    return patterns.some((p) => {
      const pat = p.toLowerCase();
      if (pat.startsWith("*.")) {
        const suffix = pat.slice(1); // ".example.com"
        return host.endsWith(suffix) && host.length > suffix.length;
      }
      return host === pat;
    });
  }

  private ipInAnyCidr(ip: string): boolean {
    return this.rules.includeCidrs.some((cidr) => cidrContains(cidr, ip));
  }
}

export function cidrContains(cidr: string, ip: string): boolean {
  const [base, bitsRaw] = cidr.split("/");
  if (!base || bitsRaw === undefined) return false;
  const bits = Number(bitsRaw);
  const toLong = (s: string): number | null => {
    const parts = s.split(".").map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
    return ((parts[0]! << 24) >>> 0) + (parts[1]! << 16) + (parts[2]! << 8) + parts[3]!;
  };
  const b = toLong(base); const i = toLong(ip);
  if (b === null || i === null || bits < 0 || bits > 32) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (b & mask) === (i & mask);
}

/** Targets that must never be scanned without an explicit internal engagement. */
const BLOCKED_PATTERNS: Array<{ test: (host: string) => boolean; reason: string }> = [
  { test: (h) => h === "localhost" || h.endsWith(".localhost"), reason: "localhost targets are blocked" },
  { test: (h) => h === "metadata.google.internal", reason: "cloud metadata host is blocked" },
  { test: (h) => cidrContains("127.0.0.0/8", h), reason: "loopback range is blocked" },
  { test: (h) => cidrContains("169.254.0.0/16", h), reason: "link-local / cloud metadata range is blocked" },
  { test: (h) => cidrContains("10.0.0.0/8", h), reason: "private range requires an approved internal engagement" },
  { test: (h) => cidrContains("172.16.0.0/12", h), reason: "private range requires an approved internal engagement" },
  { test: (h) => cidrContains("192.168.0.0/16", h), reason: "private range requires an approved internal engagement" },
  { test: (h) => h === "::1", reason: "IPv6 loopback is blocked" },
];

export function blockedTargetReason(host: string): string | null {
  const h = host.toLowerCase();
  for (const p of BLOCKED_PATTERNS) if (p.test(h)) return p.reason;
  return null;
}
