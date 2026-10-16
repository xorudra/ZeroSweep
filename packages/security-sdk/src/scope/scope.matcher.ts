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

  isIpAllowed(ip: string): boolean {
    if (!/^[0-9.]+$/.test(ip) && !ip.includes(":")) return false;
    return this.ipInAnyCidr(ip) || this.matchesAny(this.rules.includeHosts, ip.toLowerCase());
  }

  /** A discovered subdomain stays in scope only if it is allowed AND not
   *  excluded — assets found mid-scan never expand scope on their own. */
  isDiscoveredAssetInScope(host: string): { allowed: boolean; reason?: string } {
    if (this.matchesAny(this.rules.excludeHosts, host.toLowerCase())) return { allowed: false, reason: "host is explicitly excluded" };
    return this.isHostAllowed(host) ? { allowed: true } : { allowed: false, reason: "host is outside the approved scope" };
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
    if (u.username || u.password) return false; // embedded credentials are never in scope
    if (blockedTargetReason(u.hostname)) return false; // URLs to internal targets are never in scope
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
    const rawParts = s.split(".");
    // Strict canonical dotted-quad only: decimal digits, no empty
    // parts, no leading zeros (other parsers read those as octal).
    if (rawParts.length !== 4 || rawParts.some((p) => !/^\d{1,3}$/.test(p) || (p.length > 1 && p.startsWith("0")))) return null;
    const parts = rawParts.map(Number);
    if (parts.some((n) => n < 0 || n > 255)) return null;
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
  { test: (h) => /^f[cd][0-9a-f]{2}:/.test(h), reason: "IPv6 unique-local range requires an approved internal engagement" },
  { test: (h) => /^fe[89ab][0-9a-f]:/.test(h), reason: "IPv6 link-local range is blocked" },
  { test: (h) => cidrContains("0.0.0.0/8", h), reason: "unspecified range is blocked" },
  { test: (h) => cidrContains("100.64.0.0/10", h), reason: "shared address space requires an approved internal engagement" },
];

/**
 * Extract the IPv4 address embedded in an IPv6 spelling (audit:
 * ssrf-validator.ipv6-mapped-translated-bypass): IPv4-mapped
 * ::ffff:0:0/96, IPv4-compatible ::/96, NAT64 64:ff9b::/96 and
 * 64:ff9b:1::/48 — in dotted-quad tail form (::ffff:127.0.0.1), hex
 * group tail form (::ffff:7f00:1, which is what URL parsers normalize
 * mapped addresses to), and fully expanded form (0:0:0:0:0:ffff:…).
 * Returns null for native IPv6 / non-IPv6 input.
 */
export function embeddedIpv4(host: string): string | null {
  let h = host.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  const m = h.match(/^::ffff:(.+)$/)
    ?? h.match(/^0:0:0:0:0:ffff:(.+)$/)
    ?? h.match(/^64:ff9b:(?::|1::)(.+)$/)
    ?? h.match(/^::(.+)$/)
    ?? h.match(/^0:0:0:0:0:0:(.+)$/);
  if (!m) return null;
  const tail = m[1]!;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(tail)) return tail;
  const parts = tail.split(":");
  if (parts.length === 2 && parts.every((p) => /^[0-9a-f]{1,4}$/.test(p))) {
    const a = parseInt(parts[0]!, 16);
    const b = parseInt(parts[1]!, 16);
    return `${a >> 8}.${a & 255}.${b >> 8}.${b & 255}`;
  }
  return null;
}

export function blockedTargetReason(host: string): string | null {
  let h = host.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  // Non-canonical IPv4 encodings (leading-zero / octal-style parts)
  // are refused outright: downstream parsers may read them as a
  // different address than the dotted-decimal screen does.
  if (/^[0-9.]+$/.test(h) && h.split(".").some((p) => p.length > 1 && p.startsWith("0"))) {
    return "non-canonical IPv4 encoding is blocked";
  }
  for (const p of BLOCKED_PATTERNS) if (p.test(h)) return p.reason;
  if (h === "::") return "IPv6 unspecified address is blocked";
  // IPv6 spellings embedding an IPv4 address are screened as that
  // IPv4 address; mapped / NAT64 forms are refused outright even for
  // a public embedded address — they are never legitimate targets.
  const emb = embeddedIpv4(h);
  if (emb) {
    const r = blockedTargetReason(emb);
    if (r) return r;
    if (h.startsWith("::ffff:") || h.startsWith("64:ff9b:") || h.startsWith("0:0:0:0:0:ffff:")) {
      return "embedded IPv4 destination is blocked";
    }
  }
  return null;
}
