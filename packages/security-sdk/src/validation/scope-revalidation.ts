import { blockedTargetReason, ScopeMatcher } from "../scope/scope.matcher";
import type { ScopeRules } from "@dsrclone/validation";

/**
 * Scope revalidation (Prompt 16 §9) — performed IMMEDIATELY before
 * execution, in the worker, against live resolution. This is the
 * DNS-rebinding defense (§86): a hostname that resolved in scope when
 * the request was created may resolve to a protected address by the
 * time validation runs; if ANY resolved address is protected or out of
 * scope, validation is BLOCKED. Scope never drifts silently.
 */

export type HostResolver = (host: string) => Promise<string[]>;

export type ScopeRevalidationResult =
  | { ok: true; resolvedIps: string[] }
  | { ok: false; reasonCode: "OUT_OF_SCOPE" | "PROTECTED_DESTINATION" | "RESOLUTION_FAILED" | "INVALID_DESTINATION"; message: string };

export interface ScopeRevalidationInput {
  host?: string;
  port?: number;
  url?: string;
  scopeRules: ScopeRules;
  resolver: HostResolver;
  /** Only an approved internal engagement may reach private ranges
   *  (Prompt 3/10 posture) — validation does not widen that rule. */
  internalEngagementApproved?: boolean;
}

const IPV4_RE = /^[0-9.]+$/;

export async function revalidateScope(input: ScopeRevalidationInput): Promise<ScopeRevalidationResult> {
  const matcher = new ScopeMatcher(input.scopeRules);
  let host = input.host;
  let port = input.port;

  if (input.url) {
    let u: URL;
    try {
      u = new URL(input.url);
    } catch {
      return { ok: false, reasonCode: "INVALID_DESTINATION", message: "validation URL does not parse" };
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      return { ok: false, reasonCode: "INVALID_DESTINATION", message: "validation URL must be http/https" };
    }
    if (u.username || u.password) {
      return { ok: false, reasonCode: "INVALID_DESTINATION", message: "URLs with embedded credentials are never valid validation destinations" };
    }
    host = u.hostname;
    port = port ?? (u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80);
    if (!matcher.isPathAllowed(u.pathname)) {
      return { ok: false, reasonCode: "OUT_OF_SCOPE", message: "validation URL path is outside the approved scope" };
    }
  }

  if (!host) {
    // Non-network validators (cloud/source/container/AD posture) carry
    // no host to re-resolve; their destination identity is re-checked
    // against the authorization snapshot by the caller.
    return { ok: true, resolvedIps: [] };
  }

  if (!matcher.isHostAllowed(host)) {
    return { ok: false, reasonCode: "OUT_OF_SCOPE", message: `host ${host} is outside the approved scope (§85)` };
  }
  if (port !== undefined && !matcher.isPortAllowed(port)) {
    return { ok: false, reasonCode: "OUT_OF_SCOPE", message: `port ${port} is outside the approved scope` };
  }

  // Resolve NOW (§9): literal IPs skip DNS but not the checks below.
  let resolvedIps: string[];
  if (IPV4_RE.test(host) || host.includes(":")) {
    resolvedIps = [host];
  } else {
    try {
      resolvedIps = await input.resolver(host);
    } catch {
      return { ok: false, reasonCode: "RESOLUTION_FAILED", message: `host ${host} could not be resolved at execution time` };
    }
    if (resolvedIps.length === 0) {
      return { ok: false, reasonCode: "RESOLUTION_FAILED", message: `host ${host} resolved to no addresses at execution time` };
    }
  }

  for (const ip of resolvedIps) {
    const blocked = blockedTargetReason(ip);
    if (blocked && !input.internalEngagementApproved) {
      return {
        ok: false,
        reasonCode: "PROTECTED_DESTINATION",
        message: `host ${host} resolved to a protected destination (${blocked}) — DNS-rebinding protection blocks execution (§86)`,
      };
    }
    // When the scope is expressed as CIDRs, EVERY resolved address must
    // be inside them; one stray answer poisons the whole resolution.
    if (input.scopeRules.includeCidrs.length > 0 && IPV4_RE.test(ip) && !matcher.isIpAllowed(ip)) {
      return { ok: false, reasonCode: "OUT_OF_SCOPE", message: `host ${host} resolved to ${ip}, which is outside the approved CIDR scope (§86)` };
    }
  }

  return { ok: true, resolvedIps };
}
