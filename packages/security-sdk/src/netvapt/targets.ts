import {
  CidrPolicyService, canonicalizeCidr, classifyDestination, evaluateDestination,
  isCidr, isIpLiteral, parseCidr, parseIp, protectedDestinationReason,
  type CidrPolicyVerdict,
} from "../network/cidr";
import { PROTECTED_HOSTNAMES } from "../network/cidr";
import type { NetworkTargetType } from "./types";

/**
 * Network target normalization + CIDR safety (Prompt 33 §3–§6, §138–§140).
 *
 * Targets are normalized BEFORE scope exists: IPv4/IPv6 literals are
 * canonicalized through the Prompt 10 bigint arithmetic, CIDRs through
 * the Prompt 10 policy service (deny > platform ceiling; larger ranges
 * demand stricter approval tiers), and hostnames are strictly validated
 * as DATA — shell metacharacters, whitespace, option-like leading
 * dashes and URL syntax are rejected outright, never escaped-and-passed
 * (§137/§138: there is no shell anywhere downstream; argument arrays
 * only, and hostile input does not survive normalization at all).
 */

export interface NormalizedNetworkTarget {
  type: NetworkTargetType;
  /** Canonical value stored on the target + frozen into scope snapshots. */
  value: string;
  family?: 4 | 6;
  /** Address count for IP/CIDR (1 for a single IP / hostname). */
  hostCount: number;
  destinationClass: "PUBLIC" | "PRIVATE_INTERNAL" | "PROTECTED" | "HOSTNAME";
  cidrVerdict?: CidrPolicyVerdict;
}

export interface TargetNormalizationResult {
  ok: boolean;
  target?: NormalizedNetworkTarget;
  /** Machine-stable reason codes + a human explanation. */
  reason?: string;
  detail?: string;
}

/** Characters that can never appear in a legitimate network target.
 *  Their presence means the input is an injection attempt or a
 *  malformed paste — either way it is treated as hostile data (§138). */
const HOSTILE_CHARS = /[\s;|&$`"'\\<>(){}[\]!#~*?/@:]/;

const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?$/i;

export function looksLikeInjection(raw: string): boolean {
  const v = raw.trim();
  if (v.length === 0) return true;
  if (v.includes("://")) return true; // URL syntax is never a network target
  if (v.startsWith("-")) return true; // option injection (`-oX`, `--script`)
  if (/^-/.test(v)) return true;
  // A bare IP/CIDR contains only digits, dots, colons, hex letters and
  // one slash; a hostname only letters/digits/dots/dashes. Anything
  // outside the union is hostile or malformed.
  if (/[^a-zA-Z0-9.:/-]/.test(v)) return true;
  if (HOSTILE_CHARS.test(v.replace(/[/:]/g, ""))) return true;
  return false;
}

/**
 * Normalize a raw target value into its canonical form (§6).
 * `opts.internalAuthorized` records whether an APPROVED internal
 * engagement covers private address space — without it, private
 * destinations are refused for external contexts (§5 + Prompt 10 §6).
 */
export function normalizeNetworkTarget(
  rawValue: string,
  opts: { internalAuthorized?: boolean } = {},
): TargetNormalizationResult {
  const raw = String(rawValue ?? "").trim();
  if (!raw) return { ok: false, reason: "EMPTY_TARGET", detail: "Target value is empty" };
  if (looksLikeInjection(raw)) {
    return { ok: false, reason: "TARGET_INJECTION_REJECTED", detail: "Target contains characters that are never valid in an IP, CIDR or hostname — treated as hostile data, never passed to a tool (§138)" };
  }

  // --- CIDR ---
  if (raw.includes("/")) {
    if (!isCidr(raw)) return { ok: false, reason: "INVALID_CIDR", detail: `"${raw}" is not a valid CIDR range` };
    const info = parseCidr(raw)!;
    const policy = new CidrPolicyService();
    const verdict = policy.evaluate(raw);
    if (!verdict || !verdict.allowed) {
      return { ok: false, reason: "CIDR_BLOCKED", detail: verdict?.reason ?? `CIDR ${raw} exceeds platform policy` };
    }
    const dest = evaluateDestination(info.networkAddress, { internalEngagementApproved: opts.internalAuthorized ?? false });
    if (!dest.allowed) {
      return { ok: false, reason: dest.destinationClass === "PROTECTED" ? "PROTECTED_DESTINATION" : "INTERNAL_NOT_AUTHORIZED", detail: dest.reason ?? "Destination not authorized" };
    }
    return {
      ok: true,
      target: {
        type: "CIDR", value: canonicalizeCidr(raw)!, family: info.family,
        hostCount: verdict.hostCount,
        destinationClass: classifyDestination(info.networkAddress), cidrVerdict: verdict,
      },
    };
  }

  // --- IP literal (v4 or v6) ---
  if (isIpLiteral(raw)) {
    const parsed = parseIp(raw)!;
    const dest = evaluateDestination(raw, { internalEngagementApproved: opts.internalAuthorized ?? false });
    if (!dest.allowed) {
      return { ok: false, reason: protectedDestinationReason(raw) ? "PROTECTED_DESTINATION" : "INTERNAL_NOT_AUTHORIZED", detail: dest.reason ?? "Destination not authorized" };
    }
    return {
      ok: true,
      target: { type: "IP", value: raw.toLowerCase(), family: parsed.family, hostCount: 1, destinationClass: classifyDestination(raw) },
    };
  }

  // --- Hostname ---
  const host = raw.replace(/\.$/, "").toLowerCase();
  if ((PROTECTED_HOSTNAMES as readonly string[]).includes(host)) {
    return { ok: false, reason: "PROTECTED_DESTINATION", detail: `"${host}" is a protected platform/metadata hostname — always denied` };
  }
  if (!HOSTNAME_RE.test(host) || !host.includes(".")) {
    return { ok: false, reason: "INVALID_HOSTNAME", detail: `"${raw}" is not a valid fully-qualified hostname` };
  }
  return { ok: true, target: { type: "HOSTNAME", value: host, hostCount: 1, destinationClass: "HOSTNAME" } };
}

/** §7: the authorization chain a V2 target/scan must satisfy. Pure —
 *  the API layer supplies the facts from real records. */
export interface NetworkAuthorizationFacts {
  targetVerified: boolean;
  authorizationExists: boolean;
  authorizationActive: boolean;
  authorizationExpired: boolean;
  targetCoveredByScope: boolean;
  toolAllowed: boolean;
  profileAllowed: boolean;
}

export function evaluateNetworkAuthorization(facts: NetworkAuthorizationFacts): { allowed: boolean; failures: string[] } {
  const failures: string[] = [];
  if (!facts.targetVerified) failures.push("Parent target is not VERIFIED — ownership verification precedes any active network operation (§7)");
  if (!facts.authorizationExists) failures.push("No authorization record exists for this target (§7)");
  if (facts.authorizationExists && !facts.authorizationActive) failures.push("Authorization is not ACTIVE (§7)");
  if (facts.authorizationExpired) failures.push("Authorization has expired (§7)");
  if (!facts.targetCoveredByScope) failures.push("Target value is not covered by the approved scope (§7)");
  if (!facts.toolAllowed) failures.push("A requested tool is not allowed for this target/profile (§7)");
  if (!facts.profileAllowed) failures.push("The scan profile is not allowed for this target (§7)");
  return { allowed: failures.length === 0, failures };
}
