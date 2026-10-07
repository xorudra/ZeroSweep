import { TargetValidationError } from "../adapter/adapter.errors";
import { blockedTargetReason } from "../scope/scope.matcher";
import type { TargetValidationResult } from "./target.types";

/**
 * Target validation & SSRF protection (Prompt 3 §14, §46).
 *
 * Values are treated strictly as DATA: shell separators and metacharacters
 * are rejected, never escaped-and-executed, because targets only ever become
 * individual validated arguments inside a trusted ExecutionPlan.
 */
const SHELL_META = /[;&|`$<>(){}\\\n\r'"\s]/;
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

export function isValidIpv4(ip: string): boolean {
  const parts = ip.split(".");
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255 && String(Number(p)) === p.replace(/^0+(?=\d)/, ""));
}

export function isValidCidr(cidr: string): boolean {
  const [base, bits] = cidr.split("/");
  if (!base || bits === undefined || !/^\d{1,2}$/.test(bits)) return false;
  const n = Number(bits);
  if (base.includes(":")) return n >= 0 && n <= 128; // IPv6 prefix length range; address checked by caller
  return isValidIpv4(base) && n >= 0 && n <= 32;
}

export function validateTargetValue(raw: string): TargetValidationResult {
  const value = (raw ?? "").trim();
  if (!value) return { valid: false, reasonCode: "EMPTY", message: "Target value is empty" };
  if (SHELL_META.test(value)) {
    return { valid: false, reasonCode: "SHELL_METACHARACTERS", message: "Target contains shell metacharacters; targets are data, never commands" };
  }
  // URL form: only http/https, no embedded credentials.
  if (value.includes("://")) {
    let u: URL;
    try { u = new URL(value); } catch { return { valid: false, reasonCode: "INVALID_URL", message: "Malformed URL" }; }
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      return { valid: false, reasonCode: "INVALID_PROTOCOL", message: `Protocol ${u.protocol} is not allowed` };
    }
    if (u.username || u.password) {
      return { valid: false, reasonCode: "EMBEDDED_CREDENTIALS", message: "URLs with embedded credentials are not allowed" };
    }
    return validateHost(u.hostname);
  }
  if (/^\d[\d.]*$/.test(value) || value.includes("/")) {
    // IP or CIDR form
    if (value.includes("/")) {
      if (!isValidCidr(value)) return { valid: false, reasonCode: "INVALID_CIDR", message: "Malformed CIDR" };
      const host = value.split("/")[0]!;
      const blocked = blockedTargetReason(host);
      if (blocked) return { valid: false, reasonCode: "BLOCKED_TARGET", message: blocked };
      return { valid: true, normalizedHost: host };
    }
    if (!isValidIpv4(value)) return { valid: false, reasonCode: "INVALID_IP", message: "Malformed IP address" };
    return validateHost(value);
  }
  return validateHost(value);
}

function validateHost(hostRaw: string): TargetValidationResult {
  const host = hostRaw.toLowerCase();
  const blocked = blockedTargetReason(host);
  if (blocked) return { valid: false, reasonCode: "BLOCKED_TARGET", message: blocked };
  if (/^\d/.test(host) && host.includes(".")) {
    if (!isValidIpv4(host)) return { valid: false, reasonCode: "INVALID_IP", message: "Malformed IP address" };
    return { valid: true, normalizedHost: host };
  }
  if (!DOMAIN_RE.test(host)) return { valid: false, reasonCode: "INVALID_DOMAIN", message: "Malformed domain" };
  return { valid: true, normalizedHost: host };
}

export function assertValidTarget(raw: string): string {
  const r = validateTargetValue(raw);
  if (!r.valid) throw new TargetValidationError(r.message ?? "Invalid target");
  return r.normalizedHost!;
}

/**
 * DNS-rebinding guard (Prompt 3 §14): a hostname that was in scope at
 * planning time can re-resolve to an internal address at execution time.
 * The worker MUST re-resolve and call this on every resolved address
 * immediately before execution; any blocked address aborts the run.
 */
export function assertResolvedAddressesSafe(resolvedIps: string[]): void {
  for (const ip of resolvedIps) {
    const blocked = blockedTargetReason(ip);
    if (blocked) throw new TargetValidationError(`Resolved address ${ip} is blocked: ${blocked}`);
  }
}
