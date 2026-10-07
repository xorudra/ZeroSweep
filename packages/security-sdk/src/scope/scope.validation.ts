import { isValidCidr, isValidIpv4 } from "../targets/target.validation";
import type { ScopeRules } from "./scope.types";

/**
 * Structural validation of scope rules (Prompt 3 §15). Scope is structured
 * data validated by schema — never an arbitrary shell expression.
 */
export function validateScopeRules(rules: ScopeRules): string[] {
  const errors: string[] = [];
  for (const cidr of rules.includeCidrs) {
    if (!isValidCidr(cidr)) errors.push(`Invalid CIDR in scope: ${cidr}`);
  }
  for (const port of rules.allowedPorts) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) errors.push(`Invalid port in scope: ${port}`);
  }
  for (const host of [...rules.includeHosts, ...rules.excludeHosts]) {
    if (/[/?#\s;&|`$]/.test(host)) errors.push(`Invalid host rule in scope: ${host}`);
  }
  for (const p of [...rules.allowedPaths, ...rules.excludedPaths]) {
    if (!p.startsWith("/")) errors.push(`Scope paths must start with /: ${p}`);
  }
  return errors;
}

export function isValidIp(ip: string): boolean {
  return isValidIpv4(ip);
}
