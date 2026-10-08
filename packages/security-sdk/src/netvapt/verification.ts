/**
 * Fix-verification planning (Prompt 33 §110–§112, §154).
 *
 * Verification is MINIMAL-SCOPE by construction (§112): a patched SSH
 * service is verified by an SSH version/configuration recheck on that
 * host and port — never by re-running a network-wide scan. The plan
 * feeds the Prompt 31 remediation lifecycle; a VERIFIED_FIXED outcome
 * still requires the governed retest evidence there, not this plan.
 */

export type NetworkVerificationMethod =
  | "PORT_RECHECK" | "SERVICE_VERSION_RECHECK" | "TLS_RECHECK" | "CONFIGURATION_RECHECK" | "TARGETED_VULN_RESCAN";

export interface NetworkVerificationPlan {
  method: NetworkVerificationMethod;
  host: string;
  port?: number;
  /** Why this method is the minimal sufficient check (§111). */
  rationale: string;
  /** The plan never widens beyond the single finding's host/port. */
  scopeHosts: 1;
}

export function planNetworkVerification(input: {
  vulnClass?: string;
  kind?: string;
  host: string;
  port?: number;
  protocol?: string;
}): NetworkVerificationPlan {
  const cls = `${input.vulnClass ?? ""} ${input.kind ?? ""}`.toUpperCase();
  const base = { host: input.host, ...(typeof input.port === "number" ? { port: input.port } : {}), scopeHosts: 1 as const };
  if (/TLS|CERT|CIPHER|SSL|HEARTBLEED/.test(cls)) {
    return { ...base, method: "TLS_RECHECK", rationale: "TLS/certificate issue — re-run the TLS analysis on this host/port only (§111)" };
  }
  if (/VERSION|BANNER|OUTDATED/.test(cls)) {
    return { ...base, method: "SERVICE_VERSION_RECHECK", rationale: "Version-based issue — re-detect the service version on this host/port only (§111)" };
  }
  if (/PORT|EXPOSURE|OPEN/.test(cls)) {
    return { ...base, method: "PORT_RECHECK", rationale: "Exposure issue — recheck this single port's state (§111)" };
  }
  if (/SMB|SSH|FTP|DNS|LDAP|RDP|CONFIG/.test(cls)) {
    return { ...base, method: "CONFIGURATION_RECHECK", rationale: "Configuration issue — re-run the governed protocol check for this service only (§111)" };
  }
  return { ...base, method: "TARGETED_VULN_RESCAN", rationale: "Scanner-confirmed issue — targeted rescan of this host/port with the original scanner profile (§111)" };
}
