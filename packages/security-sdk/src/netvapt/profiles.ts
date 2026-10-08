import { NETWORK_PIPELINE, type NetworkStage, type NetworkVaptProfileKey, type PortPolicy, type PortSetKey } from "./types";
import type { NetworkScanBudget } from "./types";

/**
 * Network VAPT V2 profiles + port sets (Prompt 33 §15–§16, §30–§32).
 *
 * Profiles are DECLARATIVE: the §13 pipeline stages they run, the tool
 * slugs per stage, the port policy and the default budget. Production
 * defaults are conservative (§16): no vulnerability scanners in the
 * discovery/safe profiles, no full-TCP port range anywhere by default
 * (§31 — FULL_TCP only ever arrives via an explicit policy grant), UDP
 * off unless a profile deliberately enables a small set (§32), and
 * Masscan in NO profile's default tool list (§27 — it is an explicit,
 * separately-permissioned add-on, never a default).
 */

export interface NetworkProfileDefinition {
  key: NetworkVaptProfileKey;
  name: string;
  stages: NetworkStage[];
  toolSlugs: string[];
  portPolicy: PortPolicy;
  defaultBudget: NetworkScanBudget;
  /** Greenbone/Nessus logical profile this V2 profile maps to (§57/§58
   *  of Prompt 11): the connector resolves it to an administrator-
   *  configured scanner policy — undefined = no vulnerability scanner. */
  vulnScannerProfile?: { greenbone?: string; nessus?: string };
  /** FTP anonymous-access CHECK (metadata only) is profile-gated (§47). */
  ftpAnonymousCheck: boolean;
  /** DNS zone-transfer CHECK is separately authorized (§52). */
  dnsZoneTransferCheck: boolean;
  /** Credentialed scanning requires its own permission on top (§60). */
  credentialed: boolean;
  notes: string;
}

export const PRODUCTION_NETWORK_BUDGET: NetworkScanBudget = {
  maxHosts: 256, maxPortsPerHost: 100, maxTotalPorts: 25_600,
  maxRatePerSecond: 1_000, maxConcurrency: 4, maxDurationSeconds: 3_600, maxUdpPorts: 0,
};

export const DISCOVERY_NETWORK_BUDGET: NetworkScanBudget = {
  maxHosts: 1_024, maxPortsPerHost: 25, maxTotalPorts: 25_600,
  maxRatePerSecond: 1_000, maxConcurrency: 4, maxDurationSeconds: 1_800, maxUdpPorts: 0,
};

export const VULN_NETWORK_BUDGET: NetworkScanBudget = {
  maxHosts: 256, maxPortsPerHost: 1_000, maxTotalPorts: 65_536,
  maxRatePerSecond: 1_000, maxConcurrency: 4, maxDurationSeconds: 7_200, maxUdpPorts: 25,
};

/** §30 port sets — bounded, curated lists. */
export const PORT_SETS: Record<Exclude<PortSetKey, "CUSTOM_APPROVED" | "FULL_TCP">, number[]> = {
  COMMON: [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443],
  WEB: [80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 3128, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9080, 9090, 9200, 9443],
  INFRASTRUCTURE: [22, 53, 123, 161, 389, 636, 1812, 1813, 2049, 3260, 5060, 5061, 5432, 5900, 5985, 5986, 6443, 8009, 9100, 2375, 2376, 10250],
  DATABASE: [1433, 1521, 2375, 2376, 3306, 5432, 5984, 6379, 9042, 9200, 9300, 11211, 27017, 27018, 28015],
};

/** Resolve a port policy to the concrete bounded port list (§30/§31).
 *  FULL_TCP materializes ONLY when the policy carries an explicit
 *  grant — the caller sees `fullTcpGranted` so the plan can record it. */
export function resolvePortSet(policy: PortPolicy): { ports: number[]; fullTcpGranted: boolean } {
  if (policy.set === "FULL_TCP") {
    if (!policy.fullTcpApproved) return { ports: [...PORT_SETS.COMMON], fullTcpGranted: false };
    return { ports: Array.from({ length: 65_535 }, (_, i) => i + 1), fullTcpGranted: true };
  }
  if (policy.set === "CUSTOM_APPROVED") {
    const custom = [...new Set((policy.customPorts ?? []).filter((p) => Number.isInteger(p) && p >= 1 && p <= 65_535))].sort((a, b) => a - b);
    return { ports: custom.slice(0, 1_000), fullTcpGranted: false };
  }
  return { ports: [...PORT_SETS[policy.set]], fullTcpGranted: false };
}

const BASE_STAGES: NetworkStage[] = [...NETWORK_PIPELINE];
const DISCOVERY_STAGES: NetworkStage[] = ["PREFLIGHT", "HOST_DISCOVERY", "PORT_DISCOVERY", "SERVICE_ENUMERATION", "NORMALIZATION", "CORRELATION", "RISK", "REPORT"];
const TLS_STAGES: NetworkStage[] = ["PREFLIGHT", "HOST_DISCOVERY", "PORT_DISCOVERY", "SERVICE_ENUMERATION", "PROTOCOL_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK", "REPORT"];
const VERIFY_STAGES: NetworkStage[] = ["PREFLIGHT", "PORT_DISCOVERY", "SERVICE_ENUMERATION", "PROTOCOL_ANALYSIS", "VULNERABILITY_ASSESSMENT", "NORMALIZATION", "CORRELATION", "RISK", "REMEDIATION", "REPORT"];

function def(d: NetworkProfileDefinition): NetworkProfileDefinition { return d; }

export const NETWORK_PROFILE_DEFINITIONS: Record<NetworkVaptProfileKey, NetworkProfileDefinition> = {
  NETWORK_DISCOVERY: def({
    key: "NETWORK_DISCOVERY", name: "Network Discovery",
    stages: DISCOVERY_STAGES,
    toolSlugs: ["nmap", "naabu", "netdiscover", "arp-scan"],
    portPolicy: { set: "COMMON", udpEnabled: false },
    defaultBudget: DISCOVERY_NETWORK_BUDGET,
    ftpAnonymousCheck: false, dnsZoneTransferCheck: false, credentialed: false,
    notes: "Host + port + service inventory only. No vulnerability assessment, no scripts beyond SAFE discovery (§16).",
  }),
  NETWORK_SAFE: def({
    key: "NETWORK_SAFE", name: "Network Safe",
    stages: BASE_STAGES,
    toolSlugs: ["nmap", "naabu", "rustscan", "testssl", "sslyze"],
    portPolicy: { set: "COMMON", udpEnabled: false },
    defaultBudget: PRODUCTION_NETWORK_BUDGET,
    ftpAnonymousCheck: false, dnsZoneTransferCheck: false, credentialed: false,
    notes: "The production default (§16): governed SAFE NSE scripts, protocol configuration analysis, TLS analysis. No vulnerability scanner, no intrusive checks.",
  }),
  NETWORK_STANDARD: def({
    key: "NETWORK_STANDARD", name: "Network Standard",
    stages: BASE_STAGES,
    toolSlugs: ["nmap", "naabu", "rustscan", "netdiscover", "arp-scan", "testssl", "sslyze"],
    portPolicy: { set: "INFRASTRUCTURE", udpEnabled: true, udpPorts: [53, 123, 161, 500, 4500] },
    defaultBudget: PRODUCTION_NETWORK_BUDGET,
    ftpAnonymousCheck: false, dnsZoneTransferCheck: false, credentialed: false,
    notes: "Adds L2 discovery (internal workers only) and a small governed UDP set (§32). Still no vulnerability scanner.",
  }),
  NETWORK_VULNERABILITY: def({
    key: "NETWORK_VULNERABILITY", name: "Network Vulnerability",
    stages: BASE_STAGES,
    toolSlugs: ["nmap", "naabu", "rustscan", "testssl", "sslyze", "greenbone-openvas", "nessus-professional"],
    portPolicy: { set: "INFRASTRUCTURE", udpEnabled: true, udpPorts: [53, 123, 161, 500, 4500] },
    defaultBudget: VULN_NETWORK_BUDGET,
    vulnScannerProfile: { greenbone: "STANDARD", nessus: "NETWORK_STANDARD" },
    ftpAnonymousCheck: true, dnsZoneTransferCheck: false, credentialed: false,
    notes: "Adds the governed vulnerability scanners (Prompt 11 connectors) under their logical profiles + VULN_APPROVED NSE checks when separately allowlisted (§37). Scanner unavailability yields a PARTIAL scan, never a clean bill (§155).",
  }),
  TLS_NETWORK: def({
    key: "TLS_NETWORK", name: "TLS Network",
    stages: TLS_STAGES,
    toolSlugs: ["nmap", "naabu", "testssl", "sslyze"],
    portPolicy: { set: "WEB", udpEnabled: false },
    defaultBudget: PRODUCTION_NETWORK_BUDGET,
    ftpAnonymousCheck: false, dnsZoneTransferCheck: false, credentialed: false,
    notes: "TLS/protocol posture only (§53/§54): certificate, protocol, cipher and chain analysis over TLS-bearing services.",
  }),
  TARGETED_SERVICE_VERIFICATION: def({
    key: "TARGETED_SERVICE_VERIFICATION", name: "Targeted Service Verification",
    stages: VERIFY_STAGES,
    toolSlugs: ["nmap", "testssl", "sslyze"],
    portPolicy: { set: "CUSTOM_APPROVED", udpEnabled: false },
    defaultBudget: { ...PRODUCTION_NETWORK_BUDGET, maxHosts: 16, maxPortsPerHost: 10, maxTotalPorts: 160, maxDurationSeconds: 900 },
    ftpAnonymousCheck: false, dnsZoneTransferCheck: false, credentialed: false,
    notes: "Minimal-scope fix verification (§111/§112): port/service-version/TLS/configuration rechecks for specific findings, feeding the Prompt 31 lifecycle.",
  }),
};

export function networkProfileDefinition(key: NetworkVaptProfileKey): NetworkProfileDefinition {
  return NETWORK_PROFILE_DEFINITIONS[key];
}

export const NETWORK_PROFILE_KEYS = Object.keys(NETWORK_PROFILE_DEFINITIONS) as NetworkVaptProfileKey[];

/** §107 tiered continuous-monitoring model: expensive vulnerability
 *  scanners never run continuously by default (§105/§106). */
export const MONITORING_TIERS = [
  { tier: "LIGHT_SERVICE_CHECK", cadence: "HOURLY", profiles: ["NETWORK_DISCOVERY"] },
  { tier: "SAFE_DISCOVERY", cadence: "DAILY", profiles: ["NETWORK_DISCOVERY", "NETWORK_SAFE", "TLS_NETWORK"] },
  { tier: "VULNERABILITY_REASSESSMENT", cadence: "WEEKLY_OR_MONTHLY", profiles: ["NETWORK_VULNERABILITY"] },
] as const;
