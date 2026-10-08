/**
 * Network VAPT V2 shared types (Prompt 33).
 *
 * V2 deepens the Prompt 10 network engine on the SAME canonical models:
 * targets bind a VERIFIED parent Target + an APPROVED assessment (the
 * authorization record), plans freeze an immutable scope snapshot, and
 * every active capability stays behind the Prompt 10 governance —
 * NSE brute/exploit/dos are never automatable, Masscan is never a
 * default, and no login is ever attempted by any check in this package.
 */

export type NetworkTargetType = "IP" | "CIDR" | "HOSTNAME" | "AUTHORIZED_ASSET_GROUP";
export type NetworkTargetEnvironment = "PRODUCTION" | "STAGING" | "DEVELOPMENT" | "TEST" | "INTERNAL_LAB" | "UNKNOWN";
export type NetworkCriticality = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNSPECIFIED";

export type NetworkVaptProfileKey =
  | "NETWORK_DISCOVERY"
  | "NETWORK_SAFE"
  | "NETWORK_STANDARD"
  | "NETWORK_VULNERABILITY"
  | "TLS_NETWORK"
  | "TARGETED_SERVICE_VERIFICATION";

/** The §13 orchestrator pipeline, in order. */
export const NETWORK_PIPELINE = [
  "PREFLIGHT", "HOST_DISCOVERY", "PORT_DISCOVERY", "SERVICE_ENUMERATION",
  "PROTOCOL_ANALYSIS", "VULNERABILITY_ASSESSMENT", "NORMALIZATION",
  "CORRELATION", "RISK", "REMEDIATION", "REPORT",
] as const;
export type NetworkStage = (typeof NETWORK_PIPELINE)[number];

export type NetworkPreflightStatus = "READY" | "READY_WITH_WARNINGS" | "BLOCKED" | "UNREACHABLE" | "TOOL_UNAVAILABLE";

export type HostStatus = "UP" | "DOWN" | "UNKNOWN" | "FILTERED";
export type PortState = "OPEN" | "CLOSED" | "FILTERED" | "OPEN_FILTERED" | "UNKNOWN";
export type NetworkConfidenceBand = "LOW" | "MEDIUM" | "HIGH" | "VERIFIED";

export type SecurityZone = "INTERNET" | "DMZ" | "INTERNAL" | "RESTRICTED" | "MANAGEMENT" | "UNKNOWN";
export type ExposureContext = "INTERNET_EXPOSED" | "INTERNAL_ONLY" | "UNKNOWN";

/** §30 port sets. FULL_TCP is a policy object, never a default (§31). */
export type PortSetKey = "COMMON" | "WEB" | "INFRASTRUCTURE" | "DATABASE" | "CUSTOM_APPROVED" | "FULL_TCP";

export interface NetworkScanBudget {
  maxHosts: number;
  maxPortsPerHost: number;
  maxTotalPorts: number;
  /** Packet/request rate ceiling for the whole scan (§17). */
  maxRatePerSecond: number;
  maxConcurrency: number;
  maxDurationSeconds: number;
  /** UDP is separately budgeted because of cost/latency/accuracy (§32). */
  maxUdpPorts: number;
}

export interface PortPolicy {
  /** TCP port set (§30). */
  set: PortSetKey;
  /** Bounded custom list — only meaningful for CUSTOM_APPROVED (§30). */
  customPorts?: number[];
  /** UDP scanning is separately configurable and OFF unless enabled (§32). */
  udpEnabled: boolean;
  udpPorts?: number[];
  /** Full TCP range was explicitly granted by policy (§31). */
  fullTcpApproved?: boolean;
}
