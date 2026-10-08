import type { ExposureContext, SecurityZone } from "./types";

/**
 * Topology, segments, exposure and service sensitivity
 * (Prompt 33 §94–§100).
 *
 * The AssetGraph view is DERIVED from observed facts only — HOST→IP,
 * HOST→SERVICE, HOST→OS, SERVICE→SOFTWARE, HOST→CERTIFICATE,
 * HOST→NETWORK, HOST→FINDING — never from inference (§113 view rule:
 * no inferred relationships). A publicly exposed sensitive service is
 * a RISK SIGNAL, not a vulnerability (§99): it feeds Risk Engine V3
 * context and never mints a finding by itself. Firewall observations
 * record reachability EVIDENCE only (§100) — filtered ports say
 * "filtered", never "the firewall rule is X".
 */

export interface NetworkSegmentDef {
  name: string;
  cidr: string;
  environment: string;
  zone: SecurityZone;
  criticality: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  owner?: string;
}

export type SensitiveServiceClass =
  | "REMOTE_ADMINISTRATION" | "DATABASE" | "DIRECTORY" | "MANAGEMENT"
  | "FILE_SHARING" | "DEVELOPMENT_DEBUG" | "STANDARD";

const SENSITIVE_BY_PORT: Record<number, SensitiveServiceClass> = {
  22: "REMOTE_ADMINISTRATION", 23: "REMOTE_ADMINISTRATION", 3389: "REMOTE_ADMINISTRATION",
  5900: "REMOTE_ADMINISTRATION", 5985: "REMOTE_ADMINISTRATION", 5986: "REMOTE_ADMINISTRATION",
  1433: "DATABASE", 1521: "DATABASE", 3306: "DATABASE", 5432: "DATABASE", 6379: "DATABASE",
  9042: "DATABASE", 9200: "DATABASE", 11211: "DATABASE", 27017: "DATABASE",
  389: "DIRECTORY", 636: "DIRECTORY", 88: "DIRECTORY", 3268: "DIRECTORY",
  2375: "MANAGEMENT", 2376: "MANAGEMENT", 6443: "MANAGEMENT", 10250: "MANAGEMENT",
  161: "MANAGEMENT", 9100: "MANAGEMENT",
  139: "FILE_SHARING", 445: "FILE_SHARING", 2049: "FILE_SHARING",
  8080: "DEVELOPMENT_DEBUG", 9229: "DEVELOPMENT_DEBUG", 50000: "DEVELOPMENT_DEBUG",
};

const SENSITIVE_BY_NAME: Array<{ match: RegExp; cls: SensitiveServiceClass }> = [
  { match: /ssh|telnet|rdp|vnc|winrm/i, cls: "REMOTE_ADMINISTRATION" },
  { match: /mysql|postgres|mssql|oracle|redis|mongo|elastic|cassandra|memcached/i, cls: "DATABASE" },
  { match: /ldap|kerberos/i, cls: "DIRECTORY" },
  { match: /docker|kubernetes|snmp/i, cls: "MANAGEMENT" },
  { match: /smb|netbios|nfs/i, cls: "FILE_SHARING" },
];

/** §98: classify a service's sensitivity from port + name evidence. */
export function classifySensitiveService(input: { port: number; service?: string }): SensitiveServiceClass {
  const byPort = SENSITIVE_BY_PORT[input.port];
  if (byPort) return byPort;
  const name = input.service ?? "";
  for (const rule of SENSITIVE_BY_NAME) if (rule.match.test(name)) return rule.cls;
  return "STANDARD";
}

export interface ExposureAssessment {
  exposure: ExposureContext;
  zone: SecurityZone;
  /** §99: true only when a SENSITIVE service is internet-exposed. */
  sensitiveServicePubliclyExposed: boolean;
  sensitiveClass?: SensitiveServiceClass;
  /** Plain-language signal for risk context — never a finding. */
  riskSignal: string;
}

/** §97/§99: exposure context from segment zone + EASM correlation. */
export function assessExposure(input: {
  zone: SecurityZone;
  internetObserved?: boolean; // EASM saw this host/service from the internet
  port: number;
  service?: string;
}): ExposureAssessment {
  const sensitiveClass = classifySensitiveService(input);
  const sensitive = sensitiveClass !== "STANDARD";
  const internetExposed = input.internetObserved === true || input.zone === "INTERNET";
  const exposure: ExposureContext = internetExposed ? "INTERNET_EXPOSED" : input.zone === "UNKNOWN" ? "UNKNOWN" : "INTERNAL_ONLY";
  const publiclyExposedSensitive = internetExposed && sensitive;
  return {
    exposure, zone: input.zone,
    sensitiveServicePubliclyExposed: publiclyExposedSensitive,
    ...(sensitive ? { sensitiveClass } : {}),
    riskSignal: publiclyExposedSensitive
      ? `A ${sensitiveClass.toLowerCase().replace(/_/g, " ")} service is exposed to the internet — a risk signal for prioritization, NOT a vulnerability by itself (§99)`
      : exposure === "INTERNET_EXPOSED"
        ? "Service is internet-exposed (risk context, §97)"
        : "Service appears internal-only (risk context, §97)",
  };
}

/** §100: firewall/reachability evidence — claims nothing beyond it. */
export function firewallObservation(input: { openPorts: number; filteredPorts: number; closedPorts: number }): string {
  const parts: string[] = [];
  if (input.openPorts > 0) parts.push(`${input.openPorts} port(s) reachable`);
  if (input.filteredPorts > 0) parts.push(`${input.filteredPorts} port(s) filtered — consistent with packet filtering somewhere on the path; no firewall configuration is claimed (§100)`);
  if (input.closedPorts > 0) parts.push(`${input.closedPorts} port(s) closed (host reachable, service absent)`);
  return parts.length ? parts.join("; ") : "No reachability evidence recorded";
}

export interface TopologyEdge { from: string; to: string; kind: string }

/** §94: graph edges from observed facts only. */
export function buildTopologyEdges(input: {
  host: string;
  ip?: string;
  services?: Array<{ port: number; name?: string; product?: string }>;
  osFamily?: string;
  certificateSubjects?: string[];
  network?: string;
  findingFingerprints?: string[];
}): TopologyEdge[] {
  const edges: TopologyEdge[] = [];
  const hostNode = `host:${input.host}`;
  if (input.ip) edges.push({ from: hostNode, to: `ip:${input.ip}`, kind: "HOST_IP" });
  for (const svc of input.services ?? []) {
    const svcNode = `service:${input.host}:${svc.port}`;
    edges.push({ from: hostNode, to: svcNode, kind: "HOST_SERVICE" });
    if (svc.product) edges.push({ from: svcNode, to: `software:${svc.product}`, kind: "SERVICE_SOFTWARE" });
  }
  if (input.osFamily) edges.push({ from: hostNode, to: `os:${input.osFamily}`, kind: "HOST_OS" });
  for (const subject of input.certificateSubjects ?? []) edges.push({ from: hostNode, to: `cert:${subject}`, kind: "HOST_CERTIFICATE" });
  if (input.network) edges.push({ from: hostNode, to: `network:${input.network}`, kind: "HOST_NETWORK" });
  for (const fp of input.findingFingerprints ?? []) edges.push({ from: hostNode, to: `finding:${fp}`, kind: "HOST_FINDING" });
  return edges;
}
