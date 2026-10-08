import type { EasmExposureState, EasmRiskSignalKind } from "./types";

/**
 * Internet exposure classification + EASM risk signals
 * (Prompt 29 §74–§78). Classification is evidence-backed or UNKNOWN
 * (§75) — never guessed. Signals are contextual inputs TO RiskEngine
 * V3 (§77): EASM does not compute canonical risk or severity.
 */

export interface ExposureEvidenceInput {
  /** DNS resolves to a public address from an external vantage. */
  dnsPubliclyResolvable?: boolean;
  /** An HTTP response was observed from an external vantage. */
  httpResponded?: boolean;
  /** A service was observed listening from an external vantage. */
  serviceObserved?: boolean;
  /** Evidence exists but only from an internal/conditional vantage
   *  (e.g. cloud config says a rule COULD expose it). */
  conditionalEvidence?: boolean;
  /** The asset was looked for and observably absent. */
  checkedAndAbsent?: boolean;
}

export function classifyInternetExposure(ev: ExposureEvidenceInput): { state: EasmExposureState; rationale: string } {
  if (ev.dnsPubliclyResolvable || ev.httpResponded || ev.serviceObserved) {
    return { state: "INTERNET_EXPOSED", rationale: "publicly observable via DNS/HTTP/service evidence from an external vantage" };
  }
  if (ev.conditionalEvidence) {
    return { state: "CONDITIONALLY_EXPOSED", rationale: "configuration suggests possible exposure but no direct external observation exists" };
  }
  if (ev.checkedAndAbsent) {
    return { state: "NOT_OBSERVED", rationale: "checked from an external vantage and not observed" };
  }
  return { state: "UNKNOWN", rationale: "no exposure evidence recorded" };
}

/** §46 sensitive service classes (classification only — the platform
 *  never attempts authentication against these). */
export const SENSITIVE_SERVICE_CLASSES: Array<{ class: string; ports: number[]; services: string[] }> = [
  { class: "DATABASE", ports: [3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984, 8086], services: ["mysql", "postgresql", "mssql", "oracle", "mongodb", "redis", "elasticsearch", "couchdb", "influxdb"] },
  { class: "ADMINISTRATION", ports: [8080, 8443, 9000, 9090, 2375, 2376, 10250], services: ["docker", "kubelet", "jenkins", "admin"] },
  { class: "REMOTE_MANAGEMENT", ports: [22, 23, 3389, 5900, 5985, 5986], services: ["ssh", "telnet", "rdp", "vnc", "winrm"] },
  { class: "DEVELOPMENT_DEBUG", ports: [8000, 8005, 5005, 9229, 6060], services: ["debug", "pprof", "node-inspector"] },
];

export function sensitiveServiceClass(input: { port: number; service?: string | null }): string | null {
  const svc = (input.service ?? "").toLowerCase();
  for (const entry of SENSITIVE_SERVICE_CLASSES) {
    if (entry.ports.includes(input.port)) return entry.class;
    if (svc && entry.services.some((s) => svc.includes(s))) return entry.class;
  }
  return null;
}

export interface EasmSignalInput {
  exposureState: EasmExposureState;
  ownershipStatus: string;
  isNew: boolean;
  criticality?: string;
  hasKevFinding?: boolean;
  hasCriticalFinding?: boolean;
  sensitiveServiceClasses?: string[];
  outdatedTechnology?: boolean;
  certificateState?: string;
  danglingDnsCandidate?: boolean;
}

/** §78: derive the EASM risk signals that apply. Deterministic and
 *  evidence-gated: no exposure ⇒ no public-asset signals. */
export function deriveRiskSignals(input: EasmSignalInput): EasmRiskSignalKind[] {
  const signals: EasmRiskSignalKind[] = [];
  const exposed = input.exposureState === "INTERNET_EXPOSED";
  if (!exposed) {
    if (input.danglingDnsCandidate) signals.push("DANGLING_DNS_CANDIDATE");
    return signals;
  }
  if (input.isNew) signals.push("NEW_PUBLIC_ASSET");
  if (input.ownershipStatus === "UNKNOWN") signals.push("UNKNOWN_PUBLIC_ASSET");
  if (input.criticality === "CRITICAL" || input.criticality === "HIGH") signals.push("PUBLIC_CRITICAL_ASSET");
  if (input.hasKevFinding) signals.push("PUBLIC_KEV");
  if (input.hasCriticalFinding) signals.push("PUBLIC_CRITICAL_FINDING");
  if ((input.sensitiveServiceClasses ?? []).length > 0) signals.push("PUBLIC_SENSITIVE_SERVICE");
  if (input.outdatedTechnology) signals.push("OUTDATED_PUBLIC_TECHNOLOGY");
  if (input.certificateState === "EXPIRING" || input.certificateState === "URGENT" || input.certificateState === "EXPIRED") {
    signals.push("EXPIRING_PUBLIC_CERTIFICATE");
  }
  if (input.danglingDnsCandidate) signals.push("DANGLING_DNS_CANDIDATE");
  return signals;
}

/**
 * §83 drift severity policy (deterministic). A newly exposed
 * sensitive service outranks a title change; ownership loss on an
 * exposed asset outranks both.
 */
export function driftSeverity(input: {
  type: string;
  sensitiveServiceClass?: string | null;
  exposureBefore?: string;
  exposureAfter?: string;
  ownershipBefore?: string;
  ownershipAfter?: string;
}): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
  const becameExposed = input.exposureAfter === "INTERNET_EXPOSED" && input.exposureBefore !== "INTERNET_EXPOSED";
  if (input.type === "SERVICE_ADDED" && input.sensitiveServiceClass) return "CRITICAL";
  if (input.type === "OWNERSHIP_CHANGED" && input.ownershipAfter === "UNKNOWN" && input.exposureAfter === "INTERNET_EXPOSED") return "HIGH";
  if (becameExposed) return "HIGH";
  switch (input.type) {
    case "ASSET_ADDED": return "MEDIUM";
    case "SERVICE_ADDED": return "HIGH";
    case "SERVICE_REMOVED": return "LOW";
    case "ASSET_REMOVED": return "MEDIUM";
    case "CERTIFICATE_CHANGED": return "MEDIUM";
    case "EXPOSURE_CHANGED": return "HIGH";
    case "DNS_CHANGED": return "MEDIUM";
    case "IP_CHANGED": return "LOW";
    case "TECHNOLOGY_CHANGED": return "LOW";
    case "HTTP_CHANGED": return "LOW";
    case "OWNERSHIP_CHANGED": return "MEDIUM";
    default: return "LOW";
  }
}
