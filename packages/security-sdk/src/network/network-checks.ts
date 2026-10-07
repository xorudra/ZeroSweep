import type { NormalizedService } from "../findings/finding.types";
import { sanitizeScannerText } from "./sanitize";

/**
 * Safe network checks (Prompt 10 §37–§42): evidence-backed issue
 * classification over DETECTED services and governed SAFE script output.
 *
 * The discipline matters more than the list:
 * - An open port is NEVER a vulnerability (§32/§37).
 * - Database and remote-admin services are recorded as EXPOSURE
 *   observations — the platform does not attempt logins, does not
 *   brute-force, and does not guess SNMP community strings (§39–§42).
 * - A finding is created only when the detected service itself is the
 *   evidence (cleartext-by-design protocols, an unauthenticated-by-
 *   design management API) or when a governed SAFE script's output
 *   CONFIRMS the condition (§37).
 */

export interface NetworkCheckFinding {
  host: string;
  port: number;
  protocol: string;
  serviceName?: string;
  vulnClass: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  confidence: number;
  title: string;
  description: string;
  evidence: string;
  checkId: string;
}

export interface ExposureObservation {
  host: string;
  port: number;
  serviceName: string;
  kind: "DATABASE_SERVICE" | "REMOTE_ADMIN_SERVICE" | "MANAGEMENT_SERVICE";
  summary: string;
}

interface CleartextRule { service: string; severity: "MEDIUM" | "LOW"; confidence: number; label: string }

/** Curated cleartext policy (§38): finding creation depends on the actual
 *  detected service + this policy + the service evidence. */
const CLEARTEXT_RULES: Record<string, CleartextRule> = {
  telnet: { service: "telnet", severity: "MEDIUM", confidence: 0.9, label: "Telnet" },
  ftp: { service: "ftp", severity: "LOW", confidence: 0.7, label: "FTP (cleartext control channel)" },
};

/** Services whose exposure is recorded but NEVER probed for access (§39). */
const DATABASE_SERVICES: Record<number, string> = {
  1433: "Microsoft SQL Server", 1521: "Oracle Database", 3306: "MySQL/MariaDB",
  5432: "PostgreSQL", 6379: "Redis", 9042: "Cassandra", 9200: "Elasticsearch HTTP",
  11211: "Memcached", 27017: "MongoDB",
};

/** Remote administration services: inventory/exposure only (§40). */
const REMOTE_ADMIN_SERVICES: Record<number, string> = {
  22: "SSH", 3389: "RDP", 5900: "VNC", 5985: "WinRM (HTTP)", 5986: "WinRM (HTTPS)",
};

export function classifyServiceChecks(services: NormalizedService[]): { findings: NetworkCheckFinding[]; exposures: ExposureObservation[] } {
  const findings: NetworkCheckFinding[] = [];
  const exposures: ExposureObservation[] = [];
  for (const svc of services) {
    if (svc.state && svc.state !== "OPEN") continue;
    const name = (svc.name ?? "").toLowerCase();
    // Unauthenticated-by-design management API: an UNENCRYPTED Docker
    // endpoint (2375) has no authentication in its design — exposure IS
    // the confirmed condition. The TLS variant (2376) is inventory only.
    if (svc.port === 2375 && (name === "docker" || name === "http" || name === "")) {
      findings.push({
        host: svc.host, port: svc.port, protocol: svc.protocol, serviceName: svc.name,
        vulnClass: "UNAUTHENTICATED_MANAGEMENT_API", severity: "HIGH", confidence: 0.85,
        title: "Docker Remote API Exposed Without TLS/Authentication",
        description: "The Docker remote API is reachable over an unencrypted, unauthenticated-by-design endpoint (2375/tcp). Anyone able to reach it can control containers and effectively the host.",
        evidence: `Detected service ${svc.name ?? "docker"} on ${svc.host}:${svc.port}/${svc.protocol}${svc.product ? ` (${svc.product})` : ""}`,
        checkId: "service-policy:docker-api-2375",
      });
      continue;
    }
    const cleartext = CLEARTEXT_RULES[name];
    if (cleartext && !svc.tls) {
      findings.push({
        host: svc.host, port: svc.port, protocol: svc.protocol, serviceName: svc.name,
        vulnClass: "CLEARTEXT_PROTOCOL_EXPOSURE", severity: cleartext.severity, confidence: cleartext.confidence,
        title: `${cleartext.label} Cleartext Service Exposed`,
        description: `${cleartext.label} transmits credentials and data without encryption. Exposure was confirmed by service detection; no login was attempted.`,
        evidence: `Detected cleartext service ${name} on ${svc.host}:${svc.port}/${svc.protocol}${svc.product ? ` (${svc.product}${svc.version ? ` ${svc.version}` : ""})` : ""}`,
        checkId: `service-policy:cleartext-${name}`,
      });
      continue;
    }
    const db = DATABASE_SERVICES[svc.port];
    if (db) {
      exposures.push({ host: svc.host, port: svc.port, serviceName: name || db, kind: "DATABASE_SERVICE", summary: `Database service exposed: ${db} on ${svc.host}:${svc.port} — recorded as exposure; no login attempted (§39)` });
      continue;
    }
    const admin = REMOTE_ADMIN_SERVICES[svc.port];
    if (admin) {
      exposures.push({ host: svc.host, port: svc.port, serviceName: name || admin, kind: "REMOTE_ADMIN_SERVICE", summary: `Remote administration service exposed: ${admin} on ${svc.host}:${svc.port} — inventory only; no authentication attempted (§40)` });
    }
  }
  return { findings, exposures };
}

/**
 * Governed SAFE-script confirmations (§37/§41): only script ids whose
 * catalog entry declares produces=FINDING with a vulnClass can create a
 * finding, and only when the output matches the confirmation pattern for
 * that class. Everything else stays an observation.
 */
const SCRIPT_CONFIRMATIONS: Record<string, { vulnClass: string; pattern: RegExp; severity: "LOW" | "MEDIUM"; confidence: number }> = {
  SMB_SIGNING_NOT_REQUIRED: {
    vulnClass: "SMB_SIGNING_NOT_REQUIRED",
    pattern: /message signing (is )?(enabled but )?not required/i,
    severity: "LOW", confidence: 0.8,
  },
};

export function classifyScriptOutput(input: {
  host: string; port: number; protocol?: string; scriptId: string; output: string; declaredVulnClass?: string;
}): NetworkCheckFinding | null {
  if (!input.declaredVulnClass) return null;
  const rule = SCRIPT_CONFIRMATIONS[input.declaredVulnClass];
  if (!rule || rule.vulnClass !== input.declaredVulnClass) return null;
  const text = sanitizeScannerText(input.output, 2048);
  if (!rule.pattern.test(text)) return null;
  return {
    host: input.host, port: input.port, protocol: input.protocol ?? "tcp",
    vulnClass: rule.vulnClass, severity: rule.severity, confidence: rule.confidence,
    title: "SMB Message Signing Enabled But Not Required",
    description: `The governed NSE script ${input.scriptId} confirmed that SMB message signing is enabled but not required on this service.`,
    evidence: `${input.scriptId}: ${text.slice(0, 300)}`,
    checkId: `nse:${input.scriptId}`,
  };
}
