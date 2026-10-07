import type { TargetType } from "@dsrclone/types";

export const TOOL_CATEGORIES = [
  "RECON", "WEB", "NETWORK", "API", "ACTIVE_DIRECTORY", "PASSWORD_AUDIT",
  "MOBILE", "CLOUD", "CONTAINER", "SOURCE_CODE", "BINARY", "WIRELESS", "REPORTING",
] as const;
export type ToolCategory = (typeof TOOL_CATEGORIES)[number];

/** PASSIVE < LOW < MODERATE < INTRUSIVE < RESTRICTED */
export const RISK_LEVELS = ["PASSIVE", "LOW", "MODERATE", "INTRUSIVE", "RESTRICTED"] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];
export const RISK_ORDER: Record<RiskLevel, number> = { PASSIVE: 0, LOW: 1, MODERATE: 2, INTRUSIVE: 3, RESTRICTED: 4 };

export const CAPABILITIES = [
  "SUBDOMAIN_DISCOVERY", "DNS_RESOLUTION", "DNS_DISCOVERY", "HTTP_PROBING", "PORT_DISCOVERY",
  "SERVICE_DETECTION", "TECHNOLOGY_DETECTION", "WEB_CRAWLING", "URL_DISCOVERY",
  "HISTORICAL_URL_DISCOVERY", "ENDPOINT_DISCOVERY",
  "PARAMETER_DISCOVERY", "CONTENT_DISCOVERY", "DIRECTORY_DISCOVERY", "FILE_DISCOVERY",
  "RECURSIVE_CONTENT_DISCOVERY", "VHOST_DISCOVERY", "TLS_ANALYSIS", "VULNERABILITY_SCANNING",
  // Prompt 7: safe vulnerability detection + TLS assessment capabilities.
  "MISCONFIGURATION_DETECTION", "EXPOSURE_DETECTION", "TECHNOLOGY_VALIDATION",
  "WEB_SERVER_SECURITY_ASSESSMENT", "TLS_CONFIGURATION_ASSESSMENT", "CERTIFICATE_ANALYSIS",
  "API_DISCOVERY", "SAST", "SCA", "SECRET_SCANNING", "CONTAINER_SCANNING",
  "CLOUD_CONFIGURATION_AUDIT", "MOBILE_STATIC_ANALYSIS", "BINARY_ANALYSIS", "REPORT_EXPORT",
  // Prompt 8: interactive proxy/scanner connector capabilities. These belong
  // to service-style connectors (ZAP / Burp / Caido), not CLI adapters.
  // ACTIVE_WEB_SCANNING is INTRUSIVE and approval-gated — capability metadata
  // existing here never makes it selectable by default (§8/§12/§38).
  "PROXY", "PASSIVE_ANALYSIS", "CONTEXT_MANAGEMENT", "ENDPOINT_IMPORT",
  "ISSUE_IMPORT", "SITE_MAP_IMPORT", "TRAFFIC_ANALYSIS", "REQUEST_COLLECTION",
  "ACTIVE_WEB_SCANNING",
] as const;
export type Capability = (typeof CAPABILITIES)[number];

export type ExecutionMode = "CONTAINER" | "EXTERNAL_API" | "ADMIN_PROVIDED" | "MOCK";
export type LicenseType = "OPEN_SOURCE" | "COMMERCIAL" | "EXTERNAL_API" | "ADMIN_PROVIDED";
export type ToolHealthStatus = "UNKNOWN" | "HEALTHY" | "DEGRADED" | "UNAVAILABLE" | "MISCONFIGURED";
export type OutputFormat = "JSON" | "JSONL" | "XML" | "CSV" | "TEXT" | "SARIF" | "HTML";
export type NetworkPolicyMode = "NO_NETWORK" | "TARGET_ONLY" | "SCOPE_ONLY" | "INTERNET_READ_ONLY" | "CUSTOM_ALLOWLIST";

export interface ResourceRequirements { cpu: string; memory: string; timeoutSeconds: number; }

/**
 * Structured adapter input schema (Prompt 3 §8). Adapters declare the fields
 * they accept; users submit values for those fields only. There is NO field
 * type for a raw command and no API accepts one — a field named "command"
 * (or similar) is rejected by validation.
 */
export const INPUT_FIELD_TYPES = ["string", "number", "boolean", "string[]", "number[]"] as const;
export type InputFieldType = (typeof INPUT_FIELD_TYPES)[number];

export interface AdapterInputField {
  name: string;
  type: InputFieldType;
  required?: boolean;
  description?: string;
  /** Inclusive bounds for numeric fields; length bounds for strings/arrays. */
  min?: number;
  max?: number;
  enumValues?: string[];
}

export const FORBIDDEN_INPUT_FIELDS = ["command", "cmd", "shell", "exec", "script", "args"] as const;

/**
 * A credential an adapter needs (Prompt 3 §23). Only the REFERENCE is ever
 * declared, stored or logged; the secret value is resolved inside the trusted
 * worker boundary at execution time and never enters metadata or API output.
 */
export interface CredentialRequirement {
  reference: string; // e.g. "SHODAN_API_KEY" — a name, never a value
  description?: string;
  required: boolean;
}

export function credentialRequirementsOf(metadata: ToolMetadata): CredentialRequirement[] {
  return metadata.requiresCredentials.map((reference) => ({ reference, required: true }));
}

export interface ToolMetadata {
  id: string;
  slug: string;
  name: string;
  description: string;
  category: ToolCategory;
  adapterVersion: string;
  toolVersion?: string;
  homepage?: string;
  licenseType: LicenseType;
  executionMode: ExecutionMode;
  riskLevel: RiskLevel;
  supportedTargetTypes: TargetType[];
  supportedOutputFormats: OutputFormat[];
  capabilities: Capability[];
  /** Declared structured inputs; configuration is validated against this. */
  inputSchema?: AdapterInputField[];
  requiresCredentials: string[];
  requiresApproval: boolean;
  supportsContainerExecution: boolean;
  supportsCancellation: boolean;
  supportsProgress: boolean;
  defaultTimeoutSeconds: number;
  maxTimeoutSeconds: number;
  resources: ResourceRequirements;
}
