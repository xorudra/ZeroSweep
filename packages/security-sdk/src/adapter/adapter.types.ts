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
  "SUBDOMAIN_DISCOVERY", "DNS_RESOLUTION", "HTTP_PROBING", "PORT_DISCOVERY",
  "SERVICE_DETECTION", "TECHNOLOGY_DETECTION", "WEB_CRAWLING", "URL_DISCOVERY",
  "PARAMETER_DISCOVERY", "CONTENT_DISCOVERY", "TLS_ANALYSIS", "VULNERABILITY_SCANNING",
  "API_DISCOVERY", "SAST", "SCA", "SECRET_SCANNING", "CONTAINER_SCANNING",
  "CLOUD_CONFIGURATION_AUDIT", "MOBILE_STATIC_ANALYSIS", "BINARY_ANALYSIS", "REPORT_EXPORT",
] as const;
export type Capability = (typeof CAPABILITIES)[number];

export type ExecutionMode = "CONTAINER" | "EXTERNAL_API" | "ADMIN_PROVIDED" | "MOCK";
export type LicenseType = "OPEN_SOURCE" | "COMMERCIAL" | "EXTERNAL_API" | "ADMIN_PROVIDED";
export type ToolHealthStatus = "UNKNOWN" | "HEALTHY" | "DEGRADED" | "UNAVAILABLE" | "MISCONFIGURED";
export type OutputFormat = "JSON" | "JSONL" | "XML" | "CSV" | "TEXT" | "SARIF" | "HTML";
export type NetworkPolicyMode = "NO_NETWORK" | "TARGET_ONLY" | "SCOPE_ONLY" | "INTERNET_READ_ONLY" | "CUSTOM_ALLOWLIST";

export interface ResourceRequirements { cpu: string; memory: string; timeoutSeconds: number; }

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
  requiresCredentials: string[];
  requiresApproval: boolean;
  supportsContainerExecution: boolean;
  supportsCancellation: boolean;
  supportsProgress: boolean;
  defaultTimeoutSeconds: number;
  maxTimeoutSeconds: number;
  resources: ResourceRequirements;
}
