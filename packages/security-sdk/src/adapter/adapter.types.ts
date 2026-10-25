import type { TargetType } from "@zerosweep/types";

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
  // Prompt 9: API security engine capabilities. JWT capabilities are
  // INSPECTION-ONLY by design — no cracking/signature-attack capability
  // exists anywhere in this list (§22/§79). GraphQL capabilities cover
  // schema analysis; mutation execution is not a capability (§30).
  "ROUTE_DISCOVERY", "SCHEMA_BASED_API_TESTING", "API_VALIDATION",
  "JWT_INSPECTION", "JWT_CONFIGURATION_ANALYSIS",
  "GRAPHQL_ANALYSIS", "GRAPHQL_SCHEMA_ANALYSIS",
  "HTTP_TRAFFIC_CAPTURE", "WEBSOCKET_DISCOVERY", "SPEC_IMPORT",
  // Prompt 10: network VAPT engine capabilities. HIGH_SPEED_PORT_DISCOVERY
  // (Masscan) is deliberately not required by any default stage — the tool
  // is elevated-policy gated and never auto-selected (§19). LOCAL_NETWORK_
  // DISCOVERY executes only on workers advertising LOCAL_LAYER2_ACCESS
  // (§65). There is NO credential-attack capability in this list (§88).
  "HOST_DISCOVERY", "VERSION_DETECTION", "OS_HINTING", "SAFE_NETWORK_CHECKS",
  "HIGH_SPEED_PORT_DISCOVERY", "LOCAL_NETWORK_DISCOVERY", "UDP_SCANNING",
  "PACKET_CAPTURE", "PACKET_ANALYSIS",
  // Prompt 11: vulnerability-scanner connector + intelligence capabilities.
  // VULNERABILITY_REFERENCE_LOOKUP (SearchSploit) is reference-only — there
  // is deliberately NO exploit-execution capability anywhere (§17/§18/§103).
  "NETWORK_VULNERABILITY_ASSESSMENT", "SCAN_RESULT_IMPORT", "VULNERABILITY_DETECTION",
  "VULNERABILITY_REFERENCE_LOOKUP",
  // Prompt 12: source code security capabilities. There is deliberately
  // NO source-execution capability (§14) and NO secret-verification-by-
  // default flow — SECRET_VERIFICATION exists so the policy can name
  // and DENY it (§37/§44).
  "CODE_PATTERN_ANALYSIS", "SECURITY_RULE_ANALYSIS", "SECURITY_QUERY_ANALYSIS", "DATAFLOW_ANALYSIS",
  "PYTHON_SECURITY_ANALYSIS", "FRAMEWORK_SECURITY_ANALYSIS",
  "SECRET_DETECTION", "SECRET_VERIFICATION",
  "DEPENDENCY_VULNERABILITY_ANALYSIS", "PACKAGE_VULNERABILITY_ANALYSIS", "SBOM_ANALYSIS",
  // Prompt 13: container / Docker / Kubernetes capabilities. There is
  // deliberately NO image-execution, pod-execution, privilege-escalation
  // or secret-extraction capability anywhere in this list (§9/§114).
  "IMAGE_ANALYSIS", "SBOM_GENERATION", "IMAGE_VULNERABILITY_SCANNING",
  "MISCONFIGURATION_SCANNING", "DOCKERFILE_SECURITY",
  "DOCKER_CIS_ASSESSMENT", "DOCKER_HOST_CONFIGURATION",
  "KUBERNETES_CIS_ASSESSMENT", "KUBERNETES_SECURITY_DISCOVERY", "KUBERNETES_POSTURE_TESTING",
  "KUBERNETES_POSTURE", "MANIFEST_ANALYSIS", "COMPLIANCE_ASSESSMENT",
  "IAC_SECURITY", "KUBERNETES_MANIFEST_SECURITY", "HELM_SECURITY",
  "CLUSTER_INVENTORY", "RESOURCE_INVENTORY", "POSTURE_ASSESSMENT",
  "RUNTIME_SECURITY_EVENTS",
  // Prompt 14: multi-cloud security capabilities. CLOUD_OFFENSIVE_TESTING
  // exists ONLY so the policy/registry can name Pacu and keep it
  // DISABLED (§34/§106) — no adapter is ever selected for it and no
  // stage requires it. There is deliberately NO cloud-mutation,
  // privilege-escalation, secret-extraction or resource-modification
  // capability anywhere in this list.
  "CSPM", "CLOUD_POSTURE", "CLOUD_INVENTORY", "CLOUD_CONFIGURATION_ASSESSMENT",
  "CLOUD_QUERY", "COMPLIANCE_QUERY",
  "IDENTITY_INVENTORY", "DIRECTORY_ANALYSIS", "RELATIONSHIP_ANALYSIS",
  "AWS_NETWORK_ANALYSIS", "AWS_ACCOUNT_VISUALIZATION", "PUBLIC_EXPOSURE_ANALYSIS",
  "CLOUD_OFFENSIVE_TESTING",
  // Prompt 15: Active Directory capabilities. The DEFENSIVE set is what
  // adapters implement (inventory, posture, graph, attack-PATH
  // MODELING). The OFFENSIVE names (ADCS_OFFENSIVE_VALIDATION,
  // OFFENSIVE_REMOTE_OPERATIONS, CREDENTIAL_ATTACKS,
  // ACCOUNT_AUTHENTICATION_TESTING, NETWORK_POISONING,
  // CREDENTIAL_CAPTURE, OFFENSIVE_AD_OPERATIONS) exist ONLY so the
  // registry/policy can name the disabled tool categories (§47/§51–§55,
  // §120) — no adapter implements them, no stage requires them, and
  // there is deliberately NO password-spraying, hash-dumping,
  // Kerberoasting, relay, pass-the-hash/ticket, DCSync or lateral-
  // movement capability anywhere in this list.
  "DIRECTORY_INVENTORY", "LDAP_SECURITY_ANALYSIS", "IDENTITY_RELATIONSHIP_DISCOVERY",
  "DIRECTORY_RELATIONSHIP_COLLECTION",
  "IDENTITY_GRAPH", "PRIVILEGE_RELATIONSHIP_ANALYSIS", "DEFENSIVE_ATTACK_PATH_ANALYSIS",
  "AD_SECURITY_POSTURE", "AD_RISK_ASSESSMENT", "DOMAIN_CONFIGURATION_REVIEW",
  "SMB_DIRECTORY_ENUMERATION", "WINDOWS_SERVICE_DISCOVERY",
  "SMB_SHARE_INVENTORY", "SMB_PERMISSION_REVIEW",
  "ADCS_INVENTORY", "ADCS_POSTURE_ANALYSIS", "ADCS_OFFENSIVE_VALIDATION",
  "SAFE_SERVICE_ENUMERATION", "AUTHENTICATED_INVENTORY",
  "OFFENSIVE_REMOTE_OPERATIONS", "CREDENTIAL_ATTACKS",
  "ACCOUNT_AUTHENTICATION_TESTING", "NETWORK_POISONING", "CREDENTIAL_CAPTURE",
  "DIRECTORY_ENUMERATION", "OFFENSIVE_AD_OPERATIONS",
  "MANUAL_DIRECTORY_ANALYSIS", "SNAPSHOT_IMPORT",
  // Prompt 17: mobile application security capabilities. The static
  // set is what adapters implement (manifest/plist analysis,
  // decompilation-output parsing, binary static analysis, secrets,
  // SCA). DYNAMIC_INSTRUMENTATION exists ONLY so the policy can name
  // Frida/Objection and keep them behind the instrumentation policy
  // (§69–§74) — default DISABLED/APPROVAL_REQUIRED, approved modules
  // only, never arbitrary scripts. There is deliberately NO
  // generic-shell, app-execution, credential-theft, token-theft,
  // pinning-bypass or root/jailbreak-bypass capability anywhere in
  // this list (§75/§119).
  "MANIFEST_ANALYSIS", "CODE_ANALYSIS", "NETWORK_SECURITY_CONFIG_ANALYSIS",
  "ANDROID_DECOMPILATION", "STATIC_CODE_EXTRACTION",
  "APK_RESOURCE_ANALYSIS", "MANIFEST_EXTRACTION", "RESOURCE_EXTRACTION",
  "BINARY_STATIC_ANALYSIS", "NATIVE_LIBRARY_ANALYSIS",
  "DEVICE_MANAGEMENT", "APP_INSTALLATION", "LOG_COLLECTION",
  "CONTROLLED_APP_INTERACTION", "MOBILE_TRAFFIC_CAPTURE", "HTTP_ANALYSIS",
  "MOBILE_PROXY_ANALYSIS", "DYNAMIC_INSTRUMENTATION",
  // Prompt 18: binary / reverse-engineering capabilities. The static
  // set is what adapters implement (hardening analysis, disassembly /
  // decompilation inventory, function/import/export/string analysis).
  // DYNAMIC_DEBUGGING exists ONLY so the policy can name GDB/pwndbg
  // and keep them behind the BinaryDebugPolicy (§64–§68) — LAB +
  // approval gated, typed operations only, never an unrestricted
  // debugger console. There is deliberately NO exploit-generation,
  // shellcode, ROP, credential-dumping, process-injection or
  // persistence capability anywhere in this list (§78/§123).
  "BINARY_HARDENING_ANALYSIS", "DISASSEMBLY", "DECOMPILATION",
  "FUNCTION_ANALYSIS", "IMPORT_EXPORT_ANALYSIS", "STRING_REFERENCE_ANALYSIS",
  "STATIC_BINARY_ANALYSIS", "FUNCTION_INVENTORY", "STRING_ANALYSIS",
  "DYNAMIC_DEBUGGING",
  // Prompt 19: wireless capabilities. The PASSIVE/OFFLINE set is what
  // adapters implement (passive discovery, inventory, capture metadata
  // and offline inspection). ACTIVE_WIRELESS_TESTING and
  // ACTIVE_WIRELESS_CAPTURE exist ONLY so the registry/policy can name
  // Wifite and active hcxdumptool modes and keep them DISABLED outside
  // a governed lab workflow (§21/§22/§64) — no adapter implements them
  // and no baseline stage requires them. There is deliberately NO
  // credential-cracking, key-recovery, deauthentication, rogue-AP,
  // evil-twin or jamming capability anywhere in this list (§99).
  "PASSIVE_WIFI_DISCOVERY", "ACCESS_POINT_INVENTORY", "STATION_OBSERVATION",
  "CHANNEL_OBSERVATION", "WIRELESS_SECURITY_METADATA",
  "CAPTURE_METADATA_ANALYSIS", "WIRELESS_CONFIGURATION_ANALYSIS", "OFFLINE_CAPTURE_INSPECTION",
  "OFFLINE_CAPTURE_PROCESSING", "CAPTURE_METADATA_EXTRACTION",
  "PCAP_ANALYSIS", "FRAME_ANALYSIS_80211", "WIRELESS_PROTOCOL_METADATA",
  "ACTIVE_WIRELESS_TESTING", "ACTIVE_WIRELESS_CAPTURE",
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
  /** Prompt 10 §23/§86: worker type this adapter must run on when it is
   *  not a general tool (NETWORK_EXTERNAL / NETWORK_INTERNAL /
   *  PACKET_ANALYSIS). Display + scheduling metadata; enforcement lives in
   *  the worker's capability gates. */
  requiredWorkerType?: string;
  supportsContainerExecution: boolean;
  supportsCancellation: boolean;
  supportsProgress: boolean;
  defaultTimeoutSeconds: number;
  maxTimeoutSeconds: number;
  resources: ResourceRequirements;
}
