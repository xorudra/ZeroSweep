import type { AssessmentProfile } from "@zerosweep/types";
import type { Capability } from "@zerosweep/security-sdk";
import type { FailureStrategy } from "./state-machines";

/**
 * Stage definitions + assessment profile templates (Prompt 4 §7–§8).
 * Stage types mirror the Prisma ScanStageType enum exactly so a plan can be
 * persisted 1:1 into ScanStage rows. REPORT_PREPARATION in the spec maps to
 * the existing REPORT_GENERATION stage type.
 */

export const STAGE_TYPES = [
  "AUTHORIZATION_CHECK", "SCOPE_VALIDATION", "PASSIVE_RECON", "ASSET_DISCOVERY",
  "DNS_RESOLUTION", "HTTP_DISCOVERY", "TECHNOLOGY_DETECTION", "PORT_DISCOVERY",
  "CRAWLING", "CONTENT_DISCOVERY", "ENDPOINT_DISCOVERY", "PARAMETER_DISCOVERY",
  "WEB_SURFACE_NORMALIZATION", "SAFE_VULNERABILITY_SCAN",
  "PASSIVE_SECURITY_ANALYSIS", "ACTIVE_SECURITY_ANALYSIS",
  "API_DISCOVERY", "SPEC_IMPORT", "ROUTE_DISCOVERY", "AUTH_MAPPING",
  "SAFE_SCHEMA_TESTING", "JWT_ANALYSIS", "GRAPHQL_ANALYSIS", "WEBSOCKET_INVENTORY",
  "API_FINDING_NORMALIZATION",
  "TARGET_EXPANSION", "HOST_DISCOVERY", "SERVICE_DETECTION", "SAFE_NETWORK_CHECKS",
  // Prompt 12: source code security stages (§19/§96). Acquisition,
  // language detection, dependency inventory, SBOM generation and the
  // quality gate are PLATFORM stages (worker store hooks); secret
  // scanning, SAST and SCA are tool stages.
  "SOURCE_ACQUISITION", "LANGUAGE_DETECTION", "SECRET_SCANNING", "SAST",
  "DEPENDENCY_INVENTORY", "SCA", "SBOM_GENERATION", "QUALITY_GATE",
  // Prompt 13: container / Docker / Kubernetes stages (§90).
  "IMAGE_RESOLUTION", "IMAGE_VULNERABILITY_SCAN", "MANIFEST_SCAN",
  "CLUSTER_INVENTORY", "KUBERNETES_POSTURE", "DOCKER_POSTURE",
  // Prompt 14: multi-cloud stages (§86). CLOUD_AUTH / the *_ANALYSIS
  // stages / CLOUD_COMPLIANCE are PLATFORM stages (deterministic data
  // analysis over normalized inventory); CLOUD_INVENTORY and
  // CLOUD_CSPM are tool stages. CLOUD_INVENTORY mirrors the Prisma
  // ScanStageType value added by the Prompt 14 migration.
  "CLOUD_AUTH", "CLOUD_INVENTORY", "IAM_ANALYSIS", "NETWORK_ANALYSIS",
  "STORAGE_ANALYSIS", "ENCRYPTION_ANALYSIS", "LOGGING_ANALYSIS",
  "CLOUD_CSPM", "CLOUD_COMPLIANCE",
  // Prompt 15: Active Directory pipeline stages (§86).
  "DOMAIN_DISCOVERY", "DIRECTORY_INVENTORY", "LDAP_POSTURE", "SMB_POSTURE",
  "GRAPH_COLLECTION", "PINGCASTLE_POSTURE", "ADCS_POSTURE", "ATTACK_PATH_ANALYSIS",
  // Prompt 17: mobile pipeline stages (§10/§11).
  "MOBILE_ARTIFACT_INTAKE", "MOBILE_METADATA_EXTRACTION", "MOBILE_MANIFEST_ANALYSIS",
  "MOBILE_STATIC_ANALYSIS", "MOBILE_BINARY_ANALYSIS", "MOBILE_DYNAMIC_SESSION",
  "MOBILE_TRAFFIC_ANALYSIS",
  "BINARY_ARTIFACT_INTAKE", "BINARY_METADATA_EXTRACTION", "BINARY_HARDENING_ANALYSIS",
  "BINARY_STATIC_ANALYSIS", "BINARY_DEBUG_SESSION",
  // Prompt 19: wireless pipeline stages (§15).
  "WIRELESS_CAPTURE_INTAKE", "WIRELESS_PASSIVE_DISCOVERY", "WIRELESS_PCAP_ANALYSIS",
  "WIRELESS_POSTURE_ANALYSIS",
  "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "REPORT_GENERATION",
] as const;
export type StageType = (typeof STAGE_TYPES)[number];

export interface StageDefinition {
  type: StageType;
  name: string;
  description: string;
  /** Capabilities an adapter must provide to be selected for this stage. */
  requiredCapabilities: Capability[];
  /** Stage types (within the same plan) that must finish before this one. */
  dependencies: StageType[];
  /** Weighted-progress share within its profile (Prompt 4 §39). */
  weight: number;
  timeoutSeconds: number;
  failureStrategy: FailureStrategy;
  /** Network-capable stages pass the authorization + scope gates AGAIN in the
   *  worker immediately before execution (Prompt 4 §11–§12). */
  networkCapable: boolean;
  /** Optional cap on how many adapters may be selected for this stage
   *  (Prompt 6 §48: WEB_BASELINE content discovery uses a SMALL wordlist
   *  and a single adapter). Applied at selection time. */
  adapterLimit?: number;
  /** Any-of capability groups (Prompt 7 §14): an adapter is a candidate
   *  when it fully covers ANY one group. Used by SAFE_VULNERABILITY_SCAN,
   *  which unions vulnerability scanners (VULNERABILITY_SCANNING) with
   *  TLS assessors (TLS_ANALYSIS) in one stage. */
  capabilityGroups?: Capability[][];
  /** Per-profile adapter allowlist (Prompt 7 §50): when set, only these
   *  slugs may be selected for the stage (WEB_BASELINE runs Nuclei + TLS
   *  but not Nikto; WEB_COMPREHENSIVE runs all four). */
  adapterAllowlist?: string[];
  /** Whether an empty adapter selection may fall back to the labelled
   *  simulation adapter (default true). Prompt 8 §37/§66: the passive
   *  proxy-analysis stage must NEVER be simulated — when no scanner
   *  connector is configured the stage completes honestly with an empty
   *  selection and a passive_analysis.skipped event, instead of faking
   *  proxy findings. */
  simulationFallback?: boolean;
}

const S = (
  type: StageType, name: string, description: string, requiredCapabilities: Capability[],
  dependencies: StageType[], weight: number, timeoutSeconds: number,
  failureStrategy: FailureStrategy, networkCapable = false,
): StageDefinition => ({ type, name, description, requiredCapabilities, dependencies, weight, timeoutSeconds, failureStrategy, networkCapable });

export const STAGE_LIBRARY: Record<StageType, StageDefinition> = {
  AUTHORIZATION_CHECK: S("AUTHORIZATION_CHECK", "Authorization Check", "Re-verify target ownership, assessment approval and tenant ownership before any work.", [], [], 5, 60, "FAIL_SCAN"),
  SCOPE_VALIDATION: S("SCOPE_VALIDATION", "Scope Validation", "Validate the persisted scope rules against the target; discovered assets never expand scope.", [], ["AUTHORIZATION_CHECK"], 5, 60, "FAIL_SCAN"),
  PASSIVE_RECON: S("PASSIVE_RECON", "Passive Reconnaissance", "Passive intelligence gathering that does not actively interact with the target.", ["SUBDOMAIN_DISCOVERY"], ["SCOPE_VALIDATION"], 10, 900, "FAIL_STAGE_CONTINUE", true),
  ASSET_DISCOVERY: S("ASSET_DISCOVERY", "Asset Discovery", "Consolidate discovered assets, canonicalize and scope-check each one.", ["SUBDOMAIN_DISCOVERY"], ["PASSIVE_RECON"], 10, 600, "FAIL_STAGE_CONTINUE", true),
  DNS_RESOLUTION: S("DNS_RESOLUTION", "DNS Resolution", "Resolve in-scope hosts; re-validate resolved addresses against the SSRF blocker.", ["DNS_RESOLUTION"], ["ASSET_DISCOVERY"], 5, 300, "FAIL_STAGE_CONTINUE", true),
  HTTP_DISCOVERY: S("HTTP_DISCOVERY", "HTTP Discovery", "Probe in-scope hosts for live HTTP services.", ["HTTP_PROBING"], ["DNS_RESOLUTION"], 10, 600, "FAIL_STAGE_CONTINUE", true),
  TECHNOLOGY_DETECTION: S("TECHNOLOGY_DETECTION", "Technology Detection", "Fingerprint technologies on live HTTP services.", ["TECHNOLOGY_DETECTION"], ["HTTP_DISCOVERY"], 5, 600, "CONTINUE_WITH_PARTIAL_DATA", true),
  PORT_DISCOVERY: S("PORT_DISCOVERY", "Port Discovery", "Discover open ports on in-scope hosts (authorized profiles only).", ["PORT_DISCOVERY"], ["ASSET_DISCOVERY"], 10, 1200, "FAIL_STAGE_CONTINUE", true),
  CRAWLING: S("CRAWLING", "Web Crawling", "Crawl in-scope web surface for endpoints and parameters.", ["WEB_CRAWLING"], ["HTTP_DISCOVERY"], 10, 1200, "CONTINUE_WITH_PARTIAL_DATA", true),
  CONTENT_DISCOVERY: S("CONTENT_DISCOVERY", "Content Discovery", "Discover unlinked directories, files and routes with governed wordlists (Prompt 6): registered lists only, conservative rates, soft-404 calibration, budgets enforced.", ["CONTENT_DISCOVERY"], ["CRAWLING"], 10, 1200, "CONTINUE_WITH_PARTIAL_DATA", true),
  ENDPOINT_DISCOVERY: S("ENDPOINT_DISCOVERY", "Endpoint Discovery", "Consolidate endpoints from crawling and technology detection.", ["URL_DISCOVERY"], ["TECHNOLOGY_DETECTION", "CRAWLING"], 5, 600, "CONTINUE_WITH_PARTIAL_DATA", true),
  PARAMETER_DISCOVERY: S("PARAMETER_DISCOVERY", "Parameter Discovery", "Discover parameters on in-scope endpoints.", ["PARAMETER_DISCOVERY"], ["ENDPOINT_DISCOVERY"], 5, 900, "CONTINUE_WITH_PARTIAL_DATA", true),
  WEB_SURFACE_NORMALIZATION: S("WEB_SURFACE_NORMALIZATION", "Web Surface Normalization", "Merge crawl + content + parameter discovery into ONE canonical endpoint inventory with provenance and scope verdicts (Prompt 6 §39). Platform stage — no tool executes.", [], ["PARAMETER_DISCOVERY"], 3, 300, "FAIL_STAGE_CONTINUE"),
  SAFE_VULNERABILITY_SCAN: {
    ...S("SAFE_VULNERABILITY_SCAN", "Safe Vulnerability Scan", "Safe vulnerability detection (Nuclei governed SAFE templates + Nikto) and TLS assessment (testssl.sh + SSLyze) over the normalized web surface (Prompt 7 §14). Intrusive templates are excluded by the template policy.", ["VULNERABILITY_SCANNING"], ["WEB_SURFACE_NORMALIZATION"], 15, 1800, "CONTINUE_WITH_PARTIAL_DATA", true),
    capabilityGroups: [["VULNERABILITY_SCANNING"], ["TLS_ANALYSIS"]],
  },
  PASSIVE_SECURITY_ANALYSIS: {
    ...S("PASSIVE_SECURITY_ANALYSIS", "Passive Security Analysis", "Passive proxy analysis through configured scanner connectors (OWASP ZAP / Burp Suite / Caido, Prompt 8 §37): endpoint + site-map import, passive issue import and traffic analysis over an isolated per-assessment context. No traffic is generated beyond the governed safe crawl, and NO simulation fallback exists — with no connector configured the stage is honestly skipped (§66).", ["PASSIVE_ANALYSIS"], ["SAFE_VULNERABILITY_SCAN"], 8, 1800, "CONTINUE_WITH_PARTIAL_DATA", true),
    capabilityGroups: [["PASSIVE_ANALYSIS"], ["TRAFFIC_ANALYSIS"]],
    simulationFallback: false,
  },
  ACTIVE_SECURITY_ANALYSIS: {
    ...S("ACTIVE_SECURITY_ANALYSIS", "Active Security Analysis", "Governed ACTIVE scanning through scanner connectors (Prompt 8 §38). INTRUSIVE: disabled by default, present in NO profile template, and executable only behind target verification + approved scope + approved assessment + explicit active-testing enablement + RBAC + admin policy + a live, unexpired, scope-matching ScanApproval + a non-zero active budget (§8/§12/§40–§44).", ["ACTIVE_WEB_SCANNING"], ["PASSIVE_SECURITY_ANALYSIS"], 0, 1800, "FAIL_STAGE_CONTINUE", true),
    simulationFallback: false,
  },
  // Prompt 9 §39/§43: the API security pipeline. Discovery/import/auth/
  //  JWT/WebSocket stages are PLATFORM stages (engine components over
  //  captured traffic + imported inventory); route discovery, safe schema
  //  testing and GraphQL analysis are tool stages whose adapters remain
  //  policy-bound (no state-changing execution, §16/§17/§30).
  API_DISCOVERY: S("API_DISCOVERY", "API Discovery", "Consolidate the API surface from imported specifications, proxy traffic (ZAP/Burp/Caido/mitmproxy) and discovered endpoints into API service inventory (Prompt 9 §5). Platform stage — no tool executes; discovered assets never expand scope.", ["API_DISCOVERY"], ["SCOPE_VALIDATION"], 8, 300, "FAIL_STAGE_CONTINUE"),
  SPEC_IMPORT: S("SPEC_IMPORT", "Specification Import", "Summarize specifications imported for this target through the guarded import path (OpenAPI/Swagger/Postman/Insomnia/GraphQL — size/format/reference guards, §6/§7). Platform stage: the stage reports what the import store holds; it fetches nothing.", ["SPEC_IMPORT"], ["API_DISCOVERY"], 5, 300, "FAIL_STAGE_CONTINUE"),
  ROUTE_DISCOVERY: S("ROUTE_DISCOVERY", "API Route Discovery", "Discover unlinked API routes with governed route wordlists (Kiterunner, §13/§14): registered lists only, conservative rates, budgets enforced. Discovered routes are inventory, never findings.", ["ROUTE_DISCOVERY"], ["SPEC_IMPORT"], 12, 1200, "CONTINUE_WITH_PARTIAL_DATA", true),
  AUTH_MAPPING: S("AUTH_MAPPING", "Authentication Mapping", "Map declared authentication schemes and registered API auth contexts (secret REFERENCES only) onto the API inventory (Prompt 9 §19–§21). Platform stage — no credentials are used and no session is established.", [], ["ROUTE_DISCOVERY"], 5, 300, "FAIL_STAGE_CONTINUE"),
  SAFE_SCHEMA_TESTING: {
    ...S("SAFE_SCHEMA_TESTING", "Safe Schema Testing", "Schema-based API testing (Schemathesis, §15/§62): imported OpenAPI operations filtered through the API operation policy — safe methods and safe conformance checks only; state-changing, DELETE, upload, financial and auth-abuse operations are excluded before execution and counted (API_OPERATION_BLOCKED).", ["SCHEMA_BASED_API_TESTING"], ["AUTH_MAPPING"], 15, 1800, "CONTINUE_WITH_PARTIAL_DATA", true),
    capabilityGroups: [["SCHEMA_BASED_API_TESTING"], ["API_VALIDATION"]],
  },
  JWT_ANALYSIS: S("JWT_ANALYSIS", "JWT Analysis", "Inspect JWTs from authorized test contexts and captured traffic metadata: fingerprint + redacted claims + algorithm/expiry/sensitive-claim policy checks (Prompt 9 §22–§25). Inspection only — no cracking, no tampering; raw tokens are never stored. Platform stage.", ["JWT_INSPECTION"], ["SAFE_SCHEMA_TESTING"], 5, 300, "FAIL_STAGE_CONTINUE"),
  GRAPHQL_ANALYSIS: S("GRAPHQL_ANALYSIS", "GraphQL Analysis", "GraphQL endpoint confirmation + introspection schema inventory (InQL/GraphQLmap, §26–§29). Mutations are never executed; introspection availability is inventory, not a finding.", ["GRAPHQL_ANALYSIS"], ["JWT_ANALYSIS"], 8, 900, "CONTINUE_WITH_PARTIAL_DATA", true),
  WEBSOCKET_INVENTORY: S("WEBSOCKET_INVENTORY", "WebSocket Inventory", "Consolidate observed WebSocket endpoints (proxy traffic) with authentication-presence metadata (Prompt 9 §31/§32). Inventory only — no message injection or fuzzing exists. Platform stage.", ["WEBSOCKET_DISCOVERY"], ["GRAPHQL_ANALYSIS"], 3, 300, "FAIL_STAGE_CONTINUE"),
  API_FINDING_NORMALIZATION: S("API_FINDING_NORMALIZATION", "API Finding Normalization", "Fold safe-schema-testing findings, JWT inspection results and API-safe scanner checks into the normalized finding model with provenance (Prompt 9 §43). Platform stage — the shared NORMALIZATION/CORRELATION/RISK tail then applies unchanged.", [], ["PASSIVE_SECURITY_ANALYSIS"], 3, 300, "FAIL_STAGE_CONTINUE"),
  // Prompt 10 §25: the network DAG — TARGET EXPANSION (platform) → HOST
  //  DISCOVERY → PORT DISCOVERY → (port merge happens in persistence) →
  //  SERVICE DETECTION → SAFE NETWORK CHECKS → shared tail.
  TARGET_EXPANSION: S("TARGET_EXPANSION", "Target Expansion", "Canonicalize the network target and expand it into bounded, chunked target ranges (Prompt 10 §3–§5/§62): small ranges materialize, large ones stream as chunks — never millions of rows. Platform stage — no tool executes.", [], ["SCOPE_VALIDATION"], 3, 300, "FAIL_SCAN"),
  HOST_DISCOVERY: S("HOST_DISCOVERY", "Host Discovery", "Discover live hosts inside the approved network scope (Nmap; local ARP discovery on internal workers only, §21/§22/§65).", ["HOST_DISCOVERY"], ["TARGET_EXPANSION"], 8, 900, "FAIL_STAGE_CONTINUE", true),
  SERVICE_DETECTION: S("SERVICE_DETECTION", "Service Detection", "Fingerprint services and versions on discovered open ports (Nmap -sV): product, version, CPE when the tool provides it, TLS facts, OS hints with confidence (§29–§35).", ["SERVICE_DETECTION"], ["PORT_DISCOVERY"], 12, 1800, "CONTINUE_WITH_PARTIAL_DATA", true),
  SAFE_NETWORK_CHECKS: S("SAFE_NETWORK_CHECKS", "Safe Network Checks", "Governed SAFE NSE script checks over detected services (Prompt 10 §14/§37): scripts are classified and policy-selected in code; intrusive/exploit/brute/dos scripts are never selected. Findings only from confirmed check output.", ["SAFE_NETWORK_CHECKS"], ["SERVICE_DETECTION"], 10, 1800, "CONTINUE_WITH_PARTIAL_DATA", true),
  // Prompt 12 §19/§96: the source pipeline. Acquisition snapshots the
  //  repository (hostile input, §2/§5); language detection reads metadata
  //  only; secret scanning / SAST / SCA are tool stages over the snapshot
  //  (NO source execution ever, §14); dependency inventory, SBOM and the
  //  quality gate are platform stages. Source stages are NOT network
  //  stages — tools run with NO_NETWORK (§13) against the local snapshot.
  SOURCE_ACQUISITION: S("SOURCE_ACQUISITION", "Source Acquisition", "Acquire the repository into an immutable, content-hashed snapshot (approved git remote with hooks/credentials disabled, validated archive, or registered workspace snapshot) and verify it against the source budget (Prompt 12 §3–§10). Platform stage — acquisition is engine work, never a tool.", [], ["SCOPE_VALIDATION"], 8, 900, "FAIL_SCAN"),
  LANGUAGE_DETECTION: S("LANGUAGE_DETECTION", "Language Detection", "Detect languages, frameworks and build systems from the snapshot's file listing and manifest metadata (Prompt 12 §15–§17). Metadata only — nothing is built or executed. Platform stage.", [], ["SOURCE_ACQUISITION"], 3, 300, "FAIL_STAGE_CONTINUE"),
  SECRET_SCANNING: S("SECRET_SCANNING", "Secret Scanning", "Scan the snapshot (and bounded history) for secrets with Gitleaks/TruffleHog (§34/§37). Values are fingerprinted at parse time and NEVER stored or displayed — metadata only (§39–§41). External verification is disabled (§44).", ["SECRET_SCANNING"], ["LANGUAGE_DETECTION"], 12, 1800, "CONTINUE_WITH_PARTIAL_DATA"),
  SAST: {
    ...S("SAST", "Static Analysis (SAST)", "Governed static analysis over the snapshot (Prompt 12 §20–§33): Semgrep pinned rule packs, CodeQL governed suites (SARIF), Bandit, Brakeman, SpotBugs security findings, SonarQube import (hotspots stay REVIEW_REQUIRED). Build-needing cases degrade as BUILD_REQUIRED — target code is never built (§14/§29).", ["SAST"], ["LANGUAGE_DETECTION"], 20, 3600, "CONTINUE_WITH_PARTIAL_DATA"),
    capabilityGroups: [["SAST"]],
  },
  DEPENDENCY_INVENTORY: S("DEPENDENCY_INVENTORY", "Dependency Inventory", "Identify software components from manifests and lockfiles (lockfiles first, §45/§56) with PURL identities — packages are NEVER installed (§57). Platform stage.", [], ["LANGUAGE_DETECTION"], 8, 600, "FAIL_STAGE_CONTINUE"),
  SCA: {
    ...S("SCA", "Software Composition Analysis", "Match the component inventory against governed vulnerability data (Prompt 12 §49–§58): Dependency-Check + Grype tool reports merge by component+CVE; the Phase 11 local intelligence dataset adds POTENTIAL_EXPOSURE correlations and EPSS/KEV enrichment — an empty dataset honestly yields zero matches.", ["SCA"], ["DEPENDENCY_INVENTORY"], 12, 1800, "CONTINUE_WITH_PARTIAL_DATA"),
    capabilityGroups: [["SCA"]],
  },
  SBOM_GENERATION: S("SBOM_GENERATION", "SBOM Generation", "Generate the snapshot's software bill of materials (CycloneDX + SPDX, §47/§48) from the component inventory and store it as a checksummed artifact. Platform stage for source profiles; shaped into a governed Syft tool stage for container profiles (Prompt 13 §12).", [], ["SCA"], 4, 300, "CONTINUE_WITH_PARTIAL_DATA"),
  // Prompt 13 §90: cloud-native stages. IMAGE_RESOLUTION is a platform
  //  stage (tag → digest resolution + drift snapshot, §5/§78). Tool
  //  stages are static-analysis only — images are NEVER executed (§9),
  //  and the privileged benchmark stages carry no simulation fallback:
  //  without the dedicated privileged worker they are honestly denied.
  IMAGE_RESOLUTION: S("IMAGE_RESOLUTION", "Image Resolution", "Resolve the image tag to the digest this scan analyzes and record an image snapshot; a changed digest is drift — a NEW snapshot, never an overwrite (Prompt 13 §5/§78). Platform stage.", [], ["SCOPE_VALIDATION"], 4, 300, "FAIL_SCAN"),
  IMAGE_VULNERABILITY_SCAN: {
    ...S("IMAGE_VULNERABILITY_SCAN", "Image Vulnerability Scan", "Static image vulnerability scanning (Trivy + Grype, §13/§19): layers and packages analyzed without ever running the image (§9). Findings bind to the resolved digest and merge across tools by CVE + package + digest (§20).", ["IMAGE_VULNERABILITY_SCANNING"], ["IMAGE_RESOLUTION"], 14, 1800, "CONTINUE_WITH_PARTIAL_DATA"),
    capabilityGroups: [["IMAGE_VULNERABILITY_SCANNING"]],
    simulationFallback: false,
  },
  MANIFEST_SCAN: {
    ...S("MANIFEST_SCAN", "Manifest & IaC Scan", "Static analysis of Dockerfiles, Kubernetes manifests and Helm charts (Checkov §46, Kubescape §44, Trivy config §16). YAML is hostile input (§49); nothing is applied, rendered or executed (§47/§50).", ["IAC_SECURITY"], ["SCOPE_VALIDATION"], 10, 1800, "CONTINUE_WITH_PARTIAL_DATA"),
    capabilityGroups: [["IAC_SECURITY"], ["KUBERNETES_MANIFEST_SECURITY"], ["KUBERNETES_POSTURE"], ["MISCONFIGURATION_SCANNING"]],
    simulationFallback: false,
  },
  CLUSTER_INVENTORY: {
    ...S("CLUSTER_INVENTORY", "Cluster Inventory", "Read-only cluster inventory through the Kubernetes connector (§34/§35): namespaces, nodes, workloads, services, ingresses, NetworkPolicies, service accounts and RBAC — metadata only. Secret VALUES are never retrieved (§36/§105).", ["CLUSTER_INVENTORY"], ["SCOPE_VALIDATION"], 8, 900, "FAIL_STAGE_CONTINUE"),
    capabilityGroups: [["CLUSTER_INVENTORY"]],
    adapterAllowlist: ["kubernetes-connector"],
    simulationFallback: false,
  },
  KUBERNETES_POSTURE: {
    ...S("KUBERNETES_POSTURE", "Kubernetes Posture", "Cluster posture assessment (§38/§65–§73): connector posture over inventory, Kubescape controls, kube-bench CIS (privileged worker only, §39) and kube-hunter passive discovery (comprehensive only, §43).", ["KUBERNETES_POSTURE"], ["CLUSTER_INVENTORY"], 14, 1800, "CONTINUE_WITH_PARTIAL_DATA"),
    capabilityGroups: [["KUBERNETES_POSTURE"], ["POSTURE_ASSESSMENT"], ["KUBERNETES_CIS_ASSESSMENT"], ["KUBERNETES_SECURITY_DISCOVERY"]],
    simulationFallback: false,
  },
  DOCKER_POSTURE: {
    ...S("DOCKER_POSTURE", "Docker Host Posture", "CIS Docker Benchmark against an explicitly approved host (Docker Bench, §28–§31). INTERNAL_PRIVILEGED: dedicated privileged worker only; no Docker socket is mounted into any general worker (§30/§106).", ["DOCKER_CIS_ASSESSMENT"], ["SCOPE_VALIDATION"], 10, 1200, "CONTINUE_WITH_PARTIAL_DATA"),
    capabilityGroups: [["DOCKER_CIS_ASSESSMENT"]],
    adapterAllowlist: ["docker-bench-for-security"],
    simulationFallback: false,
  },
  QUALITY_GATE: S("QUALITY_GATE", "Security Quality Gate", "Evaluate the configurable security quality gate over the scan summary (Prompt 12 §81/§82): PASSED / WARNING / FAILED is recorded as a scan RESULT — a failed gate never crashes the pipeline. Platform stage.", [], ["RISK_ANALYSIS"], 2, 300, "CONTINUE_WITH_PARTIAL_DATA"),
  // Prompt 14 §86: the cloud chain. CLOUD_AUTH validates the registered
  //  account + credential lease (platform; fails the scan honestly when
  //  the account is NOT_CONFIGURED). CLOUD_INVENTORY runs the provider
  //  connector (+ ROADtools identity inventory for Entra accounts).
  //  Analysis stages are platform data analysis (§36–§57) — findings
  //  come from returned configuration data only. CLOUD_CSPM runs the
  //  governed CSPM tools (Prowler/ScoutSuite/Steampipe/CloudMapper);
  //  Pacu is selectable by NO stage (§34 — DISABLED). CLOUD_COMPLIANCE
  //  maps evidence onto CIS/provider frameworks via the shared
  //  compliance machinery (§68).
  CLOUD_AUTH: S("CLOUD_AUTH", "Cloud Account Authorization", "Validate the registered cloud account, its read-only posture and the job-scoped credential lease before any provider interaction (Prompt 14 §9–§11). Platform stage: an unregistered or unvalidated account fails honestly as NOT_CONFIGURED.", [], ["SCOPE_VALIDATION"], 3, 120, "FAIL_SCAN"),
  CLOUD_INVENTORY: {
    ...S("CLOUD_INVENTORY", "Cloud Inventory", "Read-only provider inventory: resources, identities, relationships and an inventory snapshot (Prompt 14 §13–§19). Metadata only — no object contents, secret values or key material. The executor selects the connector matching the account's provider.", ["CLOUD_INVENTORY"], ["CLOUD_AUTH"], 12, 1800, "FAIL_STAGE_CONTINUE", true),
    capabilityGroups: [["CLOUD_INVENTORY"], ["IDENTITY_INVENTORY"]],
    simulationFallback: false,
  },
  IAM_ANALYSIS: S("IAM_ANALYSIS", "IAM Analysis", "Analyze normalized identities and policy FACTS: admin equivalence, wildcards, broad trust, MFA, long-lived and stale credentials (Prompt 14 §36–§42). Policy documents were parsed under hard caps as untrusted input. Platform stage.", [], ["CLOUD_INVENTORY"], 8, 600, "FAIL_STAGE_CONTINUE"),
  NETWORK_ANALYSIS: S("NETWORK_ANALYSIS", "Cloud Network Analysis", "Analyze firewall/security-group rules and public exposure from configuration evidence (Prompt 14 §46–§48): world-open sensitive ports are findings; standard web ports are not. Platform stage.", [], ["CLOUD_INVENTORY"], 8, 600, "FAIL_STAGE_CONTINUE"),
  STORAGE_ANALYSIS: S("STORAGE_ANALYSIS", "Storage Analysis", "Analyze storage + database configuration: public access, encryption, logging, versioning, backups, TLS (Prompt 14 §43–§45). Data analysis only — nothing is downloaded or connected to. Platform stage.", [], ["CLOUD_INVENTORY"], 8, 600, "FAIL_STAGE_CONTINUE"),
  ENCRYPTION_ANALYSIS: S("ENCRYPTION_ANALYSIS", "Encryption Analysis", "Analyze encryption posture: KMS rotation and key metadata, provider-default vs customer-managed keys (Prompt 14 §54/§55). Key material is never requested. Platform stage.", [], ["CLOUD_INVENTORY"], 5, 600, "FAIL_STAGE_CONTINUE"),
  LOGGING_ANALYSIS: S("LOGGING_ANALYSIS", "Logging Analysis", "Analyze audit logging and security services: trails, multi-region coverage, detection services (Prompt 14 §56/§57). A disabled service is a policy-governed gap, not an automatic vulnerability. Platform stage.", [], ["CLOUD_INVENTORY"], 5, 600, "FAIL_STAGE_CONTINUE"),
  CLOUD_CSPM: {
    ...S("CLOUD_CSPM", "CSPM Assessment", "Governed CSPM tools over the account (Prowler §23, ScoutSuite §26, Steampipe approved packs §32, CloudMapper import §27): FAIL/alarm results become findings on canonical cloud rules and merge with native analysis (§60). No simulation fallback — unconfigured tools degrade honestly.", ["CSPM"], ["CLOUD_INVENTORY"], 12, 1800, "CONTINUE_WITH_PARTIAL_DATA", true),
    capabilityGroups: [["CSPM"], ["CLOUD_QUERY"], ["PUBLIC_EXPOSURE_ANALYSIS"]],
    simulationFallback: false,
  },
  CLOUD_COMPLIANCE: S("CLOUD_COMPLIANCE", "Cloud Compliance Assessment", "Map the scan's control assessments onto CIS AWS/Azure/GCP and the mapped frameworks (NIST 800-53 / PCI DSS / SOC 2 / ISO 27001) through the shared compliance machinery (Prompt 14 §68/§69). PASS means control evidence was observed — never certification. Platform stage.", [], ["RISK_ANALYSIS"], 3, 300, "FAIL_STAGE_CONTINUE"),
  // Prompt 15 §86: the AD chain. DOMAIN_DISCOVERY validates the
  //  registered domain + credential lease and resolves approved DCs
  //  (platform; an unregistered domain fails honestly as
  //  NOT_CONFIGURED). DIRECTORY_INVENTORY collects through the LDAP /
  //  BloodHound connectors + governed ldapsearch/SharpHound adapters.
  //  LDAP_POSTURE, GRAPH_COLLECTION and ATTACK_PATH_ANALYSIS are
  //  platform analysis over persisted inventory. NO stage in this
  //  chain can select an offensive tool (§103/§112): NetExec-offensive,
  //  Impacket, Kerbrute, Responder, PowerView-offensive and Certipy-
  //  offensive have no adapters and no capability below names them.
  DOMAIN_DISCOVERY: S("DOMAIN_DISCOVERY", "Domain Discovery", "Validate the registered AD domain, its read-only credential lease and the explicitly approved DC set before any directory contact (Prompt 15 §9–§12). DNS/SRV discovery is bounded to the authorized domain. Platform stage: an unregistered or unvalidated domain fails honestly as NOT_CONFIGURED.", [], ["SCOPE_VALIDATION"], 3, 120, "FAIL_SCAN"),
  DIRECTORY_INVENTORY: {
    ...S("DIRECTORY_INVENTORY", "Directory Inventory", "Read-only directory collection (Prompt 15 §13–§18): domains, DCs, users, groups, computers, OUs, GPO metadata, trusts, SPN/delegation metadata, password-policy metadata and AD CS metadata through the LDAP/BloodHound connectors and governed ldapsearch/SharpHound adapters. Passwords and credential material are never collected (§19).", ["DIRECTORY_INVENTORY"], ["DOMAIN_DISCOVERY"], 14, 1800, "FAIL_STAGE_CONTINUE", true),
    capabilityGroups: [["DIRECTORY_INVENTORY"], ["DIRECTORY_RELATIONSHIP_COLLECTION"], ["IDENTITY_GRAPH"]],
    simulationFallback: false,
  },
  LDAP_POSTURE: S("LDAP_POSTURE", "LDAP Posture", "LDAP/DC posture analysis over collected service metadata (Prompt 15 §70/§71): LDAP signing, channel binding, SMB dialect/signing on DCs. Platform stage — deterministic analysis, no additional directory contact.", [], ["DIRECTORY_INVENTORY"], 6, 600, "FAIL_STAGE_CONTINUE"),
  SMB_POSTURE: {
    ...S("SMB_POSTURE", "SMB Posture", "SMB share + protocol inventory over in-scope hosts (Prompt 15 §41–§45): enum4linux-ng service/share enumeration and SMBMap share/permission inventory. Contents are never downloaded (§44); findings come only from collected evidence (§43).", ["SMB_SHARE_INVENTORY"], ["DIRECTORY_INVENTORY"], 8, 1200, "CONTINUE_WITH_PARTIAL_DATA", true),
    capabilityGroups: [["SMB_SHARE_INVENTORY", "SMB_PERMISSION_REVIEW"], ["SMB_DIRECTORY_ENUMERATION", "WINDOWS_SERVICE_DISCOVERY"]],
    adapterAllowlist: ["enum4linux-ng", "smbmap"],
    simulationFallback: false,
  },
  GRAPH_COLLECTION: S("GRAPH_COLLECTION", "Identity Graph Collection", "Build the identity graph from the collected, evidence-backed relationships and resolve nested group membership with cycle/depth protection (Prompt 15 §32/§33/§65/§108). Platform stage over persisted inventory.", [], ["DIRECTORY_INVENTORY"], 6, 900, "FAIL_STAGE_CONTINUE"),
  PINGCASTLE_POSTURE: {
    ...S("PINGCASTLE_POSTURE", "PingCastle Posture", "PingCastle healthcheck posture (Prompt 15 §38/§39): rule results normalize onto canonical AD rules and merge with native analysis; the PingCastle score is preserved separately from the ZeroSweep risk score.", ["AD_SECURITY_POSTURE"], ["DIRECTORY_INVENTORY"], 8, 1200, "CONTINUE_WITH_PARTIAL_DATA", true),
    capabilityGroups: [["AD_SECURITY_POSTURE", "DOMAIN_CONFIGURATION_REVIEW", "AD_RISK_ASSESSMENT"]],
    adapterAllowlist: ["pingcastle"],
    simulationFallback: false,
  },
  ADCS_POSTURE: {
    ...S("ADCS_POSTURE", "AD CS Posture", "AD CS inventory + posture through the Certipy FIND-only adapter (Prompt 15 §47–§50): CA/template configuration classified into governed ESC-style risk classes. Never requests certificates, never authenticates as another identity.", ["ADCS_INVENTORY"], ["DIRECTORY_INVENTORY"], 8, 1200, "CONTINUE_WITH_PARTIAL_DATA", true),
    capabilityGroups: [["ADCS_INVENTORY", "ADCS_POSTURE_ANALYSIS"]],
    adapterAllowlist: ["certipy-posture"],
    simulationFallback: false,
  },
  ATTACK_PATH_ANALYSIS: S("ATTACK_PATH_ANALYSIS", "Attack-Path Analysis", "Defensive attack-path MODELING over the identity graph (Prompt 15 §34–§37): bounded graph computation with confidence and explained risk. Paths are analysis results — never executed, never labelled COMPROMISED. Platform stage.", [], ["GRAPH_COLLECTION"], 6, 900, "FAIL_STAGE_CONTINUE"),
  // Prompt 17 §10/§11: mobile stage library. Intake validates the
  // registered build (hash identity, §5); metadata + manifest stages
  // are platform analysis over the build's extracted artifacts; the
  // static/binary stages are tool stages on MOBILE_STATIC_ANALYSIS
  // workers; dynamic + traffic stages exist only in the CONTROLLED
  // profiles and run on MOBILE_DYNAMIC_ANALYSIS workers with an
  // approved lab session (§58/§73). No stage anywhere selects Frida
  // or Objection — they have no adapters (§69–§74).
  MOBILE_ARTIFACT_INTAKE: S("MOBILE_ARTIFACT_INTAKE", "Mobile Artifact Intake", "Validate the registered build for this scan: artifact hash identity, format, archive-security verdict recorded at upload (Prompt 17 §5/§6). Platform stage: a scan without a registered build fails honestly as NOT_CONFIGURED.", [], ["SCOPE_VALIDATION"], 3, 120, "FAIL_SCAN"),
  MOBILE_METADATA_EXTRACTION: S("MOBILE_METADATA_EXTRACTION", "Mobile Metadata Extraction", "Platform extraction over the build's registered artifacts (§6/§20): manifest/plist facts, permissions, components, deep links, endpoints, native-library inventory, signing metadata, dependency + SDK inventory, secret scan and SCA over extracted artifacts. Nothing is executed.", [], ["MOBILE_ARTIFACT_INTAKE"], 8, 900, "FAIL_STAGE_CONTINUE"),
  MOBILE_MANIFEST_ANALYSIS: S("MOBILE_MANIFEST_ANALYSIS", "Manifest / Plist Analysis", "AndroidManifest + network-security-config / Info.plist + ATS posture analysis (Prompt 17 §20–§41) over persisted build inventory: exported components, cleartext policy, backup/debuggable posture, MASVS control assessments. Platform stage.", [], ["MOBILE_METADATA_EXTRACTION"], 6, 600, "FAIL_STAGE_CONTINUE"),
  MOBILE_STATIC_ANALYSIS: {
    ...S("MOBILE_STATIC_ANALYSIS", "Mobile Static Analysis", "Governed static analysis (Prompt 17 §13–§19): the MobSF connector (admin-registered instance only), JADX decompilation output and apktool resource/manifest analysis in the static sandbox. App code is never executed (§8).", ["MOBILE_STATIC_ANALYSIS"], ["MOBILE_MANIFEST_ANALYSIS"], 16, 1800, "CONTINUE_WITH_PARTIAL_DATA"),
    capabilityGroups: [["MOBILE_STATIC_ANALYSIS"], ["ANDROID_DECOMPILATION", "STATIC_CODE_EXTRACTION"], ["APK_RESOURCE_ANALYSIS", "MANIFEST_EXTRACTION"]],
    adapterAllowlist: ["mobsf", "jadx", "apktool"],
    simulationFallback: false,
  },
  MOBILE_BINARY_ANALYSIS: {
    ...S("MOBILE_BINARY_ANALYSIS", "Mobile Binary Analysis", "Ghidra headless static analysis of native libraries (Prompt 17 §34–§36): hardening properties (PIE/NX/canaries/RELRO/symbols) from administrator-approved scripts only. Native binaries are never executed.", ["BINARY_STATIC_ANALYSIS"], ["MOBILE_STATIC_ANALYSIS"], 10, 1800, "CONTINUE_WITH_PARTIAL_DATA"),
    capabilityGroups: [["BINARY_STATIC_ANALYSIS", "NATIVE_LIBRARY_ANALYSIS"]],
    adapterAllowlist: ["ghidra"],
    simulationFallback: false,
  },
  MOBILE_DYNAMIC_SESSION: {
    ...S("MOBILE_DYNAMIC_SESSION", "Mobile Dynamic Session (Lab)", "Controlled device-lab session (Prompt 17 §53–§61): install the authorized build (hash verified, §60) on an approved ZeroSweep-managed device and collect governed observations. Runs only on MOBILE_DYNAMIC_ANALYSIS workers with an approved session; personal devices are never targeted (§55). No generic shell exists (§59).", ["DEVICE_MANAGEMENT"], ["MOBILE_STATIC_ANALYSIS"], 10, 1800, "CONTINUE_WITH_PARTIAL_DATA"),
    capabilityGroups: [["DEVICE_MANAGEMENT", "APP_INSTALLATION", "LOG_COLLECTION", "CONTROLLED_APP_INTERACTION"]],
    adapterAllowlist: ["adb"],
    simulationFallback: false,
  },
  MOBILE_TRAFFIC_ANALYSIS: {
    ...S("MOBILE_TRAFFIC_ANALYSIS", "Mobile Traffic Analysis (Lab)", "Lab proxy analysis (Prompt 17 §62–§68): sanitized flow metadata + API endpoint discovery from the governed mitmproxy session. TLS interception exists only in the lab with a temporary CA (§67); bodies never enter platform records (§66).", ["MOBILE_TRAFFIC_CAPTURE"], ["MOBILE_DYNAMIC_SESSION"], 8, 1200, "CONTINUE_WITH_PARTIAL_DATA"),
    capabilityGroups: [["MOBILE_TRAFFIC_CAPTURE", "HTTP_ANALYSIS", "API_DISCOVERY"]],
    adapterAllowlist: ["mitmproxy"],
    simulationFallback: false,
  },
  BINARY_ARTIFACT_INTAKE: S("BINARY_ARTIFACT_INTAKE", "Binary Artifact Intake", "Validate the registered artifact for this scan: SHA-256 identity, magic-byte format, intake verdict recorded at registration (Prompt 18 §3/§5/§6). Platform stage: a scan without a registered artifact fails honestly as NOT_CONFIGURED. The artifact is NEVER executed (§8/§100).", [], ["SCOPE_VALIDATION"], 3, 120, "FAIL_SCAN"),
  BINARY_METADATA_EXTRACTION: S("BINARY_METADATA_EXTRACTION", "Binary Metadata Extraction", "Platform static analysis over the registered artifact (§12–§50): header parsing, section inventory, hardening profile, imports/exports/symbols, bounded string extraction + classification, secret candidates (fingerprint only), crypto inventory, dependency inventory and SCA inputs. Pure parsing — nothing is executed.", [], ["BINARY_ARTIFACT_INTAKE"], 8, 900, "FAIL_STAGE_CONTINUE"),
  BINARY_HARDENING_ANALYSIS: {
    ...S("BINARY_HARDENING_ANALYSIS", "Binary Hardening Analysis", "checksec hardening properties of the registered artifact (Prompt 18 §15) on BINARY_STATIC_ANALYSIS workers. Statuses normalize to ENABLED/DISABLED/PARTIAL/NOT_APPLICABLE/UNKNOWN (§16).", ["BINARY_HARDENING_ANALYSIS"], ["BINARY_METADATA_EXTRACTION"], 4, 600, "FAIL_STAGE_CONTINUE"),
    capabilityGroups: [["BINARY_HARDENING_ANALYSIS"]],
    adapterAllowlist: ["checksec"],
    simulationFallback: false,
  },
  BINARY_STATIC_ANALYSIS: {
    ...S("BINARY_STATIC_ANALYSIS", "Binary Static Analysis", "Deep static analysis of the registered artifact (Prompt 18 §18–§34): Ghidra headless inventory (approved scripts only) and radare2 typed-operation profiles on BINARY_STATIC_ANALYSIS workers. No artifact-supplied script or command is ever run (§20/§34/§93).", ["BINARY_STATIC_ANALYSIS", "STATIC_BINARY_ANALYSIS"], ["BINARY_HARDENING_ANALYSIS"], 14, 1800, "FAIL_STAGE_CONTINUE"),
    capabilityGroups: [["BINARY_STATIC_ANALYSIS"], ["STATIC_BINARY_ANALYSIS"]],
    adapterAllowlist: ["ghidra", "radare2"],
    simulationFallback: false,
  },
  BINARY_DEBUG_SESSION: {
    ...S("BINARY_DEBUG_SESSION", "Binary Debug Session (Lab)", "Governed controlled-debugging stage (Prompt 18 §64–§74): eligible ONLY with a LAB environment, an approved BinaryDebugSession (separate approver), a BINARY_DYNAMIC_LAB worker and no active kill switch. Typed operations only — no unrestricted debugger console exists (§68/§69/§93). Without a provisioned lab transport the stage reports NOT_PROVISIONED honestly.", ["DYNAMIC_DEBUGGING"], ["BINARY_STATIC_ANALYSIS"], 10, 1800, "CONTINUE_WITH_PARTIAL_DATA"),
    capabilityGroups: [["DYNAMIC_DEBUGGING"]],
    adapterAllowlist: [],
    simulationFallback: false,
  },
  WIRELESS_CAPTURE_INTAKE: S("WIRELESS_CAPTURE_INTAKE", "Wireless Environment & Capture Intake", "Validate the registered wireless environment for this scan: explicit scope (§4), approved sensors (§12) and any registered captures proven by magic bytes (§27). Platform stage: a scan without a registered environment fails honestly as NOT_CONFIGURED. Authorization is never inferred from detectability.", [], ["SCOPE_VALIDATION"], 3, 120, "FAIL_SCAN"),
  WIRELESS_PASSIVE_DISCOVERY: {
    ...S("WIRELESS_PASSIVE_DISCOVERY", "Wireless Passive Discovery", "Passive AP/station/channel inventory via Kismet on a registered approved sensor (Prompt 19 §16) — WIRELESS_PASSIVE_ANALYSIS workers only. Kismet listens: nothing is transmitted, no station is associated with, no hidden SSID is actively disclosed (§7). Sensor-dependent: on workers without an approved sensor the stage degrades honestly (PARTIAL/NOT_CONFIGURED).", ["PASSIVE_WIFI_DISCOVERY"], ["WIRELESS_CAPTURE_INTAKE"], 14, 1800, "FAIL_STAGE_CONTINUE"),
    capabilityGroups: [["PASSIVE_WIFI_DISCOVERY", "ACCESS_POINT_INVENTORY"]],
    adapterAllowlist: ["kismet"],
    simulationFallback: false,
  },
  WIRELESS_PCAP_ANALYSIS: {
    ...S("WIRELESS_PCAP_ANALYSIS", "Wireless Capture Analysis", "Offline 802.11 analysis of APPROVED capture artifacts (Prompt 19 §23/§24): tshark fixed-field frame analysis, hcxtools session-summary metadata, aircrack-ng capture inspection (metadata only, AircrackPolicy §20). No cracking, key-recovery or hash-export mode is expressible (§67/§99).", ["PCAP_ANALYSIS"], ["WIRELESS_CAPTURE_INTAKE"], 12, 1800, "FAIL_STAGE_CONTINUE"),
    capabilityGroups: [["PCAP_ANALYSIS"], ["OFFLINE_CAPTURE_PROCESSING"], ["CAPTURE_METADATA_ANALYSIS"], ["OFFLINE_CAPTURE_INSPECTION"]],
    adapterAllowlist: ["tshark-wireless", "hcxtools", "aircrack-ng"],
    simulationFallback: false,
  },
  WIRELESS_POSTURE_ANALYSIS: S("WIRELESS_POSTURE_ANALYSIS", "Wireless Posture Analysis", "Deterministic platform analysis over persisted wireless inventory (Prompt 19 §32–§60): encryption/authentication posture, PMF/WPS assessment, defensive rogue-AP classification, drift detection, passive security events and the wireless quality gate. Unknown APs are UNKNOWN — never labelled malicious without evidence (§44).", [], ["WIRELESS_PASSIVE_DISCOVERY", "WIRELESS_PCAP_ANALYSIS"], 6, 600, "FAIL_STAGE_CONTINUE"),
  NORMALIZATION: S("NORMALIZATION", "Normalization", "Translate every tool result into the normalized security result model.", [], ["SAFE_VULNERABILITY_SCAN"], 5, 300, "FAIL_SCAN"),
  CORRELATION: S("CORRELATION", "Correlation", "Deterministically group duplicate findings by fingerprint/asset/endpoint/CVE/CWE.", [], ["NORMALIZATION"], 5, 300, "FAIL_STAGE_CONTINUE"),
  RISK_ANALYSIS: S("RISK_ANALYSIS", "Risk Analysis", "Deterministic risk scoring from normalized findings (no fabricated intel).", [], ["CORRELATION"], 3, 300, "FAIL_STAGE_CONTINUE"),
  REPORT_GENERATION: S("REPORT_GENERATION", "Report Preparation", "Mark the scan ready for reporting (REPORT_PENDING). The PDF engine is a later phase.", ["REPORT_EXPORT"], ["RISK_ANALYSIS"], 2, 300, "FAIL_STAGE_CONTINUE"),
};

/** Stages that run for every profile, in plan order. */
const TAIL: StageType[] = ["NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "REPORT_GENERATION"];
const HEAD: StageType[] = ["AUTHORIZATION_CHECK", "SCOPE_VALIDATION"];

function template(types: StageType[]): StageDefinition[] {
  return types.map((t) => STAGE_LIBRARY[t]);
}

/**
 * Profile → stage template. Since Prompt 5, PASSIVE_RECON and WEB_BASELINE
 * execute REAL recon adapters (subdomain discovery → DNS → HTTP probing →
 * technology detection → historical URL discovery → conservative crawl)
 * whenever the tool binaries are present, and degrade to the labelled
 * simulation adapter when they are not. PASSIVE_RECON stays passive: its
 * endpoint stage is fed by archive/history sources (gau/waybackurls), not by
 * active probing or crawling (Prompt 5 §40). The remaining profiles are
 * validated templates whose specialist stages land in later phases.
 * NORMALIZATION depends on the last discovery stage of each profile — handled
 * by rewriting its dependency when a profile omits SAFE_VULNERABILITY_SCAN.
 */
export const PROFILE_TEMPLATES: Record<AssessmentProfile, StageDefinition[]> = {
  PASSIVE_RECON: template([...HEAD, "PASSIVE_RECON", "ASSET_DISCOVERY", "DNS_RESOLUTION", "ENDPOINT_DISCOVERY", ...TAIL]),
  WEB_BASELINE: template([...HEAD, "PASSIVE_RECON", "ASSET_DISCOVERY", "DNS_RESOLUTION", "HTTP_DISCOVERY", "TECHNOLOGY_DETECTION", "CRAWLING", "CONTENT_DISCOVERY", "ENDPOINT_DISCOVERY", "SAFE_VULNERABILITY_SCAN", "PASSIVE_SECURITY_ANALYSIS", ...TAIL]),
  WEB_COMPREHENSIVE: template([...HEAD, "PASSIVE_RECON", "ASSET_DISCOVERY", "DNS_RESOLUTION", "HTTP_DISCOVERY", "TECHNOLOGY_DETECTION", "PORT_DISCOVERY", "CRAWLING", "CONTENT_DISCOVERY", "ENDPOINT_DISCOVERY", "PARAMETER_DISCOVERY", "WEB_SURFACE_NORMALIZATION", "SAFE_VULNERABILITY_SCAN", "PASSIVE_SECURITY_ANALYSIS", ...TAIL]),
  // Prompt 9 §39 API_BASELINE: the dedicated API pipeline (validation →
  //  discovery → spec import → routes → auth mapping → safe schema
  //  testing → JWT → GraphQL → WebSocket inventory → API-safe scan →
  //  passive analysis → API normalization → shared tail). API_COMPREHENSIVE
  //  (§40) stays architecture-only in this phase: its state-changing
  //  capabilities require per-assessment admin approval machinery.
  API_ASSESSMENT: template([...HEAD, "API_DISCOVERY", "SPEC_IMPORT", "ROUTE_DISCOVERY", "AUTH_MAPPING", "SAFE_SCHEMA_TESTING", "JWT_ANALYSIS", "GRAPHQL_ANALYSIS", "WEBSOCKET_INVENTORY", "SAFE_VULNERABILITY_SCAN", "PASSIVE_SECURITY_ANALYSIS", "API_FINDING_NORMALIZATION", ...TAIL]),
  // Prompt 10 §8/§25: network profiles share one DAG; they differ in
  //  depth (port profile + NSE approvals are worker-derived from the
  //  profile) and in policy (NETWORK_INTERNAL runs on internal workers
  //  under an approved internal engagement, §64/§65). NETWORK_ASSESSMENT
  //  is kept as the baseline-equivalent profile name from Prompt 4.
  NETWORK_DISCOVERY: template([...HEAD, "TARGET_EXPANSION", "HOST_DISCOVERY", "PORT_DISCOVERY", "SERVICE_DETECTION", ...TAIL]),
  // Prompt 11 §84: network baseline/comprehensive scans may OPTIONALLY
  // use a configured Greenbone/Nessus connector for vulnerability
  // assessment. The stage is shaped in resolveTemplate below: connector
  // slugs only, no simulation fallback — unconfigured means SKIPPED (§86).
  NETWORK_BASELINE: template([...HEAD, "TARGET_EXPANSION", "HOST_DISCOVERY", "PORT_DISCOVERY", "SERVICE_DETECTION", "SAFE_NETWORK_CHECKS", "SAFE_VULNERABILITY_SCAN", ...TAIL]),
  NETWORK_COMPREHENSIVE: template([...HEAD, "TARGET_EXPANSION", "HOST_DISCOVERY", "PORT_DISCOVERY", "SERVICE_DETECTION", "SAFE_NETWORK_CHECKS", "SAFE_VULNERABILITY_SCAN", ...TAIL]),
  NETWORK_INTERNAL: template([...HEAD, "TARGET_EXPANSION", "HOST_DISCOVERY", "PORT_DISCOVERY", "SERVICE_DETECTION", "SAFE_NETWORK_CHECKS", ...TAIL]),
  NETWORK_ASSESSMENT: template([...HEAD, "TARGET_EXPANSION", "HOST_DISCOVERY", "PORT_DISCOVERY", "SERVICE_DETECTION", "SAFE_NETWORK_CHECKS", ...TAIL]),
  // Prompt 12 §18/§19/§96: source profiles share the acquisition →
  //  detection → analysis → inventory → SCA → SBOM → normalize →
  //  correlate → risk → quality gate → report chain. The legacy
  //  SOURCE_CODE profile resolves to the baseline chain.
  SOURCE_BASELINE: template([...HEAD, "SOURCE_ACQUISITION", "LANGUAGE_DETECTION", "SECRET_SCANNING", "SAST", "DEPENDENCY_INVENTORY", "SCA", "SBOM_GENERATION", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  SOURCE_COMPREHENSIVE: template([...HEAD, "SOURCE_ACQUISITION", "LANGUAGE_DETECTION", "SECRET_SCANNING", "SAST", "DEPENDENCY_INVENTORY", "SCA", "SBOM_GENERATION", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  SECRETS_ONLY: template([...HEAD, "SOURCE_ACQUISITION", "LANGUAGE_DETECTION", "SECRET_SCANNING", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  DEPENDENCIES_ONLY: template([...HEAD, "SOURCE_ACQUISITION", "LANGUAGE_DETECTION", "DEPENDENCY_INVENTORY", "SCA", "SBOM_GENERATION", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  SAST_ONLY: template([...HEAD, "SOURCE_ACQUISITION", "LANGUAGE_DETECTION", "SAST", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  SOURCE_CODE: template([...HEAD, "SOURCE_ACQUISITION", "LANGUAGE_DETECTION", "SECRET_SCANNING", "SAST", "DEPENDENCY_INVENTORY", "SCA", "SBOM_GENERATION", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  // Prompt 13 §11/§80/§90: cloud-native profiles share the
  //  resolution/inventory → analysis → normalize → correlate → risk →
  //  quality gate → report chain. The legacy CONTAINER profile resolves
  //  to the CONTAINER_BASELINE chain.
  CONTAINER_BASELINE: template([...HEAD, "IMAGE_RESOLUTION", "SBOM_GENERATION", "IMAGE_VULNERABILITY_SCAN", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  CONTAINER_COMPREHENSIVE: template([...HEAD, "IMAGE_RESOLUTION", "SBOM_GENERATION", "IMAGE_VULNERABILITY_SCAN", "MANIFEST_SCAN", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  SBOM_ONLY: template([...HEAD, "IMAGE_RESOLUTION", "SBOM_GENERATION", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "REPORT_GENERATION"]),
  IMAGE_VULNERABILITIES_ONLY: template([...HEAD, "IMAGE_RESOLUTION", "IMAGE_VULNERABILITY_SCAN", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  CONTAINER_MISCONFIG_ONLY: template([...HEAD, "IMAGE_RESOLUTION", "MANIFEST_SCAN", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  KUBERNETES_BASELINE: template([...HEAD, "CLUSTER_INVENTORY", "KUBERNETES_POSTURE", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  KUBERNETES_COMPREHENSIVE: template([...HEAD, "CLUSTER_INVENTORY", "KUBERNETES_POSTURE", "MANIFEST_SCAN", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  DOCKER_HOST_BASELINE: template([...HEAD, "DOCKER_POSTURE", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "REPORT_GENERATION"]),
  CLOUD_NATIVE_FULL: template([...HEAD, "IMAGE_RESOLUTION", "SBOM_GENERATION", "IMAGE_VULNERABILITY_SCAN", "MANIFEST_SCAN", "CLUSTER_INVENTORY", "KUBERNETES_POSTURE", "DOCKER_POSTURE", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  CONTAINER: template([...HEAD, "IMAGE_RESOLUTION", "SBOM_GENERATION", "IMAGE_VULNERABILITY_SCAN", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  // Prompt 14 §12/§86: cloud profiles share the auth → inventory →
  //  analysis → CSPM → normalize → correlate → risk → compliance →
  //  quality gate → report chain. The legacy CLOUD profile resolves
  //  to the CLOUD_BASELINE chain.
  CLOUD_INVENTORY: template([...HEAD, "CLOUD_AUTH", "CLOUD_INVENTORY", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "CLOUD_COMPLIANCE", "QUALITY_GATE", "REPORT_GENERATION"]),
  CLOUD_BASELINE: template([...HEAD, "CLOUD_AUTH", "CLOUD_INVENTORY", "IAM_ANALYSIS", "NETWORK_ANALYSIS", "STORAGE_ANALYSIS", "ENCRYPTION_ANALYSIS", "LOGGING_ANALYSIS", "CLOUD_CSPM", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "CLOUD_COMPLIANCE", "QUALITY_GATE", "REPORT_GENERATION"]),
  CLOUD_COMPREHENSIVE: template([...HEAD, "CLOUD_AUTH", "CLOUD_INVENTORY", "IAM_ANALYSIS", "NETWORK_ANALYSIS", "STORAGE_ANALYSIS", "ENCRYPTION_ANALYSIS", "LOGGING_ANALYSIS", "CLOUD_CSPM", "MANIFEST_SCAN", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "CLOUD_COMPLIANCE", "QUALITY_GATE", "REPORT_GENERATION"]),
  IAM_REVIEW: template([...HEAD, "CLOUD_AUTH", "CLOUD_INVENTORY", "IAM_ANALYSIS", "CLOUD_CSPM", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "CLOUD_COMPLIANCE", "QUALITY_GATE", "REPORT_GENERATION"]),
  PUBLIC_EXPOSURE_REVIEW: template([...HEAD, "CLOUD_AUTH", "CLOUD_INVENTORY", "NETWORK_ANALYSIS", "CLOUD_CSPM", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "CLOUD_COMPLIANCE", "QUALITY_GATE", "REPORT_GENERATION"]),
  COMPLIANCE_ASSESSMENT: template([...HEAD, "CLOUD_AUTH", "CLOUD_INVENTORY", "IAM_ANALYSIS", "NETWORK_ANALYSIS", "STORAGE_ANALYSIS", "ENCRYPTION_ANALYSIS", "LOGGING_ANALYSIS", "CLOUD_CSPM", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "CLOUD_COMPLIANCE", "QUALITY_GATE", "REPORT_GENERATION"]),
  IAC_TO_CLOUD_CORRELATION: template([...HEAD, "CLOUD_AUTH", "CLOUD_INVENTORY", "MANIFEST_SCAN", "IAM_ANALYSIS", "NETWORK_ANALYSIS", "STORAGE_ANALYSIS", "ENCRYPTION_ANALYSIS", "LOGGING_ANALYSIS", "CLOUD_CSPM", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "CLOUD_COMPLIANCE", "QUALITY_GATE", "REPORT_GENERATION"]),
  // Prompt 15 §85/§86: AD profiles follow the governed chain
  //  DOMAIN_DISCOVERY → DIRECTORY_INVENTORY → LDAP/SMB posture →
  //  GRAPH_COLLECTION → PINGCASTLE → ADCS → NORMALIZATION →
  //  CORRELATION → ATTACK_PATH_ANALYSIS → RISK_ANALYSIS → REPORTING.
  AD_INVENTORY: template([...HEAD, "DOMAIN_DISCOVERY", "DIRECTORY_INVENTORY", ...TAIL]),
  AD_BASELINE: template([...HEAD, "DOMAIN_DISCOVERY", "DIRECTORY_INVENTORY", "LDAP_POSTURE", "GRAPH_COLLECTION", "PINGCASTLE_POSTURE", "ADCS_POSTURE", "NORMALIZATION", "CORRELATION", "ATTACK_PATH_ANALYSIS", "RISK_ANALYSIS", "REPORT_GENERATION"]),
  AD_COMPREHENSIVE: template([...HEAD, "DOMAIN_DISCOVERY", "DIRECTORY_INVENTORY", "LDAP_POSTURE", "SMB_POSTURE", "GRAPH_COLLECTION", "PINGCASTLE_POSTURE", "ADCS_POSTURE", "NORMALIZATION", "CORRELATION", "ATTACK_PATH_ANALYSIS", "RISK_ANALYSIS", "REPORT_GENERATION"]),
  ADCS_POSTURE: template([...HEAD, "DOMAIN_DISCOVERY", "DIRECTORY_INVENTORY", "ADCS_POSTURE", ...TAIL]),
  SMB_POSTURE: template([...HEAD, "DOMAIN_DISCOVERY", "DIRECTORY_INVENTORY", "SMB_POSTURE", ...TAIL]),
  IDENTITY_GRAPH: template([...HEAD, "DOMAIN_DISCOVERY", "DIRECTORY_INVENTORY", "GRAPH_COLLECTION", "NORMALIZATION", "CORRELATION", "ATTACK_PATH_ANALYSIS", "RISK_ANALYSIS", "REPORT_GENERATION"]),
  ATTACK_PATH_ANALYSIS: template([...HEAD, "DOMAIN_DISCOVERY", "DIRECTORY_INVENTORY", "GRAPH_COLLECTION", "NORMALIZATION", "CORRELATION", "ATTACK_PATH_ANALYSIS", "RISK_ANALYSIS", "REPORT_GENERATION"]),
  CLOUD: template([...HEAD, "CLOUD_AUTH", "CLOUD_INVENTORY", "IAM_ANALYSIS", "NETWORK_ANALYSIS", "STORAGE_ANALYSIS", "ENCRYPTION_ANALYSIS", "LOGGING_ANALYSIS", "CLOUD_CSPM", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "CLOUD_COMPLIANCE", "QUALITY_GATE", "REPORT_GENERATION"]),
  // Prompt 17 §12: mobile profiles follow the governed chain
  //  MOBILE_ARTIFACT_INTAKE → MOBILE_METADATA_EXTRACTION →
  //  MOBILE_MANIFEST_ANALYSIS → MOBILE_STATIC_ANALYSIS →
  //  (MOBILE_BINARY_ANALYSIS) → (MOBILE_DYNAMIC_SESSION →
  //  MOBILE_TRAFFIC_ANALYSIS) → NORMALIZATION → CORRELATION →
  //  RISK_ANALYSIS → QUALITY_GATE → REPORT_GENERATION.
  //  Static is the default; dynamic stages exist ONLY in the two
  //  CONTROLLED profiles. The legacy MOBILE profile resolves to the
  //  MOBILE_STATIC_BASELINE chain.
  MOBILE_STATIC_BASELINE: template([...HEAD, "MOBILE_ARTIFACT_INTAKE", "MOBILE_METADATA_EXTRACTION", "MOBILE_MANIFEST_ANALYSIS", "MOBILE_STATIC_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  MOBILE_STATIC_COMPREHENSIVE: template([...HEAD, "MOBILE_ARTIFACT_INTAKE", "MOBILE_METADATA_EXTRACTION", "MOBILE_MANIFEST_ANALYSIS", "MOBILE_STATIC_ANALYSIS", "MOBILE_BINARY_ANALYSIS", "DEPENDENCY_INVENTORY", "SBOM_GENERATION", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  MOBILE_SECRETS_ONLY: template([...HEAD, "MOBILE_ARTIFACT_INTAKE", "MOBILE_METADATA_EXTRACTION", "MOBILE_STATIC_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  MOBILE_BINARY_ANALYSIS: template([...HEAD, "MOBILE_ARTIFACT_INTAKE", "MOBILE_METADATA_EXTRACTION", "MOBILE_MANIFEST_ANALYSIS", "MOBILE_BINARY_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  MOBILE_DYNAMIC_CONTROLLED: template([...HEAD, "MOBILE_ARTIFACT_INTAKE", "MOBILE_METADATA_EXTRACTION", "MOBILE_MANIFEST_ANALYSIS", "MOBILE_STATIC_ANALYSIS", "MOBILE_DYNAMIC_SESSION", "MOBILE_TRAFFIC_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  MOBILE_FULL_CONTROLLED: template([...HEAD, "MOBILE_ARTIFACT_INTAKE", "MOBILE_METADATA_EXTRACTION", "MOBILE_MANIFEST_ANALYSIS", "MOBILE_STATIC_ANALYSIS", "MOBILE_BINARY_ANALYSIS", "MOBILE_DYNAMIC_SESSION", "MOBILE_TRAFFIC_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  MOBILE: template([...HEAD, "MOBILE_ARTIFACT_INTAKE", "MOBILE_METADATA_EXTRACTION", "MOBILE_MANIFEST_ANALYSIS", "MOBILE_STATIC_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  // Prompt 18 §11: binary profiles. Static is the default; the debug
  // profile appends ONLY the governed BINARY_DEBUG_SESSION stage.
  BINARY_METADATA_ONLY: template([...HEAD, "BINARY_ARTIFACT_INTAKE", "BINARY_METADATA_EXTRACTION", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  BINARY_BASELINE: template([...HEAD, "BINARY_ARTIFACT_INTAKE", "BINARY_METADATA_EXTRACTION", "BINARY_HARDENING_ANALYSIS", "BINARY_STATIC_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  BINARY_ASSESSMENT: template([...HEAD, "BINARY_ARTIFACT_INTAKE", "BINARY_METADATA_EXTRACTION", "BINARY_HARDENING_ANALYSIS", "BINARY_STATIC_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  BINARY_COMPREHENSIVE_STATIC: template([...HEAD, "BINARY_ARTIFACT_INTAKE", "BINARY_METADATA_EXTRACTION", "BINARY_HARDENING_ANALYSIS", "BINARY_STATIC_ANALYSIS", "DEPENDENCY_INVENTORY", "SBOM_GENERATION", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  BINARY_DEPENDENCY_ANALYSIS: template([...HEAD, "BINARY_ARTIFACT_INTAKE", "BINARY_METADATA_EXTRACTION", "DEPENDENCY_INVENTORY", "SBOM_GENERATION", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  BINARY_CONTROLLED_DEBUG: template([...HEAD, "BINARY_ARTIFACT_INTAKE", "BINARY_METADATA_EXTRACTION", "BINARY_HARDENING_ANALYSIS", "BINARY_STATIC_ANALYSIS", "BINARY_DEBUG_SESSION", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  // Prompt 19 §15: wireless profiles — PASSIVE only. The LAB profile
  // runs the same passive chain: lab validation is a governed API
  // workflow (§65), and its active tools (Wifite, hcxdumptool) are
  // DISABLED descriptors that no template selects (§64).
  WIRELESS_PASSIVE_BASELINE: template([...HEAD, "WIRELESS_CAPTURE_INTAKE", "WIRELESS_PASSIVE_DISCOVERY", "WIRELESS_POSTURE_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  WIRELESS_PASSIVE_COMPREHENSIVE: template([...HEAD, "WIRELESS_CAPTURE_INTAKE", "WIRELESS_PASSIVE_DISCOVERY", "WIRELESS_PCAP_ANALYSIS", "WIRELESS_POSTURE_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  PCAP_ANALYSIS_ONLY: template([...HEAD, "WIRELESS_CAPTURE_INTAKE", "WIRELESS_PCAP_ANALYSIS", "WIRELESS_POSTURE_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  WIRELESS_COMPLIANCE: template([...HEAD, "WIRELESS_CAPTURE_INTAKE", "WIRELESS_PASSIVE_DISCOVERY", "WIRELESS_PCAP_ANALYSIS", "WIRELESS_POSTURE_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  WIRELESS_LAB_VALIDATION: template([...HEAD, "WIRELESS_CAPTURE_INTAKE", "WIRELESS_PASSIVE_DISCOVERY", "WIRELESS_POSTURE_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "QUALITY_GATE", "REPORT_GENERATION"]),
  CUSTOM: template([...HEAD, "PASSIVE_RECON", "ASSET_DISCOVERY", ...TAIL]),
};

/**
 * Resolve a profile template into plan-ready stage definitions: dependencies
 * pointing at stages the profile does not include are rewired to the nearest
 * included ancestor chain (e.g. NORMALIZATION after PASSIVE_RECON profiles
 * depends on the last included stage), and unknown dependencies are dropped
 * here — DAG validation still rejects anything inconsistent afterwards.
 */
export function resolveTemplate(profile: AssessmentProfile): StageDefinition[] {
  const defs = PROFILE_TEMPLATES[profile].map((d) => ({ ...d, dependencies: [...d.dependencies] }));
  const present = new Set(defs.map((d) => d.type));
  const includedBefore = (type: StageType): StageType[] => {
    const idx = defs.findIndex((d) => d.type === type);
    return defs.slice(0, idx).map((d) => d.type);
  };
  for (const def of defs) {
    const substituted: StageType[] = [];
    def.dependencies = def.dependencies.filter((dep) => {
      if (present.has(dep)) return true;
      // Dependency not in this profile: substitute the nearest preceding
      // included stage so ordering survives (e.g. ENDPOINT_DISCOVERY in
      // PASSIVE_RECON follows DNS_RESOLUTION when the crawl/tech stages it
      // usually follows are not part of the profile).
      const before = includedBefore(def.type);
      const prev = before[before.length - 1];
      if (prev && !substituted.includes(prev)) substituted.push(prev);
      return false;
    });
    for (const s of substituted) if (!def.dependencies.includes(s)) def.dependencies.push(s);
    // Prompt 6 §48: WEB_BASELINE content discovery is deliberately small —
    // ONE adapter (the first by capability match), SMALL wordlists. The cap
    // is part of the template, so the plan itself records the bound.
    if (profile === "WEB_BASELINE" && def.type === "CONTENT_DISCOVERY") def.adapterLimit = 1;
    // Prompt 7 §50: WEB_BASELINE vulnerability detection is conservative —
    // Nuclei SAFE templates + TLS assessment only. Nikto joins in
    // WEB_COMPREHENSIVE (which also carries the larger approved template
    // set via the worker's profile-derived approvals).
    if (profile === "WEB_BASELINE" && def.type === "SAFE_VULNERABILITY_SCAN") {
      def.adapterAllowlist = ["nuclei", "testssl", "sslyze"];
    }
    // Prompt 9 §38: the API profile's vulnerability stage runs Nuclei's
    // API-safe check set only — Nikto (HTML-web oriented) and the TLS
    // assessors are not API tools.
    if (profile === "API_ASSESSMENT" && def.type === "SAFE_VULNERABILITY_SCAN") {
      def.adapterAllowlist = ["nuclei"];
    }
    // Prompt 10 §8/§11/§65: network profile shaping. Discovery stays
    // light (Nmap host discovery only); service detection and safe
    // checks are Nmap-only stages in every network profile.
    const NETWORK_PROFILES = ["NETWORK_DISCOVERY", "NETWORK_BASELINE", "NETWORK_COMPREHENSIVE", "NETWORK_INTERNAL", "NETWORK_ASSESSMENT"];
    if (NETWORK_PROFILES.includes(profile)) {
      if (def.type === "SERVICE_DETECTION" || def.type === "SAFE_NETWORK_CHECKS") {
        def.adapterAllowlist = ["nmap"];
      }
      if (profile === "NETWORK_DISCOVERY" && def.type === "HOST_DISCOVERY") {
        def.adapterAllowlist = ["nmap"];
      }
      // Prompt 11 §84/§86: the network vulnerability stage belongs to the
      // Greenbone/Nessus connectors only. No simulation fallback exists:
      // with neither configured the stage is honestly SKIPPED.
      if ((profile === "NETWORK_BASELINE" || profile === "NETWORK_COMPREHENSIVE") && def.type === "SAFE_VULNERABILITY_SCAN") {
        def.capabilityGroups = [["NETWORK_VULNERABILITY_ASSESSMENT"]];
        def.adapterAllowlist = ["greenbone-openvas", "nessus-professional"];
        def.simulationFallback = false;
      }
      // §64/§65: internal host discovery may use local layer-2 adapters
      // — but ONLY there, and the executor still gates them on the
      // worker's LOCAL_LAYER2_ACCESS capability.
      if (profile === "NETWORK_INTERNAL" && def.type === "HOST_DISCOVERY") {
        def.capabilityGroups = [["HOST_DISCOVERY"], ["LOCAL_NETWORK_DISCOVERY"]];
        def.adapterAllowlist = ["nmap", "netdiscover", "arp-scan"];
      }
    }
    // Prompt 12 §18/§19: source profile shaping. BASELINE keeps SAST to
    // the always-applicable analyzers (Semgrep + per-language linters);
    // COMPREHENSIVE adds CodeQL, SpotBugs and the SonarQube connector.
    // Baseline SCA runs Grype; comprehensive adds Dependency-Check.
    const SOURCE_PROFILES = ["SOURCE_BASELINE", "SOURCE_COMPREHENSIVE", "SECRETS_ONLY", "DEPENDENCIES_ONLY", "SAST_ONLY", "SOURCE_CODE"];
    if (SOURCE_PROFILES.includes(profile)) {
      if ((profile === "SOURCE_BASELINE" || profile === "SOURCE_CODE") && def.type === "SAST") {
        def.adapterAllowlist = ["semgrep", "bandit", "brakeman"];
      }
      if ((profile === "SOURCE_BASELINE" || profile === "SOURCE_CODE") && def.type === "SCA") {
        def.adapterAllowlist = ["grype"];
      }
      if (profile === "SAST_ONLY" && def.type === "SAST") {
        def.adapterAllowlist = ["semgrep", "codeql", "bandit", "brakeman", "spotbugs"];
      }
    }
    // Prompt 13 §11/§80: cloud-native profile shaping. In container
    // profiles SBOM_GENERATION becomes the governed Syft tool stage
    // (source profiles keep it a platform stage — no shaping there).
    // kube-hunter joins posture ONLY in comprehensive profiles, and
    // only ever in passive discovery mode (§43 — the adapter enforces
    // the mode at plan time; the executor derives nothing stronger).
    const CONTAINER_PROFILES = ["CONTAINER_BASELINE", "CONTAINER_COMPREHENSIVE", "SBOM_ONLY", "IMAGE_VULNERABILITIES_ONLY", "CONTAINER_MISCONFIG_ONLY", "CONTAINER", "CLOUD_NATIVE_FULL"];
    if (CONTAINER_PROFILES.includes(profile) && def.type === "SBOM_GENERATION") {
      def.capabilityGroups = [["SBOM_GENERATION"]];
      def.adapterAllowlist = ["syft"];
      def.simulationFallback = false;
    }
    if (def.type === "KUBERNETES_POSTURE" && profile !== "KUBERNETES_COMPREHENSIVE" && profile !== "CLOUD_NATIVE_FULL") {
      def.adapterAllowlist = ["kubernetes-connector", "kubescape", "kube-bench"];
    }
    // Prompt 15 §86: in AD profiles the attack-path analysis runs over
    // the correlated graph (after CORRELATION), and risk analysis
    // consumes its results — the chain order is part of the template.
    const AD_PROFILES = ["AD_INVENTORY", "AD_BASELINE", "AD_COMPREHENSIVE", "ADCS_POSTURE", "SMB_POSTURE", "IDENTITY_GRAPH", "ATTACK_PATH_ANALYSIS"];
    if (AD_PROFILES.includes(profile) && def.type === "ATTACK_PATH_ANALYSIS") {
      def.dependencies = present.has("CORRELATION") ? ["GRAPH_COLLECTION", "CORRELATION"] : ["GRAPH_COLLECTION"];
    }
    if (AD_PROFILES.includes(profile) && def.type === "RISK_ANALYSIS" && present.has("ATTACK_PATH_ANALYSIS")) {
      def.dependencies = ["CORRELATION", "ATTACK_PATH_ANALYSIS"];
    }
    // Tail stages keep strict ordering among themselves.
    if (def.type === "CORRELATION") def.dependencies = ["NORMALIZATION"];
    if (def.type === "RISK_ANALYSIS" && !(AD_PROFILES.includes(profile) && present.has("ATTACK_PATH_ANALYSIS"))) def.dependencies = ["CORRELATION"];
    // Prompt 12 §96: when a quality gate stage exists it sits between
    // risk analysis and report generation.
    if (def.type === "QUALITY_GATE") def.dependencies = ["RISK_ANALYSIS"];
    if (def.type === "REPORT_GENERATION") def.dependencies = present.has("QUALITY_GATE") ? ["QUALITY_GATE"] : ["RISK_ANALYSIS"];
    if (def.type === "NORMALIZATION") {
      const before = includedBefore("NORMALIZATION").filter((t) => t !== "AUTHORIZATION_CHECK" && t !== "SCOPE_VALIDATION");
      def.dependencies = before.length > 0 ? [before[before.length - 1]!] : ["SCOPE_VALIDATION"];
    }
  }
  return defs;
}
