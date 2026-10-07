import type { AssessmentProfile } from "@dsrclone/types";
import type { Capability } from "@dsrclone/security-sdk";
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
  CLOUD: template([...HEAD, "CLOUD_AUTH", "CLOUD_INVENTORY", "IAM_ANALYSIS", "NETWORK_ANALYSIS", "STORAGE_ANALYSIS", "ENCRYPTION_ANALYSIS", "LOGGING_ANALYSIS", "CLOUD_CSPM", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "CLOUD_COMPLIANCE", "QUALITY_GATE", "REPORT_GENERATION"]),
  MOBILE: template([...HEAD, "SAFE_VULNERABILITY_SCAN", ...TAIL]),
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
    // Tail stages keep strict ordering among themselves.
    if (def.type === "CORRELATION") def.dependencies = ["NORMALIZATION"];
    if (def.type === "RISK_ANALYSIS") def.dependencies = ["CORRELATION"];
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
