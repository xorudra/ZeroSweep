import {
  CidrPolicyService, DEFAULT_QUALITY_GATE_POLICY, FIXTURE_MANIFEST_CONTENTS, FIXTURE_SOURCE_FILES,
  JwtToolAdapter, MockSecurityAdapter, ToolRegistry, analyzeDatabases, analyzeDirectoryPosture, analyzeEncryption, analyzeIam, analyzeLdapPosture, analyzeLogging, analyzeMobilePosture, extractMobileArtifacts, analyzeNetwork, analyzeStorage, auditLoggingEnabled, buildCloudRiskPaths, buildCycloneDxSbom, buildIdentityGraph, classifyBaseline,
  detectRepository, diffCloudInventories, diffDirectorySnapshots, emptyMobileData, evaluateCloudSecurityGate, evaluateContainerQualityGate, evaluateMobileSecurityGate, evaluateQualityGate, expandCidrTargets, findAttackPaths, mergeMobileData, parseManifests, privilegedPrincipals, resolveNestedGroups, summarizeForQualityGate, summarizeMobileForGate,
  analyzeBinaryPlatform, evaluateBinaryDebugPolicy, extractBinaryStrings, parseBinaryHeaders,
  analyzeWirelessPosture, detectWirelessDrift, evaluateWirelessGate, mergeWirelessData,
  type ApprovedWirelessProfileShape, type NormalizedBinaryData, type NormalizedCloudIdentity, type NormalizedCloudResource, type NormalizedDirectoryData, type NormalizedMobileData, type NormalizedWirelessAccessPoint, type NormalizedWirelessData, type NormalizedWirelessSecurityEvent, type SourceFileEntry,
} from "@zerosweep/security-sdk";
import { createHash } from "node:crypto";
import { buildScanPlan, type ScanPlan, type ScanEventRecord } from "@zerosweep/orchestration";
import type { ScopeRules } from "@zerosweep/validation";
import type { ExecutionContextRecord } from "../executors/stage-executor";
import type { ScanRunRecord, ScanRunStore } from "../consumers/dag-runner";
import { correlateProcessedFindings, processNormalizedResult, type ProcessedCloudResource, type ProcessedComponent, type ProcessedResult } from "../executors/result-processor";
import { isMobileProcessedFinding, stampMobileFindings, type MobileScanIdentity } from "../executors/mobile-stamp";
import { isBinaryProcessedFinding, stampBinaryFindings, type BinaryScanIdentity } from "../executors/binary-stamp";
import { isWirelessProcessedFinding, stampWirelessFindings, type WirelessScanIdentity } from "../executors/wireless-stamp";

/**
 * In-memory ScanRunStore for worker tests (Prompt 4 §56, extended Prompt 5):
 * the same shapes the Prisma store and BullMQ dispatcher implement, backed
 * by maps. Plans can be built against any registry (mock-only by default;
 * fixture-backed recon adapters for the Prompt 5 end-to-end scenarios).
 */

export const TEST_SCOPE: ScopeRules = { includeHosts: ["example.com", "*.example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [80, 443], allowedPaths: [], excludedPaths: [] };
export const TEST_AUTH = {
  organizationId: "org-1", workspaceId: "ws-1", targetId: "t-1", targetOrganizationId: "org-1",
  assessmentId: "a-1", scanId: "scan-1", verificationStatus: "VERIFIED" as const,
  approvalStatus: "APPROVED" as const, requestedBy: "u-1",
};

export interface ExecRec { id: string; stageType: string; adapterSlug: string; status: string; patch: Record<string, unknown> }

export interface FakeStoreOptions {
  /** Registry the PLAN is built against (selection happens at plan time). */
  planRegistry?: ToolRegistry;
  healthBySlug?: Record<string, string>;
  executableSlugs?: string[];
  targetType?: "DOMAIN" | "WEB_APPLICATION" | "API" | "GRAPHQL" | "CIDR" | "IP_ADDRESS" | "SOURCE_REPOSITORY" | "CONTAINER_IMAGE" | "KUBERNETES_CLUSTER" | "DOCKER_HOST" | "AWS" | "AZURE" | "GCP" | "ACTIVE_DIRECTORY_DOMAIN" | "MOBILE_APP" | "BINARY" | "WIRELESS_LAB";
  /** Prompt 10: network target state mirroring the Prisma store — the
   *  CIDR/IP target, its scope, the store-resolved Masscan approval and
   *  the authorized capture reference for tshark analysis. */
  networkTarget?: { targetValue: string; targetHost: string; scope: ScopeRules; masscanApproved?: boolean; captureRef?: string };
  /** Prompt 8: scanner bindings per connector slug, mirroring the Prisma
   *  store's workspace resolution. Absent slug = NOT_CONFIGURED. */
  scannerBySlug?: Record<string, { instanceId: string; sessionProfileId?: string }>;
  /** Prompt 9: the guarded-import + auth-context state the API stages
   *  read, mirroring the Prisma store's import records: specification
   *  locations for Schemathesis, imported operations for its policy
   *  filter, obviously-fake JWTs for the inspection hook, imported
   *  specification counts and registered auth contexts. */
  apiFixtures?: {
    specUrls?: string[];
    operations?: string[];
    jwtTokens?: string[];
    specifications?: { operations: number }[];
    authContexts?: { role: string }[];
  };
  /** Prompt 12: the fixture repository the source stages operate on —
   *  file listing + manifest contents (defaults to the SDK fixture
   *  repo), plus the previous snapshot's finding fingerprints for
   *  baseline classification (§79). */
  sourceFixtures?: {
    files?: SourceFileEntry[];
    manifests?: Record<string, string>;
    previousFingerprints?: string[];
  };
  /** Prompt 13: the fixture cloud-native context the store resolves for
   *  a scan — registered image (tag + digest + the digest a PREVIOUS
   *  scan recorded, for drift), registered cluster and Docker host. */
  cloudFixtures?: {
    imageRef?: string;
    imageDigest?: string;
    previousDigest?: string;
    clusterId?: string;
    clusterRef?: string;
    hostRef?: string;
    kevCves?: string[];
  };
  /** Prompt 14: the fixture cloud account the store resolves for a
   *  cloud-account (AWS/AZURE/GCP target) scan — registered account identity + credential
   *  REFERENCE (never a value), scope regions, and the PREVIOUS
   *  inventory for drift comparison (§64). Absent accountId = the
   *  account is not registered (NOT_CONFIGURED). */
  /** Prompt 15: the fixture AD domain the store resolves for a
   *  directory scan — registered domain identity + credential
   *  REFERENCE (never a value), approved DC hosts, and the PREVIOUS
   *  snapshot's data for drift comparison (§79). Absent domainId = the
   *  domain is not registered (NOT_CONFIGURED). */
  directoryFixtures?: {
    domainId?: string;
    domainRef?: string;
    credentialReference?: string;
    identityKind?: string;
    dcHosts?: string[];
    previousData?: NormalizedDirectoryData;
  };
  /** Prompt 17: the fixture mobile application + build the store
   *  resolves for a mobile scan — registered application identity, the
   *  build (id + SHA-256 identity), the extracted artifacts the
   *  platform stages analyze, the approved lab session state and
   *  active kill switches (§92). Absent applicationId = NOT_CONFIGURED. */
  mobileFixtures?: {
    applicationId?: string;
    applicationRef?: string;
    platform?: "ANDROID" | "IOS";
    environment?: string;
    buildId?: string;
    buildHash?: string;
    artifactReference?: string;
    analysisArtifacts?: Record<string, unknown>;
    previousData?: NormalizedMobileData;
    deviceId?: string;
    dynamicSessionId?: string;
    dynamicSessionApproved?: boolean;
    trafficSessionId?: string;
    kevCves?: string[];
    killSwitches?: Array<{ level: string; active: boolean; scopeRef?: string }>;
  };
  cloudSecFixtures?: {
    accountId?: string;
    accountRef?: string;
    provider?: "AWS" | "AZURE" | "GCP";
    credentialReference?: string;
    regions?: string[];
    excludeRegions?: string[];
    environment?: string;
    queryPack?: string;
    previousResources?: NormalizedCloudResource[];
    previousIdentities?: NormalizedCloudIdentity[];
  };
  /** Prompt 18: the fixture binary artifact the store resolves for a
   *  binary scan — registered artifact identity (id + SHA-256), the
   *  header segment the platform stage parses, the local intel matches
   *  (the fixture "dataset") and the governed debug-session state.
   *  Absent artifactId = NOT_CONFIGURED. */
  binaryFixtures?: {
    artifactId?: string;
    artifactHash?: string;
    artifactName?: string;
    format?: string;
    architecture?: string;
    environment?: string;
    artifactReference?: string;
    headerSegment?: Buffer;
    intelMatches?: Array<{ purl: string; cveId: string; cvssScore: number; severity: string }>;
    debugSession?: { status: string; requestedBy: string; approvedBy?: string; environment?: string };
    killSwitchActive?: boolean;
  };
  /** Prompt 19: the fixture wireless environment the store resolves
   *  for a wireless scan — registered environment identity, the
   *  approved sensor + capture, the approved-AP profile (§43) for
   *  rogue classification and the previous-observations fixture for
   *  drift (§56). Absent environmentId = NOT_CONFIGURED. */
  wirelessFixtures?: {
    environmentId?: string;
    environmentRef?: string;
    environmentKind?: string;
    sensorRef?: string;
    sensorInterface?: string;
    captureId?: string;
    captureReference?: string;
    approvedProfiles?: Array<Record<string, unknown>>;
    previousAccessPoints?: Array<Record<string, unknown>>;
  };
}

export class FakeStore implements ScanRunStore {
  plan: ScanPlan;
  scanStatus = "QUEUED";
  progress = 0;
  stages = new Map<string, string>();
  executions = new Map<string, ExecRec>();
  events: ScanEventRecord[] = [];
  assets: ProcessedResult["assets"] = [];
  findings: ProcessedResult["findings"] = [];
  endpoints: ProcessedResult["endpoints"] = [];
  services: ProcessedResult["services"] = [];
  technologies: ProcessedResult["technologies"] = [];
  parameters: ProcessedResult["parameters"] = [];
  forms: ProcessedResult["forms"] = [];
  transactions: ProcessedResult["transactions"] = [];
  webSockets: ProcessedResult["webSockets"] = [];
  apiServices: ProcessedResult["apiServices"] = [];
  graphqlServices: ProcessedResult["graphqlServices"] = [];
  jwtProfiles: ProcessedResult["jwtProfiles"] = [];
  packetCaptures: ProcessedResult["packetCaptures"] = [];
  components: ProcessedComponent[] = [];
  /** Prompt 13 cloud-native state mirroring the Prisma store's rows. */
  images: ProcessedResult["cloudNative"]["images"] = [];
  workloads: ProcessedResult["cloudNative"]["workloads"] = [];
  controlAssessments: ProcessedResult["cloudNative"]["controlAssessments"] = [];
  runtimeEvents: ProcessedResult["cloudNative"]["runtimeEvents"] = [];
  imageSnapshots: Array<{ imageRef: string; digest?: string; previousDigest?: string; drift: boolean }> = [];
  containerQualityGateRecord: { status: string; failedRules: string[]; warningRules: string[] } | null = null;
  cloudFixtures: NonNullable<FakeStoreOptions["cloudFixtures"]> = {};
  /** Prompt 14 multi-cloud state mirroring the Prisma store's rows. */
  cloudResources: ProcessedCloudResource[] = [];
  cloudIdentities: NormalizedCloudIdentity[] = [];
  cloudRelationships: ProcessedResult["cloud"]["relationships"] = [];
  cloudSnapshots: Array<{ snapshotHash: string; regions: string[]; resourceCounts: Record<string, number> }> = [];
  cloudDrift: Array<{ kind: string; resourceRef?: string; detail: string }> = [];
  cloudRiskPaths: ProcessedResult["cloud"]["riskPaths"] = [];
  cloudGateRecord: { status: string; failedRules: string[]; warningRules: string[] } | null = null;
  cloudAccountStatus = "REGISTERED";
  cloudSecFixtures: NonNullable<FakeStoreOptions["cloudSecFixtures"]> = {};
  /** Prompt 15 Active Directory state mirroring the Prisma store's
   *  directory rows. */
  directoryData: NormalizedDirectoryData = {
    domainControllers: [], users: [], groups: [], computers: [], organizationalUnits: [],
    groupPolicies: [], trusts: [], relationships: [], smbShares: [],
    certificateAuthorities: [], certificateTemplates: [],
  };
  directorySnapshots: Array<{ snapshotHash: string; collectionProfile: string }> = [];
  adDrift: Array<{ kind: string; objectRef?: string; detail: string }> = [];
  attackPaths: Array<{ title: string; status: string; riskScore: number }> = [];
  directoryDomainStatus = "REGISTERED";
  directoryFixtures: NonNullable<FakeStoreOptions["directoryFixtures"]> = {};
  private directoryDriftComputed = false;
  /** Prompt 18 binary state mirroring the Prisma store's artifact rows. */
  binaryData: NormalizedBinaryData = {
    sha256: "", format: "UNKNOWN", compilerHints: [], sections: [], hardening: [],
    functions: [], imports: [], exports: [], symbols: [], dependencies: [],
    strings: [], stringsSummary: { total: 0, byCategory: {} }, cryptoReferences: [],
    discoveredReferences: [], source: "fake-store",
  };
  binaryGateRecord: { status: string; failedRules: string[]; warningRules: string[] } | null = null;
  binarySbomRecord: { format: string; checksum: string; componentCount: number } | null = null;
  binaryFixtures: NonNullable<FakeStoreOptions["binaryFixtures"]> = {};
  /** Prompt 19 wireless state mirroring the Prisma store's rows. */
  wirelessData: NormalizedWirelessData = {
    accessPoints: [], stations: [], observations: [], channelObservations: [],
    securityEvents: [], authenticationMaterialCount: 0, framesProcessed: 0, source: "fake-store",
  };
  wirelessSecurityEvents: NormalizedWirelessSecurityEvent[] = [];
  wirelessDriftRecords: Array<{ kind: string; bssid: string; field?: string; fromValue?: string; toValue?: string; securityDowngrade?: boolean }> = [];
  wirelessGateRecord: { status: string; failedRules: string[]; warningRules: string[] } | null = null;
  wirelessFixtures: NonNullable<FakeStoreOptions["wirelessFixtures"]> = {};
  private wirelessDriftComputed = false;
  /** Prompt 17 mobile state mirroring the Prisma store's build rows. */
  mobileData: NormalizedMobileData = emptyMobileData("fake-store");
  mobileComponents: ProcessedComponent[] = [];
  mobileGateRecord: { status: string; failedRules: string[]; warningRules: string[] } | null = null;
  mobileFixtures: NonNullable<FakeStoreOptions["mobileFixtures"]> = {};
  /** Prompt 17 retest mirror: mobile findings resolved/reopened by
   *  targeted rechecks across builds (§89). */
  mobileRetestOutcomes: Array<{ fingerprint: string; status: string; buildHash: string }> = [];
  /** Prompt 12 source state mirroring the Prisma store's snapshot rows. */
  sourceSnapshot: { id: string; repositoryId: string; hash: string; files: SourceFileEntry[]; manifests: Record<string, string> } | null = null;
  sourceLanguages: string[] = [];
  sbomRecord: { format: string; checksum: string; componentCount: number } | null = null;
  qualityGateRecord: { status: string; failedRules: string[]; warningRules: string[] } | null = null;
  sourceFixtures: NonNullable<FakeStoreOptions["sourceFixtures"]> = {};
  networkChunks: Array<{ chunkId: string; rangeStart: string; rangeEnd: string; hostCount: number; status: string }> = [];
  networkTarget: FakeStoreOptions["networkTarget"];
  apiFixtures: NonNullable<FakeStoreOptions["apiFixtures"]> = {};
  scannerBySlug: Record<string, { instanceId: string; sessionProfileId?: string }> = {};
  deadLetters: unknown[] = [];
  reportPending = false;
  paused = false;
  cancelled = false;
  simulationByStage: Record<string, ExecutionContextRecord["simulation"]> = {};
  verified = true;
  targetType: "DOMAIN" | "WEB_APPLICATION" | "API" | "GRAPHQL" | "CIDR" | "IP_ADDRESS" | "SOURCE_REPOSITORY" | "CONTAINER_IMAGE" | "KUBERNETES_CLUSTER" | "DOCKER_HOST" | "AWS" | "AZURE" | "GCP" | "ACTIVE_DIRECTORY_DOMAIN" | "MOBILE_APP" | "BINARY" | "WIRELESS_LAB";

  // (constructor assigns targetType from opts)

  constructor(profile: "PASSIVE_RECON" | "WEB_BASELINE" | "WEB_COMPREHENSIVE" | "API_ASSESSMENT" | "NETWORK_DISCOVERY" | "NETWORK_BASELINE" | "NETWORK_COMPREHENSIVE" | "NETWORK_INTERNAL" | "NETWORK_ASSESSMENT" | "SOURCE_BASELINE" | "SOURCE_COMPREHENSIVE" | "SECRETS_ONLY" | "DEPENDENCIES_ONLY" | "SAST_ONLY" | "CONTAINER_BASELINE" | "CONTAINER_COMPREHENSIVE" | "SBOM_ONLY" | "IMAGE_VULNERABILITIES_ONLY" | "CONTAINER_MISCONFIG_ONLY" | "KUBERNETES_BASELINE" | "KUBERNETES_COMPREHENSIVE" | "DOCKER_HOST_BASELINE" | "CLOUD_NATIVE_FULL" | "CLOUD_INVENTORY" | "CLOUD_BASELINE" | "CLOUD_COMPREHENSIVE" | "IAM_REVIEW" | "PUBLIC_EXPOSURE_REVIEW" | "COMPLIANCE_ASSESSMENT" | "IAC_TO_CLOUD_CORRELATION" | "CLOUD" | "AD_INVENTORY" | "AD_BASELINE" | "AD_COMPREHENSIVE" | "ADCS_POSTURE" | "SMB_POSTURE" | "IDENTITY_GRAPH" | "ATTACK_PATH_ANALYSIS" | "MOBILE_STATIC_BASELINE" | "MOBILE_STATIC_COMPREHENSIVE" | "MOBILE_SECRETS_ONLY" | "MOBILE_BINARY_ANALYSIS" | "MOBILE_DYNAMIC_CONTROLLED" | "MOBILE_FULL_CONTROLLED" | "MOBILE" | "BINARY_METADATA_ONLY" | "BINARY_BASELINE" | "BINARY_ASSESSMENT" | "BINARY_COMPREHENSIVE_STATIC" | "BINARY_DEPENDENCY_ANALYSIS" | "BINARY_CONTROLLED_DEBUG" | "WIRELESS_PASSIVE_BASELINE" | "WIRELESS_PASSIVE_COMPREHENSIVE" | "PCAP_ANALYSIS_ONLY" | "WIRELESS_COMPLIANCE" | "WIRELESS_LAB_VALIDATION", opts: FakeStoreOptions = {}) {
    this.targetType = opts.targetType ?? "DOMAIN";
    this.scannerBySlug = opts.scannerBySlug ?? {};
    this.apiFixtures = opts.apiFixtures ?? {};
    this.sourceFixtures = opts.sourceFixtures ?? {};
    this.cloudFixtures = opts.cloudFixtures ?? {};
    this.cloudSecFixtures = opts.cloudSecFixtures ?? {};
    this.directoryFixtures = opts.directoryFixtures ?? {};
    this.mobileFixtures = opts.mobileFixtures ?? {};
    this.binaryFixtures = opts.binaryFixtures ?? {};
    this.wirelessFixtures = opts.wirelessFixtures ?? {};
    this.networkTarget = opts.networkTarget;
    const registry = opts.planRegistry ?? (() => { const r = new ToolRegistry(); r.register(new MockSecurityAdapter()); return r; })();
    this.plan = buildScanPlan({
      scanId: "scan-1", assessmentId: "a-1", targetId: "t-1", workspaceId: "ws-1", organizationId: "org-1",
      profile, targetType: opts.targetType ?? "DOMAIN",
      targetValue: opts.networkTarget?.targetValue ?? "example.com", targetHost: opts.networkTarget?.targetHost ?? "example.com",
      scope: opts.networkTarget?.scope ?? TEST_SCOPE, targetVerified: true, assessmentApproved: true, registry,
      selection: {
        executableSlugs: opts.executableSlugs ?? ["mock", "local-echo"],
        ...(opts.healthBySlug ? { healthBySlug: opts.healthBySlug } : {}),
      },
    }).plan;
    for (const s of this.plan.stages) this.stages.set(s.type, s.dependencies.length === 0 ? "READY" : "BLOCKED");
    this.simulationByStage["PASSIVE_RECON"] = { fixture: true };
  }

  private gate() {
    return {
      auth: TEST_AUTH, targetHost: this.networkTarget?.targetHost ?? "example.com", scopeRules: this.networkTarget?.scope ?? TEST_SCOPE, targetExists: true,
      targetWorkspaceId: "ws-1", workspaceId: "ws-1",
      targetVerified: this.verified, assessmentApproved: true, scopeValid: true,
      assessmentCreatedBy: "u-creator", assessmentApprovedBy: "u-approver",
    };
  }

  async loadScanRun(): Promise<ScanRunRecord> {
    return { plan: this.plan, scanStatus: this.scanStatus, progress: this.progress, gate: this.gate() };
  }
  async stageStatuses(): Promise<Map<string, string>> { return new Map(this.stages); }
  async updateScan(_id: string, patch: Record<string, unknown>): Promise<void> {
    if (typeof patch.status === "string") this.scanStatus = patch.status;
    if (typeof patch.progress === "number") this.progress = patch.progress;
  }
  async updateStage(_id: string, stageType: string, patch: Record<string, unknown>): Promise<void> {
    if (typeof patch.status === "string") this.stages.set(stageType, patch.status);
  }
  async ensureExecution(_scanId: string, stageType: string, adapterSlug: string, _attempt = 1): Promise<{ id: string; status: string }> {
    const id = `exec-${stageType}-${adapterSlug}`;
    if (!this.executions.has(id)) this.executions.set(id, { id, stageType, adapterSlug, status: "QUEUED", patch: {} });
    return { id, status: this.executions.get(id)!.status };
  }
  async markReportPending(): Promise<void> { this.reportPending = true; }
  async isPaused(): Promise<boolean> { return this.paused; }
  async isCancelled(): Promise<boolean> { return this.cancelled || this.scanStatus === "CANCELLED"; }

  async loadExecutionContext(executionId: string): Promise<ExecutionContextRecord | null> {
    const exec = this.executions.get(executionId);
    if (!exec) return null;
    const planned = this.plan.stages.find((s) => s.type === exec.stageType)!;
    return {
      executionId, scanId: "scan-1", stageId: exec.stageType, workspaceId: "ws-1", organizationId: "org-1",
      adapterSlug: exec.adapterSlug, status: exec.status, attempt: 1, timeoutSeconds: planned.timeoutSeconds,
      targetType: this.targetType, targetValue: this.networkTarget?.targetValue ?? "example.com", targetHost: this.networkTarget?.targetHost ?? "example.com", scopeRules: this.networkTarget?.scope ?? TEST_SCOPE,
      auth: TEST_AUTH, targetExists: true, targetWorkspaceId: "ws-1",
      targetVerified: this.verified, assessmentApproved: true, scopeValid: true,
      assessmentCreatedBy: "u-creator", assessmentApprovedBy: "u-approver",
      networkCapable: planned.networkCapable,
      profile: this.plan.profile,
      assessmentId: "a-1",
      masscanApproved: this.networkTarget?.masscanApproved,
      captureRef: this.networkTarget?.captureRef,
      // Prompt 12: the scan's snapshot context (§12) — the fixture
      // snapshot the acquisition hook materialized (or the default
      // fixture workspace before it runs).
      source: this.targetType === "SOURCE_REPOSITORY" ? {
        repositoryId: "repo-1",
        snapshotId: this.sourceSnapshot?.id ?? "snap-1",
        workspacePath: "/fixtures/source-snapshot",
        languages: this.sourceLanguages,
        sonarProjectKey: "fixture-repo",
      } : undefined,
      // Prompt 13: the scan's cloud-native context (§12) — resolved
      // from the registered image/cluster/host fixtures, mirroring the
      // Prisma store's row lookups.
      cloudNative: (this.cloudFixtures.imageRef || this.cloudFixtures.clusterId || this.cloudFixtures.hostRef) ? {
        ...(this.cloudFixtures.imageRef ? { imageRef: this.cloudFixtures.imageRef } : {}),
        ...(this.cloudFixtures.imageDigest ? { imageDigest: this.cloudFixtures.imageDigest } : {}),
        ...(this.cloudFixtures.clusterId ? { clusterId: this.cloudFixtures.clusterId } : {}),
        ...(this.cloudFixtures.clusterRef ? { clusterRef: this.cloudFixtures.clusterRef } : {}),
        ...(this.cloudFixtures.hostRef ? { hostRef: this.cloudFixtures.hostRef } : {}),
      } : undefined,
      // Prompt 14: the scan's cloud account context (§10) — resolved
      // from the registered-account fixture, mirroring the Prisma
      // store's CloudAccount lookup. No accountId = NOT_CONFIGURED.
      cloud: ["AWS", "AZURE", "GCP"].includes(this.targetType) ? {
        ...(this.cloudSecFixtures.accountId ? { accountId: this.cloudSecFixtures.accountId } : {}),
        ...(this.cloudSecFixtures.accountRef ? { accountRef: this.cloudSecFixtures.accountRef } : {}),
        ...(this.cloudSecFixtures.provider ? { provider: this.cloudSecFixtures.provider } : {}),
        ...(this.cloudSecFixtures.credentialReference ? { credentialReference: this.cloudSecFixtures.credentialReference } : {}),
        ...(this.cloudSecFixtures.regions ? { regions: this.cloudSecFixtures.regions } : {}),
        ...(this.cloudSecFixtures.excludeRegions ? { excludeRegions: this.cloudSecFixtures.excludeRegions } : {}),
        ...(this.cloudSecFixtures.environment ? { environment: this.cloudSecFixtures.environment } : {}),
        ...(this.cloudSecFixtures.queryPack ? { queryPack: this.cloudSecFixtures.queryPack } : {}),
      } : undefined,
      // Prompt 15: the scan's directory context (§7/§11) — resolved
      // from the registered-domain fixture, mirroring the Prisma
      // store's ActiveDirectoryDomain lookup. No domainId =
      // NOT_CONFIGURED.
      directory: this.targetType === "ACTIVE_DIRECTORY_DOMAIN" ? {
        ...(this.directoryFixtures.domainId ? { domainId: this.directoryFixtures.domainId } : {}),
        ...(this.directoryFixtures.domainRef ? { domainRef: this.directoryFixtures.domainRef } : {}),
        ...(this.directoryFixtures.credentialReference ? { credentialReference: this.directoryFixtures.credentialReference } : {}),
        ...(this.directoryFixtures.identityKind ? { identityKind: this.directoryFixtures.identityKind } : {}),
        ...(this.directoryFixtures.dcHosts ? { dcHosts: this.directoryFixtures.dcHosts } : {}),
      } : undefined,
      // Prompt 17: the scan's mobile context (§5/§58) — resolved from
      // the registered application/build fixture, mirroring the Prisma
      // store's MobileApplication/MobileBuild lookup. No buildId =
      // NOT_CONFIGURED.
      mobile: this.targetType === "MOBILE_APP" ? {
        ...(this.mobileFixtures.applicationId ? { applicationId: this.mobileFixtures.applicationId } : {}),
        ...(this.mobileFixtures.applicationRef ? { applicationRef: this.mobileFixtures.applicationRef } : {}),
        ...(this.mobileFixtures.platform ? { platform: this.mobileFixtures.platform } : {}),
        ...(this.mobileFixtures.environment ? { environment: this.mobileFixtures.environment } : {}),
        ...(this.mobileFixtures.buildId ? { buildId: this.mobileFixtures.buildId } : {}),
        ...(this.mobileFixtures.buildHash ? { buildHash: this.mobileFixtures.buildHash } : {}),
        ...(this.mobileFixtures.artifactReference ? { artifactReference: this.mobileFixtures.artifactReference } : {}),
        ...(this.mobileFixtures.deviceId ? { deviceId: this.mobileFixtures.deviceId } : {}),
        ...(this.mobileFixtures.dynamicSessionId ? { dynamicSessionId: this.mobileFixtures.dynamicSessionId } : {}),
        ...(this.mobileFixtures.dynamicSessionApproved !== undefined ? { dynamicSessionApproved: this.mobileFixtures.dynamicSessionApproved } : {}),
        ...(this.mobileFixtures.trafficSessionId ? { trafficSessionId: this.mobileFixtures.trafficSessionId } : {}),
      } : undefined,
      // Prompt 18: the scan's binary context (§3/§6) — resolved from
      // the registered artifact fixture, mirroring the Prisma store's
      // BinaryArtifact lookup. No artifactId = NOT_CONFIGURED.
      binary: this.targetType === "BINARY" ? {
        ...(this.binaryFixtures.artifactId ? { artifactId: this.binaryFixtures.artifactId } : {}),
        ...(this.binaryFixtures.artifactHash ? { artifactHash: this.binaryFixtures.artifactHash } : {}),
        ...(this.binaryFixtures.artifactReference ? { artifactReference: this.binaryFixtures.artifactReference } : {}),
        ...(this.binaryFixtures.artifactName ? { artifactName: this.binaryFixtures.artifactName } : {}),
        ...(this.binaryFixtures.format ? { format: this.binaryFixtures.format } : {}),
        ...(this.binaryFixtures.environment ? { environment: this.binaryFixtures.environment } : {}),
      } : undefined,
      // Prompt 19: the scan's wireless context (§3/§12/§26) —
      // resolved from the registered environment fixture, mirroring
      // the Prisma store's WirelessEnvironment/Sensor/Capture
      // lookups. No environmentId = NOT_CONFIGURED.
      wireless: this.targetType === "WIRELESS_LAB" ? {
        ...(this.wirelessFixtures.environmentId ? { environmentId: this.wirelessFixtures.environmentId } : {}),
        ...(this.wirelessFixtures.environmentRef ? { environmentRef: this.wirelessFixtures.environmentRef } : {}),
        ...(this.wirelessFixtures.environmentKind ? { environmentKind: this.wirelessFixtures.environmentKind } : {}),
        ...(this.wirelessFixtures.sensorRef ? { sensorRef: this.wirelessFixtures.sensorRef } : {}),
        ...(this.wirelessFixtures.sensorInterface ? { sensorInterface: this.wirelessFixtures.sensorInterface } : {}),
        ...(this.wirelessFixtures.captureId ? { captureId: this.wirelessFixtures.captureId } : {}),
        ...(this.wirelessFixtures.captureReference ? { captureReference: this.wirelessFixtures.captureReference } : {}),
      } : undefined,
      scanner: this.scannerBySlug[exec.adapterSlug],
      simulation: this.simulationByStage[exec.stageType],
      // Discovery inputs (§26): persisted in-scope inventory so far.
      stageInputs: {
        hosts: [...new Set(this.assets.filter((a) => a.scopeStatus === "IN_SCOPE").map((a) => a.host))],
        urls: [...new Set(this.endpoints.filter((e) => e.scopeStatus === "IN_SCOPE").map((e) => e.url))],
        technologies: [...new Set(this.technologies.map((t) => t.name))],
        // TLS services (§13): TLS-looking services on in-scope assets.
        services: [...new Set(this.services
          .filter((s) => s.scheme === "https" || [443, 8443].includes(s.port) || ["https", "ssl", "tls"].includes(s.name))
          .map((s) => `${s.host}:${s.port}`))],
        // Prompt 9: imported specification locations + operations from
        // the guarded import records (fixtures here, import store in
        // production) — the executor derives schemathesis config from
        // these, never from clients.
        specUrls: this.apiFixtures.specUrls ?? [],
        operations: this.apiFixtures.operations ?? [],
      },
    };
  }

  /** Prompt 7 hooks mirroring the Prisma store's pipeline behaviour. */
  correlatedFindings: ProcessedResult["findings"] = [];
  findingStats: Record<string, unknown> | null = null;
  /** Prompt 11 §59–§64 mirror: one observation per (canonical finding,
   *  source tool) recorded at correlation time. */
  observations: Array<{ findingFingerprint: string; sourceTool: string; severity: string }> = [];

  async summarizeFindings(): Promise<Record<string, unknown> | null> {
    if (this.findings.length === 0) return null;
    const bySeverity: Record<string, number> = {};
    for (const f of this.findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    return { totalFindings: this.findings.length, bySeverity };
  }

  async correlateScanFindings(): Promise<{ canonical: number; duplicates: number; stats: Record<string, unknown> } | null> {
    if (this.findings.length === 0) return null;
    const { findings, stats } = correlateProcessedFindings(this.findings, { maxFindings: 1000 });
    this.correlatedFindings = findings;
    this.findingStats = stats as unknown as Record<string, unknown>;
    for (const f of findings) {
      for (const tool of f.sources) {
        this.observations.push({ findingFingerprint: f.fingerprint, sourceTool: tool, severity: f.severity });
      }
    }
    return { canonical: findings.length, duplicates: stats.duplicatesMerged, stats: stats as unknown as Record<string, unknown> };
  }

  async recalculateFindingRisk(): Promise<{ updated: number } | null> {
    if (this.correlatedFindings.length === 0) return null;
    return { updated: this.correlatedFindings.length };
  }
  async updateExecution(id: string, patch: Record<string, unknown>): Promise<void> {
    const exec = this.executions.get(id);
    if (!exec) return;
    Object.assign(exec.patch, patch);
    if (typeof patch.status === "string") exec.status = patch.status;
  }
  async recordEvent(event: ScanEventRecord): Promise<void> { this.events.push(event); }
  async persistResult(_scanId: string, _executionId: string, processedIn: ProcessedResult): Promise<{ assets: number; findings: number; endpoints: number; services: number; technologies: number; parameters: number; forms: number; transactions: number; webSockets: number; apiServices: number; graphqlServices: number; jwtProfiles: number; packetCaptures: number; components: number; directoryUsers?: number; directoryGroups?: number; directoryComputers?: number; directoryRelationships?: number }> {
    // Prompt 17 §50: mobile findings are stamped with their canonical
    // identity BEFORE persistence (mirrors the Prisma store).
    let processed = this.mobileIdentity() && processedIn.findings.some(isMobileProcessedFinding)
      ? { ...processedIn, findings: stampMobileFindings(processedIn.findings, this.mobileIdentity()!) }
      : processedIn;
    // Prompt 18 §50–§58: binary findings are stamped with their
    // canonical identity BEFORE persistence (mirrors the Prisma store).
    if (this.binaryIdentity() && processed.findings.some(isBinaryProcessedFinding)) {
      processed = { ...processed, findings: stampBinaryFindings(processed.findings, this.binaryIdentity()!) };
    }
    // Prompt 19 §52/§53: wireless findings are stamped with their
    // canonical identity BEFORE persistence (mirrors the Prisma store).
    if (this.wirelessIdentity() && processed.findings.some(isWirelessProcessedFinding)) {
      processed = { ...processed, findings: stampWirelessFindings(processed.findings, this.wirelessIdentity()!) };
    }
    // Assets merge by host (one canonical row, provenance unioned) —
    // mirrors the Prisma store's upsert behaviour.
    for (const a of processed.assets) {
      const existing = this.assets.find((x) => x.host === a.host);
      if (existing) {
        existing.sources = [...new Set([...existing.sources, ...a.sources])];
        existing.ip ??= a.ip;
        existing.osHint ??= a.osHint;
        existing.osConfidence ??= a.osConfidence;
      } else this.assets.push(a);
    }
    this.findings.push(...processed.findings);
    this.endpoints.push(...processed.endpoints);
    // Services merge by (host, port, protocol) with PortResultAggregator
    // semantics (§49): provenance unioned, richer evidence gap-filled,
    // OPEN outranks CLOSED — mirrors the Prisma store's merge upsert.
    const stateRank: Record<string, number> = { OPEN: 4, OPEN_FILTERED: 3, UNKNOWN: 2, FILTERED: 1, CLOSED: 0 };
    for (const s of processed.services) {
      const existing = this.services.find((x) => x.host === s.host && x.port === s.port && x.protocol === s.protocol);
      if (existing) {
        existing.sources = [...new Set([...(existing.sources ?? []), ...(s.sources ?? [])])].sort();
        existing.product ??= s.product;
        existing.version ??= s.version;
        existing.cpe ??= s.cpe;
        existing.banner ??= s.banner;
        if (s.tls !== undefined) existing.tls = existing.tls ?? s.tls;
        existing.confidence = Math.max(existing.confidence ?? 0, s.confidence ?? 0) || undefined;
        if ((stateRank[s.state ?? "UNKNOWN"] ?? 0) > (stateRank[existing.state ?? "UNKNOWN"] ?? 0)) existing.state = s.state;
        if ((!existing.name || existing.name === "unknown") && s.name) existing.name = s.name;
      } else this.services.push(s);
    }
    this.technologies.push(...processed.technologies);
    this.parameters.push(...processed.parameters);
    this.forms.push(...processed.forms);
    this.transactions.push(...processed.transactions);
    this.webSockets.push(...processed.webSockets);
    this.apiServices.push(...processed.apiServices);
    this.graphqlServices.push(...processed.graphqlServices);
    this.jwtProfiles.push(...processed.jwtProfiles);
    this.packetCaptures.push(...processed.packetCaptures);
    // Components merge by PURL (one canonical inventory row per
    // snapshot) — mirrors the Prisma store's upsert.
    for (const c of processed.components) {
      if (!this.components.some((x) => x.purl === c.purl)) this.components.push(c);
    }
    // Prompt 13 cloud-native payloads: images merge by identity key
    // (digest strongest, §5), workloads by cluster/kind/namespace/name,
    // assessments + runtime events append — mirrors the Prisma store.
    for (const img of processed.cloudNative.images) {
      const key = `${img.registry}/${img.repository}@${img.digest ?? img.tag ?? ""}`;
      if (!this.images.some((x) => `${x.registry}/${x.repository}@${x.digest ?? x.tag ?? ""}` === key)) this.images.push(img);
    }
    for (const w of processed.cloudNative.workloads) {
      const key = `${w.clusterRef}|${w.kind}|${w.namespace}|${w.name}`;
      if (!this.workloads.some((x) => `${x.clusterRef}|${x.kind}|${x.namespace}|${x.name}` === key)) this.workloads.push(w);
    }
    this.controlAssessments.push(...processed.cloudNative.controlAssessments);
    this.runtimeEvents.push(...processed.cloudNative.runtimeEvents);
    // Prompt 14 multi-cloud payloads: resources merge by provider
    // resource id (mirrors the Prisma upsert), identities by provider
    // identity id, relationships append unique, cloud control
    // assessments share the compliance record, and a full-inventory
    // result drives drift against the previous inventory (§64).
    if (processed.cloud.snapshot) {
      const previousResources = this.cloudResources.length > 0
        ? this.cloudResources.filter((r) => r.scopeStatus === "IN_SCOPE").map(({ scopeStatus: _s, ...r }) => r)
        : (this.cloudSecFixtures.previousResources ?? []);
      const previousIdentities = this.cloudIdentities.length > 0 ? this.cloudIdentities : (this.cloudSecFixtures.previousIdentities ?? []);
      const currentInScope = processed.cloud.resources.filter((r) => r.scopeStatus === "IN_SCOPE").map(({ scopeStatus: _s, ...r }) => r);
      this.cloudDrift.push(...diffCloudInventories(
        { resources: previousResources, identities: previousIdentities },
        { resources: currentInScope, identities: processed.cloud.identities },
      ));
      this.cloudSnapshots.push({ snapshotHash: processed.cloud.snapshot.snapshotHash, regions: processed.cloud.snapshot.regions, resourceCounts: processed.cloud.snapshot.resourceCounts });
    }
    for (const r of processed.cloud.resources) {
      const existing = this.cloudResources.find((x) => x.providerResourceId === r.providerResourceId);
      if (existing) Object.assign(existing, r);
      else this.cloudResources.push(r);
    }
    for (const i of processed.cloud.identities) {
      const existing = this.cloudIdentities.find((x) => x.providerIdentityId === i.providerIdentityId);
      if (existing) Object.assign(existing, i);
      else this.cloudIdentities.push(i);
    }
    for (const rel of processed.cloud.relationships) {
      const key = `${rel.fromType}|${rel.fromRef}|${rel.relationship}|${rel.toType}|${rel.toRef}`;
      if (!this.cloudRelationships.some((x) => `${x.fromType}|${x.fromRef}|${x.relationship}|${x.toType}|${x.toRef}` === key)) this.cloudRelationships.push(rel);
    }
    this.controlAssessments.push(...processed.cloud.controlAssessments);
    this.cloudRiskPaths.push(...processed.cloud.riskPaths);
    // Prompt 15 directory payloads: inventory merges by identity key
    // (mirrors the Prisma upserts); the posture analysis runs over
    // the merged inventory and its findings join the scan deduped by
    // canonical fingerprint; drift diffs against the previous
    // snapshot fixture once (§79).
    const dirCounts = this.persistDirectory(processed);
    const mobCounts = this.persistMobile(processed);
    const binCounts = this.persistBinary(processed);
    const wlCounts = this.persistWireless(processed);
    return { assets: processed.assets.length, findings: processed.findings.length + dirCounts.findings + mobCounts.findings + binCounts.findings + wlCounts.findings, endpoints: processed.endpoints.length, services: processed.services.length, technologies: processed.technologies.length, parameters: processed.parameters.length, forms: processed.forms.length, transactions: processed.transactions.length, webSockets: processed.webSockets.length, apiServices: processed.apiServices.length, graphqlServices: processed.graphqlServices.length, jwtProfiles: processed.jwtProfiles.length, packetCaptures: processed.packetCaptures.length, components: processed.components.length, directoryUsers: dirCounts.users, directoryGroups: dirCounts.groups, directoryComputers: dirCounts.computers, directoryRelationships: dirCounts.relationships };
  }

  /** Prompt 17: the scan's mobile identity when a build is registered. */
  private mobileIdentity(): MobileScanIdentity | null {
    const fx = this.mobileFixtures;
    if (this.targetType !== "MOBILE_APP" || !fx.applicationId || !fx.buildId || !fx.buildHash) return null;
    return {
      applicationId: fx.applicationId,
      applicationRef: fx.applicationRef ?? "com.example.app",
      buildId: fx.buildId,
      buildHash: fx.buildHash,
      platform: fx.platform ?? "ANDROID",
      ...(fx.environment ? { environment: fx.environment } : {}),
    };
  }

  /** Prompt 17 mobile persistence mirror (§20–§52): inventory merges
   *  by identity key; platform posture analysis runs over the merged
   *  inventory and its findings join the scan stamped + deduped by
   *  canonical fingerprint; MASVS assessments dedupe by control. */
  private persistMobile(processed: ProcessedResult): { findings: number } {
    const payload = processed.mobile;
    const has = payload.permissions.length + payload.components.length + payload.deepLinks.length
      + payload.endpoints.length + payload.nativeLibraries.length + payload.signing.length > 0;
    const identity = this.mobileIdentity();
    if (!has || !identity) return { findings: 0 };
    this.mobileData = mergeMobileData(this.mobileData, payload);
    for (const c of processed.components) {
      if (!this.mobileComponents.some((x) => x.purl === c.purl)) this.mobileComponents.push(c);
      if (!this.components.some((x) => x.purl === c.purl)) this.components.push(c);
    }
    const posture = analyzeMobilePosture(this.mobileData, {
      applicationId: identity.applicationId,
      applicationRef: identity.applicationRef,
      buildId: identity.buildId,
      buildHash: identity.buildHash,
      platform: identity.platform,
      environment: identity.environment ?? "PRODUCTION",
      toolSlug: "mobile-platform-analysis",
    });
    const stamped = stampMobileFindings(
      processNormalizedResult({
        assets: [], services: [], endpoints: [], technologies: [], findings: posture.findings,
        artifacts: [], metrics: {}, mock: false,
      }, { scopeRules: TEST_SCOPE, toolExecutionId: "platform-mobile-analysis", toolSlug: "mobile-platform-analysis" }).findings,
      identity,
    );
    const fresh = stamped.filter((f) => !this.findings.some((x) => x.fingerprint === f.fingerprint));
    if (fresh.length > 0) this.findings.push(...fresh);
    for (const a of posture.controlAssessments) {
      if (!this.controlAssessments.some((x) => x.frameworkKey === a.frameworkKey && x.controlId === a.controlId && x.subjectRef === a.subjectRef)) {
        this.controlAssessments.push({ ...a });
      }
    }
    return { findings: fresh.length };
  }

  /** Prompt 17 platform hooks mirroring the Prisma store (§6/§10/§90). */
  async validateMobileBuild(): Promise<{ buildHash: string; platform: string; artifactFormat: string } | null> {
    const identity = this.mobileIdentity();
    if (!identity) return null;
    return { buildHash: identity.buildHash, platform: identity.platform, artifactFormat: identity.platform === "ANDROID" ? "APK" : "IPA" };
  }

  async extractMobileMetadata(): Promise<{ permissions: number; components: number; endpoints: number; secrets: number; componentsScanned: number } | null> {
    const identity = this.mobileIdentity();
    if (!identity) return null;
    const artifacts = this.mobileFixtures.analysisArtifacts;
    if (!artifacts) return null;
    const extracted = extractMobileArtifacts(artifacts, {
      applicationId: identity.applicationId, applicationRef: identity.applicationRef,
      buildId: identity.buildId, buildHash: identity.buildHash,
      platform: identity.platform, environment: identity.environment ?? "PRODUCTION",
      toolSlug: "mobile-platform-analysis",
    });
    const processedExtracted = processNormalizedResult({
      assets: [], services: [], endpoints: [], technologies: [], findings: extracted.findings,
      artifacts: [], metrics: {}, mock: false, components: extracted.components, mobile: extracted.data,
    }, { scopeRules: TEST_SCOPE, toolExecutionId: "platform-mobile-metadata", toolSlug: "mobile-platform-analysis" });
    await this.persistResult("scan-1", "platform-mobile-metadata", processedExtracted);
    return {
      permissions: extracted.data.permissions.length,
      components: extracted.data.components.length,
      endpoints: extracted.data.endpoints.length,
      secrets: extracted.findings.filter((f) => f.mobileFindingType === "MOBILE_SECRET").length,
      componentsScanned: extracted.components.length,
    };
  }

  async analyzeMobileManifest(): Promise<{ findings: number; assessments: number } | null> {
    const identity = this.mobileIdentity();
    if (!identity) return null;
    const before = this.controlAssessments.length;
    const posture = analyzeMobilePosture(this.mobileData, {
      applicationId: identity.applicationId, applicationRef: identity.applicationRef,
      buildId: identity.buildId, buildHash: identity.buildHash,
      platform: identity.platform, environment: identity.environment ?? "PRODUCTION",
      toolSlug: "mobile-platform-analysis",
    });
    for (const a of posture.controlAssessments) {
      if (!this.controlAssessments.some((x) => x.frameworkKey === a.frameworkKey && x.controlId === a.controlId && x.subjectRef === a.subjectRef)) {
        this.controlAssessments.push({ ...a });
      }
    }
    return { findings: posture.findings.length, assessments: this.controlAssessments.length - before };
  }

  async evaluateMobileQualityGate(): Promise<{ status: string; failedRules: number; warningRules: number } | null> {
    const identity = this.mobileIdentity();
    if (!identity) return null;
    const canonical = this.correlatedFindings.length > 0 ? this.correlatedFindings : this.findings;
    const mobile = canonical.filter(isMobileProcessedFinding);
    if (mobile.length === 0 && this.findings.length === 0) return null;
    const kev = new Set(this.mobileFixtures.kevCves ?? []);
    const summary = summarizeMobileForGate(mobile.map((f) => ({
      severity: f.severity,
      ...(f.mobileFindingType ? { mobileFindingType: f.mobileFindingType } : {}),
      ...(f.ruleId ? { ruleId: f.ruleId } : {}),
      ...(f.secret ? { secretVerified: f.secret.verificationStatus === "VERIFIED_ACTIVE" } : {}),
      ...(f.cve ? { kevListed: kev.has(f.cve) } : {}),
    })));
    const evaluation = evaluateMobileSecurityGate(summary);
    this.mobileGateRecord = { status: evaluation.status, failedRules: evaluation.failedRules, warningRules: evaluation.warningRules };
    return { status: evaluation.status, failedRules: evaluation.failedRules.length, warningRules: evaluation.warningRules.length };
  }

  /** Prompt 18: the scan's binary identity when an artifact is registered. */
  private binaryIdentity(): BinaryScanIdentity | null {
    const fx = this.binaryFixtures;
    if (this.targetType !== "BINARY" || !fx.artifactId || !fx.artifactHash) return null;
    return {
      artifactId: fx.artifactId,
      artifactHash: fx.artifactHash,
      artifactName: fx.artifactName ?? "fixture-binary",
      format: fx.format ?? "ELF",
      ...(fx.architecture ? { architecture: fx.architecture } : {}),
      ...(fx.environment ? { environment: fx.environment } : {}),
    };
  }

  /** Prompt 18 binary persistence mirror (§12–§52): inventory merges
   *  by identity key; fixture intel matches create dependency
   *  findings (the fake "local dataset", mirroring the Prisma
   *  store's CPE/CVE correlation); nothing is executed. */
  private persistBinary(processed: ProcessedResult): { findings: number } {
    const payload = processed.binary;
    const has = payload.sections.length + payload.functions.length + payload.imports.length + payload.exports.length
      + payload.symbols.length + payload.dependencies.length + payload.hardening.length + payload.strings.length > 0;
    if (!has || this.targetType !== "BINARY" || !this.binaryFixtures.artifactId) return { findings: 0 };
    const mergeBy = <T,>(list: T[], items: T[], key: (x: T) => string) => {
      for (const item of items) {
        const idx = list.findIndex((x) => key(x) === key(item));
        if (idx >= 0) list[idx] = item; else list.push(item);
      }
    };
    mergeBy(this.binaryData.sections, payload.sections, (s) => s.name);
    mergeBy(this.binaryData.functions, payload.functions, (f) => `${f.name}|${f.address ?? ""}`);
    mergeBy(this.binaryData.imports, payload.imports, (i) => `${i.library}|${i.symbol}`);
    mergeBy(this.binaryData.exports, payload.exports, (e) => e.symbol);
    mergeBy(this.binaryData.symbols, payload.symbols, (s) => s.name);
    mergeBy(this.binaryData.dependencies, payload.dependencies, (d) => d.library);
    mergeBy(this.binaryData.strings, payload.strings, (s) => `${s.value}|${s.category}`);
    mergeBy(this.binaryData.cryptoReferences, payload.cryptoReferences, (c) => `${c.kind}|${c.name}`);
    for (const h of payload.hardening) {
      const existing = this.binaryData.hardening.find((x) => x.name === h.name);
      if (!existing) this.binaryData.hardening.push(h);
      else if (existing.status === "UNKNOWN" || h.status !== "UNKNOWN") Object.assign(existing, h);
    }
    for (const r of payload.discoveredReferences) {
      if (!this.binaryData.discoveredReferences.some((x) => x.value === r.value)) this.binaryData.discoveredReferences.push(r);
    }
    if (payload.sha256) this.binaryData.sha256 = payload.sha256;
    if (payload.format !== "UNKNOWN") this.binaryData.format = payload.format;
    // Fixture intel correlation (local dataset only, §27/§49).
    let created = 0;
    for (const match of this.binaryFixtures.intelMatches ?? []) {
      const component = processed.components.find((c) => c.purl === match.purl);
      if (!component) continue;
      const fingerprint = `intel:${match.purl}:${match.cveId}`;
      if (this.findings.some((f) => f.fingerprint === fingerprint)) continue;
      this.findings.push({
        fingerprint, title: `${component.name} ${component.version ?? ""} is affected by ${match.cveId}`.trim(),
        description: `Local intelligence dataset match for binary dependency ${match.purl} (fixture dataset).`,
        severity: match.severity as never, confidence: 0.8, sources: ["intel-dataset"], sourceTool: "intel-dataset",
        evidenceSummary: "", evidenceRows: [], riskScore: match.cvssScore * 10, riskBand: "HIGH",
        riskExplanation: [], confidenceBand: "MEDIUM", verificationStatus: "UNVERIFIED",
        cve: match.cveId, cvssScore: match.cvssScore, componentPurl: match.purl,
        componentName: component.name, ...(component.version ? { componentVersion: component.version } : {}),
        binaryArtifactId: this.binaryFixtures.artifactId, binaryArtifactHash: this.binaryFixtures.artifactHash,
        binaryFindingType: "BINARY_DEPENDENCY_VULNERABILITY", binaryComponent: match.purl,
        binaryReachability: "UNKNOWN", staticConfidence: "MEDIUM",
      } as unknown as ProcessedResult["findings"][number]);
      created++;
    }
    return { findings: created };
  }

  /** Prompt 18 platform hooks mirroring the Prisma store (§6/§64/§90). */
  async validateBinaryArtifact(): Promise<{ artifactHash: string; format: string } | null> {
    const identity = this.binaryIdentity();
    if (!identity) return null;
    return { artifactHash: identity.artifactHash, format: identity.format };
  }

  async extractBinaryMetadata(): Promise<{ sections: number; functions: number; dependencies: number; secrets: number; componentsScanned: number } | null> {
    const identity = this.binaryIdentity();
    if (!identity) return null;
    const segment = this.binaryFixtures.headerSegment;
    if (!segment) return null;
    const report = parseBinaryHeaders(segment);
    const sectionOf = (offset: number) => report.sections.find((s) => offset >= s.offset && offset < s.offset + s.size)?.name;
    const strings = extractBinaryStrings(segment, { source: "binary-platform-analysis", sectionOf });
    const analysis = analyzeBinaryPlatform({
      artifactName: identity.artifactName, sha256: identity.artifactHash, sizeBytes: segment.length,
      report, strings, environment: identity.environment ?? "PRODUCTION",
    });
    const processedExtracted = processNormalizedResult({
      assets: [], services: [], endpoints: [], technologies: [], findings: analysis.findings,
      artifacts: [], metrics: {}, mock: false, components: analysis.components, binary: analysis.data,
    }, { scopeRules: TEST_SCOPE, toolExecutionId: "platform-binary-metadata", toolSlug: "binary-platform-analysis" });
    await this.persistResult("scan-1", "platform-binary-metadata", processedExtracted);
    return {
      sections: analysis.data.sections.length, functions: analysis.data.functions.length,
      dependencies: analysis.data.dependencies.length,
      secrets: analysis.findings.filter((f) => f.binaryFindingType === "BINARY_SECRET").length,
      componentsScanned: analysis.components.length,
    };
  }

  async inventoryBinaryDependencies(): Promise<{ components: number } | null> {
    if (!this.binaryIdentity()) return null;
    if (this.binaryData.dependencies.length === 0) return null;
    return { components: this.components.length };
  }

  async generateBinarySbom(): Promise<{ format: string; checksum: string; components: number } | null> {
    if (!this.binaryIdentity()) return null;
    if (this.binarySbomRecord) return { format: this.binarySbomRecord.format, checksum: this.binarySbomRecord.checksum, components: this.binarySbomRecord.componentCount };
    if (this.components.length === 0) return null;
    const doc = buildCycloneDxSbom(this.components, {
      snapshotHash: this.binaryFixtures.artifactHash ?? "fixture", repositoryName: this.binaryFixtures.artifactName ?? "fixture-binary",
      timestamp: new Date().toISOString(),
    }).sbom;
    this.binarySbomRecord = { format: doc.format, checksum: doc.checksum, componentCount: doc.componentCount };
    return { format: doc.format, checksum: doc.checksum, components: doc.componentCount };
  }

  async evaluateBinaryDebugSession(): Promise<{ status: string; reason?: string } | null> {
    const identity = this.binaryIdentity();
    if (!identity) return null;
    const session = this.binaryFixtures.debugSession;
    if (!session) return null;
    if (session.status === "BLOCKED") return { status: "BLOCKED", reason: "session blocked by policy" };
    const decision = evaluateBinaryDebugPolicy({
      environment: session.environment ?? identity.environment ?? "LAB",
      artifactAuthorized: true, targetVerified: true,
      requestedBy: session.requestedBy,
      ...(session.approvedBy ? { approvedBy: session.approvedBy } : {}),
      // Eligibility is a POLICY question; transport provisioning is
      // resolved separately below — none is provisioned in this
      // build, so an ELIGIBLE session reports NOT_PROVISIONED (§72).
      workerCapabilityPresent: true,
      killSwitchActive: this.binaryFixtures.killSwitchActive ?? false,
      operations: [{ operation: "START_APPROVED_FIXTURE" }],
    });
    if (decision.decision === "BLOCKED") return { status: "BLOCKED", reason: decision.reasons[0] ?? "policy" };
    if (decision.decision === "PENDING_APPROVAL") return { status: "PENDING_APPROVAL", reason: decision.reasons[0] ?? "approval" };
    return { status: "NOT_PROVISIONED", reason: "eligible session, but no BINARY_DYNAMIC_LAB debugger transport is provisioned in this build (§72)" };
  }

  async evaluateBinaryQualityGate(): Promise<{ status: string; failedRules: number; warningRules: number } | null> {
    if (!this.binaryIdentity()) return null;
    const canonical = this.correlatedFindings.length > 0 ? this.correlatedFindings : this.findings;
    const binary = canonical.filter(isBinaryProcessedFinding);
    if (binary.length === 0 && this.findings.length === 0) return null;
    const failed: string[] = [];
    const warnings: string[] = [];
    if (binary.some((f) => f.severity === "CRITICAL")) failed.push("NO_CRITICAL_BINARY_FINDINGS");
    if (binary.some((f) => f.binaryFindingType === "BINARY_SECRET")) failed.push("NO_EMBEDDED_SECRETS");
    if (binary.some((f) => f.binaryFindingType === "BINARY_HARDENING_FINDING" && f.severity === "HIGH")) warnings.push("HARDENING_GAPS_REVIEWED");
    const status = failed.length > 0 ? "FAILED" : warnings.length > 0 ? "PASSED_WITH_WARNINGS" : "PASSED";
    this.binaryGateRecord = { status, failedRules: failed, warningRules: warnings };
    return { status, failedRules: failed.length, warningRules: warnings.length };
  }

  /** Prompt 19: the scan's wireless identity when an environment is registered. */
  private wirelessIdentity(): WirelessScanIdentity | null {
    const fx = this.wirelessFixtures;
    if (this.targetType !== "WIRELESS_LAB" || !fx.environmentId) return null;
    return { environmentId: fx.environmentId, environmentRef: fx.environmentRef ?? "wireless-fixture" };
  }

  /** Prompt 19 wireless persistence mirror (§5–§10/§54): inventory
   *  merges by BSSID / address fingerprint (multi-sensor dedup);
   *  adapter security events join the environment event set. */
  private persistWireless(processed: ProcessedResult): { findings: number } {
    const payload = processed.wireless;
    const has = payload.accessPoints.length + payload.stations.length + payload.observations.length
      + payload.channelObservations.length + payload.securityEvents.length > 0 || payload.framesProcessed > 0;
    if (!has || this.targetType !== "WIRELESS_LAB" || !this.wirelessFixtures.environmentId) return { findings: 0 };
    this.wirelessData = mergeWirelessData([this.wirelessData, payload]);
    this.wirelessSecurityEvents.push(...payload.securityEvents);
    return { findings: 0 };
  }

  /** Prompt 19 platform hooks mirroring the Prisma store (§3/§60). */
  async validateWirelessEnvironment(): Promise<{ environmentId: string; environmentRef?: string } | null> {
    const identity = this.wirelessIdentity();
    if (!identity) return null;
    return { environmentId: identity.environmentId, environmentRef: identity.environmentRef };
  }

  async analyzeWirelessPosture(): Promise<{ findings: number; events: number; drift: number; accessPoints: number } | null> {
    const identity = this.wirelessIdentity();
    if (!identity) return null;
    const ctx = {
      environmentId: identity.environmentId,
      environmentKind: this.wirelessFixtures.environmentKind ?? "CORPORATE",
      approvedProfiles: (this.wirelessFixtures.approvedProfiles ?? []) as unknown as ApprovedWirelessProfileShape[],
      sourceTool: "wireless-posture",
    };
    const analysis = analyzeWirelessPosture(this.wirelessData, ctx);
    const previous = (this.wirelessFixtures.previousAccessPoints ?? []) as unknown as NormalizedWirelessAccessPoint[];
    const driftResult = previous.length > 0
      ? detectWirelessDrift(previous, this.wirelessData.accessPoints, ctx)
      : { drift: [], findings: [], events: [] };
    let created = 0;
    for (const finding of [...analysis.findings, ...driftResult.findings]) {
      const processed = processNormalizedResult({
        assets: [], services: [], endpoints: [], technologies: [], findings: [finding],
        artifacts: [], metrics: {}, mock: false,
      }, { scopeRules: TEST_SCOPE, toolExecutionId: "platform-wireless-posture", toolSlug: "wireless-posture" });
      for (const f of processed.findings) {
        if (!this.findings.some((x) => x.fingerprint === f.fingerprint)) { this.findings.push(f); created++; }
      }
    }
    // Adapter events already joined at persist time; posture + drift
    // events are new (§47/§56).
    const postureEvents = [...analysis.events.filter((e) => e.source === "wireless-posture" || e.type === "ROGUE_AP_SUSPECTED" || e.type === "APPROVED_AP_MISSING"), ...driftResult.events];
    this.wirelessSecurityEvents.push(...postureEvents);
    if (!this.wirelessDriftComputed) {
      this.wirelessDriftComputed = true;
      this.wirelessDriftRecords.push(...driftResult.drift.map((d) => ({ kind: d.kind, bssid: d.bssid, field: d.field, fromValue: d.fromValue, toValue: d.toValue, securityDowngrade: d.securityDowngrade })));
    }
    return { findings: created, events: postureEvents.length, drift: driftResult.drift.length, accessPoints: this.wirelessData.accessPoints.length };
  }

  async evaluateWirelessQualityGate(): Promise<{ status: string; failedRules: number; warningRules: number } | null> {
    const identity = this.wirelessIdentity();
    if (!identity) return null;
    if (this.wirelessData.accessPoints.length === 0 && this.findings.length === 0) return null;
    const canonical = this.correlatedFindings.length > 0 ? this.correlatedFindings : this.findings;
    const gate = evaluateWirelessGate(this.wirelessData.accessPoints, canonical as never, {
      environmentId: identity.environmentId,
      environmentKind: this.wirelessFixtures.environmentKind ?? "CORPORATE",
      approvedProfiles: (this.wirelessFixtures.approvedProfiles ?? []) as unknown as ApprovedWirelessProfileShape[],
    });
    this.wirelessGateRecord = { status: gate.status, failedRules: gate.failedRules, warningRules: gate.warningRules };
    return { status: gate.status, failedRules: gate.failedRules.length, warningRules: gate.warningRules.length };
  }

  /** Prompt 16/17 (§92): active kill switches for the dynamic gate. */
  async activeKillSwitches(): Promise<Array<{ level: string; organizationId?: string | null; workspaceId?: string | null; scopeRef?: string | null; active: boolean }>> {
    return (this.mobileFixtures.killSwitches ?? []).map((s) => ({
      level: s.level, active: s.active,
      // Fixture switches bind to the fixture workspace unless a
      // scopeRef says otherwise (mirrors the Prisma rows' columns).
      ...(s.level === "WORKSPACE" ? { workspaceId: "ws-1" } : {}),
      ...(s.scopeRef ? { scopeRef: s.scopeRef } : {}),
    }));
  }

  /** Prompt 15 directory persistence mirror (§13–§19/§57–§79). */
  private persistDirectory(processed: ProcessedResult): { users: number; groups: number; computers: number; relationships: number; findings: number } {
    const payload = processed.directory;
    const has = payload.users.length + payload.groups.length + payload.computers.length + payload.domainControllers.length
      + payload.relationships.length + payload.smbShares.length + payload.certificateAuthorities.length + payload.certificateTemplates.length > 0 || !!payload.snapshot;
    if (!has || this.targetType !== "ACTIVE_DIRECTORY_DOMAIN" || !this.directoryFixtures.domainId) {
      return { users: 0, groups: 0, computers: 0, relationships: 0, findings: 0 };
    }
    const mergeBy = <T,>(list: T[], items: T[], key: (x: T) => string) => {
      for (const item of items) {
        const idx = list.findIndex((x) => key(x) === key(item));
        if (idx >= 0) list[idx] = item; else list.push(item);
      }
    };
    if (payload.domain) this.directoryData.domain = payload.domain;
    if (payload.passwordPolicy) this.directoryData.passwordPolicy = payload.passwordPolicy;
    mergeBy(this.directoryData.domainControllers, payload.domainControllers, (d) => d.hostname);
    mergeBy(this.directoryData.users, payload.users, (u) => u.objectId);
    mergeBy(this.directoryData.groups, payload.groups, (g) => g.objectId);
    mergeBy(this.directoryData.computers, payload.computers, (c) => c.objectId);
    mergeBy(this.directoryData.organizationalUnits, payload.organizationalUnits, (o) => o.objectId);
    mergeBy(this.directoryData.groupPolicies, payload.groupPolicies, (g) => g.objectId);
    mergeBy(this.directoryData.trusts, payload.trusts, (t) => t.targetDomainName);
    mergeBy(this.directoryData.relationships, payload.relationships, (r) => `${r.fromType}|${r.fromRef}|${r.relationship}|${r.toType}|${r.toRef}`);
    mergeBy(this.directoryData.smbShares, payload.smbShares, (x) => `${x.host}/${x.shareName}`);
    mergeBy(this.directoryData.certificateAuthorities, payload.certificateAuthorities, (c) => c.name);
    mergeBy(this.directoryData.certificateTemplates, payload.certificateTemplates, (t) => t.name);
    if (payload.snapshot) this.directorySnapshots.push({ snapshotHash: payload.snapshot.snapshotHash, collectionProfile: payload.snapshot.collectionProfile });
    if (!this.directoryDriftComputed && this.directoryFixtures.previousData) {
      this.directoryDriftComputed = true;
      this.adDrift.push(...diffDirectorySnapshots(this.directoryFixtures.previousData, this.directoryData, this.directoryFixtures.domainRef ?? "corp.example")
        .map((e) => ({ kind: e.kind, ...(e.objectRef ? { objectRef: e.objectRef } : {}), detail: e.detail })));
    }
    const posture = analyzeDirectoryPosture(this.directoryData, {
      domainId: this.directoryFixtures.domainId, domainRef: this.directoryFixtures.domainRef ?? "corp.example",
      toolSlug: "directory-platform-analysis",
    });
    const fresh = posture.findings.filter((f) => !this.findings.some((x) => x.fingerprint === f.sourceFingerprint));
    if (fresh.length > 0) {
      const processedFindings = processNormalizedResult({
        assets: [], services: [], endpoints: [], technologies: [], findings: fresh,
        artifacts: [], metrics: {}, mock: false,
      }, { scopeRules: TEST_SCOPE, toolExecutionId: "platform-directory-analysis", toolSlug: "directory-platform-analysis" });
      this.findings.push(...processedFindings.findings);
    }
    for (const a of posture.controlAssessments) {
      if (!this.controlAssessments.some((x) => x.frameworkKey === a.frameworkKey && x.controlId === a.controlId && x.subjectRef === a.subjectRef)) {
        this.controlAssessments.push({ ...a });
      }
    }
    return {
      users: payload.users.length, groups: payload.groups.length,
      computers: payload.computers.length, relationships: payload.relationships.length,
      findings: fresh.length,
    };
  }

  /** Prompt 12 platform hooks mirroring the Prisma store (§19). */
  async acquireSourceSnapshot(): Promise<{ snapshotHash: string; files: number; sourceKind: string } | null> {
    if (this.targetType !== "SOURCE_REPOSITORY") return null;
    const files = this.sourceFixtures.files ?? FIXTURE_SOURCE_FILES;
    const manifests = this.sourceFixtures.manifests ?? FIXTURE_MANIFEST_CONTENTS;
    const hash = createHash("sha256").update(JSON.stringify(files.map((f) => [f.path, f.sizeBytes]))).digest("hex");
    this.sourceSnapshot = { id: "snap-1", repositoryId: "repo-1", hash, files, manifests };
    return { snapshotHash: hash, files: files.length, sourceKind: "LOCAL_SOURCE_SNAPSHOT" };
  }

  async detectSourceLanguages(): Promise<{ languages: number; primaryLanguage?: string; frameworks: number; buildSystems: number } | null> {
    if (!this.sourceSnapshot) return null;
    const det = detectRepository(this.sourceSnapshot.files, this.sourceSnapshot.manifests);
    this.sourceLanguages = det.languages.map((l) => l.language);
    return { languages: det.languages.length, primaryLanguage: det.primaryLanguage, frameworks: det.frameworks.length, buildSystems: det.buildSystems.length };
  }

  async inventorySourceDependencies(): Promise<{ components: number; manifests: number } | null> {
    if (!this.sourceSnapshot) return null;
    const parsed = parseManifests(this.sourceSnapshot.manifests);
    for (const c of parsed) if (!this.components.some((x) => x.purl === c.purl)) this.components.push(c);
    return { components: parsed.length, manifests: Object.keys(this.sourceSnapshot.manifests).length };
  }

  async generateSourceSbom(): Promise<{ format: string; checksum: string; components: number } | null> {
    if (!this.sourceSnapshot) return null;
    const { sbom } = buildCycloneDxSbom(this.components, {
      snapshotHash: this.sourceSnapshot.hash, repositoryName: "fixture-repo", timestamp: new Date().toISOString(),
    });
    this.sbomRecord = { format: sbom.format, checksum: sbom.checksum, componentCount: sbom.componentCount };
    return { format: sbom.format, checksum: sbom.checksum, components: sbom.componentCount };
  }

  async evaluateSourceQualityGate(): Promise<{ status: string; failedRules: number; warningRules: number } | null> {
    if (this.targetType !== "SOURCE_REPOSITORY") return null;
    const canonical = this.correlatedFindings.length > 0 ? this.correlatedFindings : this.findings;
    if (canonical.length === 0 && this.findings.length === 0) return null;
    // Baseline classification (§79) against the previous snapshot.
    const previous = this.sourceFixtures.previousFingerprints ?? [];
    if (previous.length > 0) {
      const { statuses } = classifyBaseline(canonical.map((f) => ({ sourceFingerprint: f.fingerprint })), previous);
      for (const f of canonical) f.baselineStatus = statuses.get(f.fingerprint);
    }
    const evaluation = evaluateQualityGate(summarizeForQualityGate(canonical), DEFAULT_QUALITY_GATE_POLICY);
    this.qualityGateRecord = { status: evaluation.status, failedRules: evaluation.failedRules, warningRules: evaluation.warningRules };
    return { status: evaluation.status, failedRules: evaluation.failedRules.length, warningRules: evaluation.warningRules.length };
  }

  /** Prompt 13 platform hooks mirroring the Prisma store (§5/§75/§78). */
  async resolveContainerImage(): Promise<{ imageRef: string; digest?: string; drift?: boolean; skipped?: boolean } | null> {
    if (this.targetType !== "CONTAINER_IMAGE") {
      // A CLOUD_NATIVE_FULL scan over a cluster/host target carries no
      // image context — the stage completes without work.
      return { imageRef: "", skipped: true };
    }
    const imageRef = this.cloudFixtures.imageRef;
    if (!imageRef) return null;
    const digest = this.cloudFixtures.imageDigest;
    const drift = !!this.cloudFixtures.previousDigest && !!digest && this.cloudFixtures.previousDigest !== digest;
    this.imageSnapshots.push({ imageRef, ...(digest ? { digest } : {}), ...(this.cloudFixtures.previousDigest ? { previousDigest: this.cloudFixtures.previousDigest } : {}), drift });
    if (digest && !this.images.some((i) => i.digest === digest)) {
      const [registryHost, rest] = imageRef.includes("/") ? [imageRef.slice(0, imageRef.indexOf("/")), imageRef.slice(imageRef.indexOf("/") + 1)] : ["docker.io", imageRef];
      this.images.push({ registry: registryHost, repository: rest.split(":")[0]!.split("@")[0]!, ...(rest.includes(":") ? { tag: rest.split(":")[1]!.split("@")[0] } : {}), digest, source: "IMAGE_RESOLUTION" });
    }
    return { imageRef, ...(digest ? { digest } : {}), drift };
  }

  async evaluateContainerQualityGate(): Promise<{ status: string; failedRules: number; warningRules: number } | null> {
    const isCloudScan = ["CONTAINER_IMAGE", "KUBERNETES_CLUSTER", "DOCKER_HOST"].includes(this.targetType);
    if (!isCloudScan) return null;
    const canonical = this.correlatedFindings.length > 0 ? this.correlatedFindings : this.findings;
    const result = evaluateContainerQualityGate({
      findings: canonical.map((f) => ({
        severity: f.severity as never, ...(f.cve ? { cve: f.cve } : {}), ...(f.origin ? { origin: f.origin as never } : {}),
        ...(f.secret ? { secret: f.secret } : {}), ...(f.controlId ? { controlId: f.controlId } : {}), ...(f.resourceKind ? { resourceKind: f.resourceKind } : {}),
      })),
      kevCves: this.cloudFixtures.kevCves ?? [],
    });
    this.containerQualityGateRecord = { status: result.status, failedRules: result.failedRules, warningRules: result.warningRules };
    return { status: result.status, failedRules: result.failedRules.length, warningRules: result.warningRules.length };
  }

  /** Prompt 14 platform hooks mirroring the Prisma store (§9/§36–§70). */
  async validateCloudAccount(): Promise<{ status: string; provider?: string } | null> {
    if (!["AWS", "AZURE", "GCP"].includes(this.targetType)) return null;
    if (!this.cloudSecFixtures.accountId) return null;
    if (!this.cloudSecFixtures.credentialReference) {
      this.cloudAccountStatus = "NOT_CONFIGURED";
      return { status: "NOT_CONFIGURED", provider: this.cloudSecFixtures.provider };
    }
    this.cloudAccountStatus = "VALIDATED";
    return { status: "VALIDATED", provider: this.cloudSecFixtures.provider };
  }

  async analyzeCloudSection(_scanId: string, section: string): Promise<{ findings: number; assessments: number } | null> {
    if (!["AWS", "AZURE", "GCP"].includes(this.targetType) || !this.cloudSecFixtures.accountId) return null;
    const resources = this.cloudResources.filter((r) => r.scopeStatus === "IN_SCOPE").map(({ scopeStatus: _s, ...r }) => r);
    const identities = this.cloudIdentities;
    if (resources.length === 0 && identities.length === 0) return null;
    const ctx = {
      provider: (this.cloudSecFixtures.provider ?? "AWS") as "AWS" | "AZURE" | "GCP",
      accountId: this.cloudSecFixtures.accountId,
      accountRef: this.cloudSecFixtures.accountRef ?? "",
      ...(this.cloudSecFixtures.environment ? { environment: this.cloudSecFixtures.environment } : {}),
      toolSlug: "cloud-platform-analysis",
    };
    let result: { findings: import("@zerosweep/security-sdk").NormalizedFinding[]; controlAssessments: import("@zerosweep/security-sdk").NormalizedControlAssessment[] } | null = null;
    if (section === "IAM_ANALYSIS") result = analyzeIam(identities, ctx);
    else if (section === "STORAGE_ANALYSIS") {
      const a = analyzeStorage(resources, ctx);
      const b = analyzeDatabases(resources, ctx);
      result = { findings: [...a.findings, ...b.findings], controlAssessments: [...a.controlAssessments, ...b.controlAssessments] };
    }
    else if (section === "NETWORK_ANALYSIS") result = analyzeNetwork(resources, ctx);
    else if (section === "ENCRYPTION_ANALYSIS") result = analyzeEncryption(resources, ctx);
    else if (section === "LOGGING_ANALYSIS") result = analyzeLogging(resources, ctx);
    if (!result) return null;
    const fresh = result.findings.filter((f) => !this.findings.some((x) => x.fingerprint === f.sourceFingerprint));
    if (fresh.length > 0) {
      const processed = processNormalizedResult({
        assets: [], services: [], endpoints: [], technologies: [], findings: fresh,
        artifacts: [], metrics: {}, mock: false,
      }, { scopeRules: TEST_SCOPE, toolExecutionId: "platform-cloud-analysis", toolSlug: "cloud-platform-analysis" });
      this.findings.push(...processed.findings);
    }
    this.controlAssessments.push(...result.controlAssessments.map((a) => ({ ...a })));
    return { findings: fresh.length, assessments: result.controlAssessments.length };
  }

  async assessCloudCompliance(): Promise<{ assessed: number; failed: number; drift: number; riskPaths: number } | null> {
    if (!["AWS", "AZURE", "GCP"].includes(this.targetType) || !this.cloudSecFixtures.accountId) return null;
    const resources = this.cloudResources.filter((r) => r.scopeStatus === "IN_SCOPE").map(({ scopeStatus: _s, ...r }) => r);
    const paths = buildCloudRiskPaths({
      resources, relationships: this.cloudRelationships,
      findings: (this.correlatedFindings.length > 0 ? this.correlatedFindings : this.findings) as never,
    });
    for (const p of paths) if (!this.cloudRiskPaths.some((x) => x.title === p.title)) this.cloudRiskPaths.push(p);
    return {
      assessed: this.controlAssessments.length,
      failed: this.controlAssessments.filter((a) => a.status === "FAIL").length,
      drift: this.cloudDrift.length, riskPaths: paths.length,
    };
  }

  async evaluateCloudQualityGate(): Promise<{ status: string; failedRules: number; warningRules: number } | null> {
    if (!["AWS", "AZURE", "GCP"].includes(this.targetType)) return null;
    const canonical = this.correlatedFindings.length > 0 ? this.correlatedFindings : this.findings;
    const resources = this.cloudResources.filter((r) => r.scopeStatus === "IN_SCOPE").map(({ scopeStatus: _s, ...r }) => r);
    const byProviderId = new Map(resources.map((r) => [r.providerResourceId, r]));
    const result = evaluateCloudSecurityGate({
      findings: canonical.map((f) => ({
        severity: f.severity, findingClass: f.findingClass,
        exposureClass: f.providerResourceId ? byProviderId.get(f.providerResourceId)?.exposure : undefined,
        resourceType: f.providerResourceId ? byProviderId.get(f.providerResourceId)?.resourceType : f.cloudResourceType,
        kevListed: false,
      })),
      auditLoggingEnabled: auditLoggingEnabled(resources),
    });
    this.cloudGateRecord = { status: result.status, failedRules: result.failedRules, warningRules: result.warningRules };
    return { status: result.status, failedRules: result.failedRules.length, warningRules: result.warningRules.length };
  }

  async cloudScanProvider(): Promise<string | null> {
    return this.cloudSecFixtures.provider ?? null;
  }

  /** Prompt 10 platform hook mirroring the Prisma store: bounded target
   *  expansion over the scan's CIDR target (§5/§62). */
  async expandNetworkTargets(): Promise<{ mode: string; hosts: number; chunks: number; totalHosts: number } | null> {
    const value = this.networkTarget?.targetValue;
    if (!value) return null;
    const verdict = new CidrPolicyService().evaluate(value, { administratorApproved: false });
    if (verdict && verdict.approval === "DENY") {
      return { mode: "DENIED", hosts: 0, chunks: 0, totalHosts: verdict.hostCount };
    }
    const expansion = expandCidrTargets(value);
    if (!expansion) return null;
    this.networkChunks = expansion.chunks.map((c) => ({ chunkId: c.chunkId, rangeStart: c.rangeStart, rangeEnd: c.rangeEnd, hostCount: c.hostCount, status: "PENDING" }));
    return expansion.kind === "LIST"
      ? { mode: "LIST", hosts: expansion.hosts.length, chunks: expansion.chunks.length, totalHosts: expansion.hosts.length }
      : { mode: "RANGES", hosts: 0, chunks: expansion.chunks.length, totalHosts: expansion.totalHosts };
  }

  /** Prompt 9 platform hooks mirroring the Prisma store's behaviour. */
  async consolidateApiServices(): Promise<{ services: number; endpoints: number } | null> {
    if (this.apiServices.length === 0 && this.endpoints.length === 0) return null;
    return { services: this.apiServices.length, endpoints: this.endpoints.length };
  }

  async summarizeApiSpecifications(): Promise<{ specifications: number; operations: number } | null> {
    const specs = this.apiFixtures.specifications ?? [];
    if (specs.length === 0) return null;
    return { specifications: specs.length, operations: specs.reduce((n, s) => n + s.operations, 0) };
  }

  async mapApiAuthentication(): Promise<{ contexts: number; servicesWithAuth: number } | null> {
    const contexts = this.apiFixtures.authContexts ?? [];
    const servicesWithAuth = this.apiServices.filter((s) => s.authenticationType && s.authenticationType !== "NONE").length;
    if (contexts.length === 0 && servicesWithAuth === 0) return null;
    return { contexts: contexts.length, servicesWithAuth };
  }

  async analyzeJwtProfiles(): Promise<{ tokens: number; findings: number } | null> {
    const tokens = this.apiFixtures.jwtTokens ?? [];
    if (tokens.length === 0) return null;
    const adapter = new JwtToolAdapter();
    const parsed = adapter.inspectTokens({ tokens, host: "example.com" });
    const normalized = await adapter.normalize(parsed);
    const processed = processNormalizedResult(normalized, { scopeRules: TEST_SCOPE, toolExecutionId: "platform-jwt", toolSlug: "jwt-tool" });
    this.jwtProfiles.push(...processed.jwtProfiles);
    this.findings.push(...processed.findings);
    return { tokens: processed.jwtProfiles.length, findings: processed.findings.length };
  }

  async inventoryWebSockets(): Promise<{ webSockets: number; authenticated: number } | null> {
    if (this.webSockets.length === 0) return null;
    return { webSockets: this.webSockets.length, authenticated: this.webSockets.filter((w) => w.authPresent).length };
  }

  // ── Prompt 15 platform hooks mirroring the Prisma store ──────────

  /** DOMAIN_DISCOVERY (§9/§12): the registered fixture domain
   *  validates only when a credential REFERENCE is configured. */
  async validateDirectoryDomain(): Promise<{ status: string; domainRef?: string } | null> {
    if (this.targetType !== "ACTIVE_DIRECTORY_DOMAIN") return null;
    if (!this.directoryFixtures.domainId) return null;
    if (!this.directoryFixtures.credentialReference) {
      this.directoryDomainStatus = "NOT_CONFIGURED";
      return { status: "NOT_CONFIGURED", domainRef: this.directoryFixtures.domainRef };
    }
    this.directoryDomainStatus = "VALIDATED";
    return { status: "VALIDATED", domainRef: this.directoryFixtures.domainRef };
  }

  /** LDAP_POSTURE (§70/§71): the analyzer slice over the persisted
   *  fixture inventory; findings already joined at collection time. */
  async analyzeDirectoryLdapPosture(): Promise<{ findings: number; assessments: number } | null> {
    if (this.targetType !== "ACTIVE_DIRECTORY_DOMAIN" || this.directoryData.domainControllers.length === 0) return null;
    const findings = analyzeLdapPosture(this.directoryData, {
      domainId: this.directoryFixtures.domainId ?? "fixture-domain-1",
      domainRef: this.directoryFixtures.domainRef ?? "corp.example",
      toolSlug: "directory-platform-analysis",
    });
    const present = findings.filter((f) => this.findings.some((x) => x.fingerprint === f.sourceFingerprint)).length;
    return { findings: present, assessments: this.controlAssessments.length };
  }

  /** GRAPH_COLLECTION (§32/§65): graph build over the fixture
   *  inventory — counts, privileged principals, drift events. */
  async buildDirectoryGraph(): Promise<{ nodes: number; edges: number; privileged: number; drift: number } | null> {
    if (this.targetType !== "ACTIVE_DIRECTORY_DOMAIN") return null;
    if (this.directoryData.users.length + this.directoryData.groups.length + this.directoryData.computers.length === 0) return null;
    const domainRef = this.directoryFixtures.domainRef ?? "corp.example";
    const graph = buildIdentityGraph(this.directoryData, domainRef);
    const resolution = resolveNestedGroups(graph, this.directoryData.groups);
    const privileged = privilegedPrincipals(this.directoryData, graph, resolution);
    return { nodes: graph.nodes.size, edges: graph.edges.length, privileged: privileged.size, drift: this.adDrift.length };
  }

  /** ATTACK_PATH_ANALYSIS (§34–§37): model defensive paths over the
   *  fixture graph — analysis results only, never executed, never
   *  labelled COMPROMISED. */
  async analyzeAttackPaths(): Promise<{ paths: number; findings: number } | null> {
    if (this.targetType !== "ACTIVE_DIRECTORY_DOMAIN" || this.directoryData.relationships.length === 0) return null;
    const domainRef = this.directoryFixtures.domainRef ?? "corp.example";
    const graph = buildIdentityGraph(this.directoryData, domainRef);
    const resolution = resolveNestedGroups(graph, this.directoryData.groups);
    const paths = findAttackPaths(this.directoryData, graph, resolution, {}, domainRef);
    for (const p of paths) {
      if (!this.attackPaths.some((x) => x.title === p.title)) {
        this.attackPaths.push({ title: p.title, status: p.status, riskScore: p.riskScore });
      }
    }
    return { paths: this.attackPaths.length, findings: 0 };
  }
  async recordDeadLetter(entry: unknown): Promise<void> { this.deadLetters.push(entry); }
}
