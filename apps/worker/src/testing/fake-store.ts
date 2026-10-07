import {
  CidrPolicyService, DEFAULT_QUALITY_GATE_POLICY, FIXTURE_MANIFEST_CONTENTS, FIXTURE_SOURCE_FILES,
  JwtToolAdapter, MockSecurityAdapter, ToolRegistry, analyzeDatabases, analyzeEncryption, analyzeIam, analyzeLogging, analyzeNetwork, analyzeStorage, auditLoggingEnabled, buildCloudRiskPaths, buildCycloneDxSbom, classifyBaseline,
  detectRepository, diffCloudInventories, evaluateCloudSecurityGate, evaluateContainerQualityGate, evaluateQualityGate, expandCidrTargets, parseManifests, summarizeForQualityGate,
  type NormalizedCloudIdentity, type NormalizedCloudResource, type SourceFileEntry,
} from "@dsrclone/security-sdk";
import { createHash } from "node:crypto";
import { buildScanPlan, type ScanPlan, type ScanEventRecord } from "@dsrclone/orchestration";
import type { ScopeRules } from "@dsrclone/validation";
import type { ExecutionContextRecord } from "../executors/stage-executor";
import type { ScanRunRecord, ScanRunStore } from "../consumers/dag-runner";
import { correlateProcessedFindings, processNormalizedResult, type ProcessedCloudResource, type ProcessedComponent, type ProcessedResult } from "../executors/result-processor";

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
  targetType?: "DOMAIN" | "WEB_APPLICATION" | "API" | "GRAPHQL" | "CIDR" | "IP_ADDRESS" | "SOURCE_REPOSITORY" | "CONTAINER_IMAGE" | "KUBERNETES_CLUSTER" | "DOCKER_HOST" | "AWS" | "AZURE" | "GCP";
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
  targetType: "DOMAIN" | "WEB_APPLICATION" | "API" | "GRAPHQL" | "CIDR" | "IP_ADDRESS" | "SOURCE_REPOSITORY" | "CONTAINER_IMAGE" | "KUBERNETES_CLUSTER" | "DOCKER_HOST" | "AWS" | "AZURE" | "GCP";

  // (constructor assigns targetType from opts)

  constructor(profile: "PASSIVE_RECON" | "WEB_BASELINE" | "WEB_COMPREHENSIVE" | "API_ASSESSMENT" | "NETWORK_DISCOVERY" | "NETWORK_BASELINE" | "NETWORK_COMPREHENSIVE" | "NETWORK_INTERNAL" | "NETWORK_ASSESSMENT" | "SOURCE_BASELINE" | "SOURCE_COMPREHENSIVE" | "SECRETS_ONLY" | "DEPENDENCIES_ONLY" | "SAST_ONLY" | "CONTAINER_BASELINE" | "CONTAINER_COMPREHENSIVE" | "SBOM_ONLY" | "IMAGE_VULNERABILITIES_ONLY" | "CONTAINER_MISCONFIG_ONLY" | "KUBERNETES_BASELINE" | "KUBERNETES_COMPREHENSIVE" | "DOCKER_HOST_BASELINE" | "CLOUD_NATIVE_FULL" | "CLOUD_INVENTORY" | "CLOUD_BASELINE" | "CLOUD_COMPREHENSIVE" | "IAM_REVIEW" | "PUBLIC_EXPOSURE_REVIEW" | "COMPLIANCE_ASSESSMENT" | "IAC_TO_CLOUD_CORRELATION" | "CLOUD", opts: FakeStoreOptions = {}) {
    this.targetType = opts.targetType ?? "DOMAIN";
    this.scannerBySlug = opts.scannerBySlug ?? {};
    this.apiFixtures = opts.apiFixtures ?? {};
    this.sourceFixtures = opts.sourceFixtures ?? {};
    this.cloudFixtures = opts.cloudFixtures ?? {};
    this.cloudSecFixtures = opts.cloudSecFixtures ?? {};
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
  async persistResult(_scanId: string, _executionId: string, processed: ProcessedResult): Promise<{ assets: number; findings: number; endpoints: number; services: number; technologies: number; parameters: number; forms: number; transactions: number; webSockets: number; apiServices: number; graphqlServices: number; jwtProfiles: number; packetCaptures: number; components: number }> {
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
    return { assets: processed.assets.length, findings: processed.findings.length, endpoints: processed.endpoints.length, services: processed.services.length, technologies: processed.technologies.length, parameters: processed.parameters.length, forms: processed.forms.length, transactions: processed.transactions.length, webSockets: processed.webSockets.length, apiServices: processed.apiServices.length, graphqlServices: processed.graphqlServices.length, jwtProfiles: processed.jwtProfiles.length, packetCaptures: processed.packetCaptures.length, components: processed.components.length };
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
    let result: { findings: import("@dsrclone/security-sdk").NormalizedFinding[]; controlAssessments: import("@dsrclone/security-sdk").NormalizedControlAssessment[] } | null = null;
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
  async recordDeadLetter(entry: unknown): Promise<void> { this.deadLetters.push(entry); }
}
