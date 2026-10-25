import {
  ALL_DIRECTORY_SLUGS, API_SLUGS, BINARY_SLUGS, CLOUD_NATIVE_SLUGS, CLOUD_SEC_SLUGS, CODE_SLUGS, DIRECTORY_SLUGS, MOBILE_DYNAMIC_SLUGS, MOBILE_SLUGS, MOBILE_STATIC_SLUGS, NETWORK_SLUGS, NmapAdapter, NucleiAdapter, PRIVILEGED_CLOUD_SLUGS, PROXY_SLUGS, RECON_SLUGS, VULN_SCANNER_SLUGS, VULN_SLUGS, WEB_DISCOVERY_SLUGS, WIRELESS_SLUGS, WIRELESS_TOOL_STAGES, ScopeMatcher, ToolRegistry,
  activeKillSwitch, approvedNseIdsForProfile, approvedReviewIdsForProfile, evaluateToolPolicy, isKubernetesConnector, isScannerConnectorAdapter, isSonarQubeAdapter, isVulnScannerAdapter, resolveSemgrepPacks, type AuthorizationContext, type KillSwitchContext, type KillSwitchRecord,
} from "@zerosweep/security-sdk";
import type { ScopeRules } from "@zerosweep/validation";
import {
  assertExecutionTransition, classifyError, evaluateAuthorizationGate,
  idempotencyKey, makeEvent, type ScanEventRecord,
} from "@zerosweep/orchestration";
import { InMemoryObjectStore, rawArtifactKey, type ObjectStore } from "../artifacts/object-store";
import { S3ObjectStore } from "../artifacts/s3-object-store";
import { processNormalizedResult, type ProcessedResult } from "./result-processor";

/**
 * Stage executor (Prompt 4 §20): the worker — never the API — runs adapters.
 * It loads TRUSTED state through the store (queue payloads carry IDs only,
 * §14), re-evaluates authorization + scope + policy immediately before
 * execution (§11–§12), runs the adapter lifecycle, stores the raw artifact in
 * object storage, parses, normalizes, and persists through the store.
 * Executable adapters: the Phase 4 mock/local-echo pair, the Prompt 5
 * recon adapters (subfinder … katana) and the Prompt 6 web-discovery
 * adapters (ffuf, feroxbuster, gobuster, wfuzz, arjun). Real adapters run
 * ONLY through their validated plans and only when their binary is
 * actually present — otherwise policy denies with TOOL_UNAVAILABLE and
 * orchestration degrades the capability instead of crashing (§55–§56).
 */

export const EXECUTABLE_SLUGS = ["mock", "local-echo", ...RECON_SLUGS, ...WEB_DISCOVERY_SLUGS, ...VULN_SLUGS, ...PROXY_SLUGS, ...API_SLUGS, ...NETWORK_SLUGS, ...VULN_SCANNER_SLUGS, ...CODE_SLUGS, ...CLOUD_NATIVE_SLUGS, ...CLOUD_SEC_SLUGS, ...ALL_DIRECTORY_SLUGS, ...MOBILE_SLUGS, ...BINARY_SLUGS, ...WIRELESS_SLUGS] as const;

/** Prompt 18 §10: binary-only slugs (checksec / radare2). "ghidra" is
 *  shared with the mobile family — its binary mode is selected by the
 *  scan's binary context, never by the slug alone. */
export const BINARY_ONLY_SLUGS = ["checksec", "radare2"] as const;

/** Prompt 15 §10/§15: directory connectors resolve a registered domain
 *  through the store context — they never take an endpoint or a
 *  credential from a plan. */
export const DIRECTORY_CONNECTOR_SLUGS = DIRECTORY_SLUGS.connectors;

/** Prompt 14 §10/§21: cloud connectors resolve a registered account
 *  through the store context — they never take an endpoint or a
 *  credential from anywhere else. */
export const CLOUD_CONNECTOR_SLUGS = ["aws-inventory", "azure-inventory", "gcp-inventory", "cloudmapper", "roadtools"] as const;

/** Slugs whose execution requires the worker to hold the local layer-2
 *  capability (Prompt 10 §65) — meaningless and denied anywhere else. */
export const LOCAL_DISCOVERY_SLUGS = ["netdiscover", "arp-scan"] as const;

export interface ExecutionContextRecord {
  executionId: string;
  scanId: string;
  stageId: string; // stage TYPE (plan stage id)
  workspaceId: string;
  organizationId: string;
  adapterSlug: string;
  status: string;
  attempt: number;
  timeoutSeconds: number;
  targetType: string;
  targetValue: string;
  targetHost: string;
  scopeRules: ScopeRules;
  auth: AuthorizationContext;
  targetExists: boolean;
  targetWorkspaceId: string;
  targetVerified: boolean;
  assessmentApproved: boolean;
  assessmentCreatedBy: string;
  assessmentApprovedBy: string | null;
  scopeValid: boolean;
  networkCapable: boolean;
  /** Discovery inputs produced by earlier stages (Prompt 5 §26): in-scope
   *  asset hostnames and endpoint URLs, loaded from persisted state by the
   *  store — never from queue payloads. Adapters receive only the fields
   *  their declared input schema accepts. */
  stageInputs?: {
    hosts: string[]; urls: string[]; technologies?: string[]; services?: string[];
    /** Prompt 9: imported specification locations + imported operations
     *  (encoded "METHOD path operationId?"), loaded by the store from the
     *  guarded import records — never from queue payloads (§15). */
    specUrls?: string[]; operations?: string[];
  };
  /** The scan's assessment profile (from the persisted plan) — drives
   *  Prompt 6 wordlist profile selection: WEB_BASELINE → SMALL, anything
   *  broader → STANDARD. COMPREHENSIVE is never selected automatically. */
  profile?: string;
  /** The scan's assessment id (trusted state, for connector context
   *  binding — Prompt 8 §6). */
  assessmentId?: string;
  /** Prompt 8 scanner binding, resolved by the STORE from admin-registered
   *  ScannerInstance rows for this workspace — never from queue payloads
   *  or client input (§16/§17). Absent instanceId = NOT_CONFIGURED. */
  scanner?: { instanceId?: string; sessionProfileId?: string };
  /** Prompt 10 §19/§20: Masscan runs ONLY under a recorded administrator
   *  approval resolved by the store from platform policy state — never
   *  from queue payloads or client input. Absent/false = denied. */
  masscanApproved?: boolean;
  /** Prompt 10 §45: the authorized packet-capture artifact reference this
   *  execution may analyze (store-resolved from PacketCaptureArtifact
   *  rows for this scan — never client input). */
  captureRef?: string;
  /** Prompt 12: the scan's source snapshot context, resolved by the
   *  STORE from SourceRepository/SourceSnapshot rows — the workspace
   *  path tools analyze, the repository identity fingerprints use, and
   *  the languages the detection stage found. Never client input. */
  source?: {
    repositoryId?: string;
    snapshotId?: string;
    workspacePath?: string;
    commitSha?: string;
    languages?: string[];
    sonarProjectKey?: string;
  };
  /** Prompt 13: the scan's cloud-native context, resolved by the STORE
   *  from ContainerImage / KubernetesCluster / DockerHost rows — the
   *  image reference + resolved digest, the cluster id (credential
   *  REFERENCE only, never a value) and the approved Docker host.
   *  Never client input (§12). */
  cloudNative?: {
    imageRef?: string;
    imageDigest?: string;
    imageId?: string;
    clusterId?: string;
    clusterRef?: string;
    hostRef?: string;
  };
  /** Prompt 14: the scan's multi-cloud context, resolved by the STORE
   *  from the registered CloudAccount row — account id, provider,
   *  provider-side reference, credential REFERENCE name (never a
   *  value) and the account scope's regions. Never client input (§10). */
  cloud?: {
    accountId?: string;
    accountRef?: string;
    provider?: string;
    credentialReference?: string;
    regions?: string[];
    excludeRegions?: string[];
    environment?: string;
    queryPack?: string;
  };
  /** Prompt 15: the scan's Active Directory context, resolved by the
   *  STORE from the registered ActiveDirectoryDomain row — domain id,
   *  DNS ref (fingerprint component), forest id, credential REFERENCE
   *  name (never a value) and the explicitly approved DC hosts (§11).
   *  Never client input. */
  directory?: {
    domainId?: string;
    domainRef?: string;
    forestId?: string;
    credentialReference?: string;
    identityKind?: string;
    dcHosts?: string[];
  };
  /** Prompt 17: the scan's mobile context, resolved by the STORE from
   *  the registered MobileApplication / MobileBuild rows — application
   *  + build identity (the artifact SHA-256, §5), the artifact
   *  reference, and the APPROVED lab session ids for dynamic stages
   *  (§58/§73). Never client input. */
  mobile?: {
    applicationId?: string;
    applicationRef?: string;
    platform?: string;
    environment?: string;
    buildId?: string;
    buildHash?: string;
    artifactReference?: string;
    deviceId?: string;
    dynamicSessionId?: string;
    dynamicSessionApproved?: boolean;
    trafficSessionId?: string;
  };
  /** Prompt 18: the scan's binary context, resolved by the STORE from
   *  the registered BinaryArtifact row — artifact identity (the
   *  SHA-256, §3), object-storage reference, format and environment
   *  (§64: debug eligibility reads the environment). Never client
   *  input. */
  binary?: {
    artifactId?: string;
    artifactHash?: string;
    artifactReference?: string;
    artifactName?: string;
    format?: string;
    environment?: string;
  };
  /** Prompt 19: the scan's wireless context, resolved by the STORE
   *  from the registered WirelessEnvironment / WirelessSensor /
   *  WirelessCapture rows — environment identity (§3), the approved
   *  sensor (reference + interface, §12) and the approved capture
   *  artifact (§26). Never client input. No wireless context =
   *  NOT_CONFIGURED for sensor/capture-bound adapters. */
  wireless?: {
    environmentId?: string;
    environmentRef?: string;
    environmentKind?: string;
    sensorRef?: string;
    sensorInterface?: string;
    captureId?: string;
    captureReference?: string;
  };
  /** Deterministic test/simulation hooks (never set by clients). */
  simulation?: { delayMs?: number; failWith?: "TOOL_ERROR" | "TIMEOUT"; fixture?: boolean };
}

export interface ExecutionStore {
  loadExecutionContext(executionId: string): Promise<ExecutionContextRecord | null>;
  updateExecution(id: string, patch: Record<string, unknown>): Promise<void>;
  recordEvent(event: ScanEventRecord): Promise<void>;
  persistResult(scanId: string, executionId: string, processed: ProcessedResult): Promise<{ assets: number; findings: number; endpoints?: number; services?: number; technologies?: number; parameters?: number; forms?: number; transactions?: number; webSockets?: number; apiServices?: number; graphqlServices?: number; jwtProfiles?: number; packetCaptures?: number; components?: number; directoryUsers?: number; directoryGroups?: number; directoryComputers?: number; directoryRelationships?: number; attackPaths?: number }>;
  recordDeadLetter(entry: { jobId: string; queue: string; scanId: string; stageId: string; executionId: string; errorCategory: string; errorMessage: string; attempts: number }): Promise<void>;
  isCancelled(scanId: string): Promise<boolean>;
  /** Prompt 16/17 (§92): active kill switches for the mobile dynamic
   *  gate — optional: stores that do not implement it leave the gate
   *  to the session-approval checks. */
  activeKillSwitches?(ctx: KillSwitchContext): Promise<KillSwitchRecord[]>;
}

export interface StageJobData {
  kind: "STAGE_EXECUTION";
  scanId: string;
  stageId: string;
  toolExecutionId: string;
  attempt: number;
}

export type StageExecutionOutcome =
  | { status: "COMPLETED"; assets: number; findings: number }
  | { status: "PARTIAL_DATA" } // synthesized by the DAG runner when some adapters of a stage completed (§55)
  | { status: "ALREADY_COMPLETED" }
  | { status: "DENIED"; reasonCode: string }
  | { status: "CANCELLED" }
  | { status: "FAILED" | "TIMED_OUT"; category: string };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Prompt 10 §23/§24/§65: process-level worker capabilities the executor
 *  gates privileged adapters on. They come from the worker's own
 *  deployment configuration (env), never from job payloads: a general
 *  worker simply does not hold LOCAL_LAYER2_ACCESS or PACKET_CAPTURE. */
export interface StageExecutorOptions {
  workerCapabilities?: string[];
}

export class StageExecutor {
  private readonly objectStore: ObjectStore;
  private readonly workerCapabilities: string[];

  constructor(
    private readonly registry: ToolRegistry,
    private readonly store: ExecutionStore,
    objectStore?: ObjectStore,
    options: StageExecutorOptions = {},
  ) {
    // Prompt 38 §58: when S3-compatible object storage is configured in
    // the worker's environment, artifacts go there; otherwise the
    // labelled in-memory store (tests / local dev without infra).
    this.objectStore = objectStore ?? S3ObjectStore.fromEnv() ?? new InMemoryObjectStore();
    this.workerCapabilities = options.workerCapabilities ?? [];
  }

  async run(job: StageJobData): Promise<StageExecutionOutcome> {
    const ctx = await this.store.loadExecutionContext(job.toolExecutionId);
    if (!ctx) return { status: "FAILED", category: "CONFIGURATION" };
    const emit = (type: ScanEventRecord["type"], payload: ScanEventRecord["payload"]) =>
      this.store.recordEvent(makeEvent(ctx.scanId, ctx.workspaceId, type, payload));

    // Idempotency (§15): a duplicate delivery of a finished execution is a no-op.
    if (ctx.status === "COMPLETED") return { status: "ALREADY_COMPLETED" };
    if (await this.store.isCancelled(ctx.scanId)) {
      await this.transition(ctx, "CANCELLING").catch(() => undefined);
      await this.store.updateExecution(ctx.executionId, { status: "CANCELLED", completedAt: new Date() });
      return { status: "CANCELLED" };
    }

    try {
      await this.transition(ctx, "PREPARING");

      // --- Gates, re-evaluated with trusted state (§11–§12) ---
      const gate = evaluateAuthorizationGate({
        auth: ctx.auth, targetHost: ctx.targetHost, scopeRules: ctx.scopeRules,
        targetExists: ctx.targetExists, targetWorkspaceId: ctx.targetWorkspaceId, workspaceId: ctx.workspaceId,
        targetVerified: ctx.targetVerified, assessmentApproved: ctx.assessmentApproved, scopeValid: ctx.scopeValid,
        assessmentCreatedBy: ctx.assessmentCreatedBy, assessmentApprovedBy: ctx.assessmentApprovedBy,
      });
      if (!gate.allowed) {
        await emit(gate.reasonCode === "TARGET_OUT_OF_SCOPE" ? "scope.violation" : "policy.denied", { stageId: ctx.stageId, reasonCode: gate.reasonCode });
        await this.failExecution(ctx, "POLICY", gate.message);
        return { status: "DENIED", reasonCode: gate.reasonCode };
      }

      const adapter = this.registry.resolve(ctx.adapterSlug);
      if (!adapter || !EXECUTABLE_SLUGS.includes(ctx.adapterSlug as (typeof EXECUTABLE_SLUGS)[number])) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "ADAPTER_DISABLED" });
        await this.failExecution(ctx, "POLICY", `Adapter ${ctx.adapterSlug} is not executable in this phase`);
        return { status: "DENIED", reasonCode: "ADAPTER_DISABLED" };
      }
      // Prompt 8 (§16/§66): a scanner connector executes ONLY against an
      // admin-registered instance resolved for THIS workspace by the
      // store. No instance → NOT_CONFIGURED → TOOL_UNAVAILABLE denial;
      // the DAG degrades the stage instead of inventing scanner output.
      const isVulnScanner = isVulnScannerAdapter(adapter);
      const isSonar = isSonarQubeAdapter(adapter);
      const isK8sConnector = isKubernetesConnector(adapter);
      const isConnector = isScannerConnectorAdapter(adapter) || isVulnScanner || isSonar;
      // Defense in depth (§37/§38): proxy connectors execute ONLY in the
      // passive stage; Prompt 11 vulnerability scanners execute ONLY in
      // the network profiles' SAFE_VULNERABILITY_SCAN stage (§84);
      // Prompt 12's SonarQube connector executes ONLY in the SAST stage
      // (§23) — and the ACTIVE stage stays approval-gated in a later phase.
      if (isConnector && ctx.stageId !== "PASSIVE_SECURITY_ANALYSIS" && !(isVulnScanner && ctx.stageId === "SAFE_VULNERABILITY_SCAN") && !(isSonar && ctx.stageId === "SAST")) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "ADAPTER_DISABLED" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: scanner connectors execute only in their governed stage (proxy: PASSIVE_SECURITY_ANALYSIS; vulnerability scanners: SAFE_VULNERABILITY_SCAN; sonarqube: SAST)`);
        return { status: "DENIED", reasonCode: "ADAPTER_DISABLED" };
      }
      if (isConnector && !ctx.scanner?.instanceId) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "TOOL_UNAVAILABLE" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: no scanner instance is configured for this workspace (NOT_CONFIGURED)`);
        return { status: "DENIED", reasonCode: "TOOL_UNAVAILABLE" };
      }
      // Prompt 13 gates (§28/§34/§39): the Kubernetes connector executes
      // ONLY in the inventory/posture stages and only against a cluster
      // the STORE resolved for this scan (absent = NOT_CONFIGURED);
      // INTERNAL_PRIVILEGED benchmark adapters (Docker Bench /
      // kube-bench) additionally require THIS worker to hold the
      // PRIVILEGED_HOST_ASSESSMENT capability — a general worker denies
      // them even inside an approved assessment.
      if (isK8sConnector && ctx.stageId !== "CLUSTER_INVENTORY" && ctx.stageId !== "KUBERNETES_POSTURE") {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "ADAPTER_DISABLED" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: the Kubernetes connector executes only in CLUSTER_INVENTORY / KUBERNETES_POSTURE (§34)`);
        return { status: "DENIED", reasonCode: "ADAPTER_DISABLED" };
      }
      if (isK8sConnector && !ctx.cloudNative?.clusterId) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "TOOL_UNAVAILABLE" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: no Kubernetes cluster is registered for this scan (NOT_CONFIGURED)`);
        return { status: "DENIED", reasonCode: "TOOL_UNAVAILABLE" };
      }
      // Prompt 14 gates (§9/§10): cloud adapters run ONLY on
      // CLOUD_ANALYSIS workers (cloud credentials are issued only
      // there), and cloud connectors additionally require the store to
      // have resolved a registered account for this scan — absent =
      // NOT_CONFIGURED → TOOL_UNAVAILABLE, never a fabricated run.
      const isCloudSecAdapter = (CLOUD_SEC_SLUGS as readonly string[]).includes(ctx.adapterSlug);
      const isCloudConnector = (CLOUD_CONNECTOR_SLUGS as readonly string[]).includes(ctx.adapterSlug);
      if (isCloudSecAdapter && !this.workerCapabilities.includes("CLOUD_ANALYSIS")) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "UNAVAILABLE_FOR_WORKER" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: cloud assessment runs only on CLOUD_ANALYSIS workers (§10) — this worker does not hold CLOUD_ANALYSIS`);
        return { status: "DENIED", reasonCode: "UNAVAILABLE_FOR_WORKER" };
      }
      if (isCloudConnector && !ctx.cloud?.accountId) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "TOOL_UNAVAILABLE" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: no cloud account is registered for this scan (NOT_CONFIGURED)`);
        return { status: "DENIED", reasonCode: "TOOL_UNAVAILABLE" };
      }
      // Prompt 15 gates (§10/§11/§15): directory adapters run ONLY on
      // DIRECTORY_ANALYSIS workers (directory credentials are leased
      // only there, and only approved internal workers may contact a
      // domain), and directory connectors additionally require the
      // store to have resolved a registered domain for this scan —
      // absent = NOT_CONFIGURED → TOOL_UNAVAILABLE, never fabricated.
      const isDirectoryAdapter = (ALL_DIRECTORY_SLUGS as readonly string[]).includes(ctx.adapterSlug);
      const isDirectoryConnector = (DIRECTORY_CONNECTOR_SLUGS as readonly string[]).includes(ctx.adapterSlug);
      if (isDirectoryAdapter && !this.workerCapabilities.includes("DIRECTORY_ANALYSIS")) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "UNAVAILABLE_FOR_WORKER" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: Active Directory assessment runs only on DIRECTORY_ANALYSIS workers (§10) — this worker does not hold DIRECTORY_ANALYSIS`);
        return { status: "DENIED", reasonCode: "UNAVAILABLE_FOR_WORKER" };
      }
      if (isDirectoryConnector && !ctx.directory?.domainId) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "TOOL_UNAVAILABLE" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: no Active Directory domain is registered for this scan (NOT_CONFIGURED)`);
        return { status: "DENIED", reasonCode: "TOOL_UNAVAILABLE" };
      }
      // Prompt 17 gates (§10/§14/§58/§73/§92): the two mobile worker
      // capabilities stay SEPARATE — static adapters run ONLY on
      // MOBILE_STATIC_ANALYSIS workers in the static/binary stages;
      // the MobSF connector additionally requires the admin-registered
      // instance the store resolved (absent = NOT_CONFIGURED); dynamic
      // lab adapters run ONLY on MOBILE_DYNAMIC_ANALYSIS workers in
      // the dynamic/traffic stages, only with an APPROVED lab session
      // resolved by the store, and never under an active kill switch.
      // Prompt 18: "ghidra" is shared — on a scan WITH a binary context
      // the binary gates below own it; the mobile gates own it only on
      // mobile scans (store-resolved context, never client input).
      const isMobileStatic = (MOBILE_STATIC_SLUGS as readonly string[]).includes(ctx.adapterSlug) && !ctx.binary?.artifactId;
      const isMobileDynamic = (MOBILE_DYNAMIC_SLUGS as readonly string[]).includes(ctx.adapterSlug);
      if (isMobileStatic && !["MOBILE_STATIC_ANALYSIS", "MOBILE_BINARY_ANALYSIS"].includes(ctx.stageId)) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "ADAPTER_DISABLED" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: mobile static adapters execute only in MOBILE_STATIC_ANALYSIS / MOBILE_BINARY_ANALYSIS (§10)`);
        return { status: "DENIED", reasonCode: "ADAPTER_DISABLED" };
      }
      if (isMobileStatic && !this.workerCapabilities.includes("MOBILE_STATIC_ANALYSIS")) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "UNAVAILABLE_FOR_WORKER" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: mobile static analysis runs only on MOBILE_STATIC_ANALYSIS workers (§10) — this worker does not hold MOBILE_STATIC_ANALYSIS`);
        return { status: "DENIED", reasonCode: "UNAVAILABLE_FOR_WORKER" };
      }
      if (isMobileStatic && !ctx.mobile?.buildId) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "TOOL_UNAVAILABLE" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: no mobile build is registered for this scan (NOT_CONFIGURED)`);
        return { status: "DENIED", reasonCode: "TOOL_UNAVAILABLE" };
      }
      if (ctx.adapterSlug === "mobsf" && !ctx.scanner?.instanceId) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "TOOL_UNAVAILABLE" });
        await this.failExecution(ctx, "POLICY", "mobsf: no MobSF ScannerInstance is registered for this workspace (NOT_CONFIGURED, §14)");
        return { status: "DENIED", reasonCode: "TOOL_UNAVAILABLE" };
      }
      if (isMobileDynamic && !["MOBILE_DYNAMIC_SESSION", "MOBILE_TRAFFIC_ANALYSIS"].includes(ctx.stageId)) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "ADAPTER_DISABLED" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: mobile lab adapters execute only in MOBILE_DYNAMIC_SESSION / MOBILE_TRAFFIC_ANALYSIS (§58)`);
        return { status: "DENIED", reasonCode: "ADAPTER_DISABLED" };
      }
      if (isMobileDynamic && !this.workerCapabilities.includes("MOBILE_DYNAMIC_ANALYSIS")) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "UNAVAILABLE_FOR_WORKER" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: mobile dynamic analysis runs only on MOBILE_DYNAMIC_ANALYSIS workers (§10) — this worker does not hold MOBILE_DYNAMIC_ANALYSIS`);
        return { status: "DENIED", reasonCode: "UNAVAILABLE_FOR_WORKER" };
      }
      if (isMobileDynamic && ctx.mobile?.dynamicSessionApproved !== true) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "TOOL_UNAVAILABLE" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: no APPROVED dynamic lab session exists for this scan (NOT_CONFIGURED, §58/§73)`);
        return { status: "DENIED", reasonCode: "TOOL_UNAVAILABLE" };
      }
      if (isMobileDynamic && this.store.activeKillSwitches) {
        const switches = await this.store.activeKillSwitches({
          organizationId: ctx.organizationId, workspaceId: ctx.workspaceId,
          scanId: ctx.scanId, targetId: ctx.auth.targetId,
          ...(ctx.mobile?.dynamicSessionId ? { sessionId: ctx.mobile.dynamicSessionId } : {}),
        }).catch(() => []);
        const active = activeKillSwitch(switches, {
          organizationId: ctx.organizationId, workspaceId: ctx.workspaceId,
          scanId: ctx.scanId, targetId: ctx.auth.targetId,
          ...(ctx.mobile?.dynamicSessionId ? { sessionId: ctx.mobile.dynamicSessionId } : {}),
        });
        if (active) {
          await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "KILL_SWITCH_ACTIVE" });
          await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: a ${active.level} kill switch is active — dynamic work is terminated (§92)`);
          return { status: "DENIED", reasonCode: "KILL_SWITCH_ACTIVE" };
        }
      }
      // Prompt 18 gates (§9/§10): binary static adapters run ONLY on
      // BINARY_STATIC_ANALYSIS workers, ONLY in the hardening/static
      // stages, and ONLY against a store-resolved registered artifact
      // (absent = NOT_CONFIGURED). The artifact is tool INPUT — no
      // gate here can ever turn it into the executable (§8/§100), and
      // GDB/pwndbg/Cutter/IDA/Binary Ninja have no adapter at all
      // (§35–§39/§64–§66), so no job can reach them.
      const isBinaryStatic = (BINARY_ONLY_SLUGS as readonly string[]).includes(ctx.adapterSlug)
        || (ctx.adapterSlug === "ghidra" && Boolean(ctx.binary?.artifactId));
      if (isBinaryStatic && !["BINARY_HARDENING_ANALYSIS", "BINARY_STATIC_ANALYSIS"].includes(ctx.stageId)) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "ADAPTER_DISABLED" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: binary static adapters execute only in BINARY_HARDENING_ANALYSIS / BINARY_STATIC_ANALYSIS (§10)`);
        return { status: "DENIED", reasonCode: "ADAPTER_DISABLED" };
      }
      if (isBinaryStatic && !this.workerCapabilities.includes("BINARY_STATIC_ANALYSIS")) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "UNAVAILABLE_FOR_WORKER" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: binary static analysis runs only on BINARY_STATIC_ANALYSIS workers (§9/§10) — this worker does not hold BINARY_STATIC_ANALYSIS`);
        return { status: "DENIED", reasonCode: "UNAVAILABLE_FOR_WORKER" };
      }
      if (isBinaryStatic && !ctx.binary?.artifactId) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "TOOL_UNAVAILABLE" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: no binary artifact is registered for this scan (NOT_CONFIGURED)`);
        return { status: "DENIED", reasonCode: "TOOL_UNAVAILABLE" };
      }
      // Prompt 19 gates (§13/§14/§64): wireless adapters run ONLY on
      // WIRELESS_PASSIVE_ANALYSIS workers, ONLY in the wireless tool
      // stages, and ONLY against store-resolved context — Kismet
      // needs a registered approved sensor, capture analysis needs a
      // registered approved capture (absent = NOT_CONFIGURED).
      // Wifite / hcxdumptool / Wireshark have no adapter at all
      // (§21/§22/§25), so no job can ever reach them.
      const isWireless = (WIRELESS_SLUGS as readonly string[]).includes(ctx.adapterSlug);
      if (isWireless && !(WIRELESS_TOOL_STAGES as readonly string[]).includes(ctx.stageId)) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "ADAPTER_DISABLED" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: wireless adapters execute only in WIRELESS_PASSIVE_DISCOVERY / WIRELESS_PCAP_ANALYSIS (§15)`);
        return { status: "DENIED", reasonCode: "ADAPTER_DISABLED" };
      }
      if (isWireless && !this.workerCapabilities.includes("WIRELESS_PASSIVE_ANALYSIS")) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "UNAVAILABLE_FOR_WORKER" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: wireless collection/analysis runs only on dedicated WIRELESS_PASSIVE_ANALYSIS sensor workers (§13/§14) — this worker does not hold it`);
        return { status: "DENIED", reasonCode: "UNAVAILABLE_FOR_WORKER" };
      }
      if (ctx.adapterSlug === "kismet" && !ctx.wireless?.sensorRef) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "TOOL_UNAVAILABLE" });
        await this.failExecution(ctx, "POLICY", "kismet: no approved wireless sensor is registered for this scan (NOT_CONFIGURED, §12)");
        return { status: "DENIED", reasonCode: "TOOL_UNAVAILABLE" };
      }
      if (isWireless && ctx.adapterSlug !== "kismet" && ctx.stageId === "WIRELESS_PCAP_ANALYSIS" && !ctx.wireless?.captureId && !ctx.wireless?.captureReference) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "TOOL_UNAVAILABLE" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: no approved wireless capture is registered for this scan (NOT_CONFIGURED, §26)`);
        return { status: "DENIED", reasonCode: "TOOL_UNAVAILABLE" };
      }
      if ((PRIVILEGED_CLOUD_SLUGS as readonly string[]).includes(ctx.adapterSlug)
        && !this.workerCapabilities.includes("PRIVILEGED_HOST_ASSESSMENT")) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "UNAVAILABLE_FOR_WORKER" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: INTERNAL_PRIVILEGED benchmark — this worker does not hold PRIVILEGED_HOST_ASSESSMENT (§28/§39)`);
        return { status: "DENIED", reasonCode: "UNAVAILABLE_FOR_WORKER" };
      }
      // Prompt 10 gates (§19/§20/§44/§65) — evaluated BEFORE health and
      // policy, because they are deployment/approval facts, not tool
      // health: Masscan needs a recorded administrator approval; local
      // layer-2 discovery needs this worker to actually hold
      // LOCAL_LAYER2_ACCESS; packet capture needs PACKET_CAPTURE.
      if (ctx.adapterSlug === "masscan" && ctx.masscanApproved !== true) {
        await emit("network.masscan_denied", { stageId: ctx.stageId, reasonCode: "MASSCAN_NOT_APPROVED" });
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "MASSCAN_NOT_APPROVED" });
        await this.failExecution(ctx, "POLICY", "masscan: high-speed discovery requires an explicit profile, administrator policy approval and strict rate limits (§19/§20) — no approval is recorded for this scan");
        return { status: "DENIED", reasonCode: "MASSCAN_NOT_APPROVED" };
      }
      if ((LOCAL_DISCOVERY_SLUGS as readonly string[]).includes(ctx.adapterSlug)
        && !this.workerCapabilities.includes("LOCAL_LAYER2_ACCESS")) {
        await emit("network.local_discovery_unavailable", { stageId: ctx.stageId, tool: ctx.adapterSlug, reasonCode: "UNAVAILABLE_FOR_WORKER" });
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "UNAVAILABLE_FOR_WORKER" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: local layer-2 discovery is UNAVAILABLE_FOR_WORKER — this worker does not hold LOCAL_LAYER2_ACCESS (§65)`);
        return { status: "DENIED", reasonCode: "UNAVAILABLE_FOR_WORKER" };
      }
      if (ctx.adapterSlug === "tcpdump" && !this.workerCapabilities.includes("PACKET_CAPTURE")) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "UNAVAILABLE_FOR_WORKER" });
        await this.failExecution(ctx, "POLICY", "tcpdump: packet capture is UNAVAILABLE_FOR_WORKER — this worker does not hold the PACKET_CAPTURE capability (§44)");
        return { status: "DENIED", reasonCode: "UNAVAILABLE_FOR_WORKER" };
      }
      // Real health (§2/§55): a recon adapter whose binary is absent is
      // denied by policy as TOOL_UNAVAILABLE — never executed, never faked.
      const toolHealthy = await adapter.checkAvailability().catch(() => false);
      const policy = evaluateToolPolicy({
        tool: adapter.metadata, toolEnabled: true, adapterEnabled: true, toolHealthy,
        targetType: ctx.targetType, targetHost: ctx.targetHost, auth: ctx.auth,
        scopeRules: ctx.scopeRules, availableCredentialRefs: [], currentConcurrency: 0, maxConcurrency: 4,
      });
      if (policy.decision !== "ALLOW") {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: policy.reasonCode });
        await this.failExecution(ctx, "POLICY", policy.message);
        return { status: "DENIED", reasonCode: policy.reasonCode };
      }

      // Scope matcher double-check for network-capable stages (§12).
      if (ctx.networkCapable && !new ScopeMatcher(ctx.scopeRules).isHostAllowed(ctx.targetHost)) {
        await emit("scope.violation", { stageId: ctx.stageId, reasonCode: "TARGET_OUT_OF_SCOPE" });
        await this.failExecution(ctx, "SCOPE", "Target host is outside the approved scope");
        return { status: "DENIED", reasonCode: "TARGET_OUT_OF_SCOPE" };
      }

      // --- Adapter lifecycle ---
      await this.store.updateExecution(ctx.executionId, { status: "RUNNING", startedAt: new Date() });
      ctx.status = "RUNNING";
      await emit("tool.started", { stageId: ctx.stageId, tool: ctx.adapterSlug });

      const target = { type: ctx.targetType as never, value: ctx.targetValue, host: ctx.targetHost };
      await adapter.validateTarget(target);
      // Adapter config is assembled ONLY from fields the adapter declares
      // (§11): the simulation fixture (mock) and the discovery inputs this
      // stage inherits from earlier stages (Prompt 5 §26).
      const declared = new Set((adapter.metadata.inputSchema ?? []).map((f) => f.name));
      const config: Record<string, unknown> = {};
      // Adapters WITH a declared schema get only declared fields (a recon
      // adapter must never see the simulation knob); schema-less legacy
      // adapters (mock) keep the Phase 4 fixture behaviour.
      if (ctx.simulation?.fixture && (declared.size === 0 || declared.has("fixture"))) config.fixture = "orchestration-e2e";
      if (ctx.stageInputs) {
        if (declared.has("hosts") && ctx.stageInputs.hosts.length > 0) config.hosts = ctx.stageInputs.hosts;
        if (declared.has("urls") && ctx.stageInputs.urls.length > 0) config.urls = ctx.stageInputs.urls;
        if (declared.has("technologies") && (ctx.stageInputs.technologies?.length ?? 0) > 0) config.technologies = ctx.stageInputs.technologies;
        if (declared.has("services") && (ctx.stageInputs.services?.length ?? 0) > 0) config.services = ctx.stageInputs.services;
      }
      // Prompt 7 derived configuration — worker-computed, never client
      // input (§4/§8/§52): Nuclei template approvals follow the PROFILE
      // (WEB_COMPREHENSIVE carries the pre-approved REVIEW_REQUIRED set;
      // baseline runs SAFE only), and rates default to the platform
      // budget's conservative values. The template snapshot chosen here is
      // frozen into the execution metrics below (§6).
      let templateSelection: { snapshot: unknown; selected: string[] } | undefined;
      if (declared.has("approvedTemplateIds")) {
        config.approvedTemplateIds = approvedReviewIdsForProfile(ctx.profile ?? "");
      }
      if (declared.has("requestsPerSecond")) config.requestsPerSecond = 50;
      if (declared.has("concurrency") && ctx.adapterSlug === "nuclei") config.concurrency = 10;
      if (adapter instanceof NucleiAdapter) {
        const sel = adapter.selectionFor(config);
        templateSelection = { snapshot: sel.snapshot, selected: sel.selected.map((t) => t.id) };
      }
      // Prompt 6 derived configuration — computed by the WORKER from the
      // persisted plan/stage, never accepted from clients (§12/§29):
      // wordlist profile follows the assessment profile (never
      // COMPREHENSIVE automatically), and wfuzz's template follows the
      // stage (parameter stage → PARAMETER template, else CONTENT).
      if (declared.has("wordlistProfile")) {
        // Prompt 9 §14/§39: the API baseline also stays SMALL — bigger
        // route lists are never auto-selected for baseline profiles.
        config.wordlistProfile = ctx.profile === "WEB_BASELINE" || ctx.profile === "API_ASSESSMENT" ? "SMALL" : "STANDARD";
      }
      // Prompt 9 derived configuration — worker-computed from the
      // guarded import store, never client input (§15): the schema
      // location Schemathesis tests against and the imported operations
      // its policy filter partitions. allowStateChanging is NEVER set
      // here: the baseline cannot execute state-changing operations.
      if (declared.has("schemaUrl") && (ctx.stageInputs?.specUrls?.length ?? 0) > 0) {
        config.schemaUrl = ctx.stageInputs!.specUrls![0];
      }
      if (declared.has("operations") && (ctx.stageInputs?.operations?.length ?? 0) > 0) {
        config.operations = ctx.stageInputs!.operations;
      }
      if (declared.has("template")) {
        config.template = ctx.stageId === "PARAMETER_DISCOVERY" ? "PARAMETER" : "CONTENT";
      }
      // Prompt 8 derived configuration — trusted worker state only (§6/
      // §16): the workspace's registered scanner instance + session
      // profile binding (store-resolved), tenancy ids for context
      // isolation, and the persisted scope snapshot the connector checks
      // its context against. Clients can supply none of this.
      if (isConnector) {
        if (declared.has("instanceId") && ctx.scanner?.instanceId) config.instanceId = ctx.scanner.instanceId;
        if (declared.has("sessionProfileId") && ctx.scanner?.sessionProfileId) config.sessionProfileId = ctx.scanner.sessionProfileId;
        if (declared.has("workspaceId")) config.workspaceId = ctx.workspaceId;
        if (declared.has("assessmentId") && ctx.assessmentId) config.assessmentId = ctx.assessmentId;
        if (declared.has("scanId")) config.scanId = ctx.scanId;
        if (declared.has("scopeIncludeHosts")) config.scopeIncludeHosts = ctx.scopeRules.includeHosts;
        if (declared.has("scopeExcludeHosts")) config.scopeExcludeHosts = ctx.scopeRules.excludeHosts;
        if (declared.has("scopeAllowedPorts")) config.scopeAllowedPorts = ctx.scopeRules.allowedPorts;
        if (declared.has("scopeAllowedPaths")) config.scopeAllowedPaths = ctx.scopeRules.allowedPaths;
        if (declared.has("scopeExcludedPaths")) config.scopeExcludedPaths = ctx.scopeRules.excludedPaths;
        // Prompt 11 §6/§12/§84: vulnerability scanners also receive the
        // scope CIDRs and the LOGICAL profile derived from the scan
        // profile — never a scanner policy id (admin config maps it).
        if (declared.has("scopeIncludeCidrs")) config.scopeIncludeCidrs = ctx.scopeRules.includeCidrs;
        if (declared.has("logicalProfile")) {
          config.logicalProfile = ctx.adapterSlug === "nessus-professional"
            ? (ctx.profile === "NETWORK_COMPREHENSIVE" ? "NETWORK_COMPREHENSIVE" : "NETWORK_BASELINE")
            : (ctx.profile === "NETWORK_COMPREHENSIVE" ? "COMPREHENSIVE" : "BASELINE");
        }
        if (!isSonar) await emit("passive_analysis.started", { stageId: ctx.stageId, tool: ctx.adapterSlug, instanceId: ctx.scanner?.instanceId ?? null });
      }
      // Prompt 10 derived configuration — worker-computed from the
      // persisted plan + profile, never client input (§8/§11/§13/§27):
      // Nmap's scan mode follows the STAGE, the port profile follows the
      // ASSESSMENT PROFILE (FULL_TCP is never derived), NSE approvals
      // follow the profile through the script policy, local discovery
      // gets the approved CIDR from the target, tshark gets the
      // store-resolved capture reference.
      let nseSelection: { snapshot: unknown; selected: string[] } | undefined;
      if (declared.has("scanMode")) {
        config.scanMode = ctx.stageId === "HOST_DISCOVERY" ? "HOST_DISCOVERY"
          : ctx.stageId === "SERVICE_DETECTION" ? "SERVICE"
          : ctx.stageId === "SAFE_NETWORK_CHECKS" ? "SAFE_CHECKS" : "PORT_SCAN";
      }
      if (declared.has("portProfile")) {
        config.portProfile = ctx.profile === "NETWORK_DISCOVERY" ? "WEB_COMMON"
          : ctx.profile === "NETWORK_COMPREHENSIVE" || ctx.profile === "NETWORK_INTERNAL" ? "STANDARD"
          : "COMMON_SERVICES";
      }
      if (declared.has("approvedScriptIds")) {
        config.approvedScriptIds = approvedNseIdsForProfile(ctx.profile ?? "");
      }
      if (declared.has("osDetection")) {
        config.osDetection = ctx.profile === "NETWORK_COMPREHENSIVE" || ctx.profile === "NETWORK_INTERNAL";
      }
      if (declared.has("networkRange") && ctx.targetType === "CIDR") {
        config.networkRange = ctx.targetValue;
      }
      if (declared.has("captureArtifactRef") && ctx.captureRef) {
        config.captureArtifactRef = ctx.captureRef;
      }
      if (adapter instanceof NmapAdapter) {
        const sel = adapter.scriptSelectionFor(config);
        nseSelection = { snapshot: sel.snapshot, selected: sel.selected };
      }
      // Prompt 12 derived configuration — worker-computed from the
      // scan's snapshot (store-resolved), never client input (§12):
      // snapshot path, repository identity, detected languages, the
      // governed Semgrep packs for the profile (§22), the bounded
      // history depth (§83), and the repository's SonarQube project key.
      // External secret verification is NEVER enabled here (§37/§44).
      if ((CODE_SLUGS as readonly string[]).includes(ctx.adapterSlug)) {
        if (declared.has("sourcePath") && ctx.source?.workspacePath) config.sourcePath = ctx.source.workspacePath;
        if (declared.has("repositoryId") && ctx.source?.repositoryId) config.repositoryId = ctx.source.repositoryId;
        const detectedLanguages = ctx.source?.languages;
        if (declared.has("languages") && detectedLanguages && detectedLanguages.length > 0) config.languages = detectedLanguages;
        if (declared.has("historyDepth")) config.historyDepth = 100;
        if (declared.has("rulePacks") && ctx.adapterSlug === "semgrep") {
          const profile = ctx.profile === "SOURCE_CODE" ? "SOURCE_BASELINE" : (ctx.profile ?? "SOURCE_BASELINE");
          config.rulePacks = resolveSemgrepPacks({ profile, languages: ctx.source?.languages ?? [] }).packs;
        }
        if (declared.has("externalVerification")) config.externalVerification = false;
        if (isSonar && declared.has("sonarProjectKey") && ctx.source?.sonarProjectKey) config.sonarProjectKey = ctx.source.sonarProjectKey;
      }
      // Prompt 13 derived configuration — worker-computed from the
      // scan's cloud-native context (store-resolved), never client
      // input (§12): image reference + resolved digest, cluster/host
      // references, Trivy's profile-derived scanner kinds and target
      // kind, Kubescape's mode, kube-hunter's mode (PASSIVE_DISCOVERY
      // is the ONLY mode ever derived, §43) and the connector's
      // stage-derived inventory mode.
      if ((CLOUD_NATIVE_SLUGS as readonly string[]).includes(ctx.adapterSlug) || ctx.adapterSlug === "grype") {
        if (declared.has("imageRef") && ctx.cloudNative?.imageRef) config.imageRef = ctx.cloudNative.imageRef;
        if (declared.has("imageDigest") && ctx.cloudNative?.imageDigest) config.imageDigest = ctx.cloudNative.imageDigest;
        if (declared.has("clusterRef") && ctx.cloudNative?.clusterRef) config.clusterRef = ctx.cloudNative.clusterRef;
        if (declared.has("hostRef") && ctx.cloudNative?.hostRef) config.hostRef = ctx.cloudNative.hostRef;
        if (declared.has("clusterId") && ctx.cloudNative?.clusterId) config.clusterId = ctx.cloudNative.clusterId;
        if (declared.has("sourcePath") && ctx.source?.workspacePath) config.sourcePath = ctx.source.workspacePath;
        if (ctx.adapterSlug === "trivy") {
          if (declared.has("scanKinds")) {
            config.scanKinds = ctx.profile === "CONTAINER_MISCONFIG_ONLY" ? ["config"]
              : ctx.profile === "IMAGE_VULNERABILITIES_ONLY" ? ["vuln", "secret"]
                : ["vuln", "config", "secret"];
          }
          if (declared.has("scanTarget")) config.scanTarget = ctx.profile === "CONTAINER_MISCONFIG_ONLY" ? "fs" : "image";
        }
        if (ctx.adapterSlug === "kubescape" && declared.has("scanMode")) {
          config.scanMode = ctx.stageId === "MANIFEST_SCAN" ? "manifests" : "cluster";
        }
        if (ctx.adapterSlug === "kube-hunter" && declared.has("hunterMode")) {
          config.hunterMode = "PASSIVE_DISCOVERY";
        }
        if (isK8sConnector && declared.has("inventoryMode")) {
          config.inventoryMode = ctx.stageId === "CLUSTER_INVENTORY" ? "CLUSTER_INVENTORY" : "POSTURE_ASSESSMENT";
        }
      }
      // Prompt 14 derived configuration — worker-computed from the
      // scan's cloud account context (store-resolved), never client
      // input (§10): account id + provider-side reference + provider,
      // the credential REFERENCE name (the value is resolved inside
      // this worker boundary only, §6/§11), the account scope regions,
      // and the governed Steampipe pack when the scan selected one.
      if ((CLOUD_SEC_SLUGS as readonly string[]).includes(ctx.adapterSlug)) {
        const cloudCtx = ctx.cloud;
        if (cloudCtx) {
          if (declared.has("cloudAccountId") && cloudCtx.accountId) config.cloudAccountId = cloudCtx.accountId;
          if (declared.has("cloudAccountRef") && cloudCtx.accountRef) config.cloudAccountRef = cloudCtx.accountRef;
          if (declared.has("cloudProvider") && cloudCtx.provider) config.cloudProvider = cloudCtx.provider;
          if (declared.has("credentialReference") && cloudCtx.credentialReference) config.credentialReference = cloudCtx.credentialReference;
          if (declared.has("regions") && (cloudCtx.regions?.length ?? 0) > 0) config.regions = cloudCtx.regions;
          if (declared.has("excludeRegions") && (cloudCtx.excludeRegions?.length ?? 0) > 0) config.excludeRegions = cloudCtx.excludeRegions;
          if (declared.has("queryPack") && cloudCtx.queryPack) config.queryPack = cloudCtx.queryPack;
        }
      }
      // Prompt 15 derived configuration — worker-computed from the
      // scan's directory context (store-resolved), never client input
      // (§7/§11/§14): domain id + DNS ref, the credential REFERENCE
      // name (the value is resolved inside this worker boundary only),
      // the approved DC hosts, and the governed LDAP query kind for
      // the inventory stage. SharpHound collection methods are NEVER
      // derived here — the adapter's SAFE default applies unless an
      // administrator-approved set was recorded (§29), which this
      // build does not auto-approve.
      if ((ALL_DIRECTORY_SLUGS as readonly string[]).includes(ctx.adapterSlug)) {
        const dirCtx = ctx.directory;
        if (dirCtx) {
          if (declared.has("directoryDomainId") && dirCtx.domainId) config.directoryDomainId = dirCtx.domainId;
          if (declared.has("directoryDomainRef") && dirCtx.domainRef) config.directoryDomainRef = dirCtx.domainRef;
          if (declared.has("credentialReference") && dirCtx.credentialReference) config.credentialReference = dirCtx.credentialReference;
          if (declared.has("dcHosts") && (dirCtx.dcHosts?.length ?? 0) > 0) config.dcHosts = dirCtx.dcHosts;
        }
        if (declared.has("queryKind")) config.queryKind = "USERS";
        if (declared.has("mode") && ctx.adapterSlug === "pingcastle") config.mode = "healthcheck";
        if (declared.has("action") && ctx.adapterSlug === "certipy-posture") config.action = "find";
      }
      // Prompt 17 derived configuration — worker-computed from the
      // scan's mobile context (store-resolved), never client input
      // (§5/§14/§58): application + build identity, the artifact
      // reference (mounted read-only in the sandbox), the MobSF
      // instance id (from the scanner binding, like other connectors)
      // and the APPROVED lab session ids for dynamic stages.
      if ((MOBILE_SLUGS as readonly string[]).includes(ctx.adapterSlug)) {
        const mobCtx = ctx.mobile;
        if (mobCtx) {
          if (declared.has("mobileApplicationId") && mobCtx.applicationId) config.mobileApplicationId = mobCtx.applicationId;
          if (declared.has("mobileBuildId") && mobCtx.buildId) config.mobileBuildId = mobCtx.buildId;
          if (declared.has("mobileBuildHash") && mobCtx.buildHash) config.mobileBuildHash = mobCtx.buildHash;
          if (declared.has("mobileApplicationRef") && mobCtx.applicationRef) config.mobileApplicationRef = mobCtx.applicationRef;
          if (declared.has("mobilePlatform") && mobCtx.platform) config.mobilePlatform = mobCtx.platform;
          if (declared.has("mobileArtifactReference") && mobCtx.artifactReference) config.mobileArtifactReference = mobCtx.artifactReference;
          if (declared.has("mobileDeviceId") && mobCtx.deviceId) config.mobileDeviceId = mobCtx.deviceId;
          if (declared.has("mobileDynamicSessionId") && mobCtx.dynamicSessionId) config.mobileDynamicSessionId = mobCtx.dynamicSessionId;
          if (declared.has("mobileTrafficSessionId") && mobCtx.trafficSessionId) config.mobileTrafficSessionId = mobCtx.trafficSessionId;
        }
        if (declared.has("mobileScannerInstanceId") && ctx.scanner?.instanceId) config.mobileScannerInstanceId = ctx.scanner.instanceId;
      }
      // Prompt 18 derived configuration — worker-computed from the
      // scan's binary context (store-resolved), never client input
      // (§6): artifact identity + reference only. No script, command
      // or operation list is ever derived from scan input — radare2
      // runs its platform STANDARD profile unless the plan recorded
      // an approved profile name.
      if ((BINARY_SLUGS as readonly string[]).includes(ctx.adapterSlug)) {
        const binCtx = ctx.binary;
        if (binCtx) {
          if (declared.has("binaryArtifactId") && binCtx.artifactId) config.binaryArtifactId = binCtx.artifactId;
          if (declared.has("binaryArtifactHash") && binCtx.artifactHash) config.binaryArtifactHash = binCtx.artifactHash;
          if (declared.has("binaryArtifactReference") && binCtx.artifactReference) config.binaryArtifactReference = binCtx.artifactReference;
          if (declared.has("binaryArtifactName") && binCtx.artifactName) config.binaryArtifactName = binCtx.artifactName;
        }
        if (declared.has("binaryAnalysisProfile")) config.binaryAnalysisProfile = "STANDARD";
      }
      // Prompt 19 derived configuration — worker-computed from the
      // scan's wireless context (store-resolved), never client input
      // (§12/§26): environment identity, the approved sensor
      // (reference + interface) and the approved capture artifact.
      // No command, filter or credential is ever derived here (§78).
      if ((WIRELESS_SLUGS as readonly string[]).includes(ctx.adapterSlug)) {
        const wlCtx = ctx.wireless;
        if (wlCtx) {
          if (declared.has("wirelessEnvironmentId") && wlCtx.environmentId) config.wirelessEnvironmentId = wlCtx.environmentId;
          if (declared.has("wirelessSensorRef") && wlCtx.sensorRef) config.wirelessSensorRef = wlCtx.sensorRef;
          if (declared.has("wirelessSensorInterface") && wlCtx.sensorInterface) config.wirelessSensorInterface = wlCtx.sensorInterface;
          if (declared.has("wirelessCaptureId") && wlCtx.captureId) config.wirelessCaptureId = wlCtx.captureId;
          if (declared.has("wirelessCaptureRef") && wlCtx.captureReference) config.wirelessCaptureRef = wlCtx.captureReference;
        }
        if (declared.has("workspaceKey")) config.workspaceKey = ctx.workspaceId;
      }
      const plan = await adapter.buildExecutionPlan(target, config);

      const timeoutMs = ctx.simulation?.failWith === "TIMEOUT"
        ? Math.min(50, ctx.timeoutSeconds * 1000)
        : ctx.timeoutSeconds * 1000;
      let rawOutput: string | undefined;
      await this.runWithTimeoutAndCancellation(ctx, async () => {
        if (ctx.simulation?.failWith === "TOOL_ERROR") throw new Error("deterministic mock tool failure");
        if (ctx.simulation?.failWith === "TIMEOUT") await sleep(1_000); // overruns the clamped test timeout (§58)
        if (ctx.simulation?.delayMs) {
          // Chunked cooperative delay: cancellation is observed within ~25ms
          // instead of after the whole simulated duration (§26).
          let remaining = ctx.simulation.delayMs;
          while (remaining > 0) {
            await sleep(Math.min(25, remaining));
            remaining -= 25;
            if (await this.store.isCancelled(ctx.scanId)) return;
          }
        }
        const execResult = await adapter.execute(plan);
        rawOutput = execResult.rawOutput;
      }, timeoutMs);

      if (await this.store.isCancelled(ctx.scanId)) {
        await this.store.updateExecution(ctx.executionId, { status: "CANCELLED", completedAt: new Date() });
        await emit("tool.failed", { stageId: ctx.stageId, reasonCode: "CANCELLED" });
        return { status: "CANCELLED" };
      }

      await this.transition(ctx, "PARSING");
      const parsed = await adapter.parse(rawOutput ?? "");
      // Raw tool output is preserved as the execution artifact (§31/§35),
      // named for the tool + format — never the normalized form.
      const ext = plan.expectedOutputFormat === "JSONL" ? "jsonl" : plan.expectedOutputFormat === "JSON" ? "json" : plan.expectedOutputFormat === "SARIF" ? "sarif" : plan.expectedOutputFormat === "XML" ? "xml" : "txt";
      const raw = rawOutput ?? JSON.stringify(parsed);
      const artifact = await this.objectStore.put(
        rawArtifactKey(ctx.scanId, ctx.executionId, `${ctx.adapterSlug}.${ext}`),
        raw,
        plan.expectedOutputFormat === "TEXT" ? "text/plain" : "application/json",
      );
      await this.transition(ctx, "NORMALIZING");
      const normalized = await adapter.normalize(parsed);
      const processed = processNormalizedResult(normalized, { scopeRules: ctx.scopeRules, toolExecutionId: ctx.executionId, toolSlug: ctx.adapterSlug, artifactKey: artifact.storageKey });
      const counts = await this.store.persistResult(ctx.scanId, ctx.executionId, processed);
      // Prompt 8 connector lifecycle events (§72): ids + counts only —
      // never secrets, never traffic (§20). (SonarQube has no proxy
      // context lifecycle — its findings flow through finding events.)
      if (isConnector && !isSonar) {
        await emit("scanner.context_created", { stageId: ctx.stageId, tool: ctx.adapterSlug, instanceId: ctx.scanner?.instanceId ?? null });
        if (normalized.metrics.sessionExpired === 1) {
          await emit("auth_session.expired", { stageId: ctx.stageId, tool: ctx.adapterSlug });
        }
        await emit("passive_analysis.completed", {
          stageId: ctx.stageId, tool: ctx.adapterSlug,
          transactions: counts.transactions ?? processed.transactions.length,
          issues: normalized.metrics.passiveIssues ?? processed.findings.length,
          endpointsImported: normalized.metrics.endpointsImported ?? processed.endpoints.length,
        });
        await emit("scanner.context_destroyed", { stageId: ctx.stageId, tool: ctx.adapterSlug });
      }
      // §59: aggregated recon events, never one record per discovered URL.
      for (const a of processed.assets) {
        if (a.scopeStatus === "IN_SCOPE") await emit("asset.discovered", { stageId: ctx.stageId, host: a.host, tool: ctx.adapterSlug });
        else await emit("asset.out_of_scope", { stageId: ctx.stageId, host: a.host, tool: ctx.adapterSlug });
      }
      if (processed.endpoints.length > 0) await emit("endpoint.discovered", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: processed.endpoints.length });
      // Prompt 9 §78: API inventory/test events — counts and verdicts
      // only, never payloads, tokens or traffic.
      if (processed.apiServices.length > 0) {
        await emit("api.service_discovered", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: processed.apiServices.length });
      }
      if (processed.graphqlServices.length > 0) {
        await emit("graphql.schema_imported", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: processed.graphqlServices.length });
      }
      if (processed.jwtProfiles.length > 0) {
        await emit("jwt.analyzed", { stageId: ctx.stageId, tool: ctx.adapterSlug, tokens: processed.jwtProfiles.length });
      }
      if (typeof normalized.metrics.blockedOperations === "number" && normalized.metrics.blockedOperations > 0) {
        await emit("api.operation_blocked", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: normalized.metrics.blockedOperations });
      }
      // Prompt 10 §84: aggregated network events — counts only, never
      // per-packet data or raw output.
      if ((NETWORK_SLUGS as readonly string[]).includes(ctx.adapterSlug)) {
        if (counts.assets > 0) await emit("network.host_discovered", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: counts.assets });
        if (processed.services.length > 0) {
          await emit("network.port_discovered", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: processed.services.length });
          const identified = processed.services.filter((s) => s.name && s.name !== "unknown").length;
          if (identified > 0) await emit("network.service_identified", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: identified });
        }
      }
      for (const f of processed.findings) await emit("finding.created", { stageId: ctx.stageId, isMock: f.isMock, severity: f.severity });
      // Prompt 12 §110: source events — counts only. A secret event
      // carries the TYPE and detector, never the value or its preview.
      const secretFindings = processed.findings.filter((f) => f.secret);
      if (secretFindings.length > 0) {
        await emit("source.secret_detected", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: secretFindings.length, types: [...new Set(secretFindings.map((f) => f.secret!.secretType))].join(",") });
      }
      const depFindings = processed.findings.filter((f) => f.componentPurl);
      if (depFindings.length > 0) {
        await emit("source.dependency_vulnerability_detected", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: depFindings.length });
      }
      // Prompt 13 §111-adjacent scan events — counts/ids only, never
      // credentials or secret values.
      if (processed.cloudNative.images.length > 0) {
        await emit("container.image_resolved", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: processed.cloudNative.images.length });
      }
      if (processed.cloudNative.workloads.length > 0) {
        await emit("kubernetes.inventory_recorded", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: processed.cloudNative.workloads.length });
      }
      if (processed.cloudNative.controlAssessments.length > 0) {
        await emit("compliance.assessed", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: processed.cloudNative.controlAssessments.length, failed: processed.cloudNative.controlAssessments.filter((a) => a.status === "FAIL").length });
      }
      if (ctx.adapterSlug === "docker-bench-for-security") {
        await emit("docker.posture_assessed", { stageId: ctx.stageId, tool: ctx.adapterSlug, checks: processed.cloudNative.controlAssessments.length });
      }
      if (isK8sConnector) {
        await emit("kubernetes.posture_assessed", { stageId: ctx.stageId, tool: ctx.adapterSlug, workloads: processed.cloudNative.workloads.length });
      }
      // Prompt 14 §103-adjacent scan events — counts/ids only, never
      // credentials, never configuration payloads.
      if (processed.cloud.resources.length > 0) {
        await emit("cloud.inventory_recorded", { stageId: ctx.stageId, tool: ctx.adapterSlug, resources: processed.cloud.resources.filter((r) => r.scopeStatus === "IN_SCOPE").length, identities: processed.cloud.identities.length, outOfScope: processed.cloud.resources.filter((r) => r.scopeStatus === "OUT_OF_SCOPE").length });
        const exposed = processed.cloud.resources.filter((r) => r.exposure === "PUBLIC");
        if (exposed.length > 0) await emit("cloud.public_exposure_detected", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: exposed.length });
      }
      if (processed.cloud.controlAssessments.length > 0) {
        await emit("cloud.compliance_assessed", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: processed.cloud.controlAssessments.length, failed: processed.cloud.controlAssessments.filter((a) => a.status === "FAIL").length });
      }
      // Prompt 15 §117/§118 scan events — counts/ids only, never
      // credentials, never directory payloads (§113).
      const dirPayload = processed.directory;
      const dirObjectCount = dirPayload.users.length + dirPayload.groups.length + dirPayload.computers.length + dirPayload.domainControllers.length;
      if (dirObjectCount > 0 || dirPayload.relationships.length > 0) {
        await emit("ad.inventory_recorded", {
          stageId: ctx.stageId, tool: ctx.adapterSlug,
          users: dirPayload.users.length, groups: dirPayload.groups.length,
          computers: dirPayload.computers.length, domainControllers: dirPayload.domainControllers.length,
          relationships: dirPayload.relationships.length, trusts: dirPayload.trusts.length,
        });
        if (dirPayload.trusts.length > 0) {
          await emit("ad.trust_discovered", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: dirPayload.trusts.length });
        }
        if (dirPayload.certificateTemplates.some((t) => (t.riskClasses ?? []).length > 0)) {
          await emit("ad.adcs_risk_detected", { stageId: ctx.stageId, tool: ctx.adapterSlug, templates: dirPayload.certificateTemplates.filter((t) => (t.riskClasses ?? []).length > 0).length });
        }
      }
      // Prompt 17 §117 scan events — counts/ids only, never secret
      // values, never decompiled source, never traffic bodies (§28/§66).
      const mobPayload = processed.mobile;
      const mobInventoryCount = mobPayload.permissions.length + mobPayload.components.length
        + mobPayload.deepLinks.length + mobPayload.endpoints.length + mobPayload.nativeLibraries.length;
      if (mobInventoryCount > 0) {
        await emit("mobile.inventory_recorded", {
          stageId: ctx.stageId, tool: ctx.adapterSlug,
          permissions: mobPayload.permissions.length, components: mobPayload.components.length,
          deepLinks: mobPayload.deepLinks.length, endpoints: mobPayload.endpoints.length,
          nativeLibraries: mobPayload.nativeLibraries.length,
        });
        if (mobPayload.endpoints.length > 0) {
          await emit("mobile.endpoints_discovered", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: mobPayload.endpoints.length, classification: "DISCOVERED_REFERENCE" });
        }
      }
      // Prompt 18 §120 scan events — counts/ids only, never secret
      // values, never decompiled code, never memory content (§30/§74).
      const binPayload = processed.binary;
      const binInventoryCount = binPayload.sections.length + binPayload.functions.length
        + binPayload.imports.length + binPayload.exports.length + binPayload.dependencies.length;
      if (binInventoryCount > 0) {
        await emit("binary.inventory_recorded", {
          stageId: ctx.stageId, tool: ctx.adapterSlug,
          sections: binPayload.sections.length, functions: binPayload.functions.length,
          imports: binPayload.imports.length, exports: binPayload.exports.length,
          dependencies: binPayload.dependencies.length,
        });
        if (binPayload.discoveredReferences.length > 0) {
          await emit("binary.references_discovered", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: binPayload.discoveredReferences.length, classification: "DISCOVERED_REFERENCE" });
        }
      }

      await this.store.updateExecution(ctx.executionId, {
        status: "COMPLETED", completedAt: new Date(), exitCode: 0,
        outputLocation: artifact.storageKey,
        metrics: {
          checksum: artifact.checksum, size: artifact.size,
          assets: counts.assets, findings: counts.findings,
          endpoints: counts.endpoints ?? processed.endpoints.length,
          services: counts.services ?? processed.services.length,
          technologies: counts.technologies ?? processed.technologies.length,
          parameters: counts.parameters ?? processed.parameters.length,
          forms: counts.forms ?? processed.forms.length,
          transactions: counts.transactions ?? processed.transactions.length,
          webSockets: counts.webSockets ?? processed.webSockets.length,
          packetCaptures: counts.packetCaptures ?? processed.packetCaptures.length,
          components: counts.components ?? processed.components.length,
          images: processed.cloudNative.images.length,
          workloads: processed.cloudNative.workloads.length,
          controlAssessments: processed.cloudNative.controlAssessments.length,
          runtimeEvents: processed.cloudNative.runtimeEvents.length,
          cloudResources: processed.cloud.resources.length,
          cloudIdentities: processed.cloud.identities.length,
          cloudRelationships: processed.cloud.relationships.length,
          mobilePermissions: processed.mobile.permissions.length,
          mobileComponents: processed.mobile.components.length,
          mobileEndpoints: processed.mobile.endpoints.length,
          mobileNativeLibraries: processed.mobile.nativeLibraries.length,
          suppressedEndpoints: processed.suppressedEndpoints,
          ...(templateSelection ? { templateSnapshot: templateSelection.snapshot, templatesSelected: templateSelection.selected } : {}),
          ...(nseSelection ? { nseSnapshot: nseSelection.snapshot, nseScriptsSelected: nseSelection.selected } : {}),
          ...normalized.metrics,
        },
      });
      await emit("tool.completed", { stageId: ctx.stageId, tool: ctx.adapterSlug, assets: counts.assets, findings: counts.findings });
      return { status: "COMPLETED", assets: counts.assets, findings: counts.findings };
    } catch (error) {
      const category = classifyError(error);
      if (category === "TIMEOUT") {
        await this.store.updateExecution(ctx.executionId, { status: "TIMED_OUT", completedAt: new Date(), error: "Execution timed out" });
        await emit("tool.failed", { stageId: ctx.stageId, reasonCode: "TIMED_OUT" });
        return { status: "TIMED_OUT", category };
      }
      await this.failExecution(ctx, category, error instanceof Error ? error.message : "unknown error");
      await this.store.recordDeadLetter({
        jobId: idempotencyKey(ctx.scanId, ctx.stageId, ctx.attempt), queue: "stage-execution",
        scanId: ctx.scanId, stageId: ctx.stageId, executionId: ctx.executionId,
        errorCategory: category, errorMessage: error instanceof Error ? error.message : "unknown", attempts: ctx.attempt,
      });
      return { status: "FAILED", category };
    }
  }

  /** Availability probe used by the DAG runner to degrade gracefully when
   *  one adapter of a multi-adapter stage is unavailable (§56). */
  async isExecutable(slug: string): Promise<boolean> {
    if (!EXECUTABLE_SLUGS.includes(slug as (typeof EXECUTABLE_SLUGS)[number])) return false;
    const adapter = this.registry.resolve(slug);
    if (!adapter) return false;
    return adapter.checkAvailability().catch(() => false);
  }

  private async transition(ctx: ExecutionContextRecord, to: string): Promise<void> {
    assertExecutionTransition(ctx.status as never, to as never);
    await this.store.updateExecution(ctx.executionId, { status: to });
    ctx.status = to;
  }

  private async failExecution(ctx: ExecutionContextRecord, category: string, message: string): Promise<void> {
    await this.store.updateExecution(ctx.executionId, { status: "FAILED", completedAt: new Date(), error: message });
    await this.store.recordEvent(makeEvent(ctx.scanId, ctx.workspaceId, "tool.failed", { stageId: ctx.stageId, reasonCode: category }));
  }

  /** Cooperative cancellation + hard timeout (§26/§28): the work races a
   *  timer, and cancellation is polled so a delayed mock stops promptly. */
  private async runWithTimeoutAndCancellation(ctx: ExecutionContextRecord, work: () => Promise<void>, timeoutMs: number): Promise<void> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error("Execution timed out"), { name: "ExecutionTimeoutError" })), timeoutMs);
    });
    void ctx;
    try {
      await Promise.race([work(), timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}
