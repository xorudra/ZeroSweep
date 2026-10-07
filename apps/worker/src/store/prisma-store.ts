import { prisma } from "@dsrclone/database";
import { scopeRulesSchema } from "@dsrclone/validation";
import { idempotencyKey, type ScanEventRecord, type ScanPlan } from "@dsrclone/orchestration";
import {
  CidrPolicyService, DEFAULT_QUALITY_GATE_POLICY, EnvSecretResolver, InMemoryIntelligenceDataset, JwtToolAdapter, PROXY_SLUGS, VULN_SCANNER_SLUGS, analyzeDatabases, analyzeEncryption, analyzeIam, analyzeLogging, analyzeNetwork, analyzeStorage, auditLoggingEnabled, buildCloudRiskPaths, buildCycloneDxSbom, classifyBaseline, clampDiscoveryBudget, computeDueAt, computeRiskV2, confidenceUpdateForOutcome, detectRepository, enrichDependencyFindings, enrichFinding, evaluateCloudSecurityGate, evaluateContainerQualityGate, evaluateQualityGate, expandCidrTargets, DEFAULT_SLA_POLICY, matchComponentsAgainstIntel, parseImageReference, parseManifests, planCloudNativeRetest, planCloudRetest, planRetest, summarizeForQualityGate, analyzeDirectoryPosture, analyzeLdapPosture, buildIdentityGraph, diffDirectorySnapshots, findAttackPaths, planAdRetest, privilegedPrincipals, resolveNestedGroups, analyzeMobilePosture, extractMobileArtifacts, buildSpdxSbom, emptyMobileData, evaluateMobileSecurityGate, mergeMobileData, planMobileRetest, summarizeMobileForGate, analyzeBinaryPlatform, binaryFindingFingerprint, evaluateBinaryDebugPolicy, extractBinaryStrings, parseBinaryHeaders, planBinaryRetest, type CvssRecord, type KillSwitchRecord, type NormalizedBinaryData, type NormalizedCloudIdentity, type NormalizedCloudResource, type NormalizedDirectoryData, type NormalizedMobileData,
} from "@dsrclone/security-sdk";
import { createHash } from "node:crypto";
import type { ExecutionContextRecord } from "../executors/stage-executor";
import type { ScanRunRecord, ScanRunStore } from "../consumers/dag-runner";
import { correlateProcessedFindings, processNormalizedResult, type ProcessedFinding, type ProcessedResult } from "../executors/result-processor";
import { isMobileProcessedFinding, stampMobileFindings, type MobileScanIdentity } from "../executors/mobile-stamp";
import { isBinaryProcessedFinding, stampBinaryFindings, type BinaryScanIdentity } from "../executors/binary-stamp";

/**
 * Prisma implementation of the worker stores. Workers load ALL trusted state
 * from the database (Prompt 4 §14) — queue payloads carry IDs only, so
 * nothing in Redis is ever trusted for authorization, scope or tenancy.
 */

/** Prompt 14: fold several section analyzers into one result (the
 *  STORAGE_ANALYSIS stage covers storage + database engines, §43/§45). */
function mergeSections<T extends { findings: unknown[]; controlAssessments: unknown[] }>(parts: T[]): { findings: T["findings"]; controlAssessments: T["controlAssessments"] } {
  return {
    findings: parts.flatMap((p) => p.findings) as T["findings"],
    controlAssessments: parts.flatMap((p) => p.controlAssessments) as T["controlAssessments"],
  };
}

function hostOf(value: string): string {
  try {
    if (value.includes("://")) return new URL(value).hostname;
  } catch { /* fall through */ }
  return value.split("/")[0]!.split(":")[0]!.toLowerCase();
}

async function loadScanGraph(scanId: string) {
  // Scan has no direct workspace relation — tenancy resolves via workspaceId.
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: {
      plan: true,
      assessment: { include: { target: true, scope: true } },
    },
  });
  if (!scan) return null;
  const workspace = await prisma.workspace.findUnique({ where: { id: scan.workspaceId } });
  if (!workspace) return null;
  return { ...scan, workspace };
}

export class PrismaWorkerStore implements ScanRunStore {
  // ---------- ExecutionStore ----------
  async loadExecutionContext(executionId: string): Promise<ExecutionContextRecord | null> {
    const exec = await prisma.toolExecution.findUnique({
      where: { id: executionId },
      include: { scanStage: true, tool: true },
    });
    if (!exec) return null;
    const graph = await loadScanGraph(exec.scanId);
    if (!graph?.plan || !graph.assessment) return null;
    const plan = graph.plan.plan as unknown as ScanPlan;
    const stageType = exec.scanStage?.type ?? "";
    const planned = plan.stages.find((s) => s.type === stageType);
    const scopeParse = scopeRulesSchema.safeParse(graph.assessment.scope?.rules ?? {});
    const target = graph.assessment.target;
    return {
      executionId: exec.id,
      scanId: exec.scanId,
      stageId: stageType,
      workspaceId: graph.workspaceId,
      organizationId: graph.workspace.organizationId,
      adapterSlug: exec.tool.slug,
      status: exec.status,
      attempt: exec.attempt,
      timeoutSeconds: planned?.timeoutSeconds ?? 300,
      targetType: target.type,
      targetValue: target.value,
      targetHost: hostOf(target.value),
      scopeRules: scopeParse.success ? scopeParse.data : { includeHosts: [], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
      auth: {
        organizationId: graph.workspace.organizationId,
        workspaceId: graph.workspaceId,
        targetId: target.id,
        targetOrganizationId: graph.workspace.organizationId,
        assessmentId: graph.assessmentId,
        scanId: exec.scanId,
        verificationStatus: target.verified ? "VERIFIED" : "PENDING",
        approvalStatus: graph.assessment.status === "APPROVED" ? "APPROVED" : "PENDING",
        requestedBy: graph.requestedBy,
      },
      targetExists: true,
      targetWorkspaceId: graph.workspaceId,
      targetVerified: target.verified,
      assessmentApproved: graph.assessment.status === "APPROVED",
      scopeValid: scopeParse.success,
      // Prompt 12 (§12): source context resolved from repository +
      // snapshot rows — workspace paths never come from client input.
      source: await this.loadSourceContext(graph.workspaceId, target.id, exec.scanId),
      // Prompt 13 (§12): cloud-native context resolved from image /
      // cluster / Docker host rows — references only, never credentials.
      cloudNative: await this.loadCloudContext(graph.workspaceId, target.id, target.type, target.value),
      // Prompt 14 (§10): multi-cloud context resolved from the
      // registered CloudAccount row — the credential REFERENCE name
      // only; the value is resolved inside the CLOUD_ANALYSIS worker.
      cloud: await this.loadCloudAccountContext(graph.workspaceId, target.id, target.type),
      // Prompt 15 (§7/§11): Active Directory context resolved from the
      // registered ActiveDirectoryDomain row — the credential
      // REFERENCE name only; the value is resolved inside the
      // DIRECTORY_ANALYSIS worker.
      directory: await this.loadDirectoryContext(graph.workspaceId, target.id, target.type),
      // Prompt 17 (§5/§58): mobile context resolved from the
      // registered MobileApplication + latest MobileBuild rows — the
      // build's SHA-256 identity, the artifact reference and the
      // APPROVED lab session ids. Never client input.
      mobile: await this.loadMobileContext(graph.workspaceId, target.id, target.type),
      // Prompt 18 (§3/§6): binary context resolved from the registered
      // BinaryArtifact row — the artifact's SHA-256 identity, object
      // reference, format and environment. Never client input.
      binary: await this.loadBinaryContext(graph.workspaceId, target.id, target.type),
      networkCapable: planned?.networkCapable ?? false,
      profile: plan.profile,
      assessmentId: graph.assessmentId,
      // Prompt 10 §19/§20: no administrator-approval record source exists
      // in this phase's data model, so Masscan stays denied by default —
      // the honest state. The approval record lands with the admin
      // policy surface; until then the executor gate refuses Masscan.
      masscanApproved: false,
      // Prompt 10 §45: the newest authorized capture for this scan is
      // what tshark may analyze — resolved from trusted rows only.
      captureRef: await this.loadCaptureRef(exec.scanId),
      scanner: await this.loadScannerBinding(exec.tool.slug, graph.workspaceId, graph.workspace.organizationId),
      stageInputs: await this.loadStageInputs(target.id),
      simulation: {
        fixture: (plan.profile === "PASSIVE_RECON" || plan.profile === "WEB_BASELINE") && stageType === "PASSIVE_RECON",
      },
    };
  }

  /** Prompt 12: repository + snapshot resolution shared by the
   *  execution context and the source platform hooks. */
  private async loadSourceContext(workspaceId: string, targetId: string, scanId: string): Promise<ExecutionContextRecord["source"]> {
    const repo = await prisma.sourceRepository.findFirst({ where: { workspaceId, targetId } });
    if (!repo) return undefined;
    const snap = (await prisma.sourceSnapshot.findFirst({ where: { repositoryId: repo.id, scanId }, orderBy: { createdAt: "desc" } }))
      ?? (await prisma.sourceSnapshot.findFirst({ where: { repositoryId: repo.id }, orderBy: { createdAt: "desc" } }));
    const langs = ((snap?.languages as { language: string }[] | null) ?? []).map((l) => l.language);
    return {
      repositoryId: repo.id,
      ...(snap ? { snapshotId: snap.id } : {}),
      ...(snap?.artifactReference ? { workspacePath: snap.artifactReference } : {}),
      ...(snap?.commitSha ? { commitSha: snap.commitSha } : {}),
      languages: langs,
      sonarProjectKey: repo.name,
    };
  }

  /** Prompt 13: cloud-native context for a scan's target — the
   *  registered image (with its recorded digest), cluster or Docker
   *  host. Credential REFERENCES live on those rows; values never
   *  enter an execution context. */
  private async loadCloudContext(workspaceId: string, targetId: string, targetType: string, targetValue: string): Promise<ExecutionContextRecord["cloudNative"]> {
    if (targetType === "CONTAINER_IMAGE") {
      const image = await prisma.containerImage.findFirst({ where: { workspaceId, targetId } });
      return {
        imageRef: targetValue,
        ...(image?.digest ? { imageDigest: image.digest } : {}),
        ...(image ? { imageId: image.id } : {}),
      };
    }
    if (targetType === "KUBERNETES_CLUSTER" || targetType === "KUBERNETES") {
      const cluster = await prisma.kubernetesCluster.findFirst({ where: { workspaceId, targetId } });
      if (!cluster) return undefined;
      return { clusterId: cluster.id, clusterRef: cluster.name };
    }
    if (targetType === "DOCKER_HOST" || targetType === "DOCKER") {
      const host = await prisma.dockerHost.findFirst({ where: { workspaceId, targetId } });
      if (!host) return undefined;
      return { hostRef: host.name };
    }
    if (targetType === "KUBERNETES_MANIFEST" || targetType === "HELM_CHART" || targetType === "SOURCE_REPOSITORY") {
      // Manifest scans ride the source snapshot (ctx.source) — no
      // cluster context exists or is needed.
      return undefined;
    }
    return undefined;
  }

  /** Prompt 14: multi-cloud context for a scan's target — the
   *  registered CloudAccount (id, provider, provider-side reference,
   *  credential REFERENCE name, account scope regions). An account
   *  that is not registered yields an empty context and the executor
   *  denies cloud connectors as NOT_CONFIGURED (§9). */
  private async loadCloudAccountContext(workspaceId: string, targetId: string, targetType: string): Promise<ExecutionContextRecord["cloud"]> {
    if (!["AWS", "AZURE", "GCP"].includes(targetType)) return undefined;
    const account = await prisma.cloudAccount.findFirst({
      where: { workspaceId, targetId },
      include: { scopes: { orderBy: { createdAt: "asc" }, take: 1 } },
    });
    if (!account) return {};
    const scope = account.scopes[0];
    return {
      accountId: account.id,
      accountRef: account.externalAccountId,
      provider: account.provider,
      ...(account.credentialReference ? { credentialReference: account.credentialReference } : {}),
      regions: scope?.includeRegions ?? [],
      excludeRegions: scope?.excludeRegions ?? [],
      environment: account.environment,
    };
  }

  /** Prompt 15: Active Directory context for a scan's target — the
   *  registered ActiveDirectoryDomain (id, DNS ref, forest, credential
   *  REFERENCE name from its credential profile, approved DC hosts).
   *  An unregistered domain yields an empty context and the executor
   *  denies directory connectors as NOT_CONFIGURED (§15). */
  private async loadDirectoryContext(workspaceId: string, targetId: string, targetType: string): Promise<ExecutionContextRecord["directory"]> {
    if (!["ACTIVE_DIRECTORY", "ACTIVE_DIRECTORY_DOMAIN", "ACTIVE_DIRECTORY_FOREST", "DOMAIN_CONTROLLER", "LDAP_DIRECTORY"].includes(targetType)) return undefined;
    const domain = await prisma.activeDirectoryDomain.findFirst({
      where: { workspaceId, targetId },
      include: { credentialProfile: true, controllers: { select: { hostname: true, dnsName: true } } },
    });
    if (!domain) return {};
    return {
      domainId: domain.id,
      domainRef: domain.dnsName,
      ...(domain.forestId ? { forestId: domain.forestId } : {}),
      ...(domain.credentialProfile?.credentialReference ? { credentialReference: domain.credentialProfile.credentialReference } : {}),
      ...(domain.credentialProfile?.identityKind ? { identityKind: domain.credentialProfile.identityKind } : {}),
      dcHosts: domain.controllers.map((c) => c.dnsName ?? c.hostname),
    };
  }

  /** Prompt 17: mobile context for a scan's target — the registered
   *  MobileApplication and its LATEST build (the artifact SHA-256 is
   *  the build identity, §5), plus the APPROVED dynamic session state
   *  for the controlled profiles (§58/§73). Retests (§89) therefore
   *  resolve the NEWEST build automatically. */
  private async loadMobileContext(workspaceId: string, targetId: string, targetType: string): Promise<ExecutionContextRecord["mobile"]> {
    if (targetType !== "MOBILE_APP") return undefined;
    const app = await prisma.mobileApplication.findFirst({
      where: { workspaceId, targetId },
      include: { builds: { orderBy: { createdAt: "desc" }, take: 1 } },
    });
    if (!app) return {};
    const build = app.builds[0];
    const session = build
      ? await prisma.mobileDynamicSession.findFirst({
          where: { buildId: build.id, status: { in: ["APPROVED", "RUNNING"] } },
          orderBy: { createdAt: "desc" },
        })
      : null;
    const traffic = build
      ? await prisma.mobileTrafficSession.findFirst({
          where: { buildId: build.id, status: { in: ["APPROVED", "RUNNING"] } },
          orderBy: { createdAt: "desc" },
        })
      : null;
    return {
      applicationId: app.id,
      applicationRef: app.packageName ?? app.bundleId ?? app.name,
      platform: app.platform,
      environment: app.environment,
      ...(build ? { buildId: build.id, buildHash: build.artifactHash } : {}),
      ...(build?.artifactReference ? { artifactReference: build.artifactReference } : {}),
      ...(session?.deviceId ? { deviceId: session.deviceId } : {}),
      ...(session ? { dynamicSessionId: session.id, dynamicSessionApproved: session.status === "APPROVED" || session.status === "RUNNING" } : {}),
      ...(traffic ? { trafficSessionId: traffic.id } : {}),
    };
  }

  /** Prompt 18: binary context for a scan's target — the registered
   *  BinaryArtifact bound to the target (the SHA-256 is the artifact
   *  identity, §3). Retests therefore resolve the artifact row
   *  directly. */
  private async loadBinaryContext(workspaceId: string, targetId: string, targetType: string): Promise<ExecutionContextRecord["binary"]> {
    if (targetType !== "BINARY") return undefined;
    const artifact = await prisma.binaryArtifact.findFirst({
      where: { workspaceId, targetId },
      orderBy: { createdAt: "desc" },
    });
    if (!artifact) return {};
    return {
      artifactId: artifact.id,
      artifactHash: artifact.sha256,
      ...(artifact.artifactReference ? { artifactReference: artifact.artifactReference } : {}),
      artifactName: artifact.name,
      format: artifact.format,
      environment: artifact.environment,
    };
  }

  /** Prompt 18: the scan's registered artifact row (shared by the
   *  binary hooks and payload persistence). */
  private async binaryArtifactForScan(scanId: string) {
    const graph = await loadScanGraph(scanId);
    if (!graph?.assessment || graph.assessment.target.type !== "BINARY") return null;
    const artifact = await prisma.binaryArtifact.findFirst({
      where: { workspaceId: graph.workspaceId, targetId: graph.assessment.targetId },
      orderBy: { createdAt: "desc" },
    });
    if (!artifact) return null;
    return { graph, artifact };
  }

  private binaryIdentityOf(artifact: { id: string; sha256: string; name: string; format: string; architecture: string | null; environment: string }): BinaryScanIdentity {
    return {
      artifactId: artifact.id, artifactHash: artifact.sha256, artifactName: artifact.name,
      format: artifact.format, ...(artifact.architecture ? { architecture: artifact.architecture } : {}),
      environment: artifact.environment,
    };
  }

  /** Prompt 17: the scan's registered application + latest build rows
   *  (shared by the mobile hooks and payload persistence). */
  private async mobileBuildForScan(scanId: string) {
    const graph = await loadScanGraph(scanId);
    if (!graph?.assessment || graph.assessment.target.type !== "MOBILE_APP") return null;
    const app = await prisma.mobileApplication.findFirst({
      where: { workspaceId: graph.workspaceId, targetId: graph.assessment.targetId },
      include: { builds: { orderBy: { createdAt: "desc" }, take: 1 } },
    });
    if (!app || !app.builds[0]) return null;
    return { graph, app, build: app.builds[0] };
  }

  private mobileIdentityOf(app: { id: string; name: string; packageName: string | null; bundleId: string | null; platform: string; environment: string }, build: { id: string; artifactHash: string }): MobileScanIdentity {
    return {
      applicationId: app.id, applicationRef: app.packageName ?? app.bundleId ?? app.name,
      buildId: build.id, buildHash: build.artifactHash,
      platform: app.platform as "ANDROID" | "IOS", environment: app.environment,
    };
  }

  /** Prompt 10 §45: latest packet-capture artifact reference for a scan. */
  private async loadCaptureRef(scanId: string): Promise<string | undefined> {
    const capture = await prisma.packetCaptureArtifact.findFirst({
      where: { scanId },
      orderBy: { createdAt: "desc" },
      select: { storageKey: true },
    });
    return capture?.storageKey;
  }

  /** Prompt 8 scanner binding (§16): the workspace's admin-registered
   *  instance for this connector — workspace-specific rows win over
   *  org-wide ones. Resolved from trusted DB state only; the queue
   *  payload and the client never name an instance or an endpoint. */
  private async loadScannerBinding(toolSlug: string, workspaceId: string, organizationId: string): Promise<{ instanceId?: string } | undefined> {
    if (!(PROXY_SLUGS as readonly string[]).includes(toolSlug) && !(VULN_SCANNER_SLUGS as readonly string[]).includes(toolSlug) && toolSlug !== "sonarqube" && toolSlug !== "mobsf") return undefined;
    const own = await prisma.scannerInstance.findFirst({
      where: { workspaceId, enabled: true, tool: { slug: toolSlug } },
      orderBy: { createdAt: "asc" },
    });
    if (own) return { instanceId: own.id };
    const orgWide = await prisma.scannerInstance.findFirst({
      where: { workspaceId: null, organizationId, enabled: true, tool: { slug: toolSlug } },
      orderBy: { createdAt: "asc" },
    });
    return orgWide ? { instanceId: orgWide.id } : {};
  }

  /** Discovery inputs for downstream stages (Prompt 5 §26): the target's
   *  in-scope asset hostnames and endpoint URLs discovered so far. Capped so
   *  a huge inventory can't blow up an adapter invocation; out-of-scope
   *  assets are NEVER handed to downstream tools. */
  private async loadStageInputs(targetId: string): Promise<{ hosts: string[]; urls: string[]; technologies: string[]; services: string[]; specUrls: string[]; operations: string[] }> {
    const assets = await prisma.asset.findMany({
      where: { targetId, scopeStatus: "IN_SCOPE" },
      select: { id: true, host: true },
      take: 2000,
      orderBy: { firstSeen: "asc" },
    });
    const endpoints = assets.length === 0 ? [] : await prisma.endpoint.findMany({
      where: { assetId: { in: assets.map((a) => a.id) }, scopeStatus: "IN_SCOPE" },
      select: { url: true },
      take: 2000,
      orderBy: { createdAt: "asc" },
    });
    // Technology names detected so far (Prompt 6 §13 hints for
    // technology-aware wordlist selection).
    const technologies = assets.length === 0 ? [] : await prisma.technology.findMany({
      where: { assetId: { in: assets.map((a) => a.id) } },
      select: { name: true },
      distinct: ["name"],
      take: 200,
    });
    // TLS services for the Prompt 7 TLS stage (§13): only services that
    // look like TLS endpoints (https scheme/name or TLS ports) on in-scope
    // assets — host:port pairs, capped like the rest of the inputs.
    const tlsServices = assets.length === 0 ? [] : await prisma.service.findMany({
      where: {
        assetId: { in: assets.map((a) => a.id) },
        OR: [{ name: { in: ["https", "ssl", "tls"] } }, { port: { in: [443, 8443] } }],
      },
      include: { asset: { select: { host: true } } },
      take: 200,
    });
    const services = [...new Set(tlsServices.map((s) => `${s.asset.host}:${s.port}`))];
    // Prompt 9 (§15): specification locations + imported operations for
    // the schema-testing stage, from the guarded import records of THIS
    // target. Locations are the discovered document URLs; content
    // imports contribute their object-storage reference. Operations are
    // encoded "METHOD path operationId?" for the adapter's policy
    // filter — derived from persisted endpoint inventory only.
    const specifications = await prisma.apiSpecification.findMany({
      where: { targetId, kind: { in: ["OPENAPI", "SWAGGER"] }, parsedStatus: "PARSED" },
      select: { location: true, artifactRef: true },
      take: 20,
      orderBy: { createdAt: "asc" },
    });
    const specUrls = specifications.map((s) => s.location ?? s.artifactRef).filter((v): v is string => !!v);
    const operationRows = assets.length === 0 ? [] : await prisma.endpoint.findMany({
      where: { assetId: { in: assets.map((a) => a.id) }, scopeStatus: "IN_SCOPE" },
      select: { url: true, method: true, path: true, operationId: true },
      take: 2000,
      orderBy: { createdAt: "asc" },
    });
    const operations = operationRows.map((e) => {
      let path = e.path ?? undefined;
      if (!path) { try { path = new URL(e.url).pathname; } catch { path = e.url; } }
      return `${e.method} ${path}${e.operationId ? ` ${e.operationId}` : ""}`;
    });
    return { hosts: assets.map((a) => a.host), urls: endpoints.map((e) => e.url), technologies: technologies.map((t) => t.name), services, specUrls, operations };
  }

  async updateExecution(id: string, patch: Record<string, unknown>): Promise<void> {
    await prisma.toolExecution.update({ where: { id }, data: patch as never });
  }

  async recordEvent(event: ScanEventRecord): Promise<void> {
    await prisma.scanEvent.create({
      data: { scanId: event.scanId, workspaceId: event.workspaceId, type: event.type, payload: event.payload as never },
    });
  }

  async persistResult(scanId: string, executionId: string, processedIn: ProcessedResult): Promise<{ assets: number; findings: number; endpoints: number; services: number; technologies: number; parameters: number; forms: number; transactions: number; webSockets: number; apiServices: number; graphqlServices: number; jwtProfiles: number; packetCaptures: number; components: number; directoryUsers?: number; directoryGroups?: number; directoryComputers?: number; directoryRelationships?: number }> {
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { assessment: true } });
    if (!scan) return { assets: 0, findings: 0, endpoints: 0, services: 0, technologies: 0, parameters: 0, forms: 0, transactions: 0, webSockets: 0, apiServices: 0, graphqlServices: 0, jwtProfiles: 0, packetCaptures: 0, components: 0 };
    // Prompt 17 §50: mobile findings are stamped with their canonical
    // identity (application + build hash + platform + rule + class)
    // BEFORE persistence so correlation, the quality gate and retests
    // all key on the same fingerprint.
    let processed = processedIn;
    if (processedIn.findings.some(isMobileProcessedFinding)) {
      const mobileCtx = await this.mobileBuildForScan(scanId);
      if (mobileCtx) {
        processed = { ...processedIn, findings: stampMobileFindings(processedIn.findings, this.mobileIdentityOf(mobileCtx.app, mobileCtx.build)) };
      }
    }
    // Prompt 18 §50–§58: binary findings are stamped with their
    // canonical identity (artifact + §57 fingerprint) BEFORE
    // persistence so correlation, diffing and retests key on the same
    // fingerprint across tools and builds.
    if (processed.findings.some(isBinaryProcessedFinding)) {
      const binaryCtx = await this.binaryArtifactForScan(scanId);
      if (binaryCtx) {
        processed = { ...processed, findings: stampBinaryFindings(processed.findings, this.binaryIdentityOf(binaryCtx.artifact)) };
      }
    }
    const assetIdByHost = new Map<string, string>();
    for (const asset of processed.assets) {
      const existing = await prisma.asset.findFirst({ where: { targetId: scan.assessment.targetId, host: asset.host } });
      const row = existing
        ? await prisma.asset.update({
            where: { id: existing.id },
            data: {
              scopeStatus: asset.scopeStatus, ip: asset.ip ?? existing.ip, lastSeen: new Date(),
              // Provenance unions across tools/scans (§18); first discoverer
              // scan is kept for the asset's scan history (§44).
              sources: [...new Set([...existing.sources, ...asset.sources])],
              httpStatus: asset.httpStatus ?? existing.httpStatus,
              discoveredByScanId: existing.discoveredByScanId ?? scanId,
              // Prompt 10 §35: OS hints gap-fill only — a later, weaker
              // guess never overwrites a recorded hint.
              osHint: existing.osHint ?? asset.osHint,
              osConfidence: existing.osConfidence ?? asset.osConfidence,
              network: existing.network ?? asset.network,
            },
          })
        : await prisma.asset.create({
            data: {
              workspaceId: scan.workspaceId, targetId: scan.assessment.targetId, host: asset.host,
              ip: asset.ip, type: asset.type, scopeStatus: asset.scopeStatus,
              sources: asset.sources, httpStatus: asset.httpStatus, discoveredByScanId: scanId,
              osHint: asset.osHint, osConfidence: asset.osConfidence, network: asset.network,
            },
          });
      assetIdByHost.set(asset.host, row.id);
    }
    // Services attach to their host's asset (Prompt 5 §32) — upserted on the
    // (assetId, port, protocol) unique key so re-runs refresh metadata.
    // Prompt 10 §49: the update path applies PortResultAggregator
    // semantics — provenance unions, descriptive fields gap-fill from
    // the richer reporter, OPEN outranks CLOSED, confidence takes the
    // max. One canonical row per (asset, port, protocol), always (§31).
    const STATE_RANK: Record<string, number> = { OPEN: 4, OPEN_FILTERED: 3, UNKNOWN: 2, FILTERED: 1, CLOSED: 0 };
    let services = 0;
    for (const svc of processed.services) {
      const assetId = assetIdByHost.get(svc.host);
      if (!assetId) continue;
      const existingSvc = await prisma.service.findUnique({
        where: { assetId_port_protocol: { assetId, port: svc.port, protocol: svc.protocol } },
      });
      if (!existingSvc) {
        await prisma.service.create({
          data: {
            assetId, port: svc.port, protocol: svc.protocol, name: svc.name, product: svc.product, version: svc.version,
            state: svc.state ?? "OPEN", cpe: svc.cpe, banner: svc.banner, tls: svc.tls, confidence: svc.confidence,
            sources: svc.sources ?? [],
          },
        });
      } else {
        await prisma.service.update({
          where: { id: existingSvc.id },
          data: {
            name: (!existingSvc.name || existingSvc.name === "unknown") && svc.name ? svc.name : existingSvc.name,
            product: existingSvc.product ?? svc.product,
            version: existingSvc.version ?? svc.version,
            cpe: existingSvc.cpe ?? svc.cpe,
            banner: existingSvc.banner ?? svc.banner,
            tls: existingSvc.tls ?? svc.tls,
            confidence: Math.max(existingSvc.confidence ?? 0, svc.confidence ?? 0) || existingSvc.confidence,
            state: (STATE_RANK[svc.state ?? "UNKNOWN"] ?? 0) > (STATE_RANK[existingSvc.state] ?? 0) ? (svc.state ?? existingSvc.state) : existingSvc.state,
            sources: [...new Set([...existingSvc.sources, ...(svc.sources ?? [])])].sort(),
          },
        });
      }
      services++;
    }
    // Technologies attach to their host's asset (§34), deduped per asset+name.
    let technologies = 0;
    for (const tech of processed.technologies) {
      const assetId = tech.host ? assetIdByHost.get(tech.host) : undefined;
      if (!assetId) continue;
      const existing = await prisma.technology.findFirst({ where: { assetId, name: tech.name } });
      if (existing) {
        await prisma.technology.update({
          where: { id: existing.id },
          data: { version: tech.version ?? existing.version, category: tech.category ?? existing.category, source: tech.source ?? existing.source, confidence: tech.confidence ?? existing.confidence },
        });
      } else {
        await prisma.technology.create({ data: { assetId, name: tech.name, version: tech.version, category: tech.category, source: tech.source, confidence: tech.confidence } });
      }
      technologies++;
    }
    // Endpoints attach to their host's asset; deduped per asset+URL so
    // repeated stages/scans refresh status + parameter names (§33).
    // Prompt 6: response-classification metadata, route classification and
    // the full provenance list refresh the same way (§16/§26).
    let endpoints = 0;
    const endpointIdByUrl = new Map<string, string>();
    for (const ep of processed.endpoints) {
      const host = hostOf(ep.url);
      // Fallback (Prompt 9): endpoints from stages whose own result
      // carried no assets (route discovery, traffic import) attach to
      // the asset row earlier stages already recorded for this target.
      let assetId = assetIdByHost.get(host);
      if (!assetId) {
        const existingAsset = await prisma.asset.findFirst({ where: { targetId: scan.assessment.targetId, host } });
        if (existingAsset) { assetId = existingAsset.id; assetIdByHost.set(host, assetId); }
      }
      if (!assetId) continue;
      const existingEp = await prisma.endpoint.findFirst({ where: { assetId, url: ep.url } });
      if (existingEp) {
        const updated = await prisma.endpoint.update({
          where: { id: existingEp.id },
          data: {
            statusCode: ep.statusCode ?? existingEp.statusCode,
            parameterNames: [...new Set([...existingEp.parameterNames, ...ep.parameterNames])].sort(),
            source: ep.source ?? existingEp.source, scopeStatus: ep.scopeStatus,
            contentType: ep.contentType ?? existingEp.contentType,
            contentLength: ep.contentLength ?? existingEp.contentLength,
            title: ep.title ?? existingEp.title,
            redirectLocation: ep.redirectLocation ?? existingEp.redirectLocation,
            endpointType: ep.endpointType !== "UNKNOWN" ? ep.endpointType : existingEp.endpointType,
            classification: ep.classification ?? existingEp.classification,
            sources: [...new Set([...existingEp.sources, ...ep.sources])].sort(),
          },
        });
        endpointIdByUrl.set(ep.url, updated.id);
      } else {
        const created = await prisma.endpoint.create({
          data: {
            assetId, url: ep.url, method: ep.method, statusCode: ep.statusCode, parameterNames: ep.parameterNames,
            source: ep.source, scopeStatus: ep.scopeStatus, contentType: ep.contentType, contentLength: ep.contentLength,
            title: ep.title, redirectLocation: ep.redirectLocation, endpointType: ep.endpointType,
            classification: ep.classification, sources: ep.sources,
          },
        });
        endpointIdByUrl.set(ep.url, created.id);
      }
      endpoints++;
    }
    // Parameters (Prompt 6 §27): upserted on (endpoint, name, location) —
    // NAMES and provenance only; a parameter value is never written.
    let parameters = 0;
    for (const param of processed.parameters) {
      const endpointId = endpointIdByUrl.get(param.endpointUrl) ?? endpointIdByUrl.get(param.endpointUrl.split("?")[0]!);
      if (!endpointId) continue;
      await prisma.endpointParameter.upsert({
        where: { endpointId_name_location: { endpointId, name: param.name, location: param.location } },
        create: { endpointId, name: param.name, location: param.location, sources: param.sources, confidence: param.confidence },
        update: { sources: param.sources, confidence: param.confidence },
      });
      parameters++;
    }
    // Forms (§33): structure metadata, refreshed per endpoint+method.
    let forms = 0;
    for (const form of processed.forms) {
      const endpointId = endpointIdByUrl.get(form.endpointUrl);
      if (!endpointId) continue;
      const existingForm = await prisma.endpointForm.findFirst({ where: { endpointId, method: form.method } });
      if (existingForm) {
        await prisma.endpointForm.update({
          where: { id: existingForm.id },
          data: { fieldNames: [...new Set([...existingForm.fieldNames, ...form.fieldNames])].sort(), encodingType: form.encodingType ?? existingForm.encodingType, source: form.source ?? existingForm.source },
        });
      } else {
        await prisma.endpointForm.create({ data: { endpointId, method: form.method, fieldNames: form.fieldNames, encodingType: form.encodingType, source: form.source } });
      }
      forms++;
    }
    // ── Prompt 14 multi-cloud payloads (§14/§15/§19/§20/§64) ──
    // Resources persist as BOTH asset rows (provider resource id is
    // the asset identity) and CloudResource rows; a full-inventory
    // result (snapshot present) drives drift: changed exposure /
    // encryption / logging and disappeared resources become drift
    // events, and disappeared resources are marked NOT_SEEN — never
    // deleted (§20). Out-of-scope resources persist with their
    // verdict and are never analyzed (§15).
    const cloudResourceRowByProviderId = new Map<string, string>();
    const cloudAccountRow = (processed.cloud.resources.length > 0 || processed.cloud.identities.length > 0 || processed.cloud.snapshot)
      ? await prisma.cloudAccount.findFirst({ where: { workspaceId: scan.workspaceId, targetId: scan.assessment.targetId } })
      : null;
    if (cloudAccountRow) {
      const account = cloudAccountRow;
      const fullInventory = !!processed.cloud.snapshot;
      const existingResources = fullInventory ? await prisma.cloudResource.findMany({ where: { cloudAccountId: account.id } }) : [];
      const existingByProviderId = new Map(existingResources.map((r) => [r.providerResourceId, r]));
      const seenProviderIds = new Set<string>();
      for (const r of processed.cloud.resources) {
        seenProviderIds.add(r.providerResourceId);
        let assetId = assetIdByHost.get(r.providerResourceId);
        if (!assetId) {
          const existingAsset = await prisma.asset.findFirst({ where: { targetId: scan.assessment.targetId, host: r.providerResourceId } });
          const row = existingAsset
            ? await prisma.asset.update({ where: { id: existingAsset.id }, data: { scopeStatus: r.scopeStatus, lastSeen: new Date(), sources: [...new Set([...existingAsset.sources, r.source])] } })
            : await prisma.asset.create({
                data: {
                  workspaceId: scan.workspaceId, targetId: scan.assessment.targetId, host: r.providerResourceId,
                  type: r.resourceType, scopeStatus: r.scopeStatus, sources: [r.source], discoveredByScanId: scanId,
                },
              });
          assetId = row.id;
          assetIdByHost.set(r.providerResourceId, assetId);
        }
        const prev = existingByProviderId.get(r.providerResourceId);
        const row = await prisma.cloudResource.upsert({
          where: { cloudAccountId_providerResourceId: { cloudAccountId: account.id, providerResourceId: r.providerResourceId } },
          create: {
            workspaceId: scan.workspaceId, cloudAccountId: account.id, provider: account.provider as never,
            resourceType: r.resourceType, providerResourceId: r.providerResourceId, name: r.name,
            region: r.region, zone: r.zone, tags: r.tags as never,
            configurationMetadata: r.configuration as never, exposure: r.exposure,
            criticality: r.criticality ?? "UNSPECIFIED", status: "ACTIVE", scopeStatus: r.scopeStatus,
            sources: [r.source],
          },
          update: {
            name: r.name, region: r.region, zone: r.zone, tags: r.tags as never,
            configurationMetadata: r.configuration as never, exposure: r.exposure,
            status: "ACTIVE", scopeStatus: r.scopeStatus, lastSeen: new Date(),
            sources: [...new Set([...(prev?.sources ?? []), r.source])],
          },
        });
        cloudResourceRowByProviderId.set(r.providerResourceId, row.id);
        if (fullInventory && prev && prev.status === "ACTIVE" && r.scopeStatus === "IN_SCOPE") {
          const prevCfg = (prev.configurationMetadata ?? {}) as Record<string, unknown>;
          const drift = (kind: string, detail: string) => prisma.cloudDriftEvent.create({
            data: { workspaceId: scan.workspaceId, cloudAccountId: account.id, scanId, kind, resourceRef: r.providerResourceId, detail },
          });
          if (prev.exposure !== r.exposure) await drift("EXPOSURE_CHANGED", `exposure ${prev.exposure} → ${r.exposure}`);
          if (JSON.stringify(prevCfg.encryption ?? null) !== JSON.stringify(r.configuration.encryption ?? null)) await drift("ENCRYPTION_CHANGED", "encryption configuration changed");
          if (JSON.stringify(prevCfg.logging ?? prevCfg.enabled ?? null) !== JSON.stringify(r.configuration.logging ?? r.configuration.enabled ?? null)) await drift("LOGGING_CHANGED", "logging configuration changed");
        }
      }
      if (fullInventory) {
        for (const prev of existingResources) {
          if (prev.status === "ACTIVE" && !seenProviderIds.has(prev.providerResourceId)) {
            await prisma.cloudResource.update({ where: { id: prev.id }, data: { status: "NOT_SEEN" } });
            await prisma.cloudDriftEvent.create({
              data: {
                workspaceId: scan.workspaceId, cloudAccountId: account.id, scanId, kind: "RESOURCE_REMOVED",
                resourceRef: prev.providerResourceId,
                detail: `${prev.resourceType} ${prev.name} no longer in inventory — marked NOT_SEEN, history retained (§20)`,
              },
            });
          }
        }
        await prisma.cloudAccount.update({ where: { id: account.id }, data: { lastInventoryAt: new Date(), lastAssessmentAt: new Date() } });
        if (processed.cloud.snapshot) {
          const existingSnap = await prisma.cloudInventorySnapshot.findFirst({ where: { cloudAccountId: account.id, scanId } });
          if (!existingSnap) {
            await prisma.cloudInventorySnapshot.create({
              data: {
                workspaceId: scan.workspaceId, cloudAccountId: account.id, scanId,
                provider: account.provider as never, regions: processed.cloud.snapshot.regions,
                resourceCounts: processed.cloud.snapshot.resourceCounts as never,
                snapshotHash: processed.cloud.snapshot.snapshotHash,
              },
            });
          }
        }
      }
      for (const i of processed.cloud.identities) {
        if (!i.providerIdentityId) continue;
        const prev = fullInventory
          ? await prisma.cloudIdentity.findUnique({ where: { cloudAccountId_providerIdentityId: { cloudAccountId: account.id, providerIdentityId: i.providerIdentityId } } })
          : null;
        await prisma.cloudIdentity.upsert({
          where: { cloudAccountId_providerIdentityId: { cloudAccountId: account.id, providerIdentityId: i.providerIdentityId } },
          create: {
            workspaceId: scan.workspaceId, cloudAccountId: account.id, provider: account.provider as never,
            identityType: i.identityType, providerIdentityId: i.providerIdentityId, name: i.name,
            privileged: i.privileged ?? false, privilegeEvidence: (i.privilegeEvidence ?? undefined) as never,
            mfaEnabled: i.mfaEnabled,
            ...(i.lastUsedAt ? { lastUsedAt: new Date(i.lastUsedAt) } : {}),
            ...(i.lastSignInAt ? { lastSignInAt: new Date(i.lastSignInAt) } : {}),
            keyAgeDays: i.keyAgeDays, metadata: i.metadata as never,
          },
          update: {
            name: i.name, privileged: i.privileged ?? false,
            privilegeEvidence: (i.privilegeEvidence ?? undefined) as never, mfaEnabled: i.mfaEnabled,
            ...(i.lastUsedAt ? { lastUsedAt: new Date(i.lastUsedAt) } : {}),
            keyAgeDays: i.keyAgeDays, metadata: i.metadata as never, lastSeen: new Date(),
          },
        });
        if (fullInventory && prev && prev.privileged !== (i.privileged ?? false)) {
          await prisma.cloudDriftEvent.create({
            data: {
              workspaceId: scan.workspaceId, cloudAccountId: account.id, scanId, kind: "IAM_CHANGED",
              resourceRef: i.providerIdentityId,
              detail: `identity ${i.name} privilege ${String(prev.privileged)} → ${String(i.privileged ?? false)}`,
            },
          });
        }
      }
      for (const rel of processed.cloud.relationships) {
        await prisma.cloudRelationship.upsert({
          where: {
            cloudAccountId_fromType_fromRef_relationship_toType_toRef: {
              cloudAccountId: account.id, fromType: rel.fromType, fromRef: rel.fromRef,
              relationship: rel.relationship, toType: rel.toType, toRef: rel.toRef,
            },
          },
          create: {
            workspaceId: scan.workspaceId, cloudAccountId: account.id,
            fromType: rel.fromType, fromRef: rel.fromRef, toType: rel.toType, toRef: rel.toRef,
            relationship: rel.relationship, evidence: rel.evidence,
          },
          update: { evidence: rel.evidence, lastSeen: new Date() },
        });
      }
      for (const a of processed.cloud.controlAssessments) {
        await prisma.controlAssessment.create({
          data: {
            workspaceId: scan.workspaceId, scanId, frameworkKey: a.frameworkKey, controlId: a.controlId,
            subjectRef: a.subjectRef, status: a.status as never, evidence: a.evidence,
          },
        });
      }
    }
    // Prompt 12: the scan's source context (repository + snapshot) for
    // attaching code locations, secret metadata and components.
    const sourceCtx = processed.findings.some((f) => f.filePath || f.componentPurl || f.secret) || processed.components.length > 0
      ? await this.loadSourceContext(scan.workspaceId, scan.assessment.targetId, scanId)
      : undefined;
    let findings = 0;
    for (const f of processed.findings) {
      // Prompt 7 §16/§17/§29: the full normalized record persists — CVE /
      // CWE / CVSS only when present on the processed finding (sourced by
      // the tool output or the curated taxonomy upstream, never invented
      // here). Every source gets its own evidence row; references are
      // validated upstream by sanitizeReferenceUrl (§54).
      const created = await prisma.finding.create({
        data: {
          workspaceId: scan.workspaceId, scanId, assetId: f.host ? assetIdByHost.get(f.host) : undefined,
          title: f.title, description: f.description, severity: f.severity as never, confidence: f.confidence,
          host: f.host, endpoint: f.endpoint, fingerprint: f.fingerprint, isMock: f.isMock,
          toolExecutionId: executionId, status: "OPEN", verificationStatus: "UNVERIFIED",
          vulnClass: f.vulnClass, sources: f.sources,
          cve: f.cve, cwe: f.cwe, owaspCategory: f.owaspCategory,
          cvssScore: f.cvssScore, cvssVector: f.cvssVector,
          port: f.port, protocol: f.protocol, parameter: f.parameter,
          technicalImpact: f.technicalImpact, businessImpact: f.businessImpact, remediation: f.remediation,
          // Prompt 12 (§59/§92): source location + dependency identity.
          // Secret findings persist ONLY their metadata row (§42) — the
          // raw value does not exist in any processed shape.
          repositoryId: f.filePath || f.componentPurl || f.secret ? sourceCtx?.repositoryId : undefined,
          snapshotId: f.filePath || f.componentPurl || f.secret ? sourceCtx?.snapshotId : undefined,
          filePath: f.filePath, startLine: f.startLine, endLine: f.endLine,
          startColumn: f.startColumn, endColumn: f.endColumn,
          ruleId: f.ruleId, codeFlow: (f.codeFlow ?? undefined) as never,
          componentPurl: f.componentPurl, fixedVersion: f.fixedVersion,
          dependencyScope: f.dependencyScope, reachability: f.reachability,
          baselineStatus: f.baselineStatus,
          reviewStatus: f.reviewStatus,
          // Prompt 13 (§51/§94): cloud-native identity — origin, image
          // digest binding, cluster/workload identity, control id.
          origin: f.origin, imageDigest: f.imageDigest, imageRef: f.imageRef,
          clusterRef: f.clusterRef, namespace: f.namespace,
          resourceKind: f.resourceKind, resourceName: f.resourceName,
          containerName: f.containerName, controlId: f.controlId,
          // Prompt 14 (§58/§61): multi-cloud identity — provider,
          // account, resource row (resolved from the payload above),
          // provider resource id, region and finding class.
          cloudProvider: f.cloudProvider, cloudAccountId: f.cloudAccountId ?? cloudAccountRow?.id,
          cloudResourceId: f.providerResourceId ? cloudResourceRowByProviderId.get(f.providerResourceId) : undefined,
          providerResourceId: f.providerResourceId, cloudRegion: f.cloudRegion,
          findingClass: f.findingClass,
          // Prompt 15 (§61/§67): directory identity — domain row +
          // directory object the finding concerns.
          directoryDomainId: f.directoryDomainId, directoryObjectId: f.directoryObjectId,
          // Prompt 17 (§49–§52): mobile identity — application + build
          // rows resolved from the stamped identity, platform, finding
          // type, OWASP Mobile / MASVS mappings, cross-build key and
          // the dynamic-confirmation flag (§88).
          mobileApplicationId: f.mobileApplicationId, mobileBuildId: f.mobileBuildId,
          mobileBuildHash: f.mobileBuildHash, mobilePlatform: f.mobilePlatform,
          mobileFindingType: f.mobileFindingType as never, mobileComponent: f.mobileComponent,
          owaspMobile: f.owaspMobile, masvsControl: f.masvsControl,
          crossBuildFingerprint: f.crossBuildFingerprint,
          dynamicConfirmed: f.dynamicConfirmed ?? false,
          // Prompt 18 (§50–§63): binary identity — artifact row +
          // SHA-256, §56 type, concerned component, §62 reachability
          // evidence state, §57 cross-build fingerprint, §63 static
          // confidence band.
          binaryArtifactId: f.binaryArtifactId, binaryArtifactHash: f.binaryArtifactHash,
          binaryFindingType: f.binaryFindingType, binaryComponent: f.binaryComponent,
          binaryReachability: f.binaryReachability, binaryFingerprint: f.binaryFingerprint,
          staticConfidence: f.staticConfidence,
          ...(f.secret ? {
            secretMetadata: {
              create: {
                secretType: f.secret.secretType as never,
                detector: f.secret.detector,
                // Location lives on the finding (§59); the metadata row
                // mirrors file/line for the secret dashboard (§93).
                filePath: f.filePath,
                startLine: f.startLine,
                commitSha: f.secret.commitSha,
                fingerprint: f.secret.fingerprint,
                redactedPreview: f.secret.redactedPreview,
                verificationStatus: f.secret.verificationStatus as never,
              },
            },
          } : {}),
          evidence: {
            create: f.evidenceRows.map((e) => ({
              sourceTool: e.sourceTool, evidenceType: "TEXT", summary: e.summary,
              fingerprint: e.fingerprint, matchedAt: e.matchedAt,
              metadata: (e.metadata ?? undefined) as never,
            })),
          },
          references: { create: f.references.map((r) => ({ type: r.type, label: r.label, url: r.url })) },
          history: { create: { workspaceId: scan.workspaceId, event: "CREATED", metadata: { sourceTool: f.sourceTool } as never } },
        },
      });
      void created;
      findings++;
    }
    // Software components (Prompt 12 §45): upserted per snapshot+PURL so
    // the inventory is canonical per snapshot across tools and stages.
    let components = 0;
    if (sourceCtx?.snapshotId) {
      for (const c of processed.components) {
        await prisma.softwareComponent.upsert({
          where: { snapshotId_purl: { snapshotId: sourceCtx.snapshotId, purl: c.purl } },
          create: {
            snapshotId: sourceCtx.snapshotId,
            name: c.name, version: c.version, ecosystem: c.ecosystem, purl: c.purl,
            sourceManifest: c.sourceManifest, scope: c.scope,
            dependencyScope: c.dependencyScope, licenses: c.licenses,
            ...(c.supplier ? { supplier: c.supplier } : {}),
          },
          update: { licenses: c.licenses, dependencyScope: c.dependencyScope },
        });
        components++;
      }
    }
    // HTTP transactions (Prompt 8 §25/§26): metadata, hashes, sizes,
    // artifact references and redacted display copies — raw bodies are
    // never written to Postgres.
    let transactions = 0;
    for (const tx of processed.transactions) {
      await prisma.httpTransaction.create({
        data: {
          scanId, workspaceId: scan.workspaceId,
          assetId: assetIdByHost.get(tx.host),
          endpointId: endpointIdByUrl.get(tx.url) ?? endpointIdByUrl.get(tx.url.split("?")[0]!),
          toolExecutionId: executionId,
          method: tx.method, url: tx.url, host: tx.host, statusCode: tx.statusCode,
          source: tx.source, scopeStatus: tx.scopeStatus, apiKind: tx.apiKind,
          requestHash: tx.requestHash, responseHash: tx.responseHash,
          requestSize: tx.requestSize, responseSize: tx.responseSize,
          requestArtifactRef: tx.requestArtifactRef, responseArtifactRef: tx.responseArtifactRef,
          requestRedacted: tx.requestRedacted, responseRedacted: tx.responseRedacted,
          ...(tx.observedAt ? { observedAt: new Date(tx.observedAt) } : {}),
        },
      });
      transactions++;
    }
    // WebSocket inventory (§49): upserted per scan+URL.
    let webSockets = 0;
    for (const ws of processed.webSockets) {
      await prisma.webSocketEndpoint.upsert({
        where: { scanId_url: { scanId, url: ws.url } },
        create: { scanId, workspaceId: scan.workspaceId, url: ws.url, origin: ws.origin, subprotocol: ws.subprotocol, source: ws.source, scopeStatus: ws.scopeStatus, authPresent: ws.authPresent },
        update: { origin: ws.origin, subprotocol: ws.subprotocol, source: ws.source, scopeStatus: ws.scopeStatus, authPresent: ws.authPresent ?? undefined },
      });
      webSockets++;
    }
    // API services (Prompt 9 §3/§37): upserted per asset+baseUrl. The
    // owning asset is resolved from this result, from earlier stages'
    // rows, or created as a recorded (never promoted) asset — an
    // out-of-scope API base is stored with its verdict, exactly like a
    // discovered asset (§5).
    let apiServices = 0;
    const resolveAssetId = async (host: string, scopeStatus: string): Promise<string | undefined> => {
      const known = assetIdByHost.get(host);
      if (known) return known;
      const existing = await prisma.asset.findFirst({ where: { targetId: scan.assessment.targetId, host } });
      if (existing) { assetIdByHost.set(host, existing.id); return existing.id; }
      const created = await prisma.asset.create({
        data: { workspaceId: scan.workspaceId, targetId: scan.assessment.targetId, host, type: "HOST", scopeStatus, sources: [], discoveredByScanId: scanId },
      });
      assetIdByHost.set(host, created.id);
      return created.id;
    };
    for (const svc of processed.apiServices) {
      const assetId = await resolveAssetId(svc.host, svc.scopeStatus);
      if (!assetId) continue;
      await prisma.apiService.upsert({
        where: { assetId_baseUrl: { assetId, baseUrl: svc.baseUrl } },
        create: {
          workspaceId: scan.workspaceId, assetId, baseUrl: svc.baseUrl, host: svc.host, apiType: svc.apiType,
          version: svc.version, authenticationType: svc.authenticationType, specificationId: svc.specificationId,
          source: svc.source, scopeStatus: svc.scopeStatus,
        },
        update: {
          apiType: svc.apiType, version: svc.version, authenticationType: svc.authenticationType,
          specificationId: svc.specificationId, source: svc.source, scopeStatus: svc.scopeStatus, lastSeen: new Date(),
        },
      });
      apiServices++;
    }
    // GraphQL services (§26): upserted per workspace+endpoint.
    let graphqlServices = 0;
    for (const g of processed.graphqlServices) {
      const assetId = await resolveAssetId(g.host, g.scopeStatus);
      await prisma.graphqlService.upsert({
        where: { workspaceId_endpointUrl: { workspaceId: scan.workspaceId, endpointUrl: g.endpointUrl } },
        create: {
          workspaceId: scan.workspaceId, assetId, endpointUrl: g.endpointUrl, schemaAvailable: g.schemaAvailable,
          queries: g.queries, mutations: g.mutations, subscriptions: g.subscriptions, types: g.types,
          authenticationRequired: g.authenticationRequired, source: g.source, scopeStatus: g.scopeStatus,
        },
        update: {
          assetId, schemaAvailable: g.schemaAvailable, queries: g.queries, mutations: g.mutations,
          subscriptions: g.subscriptions, types: g.types, authenticationRequired: g.authenticationRequired,
          source: g.source, scopeStatus: g.scopeStatus,
        },
      });
      graphqlServices++;
    }
    // JWT profiles (§25): metadata only — fingerprint, header and
    // redacted claims. Deduped per scan+fingerprint; the raw token does
    // not exist in any processed shape, so nothing secret can land here.
    let jwtProfiles = 0;
    for (const p of processed.jwtProfiles) {
      const existing = await prisma.jwtProfile.findFirst({ where: { scanId, fingerprint: p.fingerprint } });
      if (existing) continue;
      await prisma.jwtProfile.create({
        data: {
          workspaceId: scan.workspaceId, scanId, targetId: scan.assessment.targetId,
          fingerprint: p.fingerprint, algorithm: p.algorithm, tokenType: p.tokenType, keyId: p.keyId,
          issuer: p.issuer, audience: p.audience ?? [], source: p.source, host: p.host, endpoint: p.endpoint,
          lifetimeSeconds: p.lifetimeSeconds,
          claimsSummary: p.claimsSummary as never,
          ...(p.expiresAt ? { expiresAt: new Date(p.expiresAt) } : {}),
          ...(p.notBefore ? { notBefore: new Date(p.notBefore) } : {}),
          ...(p.issuedAt ? { issuedAt: new Date(p.issuedAt) } : {}),
        },
      });
      jwtProfiles++;
    }
    // Packet captures (Prompt 10 §43/§74): METADATA rows only — the
    // bytes are the execution's object-storage artifact; storageKey
    // points at it, and raw access is VIEW_RAW_PCAP-gated + audited at
    // the API layer (§47). Deduped per scan+storageKey.
    let packetCaptures = 0;
    for (const cap of processed.packetCaptures) {
      const existingCap = await prisma.packetCaptureArtifact.findFirst({ where: { scanId, storageKey: cap.artifactRef } });
      if (existingCap) continue;
      await prisma.packetCaptureArtifact.create({
        data: {
          workspaceId: scan.workspaceId, scanId, toolExecutionId: executionId,
          assetId: cap.assetHost ? assetIdByHost.get(cap.assetHost) : undefined,
          format: cap.format, source: cap.source, storageKey: cap.artifactRef,
          sha256: cap.sha256, sizeBytes: cap.sizeBytes, durationSeconds: cap.durationSeconds,
          interfaceName: cap.interfaceName,
        },
      });
      packetCaptures++;
    }
    // ── Prompt 13 cloud-native payloads (§5/§37/§56/§59) ──
    // Images upsert on (workspace, registry, repository, digest) — the
    // digest is the identity; a new digest is a NEW row + snapshot
    // (drift), never an overwrite (§78). Components from image scans
    // (Syft) bind to the image (§13). Workloads upsert per cluster
    // identity; control assessments and runtime events append.
    const targetRow = await prisma.target.findUnique({ where: { id: scan.assessment.targetId } });
    const cloudCtx = targetRow ? await this.loadCloudContext(scan.workspaceId, targetRow.id, targetRow.type, targetRow.value) : undefined;
    for (const img of processed.cloudNative.images) {
      const existingImg = await prisma.containerImage.findFirst({
        where: { workspaceId: scan.workspaceId, registry: img.registry, repository: img.repository, digest: img.digest ?? null },
      });
      const row = existingImg
        ? await prisma.containerImage.update({ where: { id: existingImg.id }, data: { lastSeen: new Date(), tag: img.tag ?? existingImg.tag } })
        : await prisma.containerImage.create({
            data: {
              workspaceId: scan.workspaceId, targetId: scan.assessment.targetId,
              reference: img.reference ?? `${img.registry}/${img.repository}${img.tag ? `:${img.tag}` : ""}${img.digest ? `@${img.digest}` : ""}`, registry: img.registry, repository: img.repository, tag: img.tag, digest: img.digest,
              platform: img.platform, architecture: img.architecture, os: img.os, source: img.source,
            },
          });
      await prisma.containerImageSnapshot.create({
        data: {
          imageId: row.id, scanId, digest: img.digest ?? "unknown",
          config: (img.config ?? {}) as never, layers: (img.layers ?? []) as never,
          baseImage: (img.baseImage ?? undefined) as never,
        },
      });
      void row;
    }
    if (cloudCtx?.imageId && processed.components.length > 0) {
      for (const c of processed.components) {
        await prisma.softwareComponent.upsert({
          where: { imageId_purl: { imageId: cloudCtx.imageId, purl: c.purl } },
          create: {
            imageId: cloudCtx.imageId,
            name: c.name, version: c.version, ecosystem: c.ecosystem, purl: c.purl,
            sourceManifest: c.sourceManifest, scope: c.scope,
            dependencyScope: c.dependencyScope, licenses: c.licenses,
            ...(c.supplier ? { supplier: c.supplier } : {}),
          },
          update: { licenses: c.licenses, dependencyScope: c.dependencyScope },
        });
        components++;
      }
    }
    for (const w of processed.cloudNative.workloads) {
      const cluster = cloudCtx?.clusterId
        ? await prisma.kubernetesCluster.findUnique({ where: { id: cloudCtx.clusterId } })
        : await prisma.kubernetesCluster.findFirst({ where: { workspaceId: scan.workspaceId, name: w.clusterRef } });
      if (!cluster) continue;
      await prisma.kubernetesWorkload.upsert({
        where: { clusterId_kind_namespace_name: { clusterId: cluster.id, kind: w.kind, namespace: w.namespace, name: w.name } },
        create: {
          workspaceId: scan.workspaceId, clusterId: cluster.id, scanId,
          kind: w.kind, namespace: w.namespace, name: w.name, replicas: w.replicas,
          serviceAccount: w.serviceAccount, images: w.images as never,
          securityContext: w.securityContext as never, exposure: w.exposure, labels: w.labels as never,
        },
        update: {
          scanId, replicas: w.replicas, serviceAccount: w.serviceAccount,
          images: w.images as never, securityContext: w.securityContext as never,
          exposure: w.exposure, labels: w.labels as never, lastSeen: new Date(),
        },
      });
    }
    for (const a of processed.cloudNative.controlAssessments) {
      await prisma.controlAssessment.create({
        data: {
          workspaceId: scan.workspaceId, scanId, frameworkKey: a.frameworkKey, controlId: a.controlId,
          subjectRef: a.subjectRef, status: a.status as never, evidence: a.evidence,
        },
      });
    }
    for (const e of processed.cloudNative.runtimeEvents) {
      await prisma.runtimeSecurityEvent.create({
        data: {
          workspaceId: scan.workspaceId, clusterId: cloudCtx?.clusterId,
          clusterName: e.clusterName, node: e.node, namespace: e.namespace, pod: e.pod,
          container: e.container, rule: e.rule, priority: e.priority,
          eventTime: new Date(e.eventTime), metadata: e.metadata as never, source: e.source,
        },
      });
    }
    for (const m of processed.cloudNative.manifests) {
      await prisma.infrastructureManifest.create({
        data: {
          workspaceId: scan.workspaceId, scanId, filePath: m.filePath,
          manifestType: m.manifestType, resourceCount: m.resourceCount, checksum: m.checksum,
        },
      });
    }
    // ── Prompt 15 Active Directory payload (§13–§19/§79) ──
    // Directory inventory persists into the dedicated directory
    // tables (upserts keyed by domain + object id); the posture
    // analysis runs over the persisted inventory and its findings
    // join the scan deduped by canonical fingerprint (§61). Drift is
    // diffed against the pre-collection persisted state (§79/§80).
    const directoryCounts = await this.persistDirectoryPayload(scan, processed);
    const mobileCounts = await this.persistMobilePayload(scan, processed);
    const binaryCounts = await this.persistBinaryPayload(scan, processed);
    return { assets: processed.assets.length, findings: findings + directoryCounts.findings + mobileCounts.findings + binaryCounts.findings, endpoints, services, technologies, parameters, forms, transactions, webSockets, apiServices, graphqlServices, jwtProfiles, packetCaptures, components, directoryUsers: directoryCounts.users, directoryGroups: directoryCounts.groups, directoryComputers: directoryCounts.computers, directoryRelationships: directoryCounts.relationships };
  }

  /** Reconstruct the normalized directory inventory for a domain from
   *  its persisted rows — the single read path every AD platform hook
   *  and the persistence analysis share. */
  private async loadDirectoryInventory(domainId: string): Promise<NormalizedDirectoryData> {
    const [domain, dcs, users, groups, computers, ous, gpos, trusts, rels, shares, cas, templates] = await Promise.all([
      prisma.activeDirectoryDomain.findUnique({ where: { id: domainId } }),
      prisma.domainController.findMany({ where: { domainId } }),
      prisma.directoryUser.findMany({ where: { domainId } }),
      prisma.directoryGroup.findMany({ where: { domainId } }),
      prisma.directoryComputer.findMany({ where: { domainId } }),
      prisma.directoryOrganizationalUnit.findMany({ where: { domainId } }),
      prisma.groupPolicyObject.findMany({ where: { domainId } }),
      prisma.directoryTrust.findMany({ where: { domainId } }),
      prisma.directoryRelationship.findMany({ where: { domainId } }),
      prisma.smbShare.findMany({ where: { domainId } }),
      prisma.certificateAuthority.findMany({ where: { domainId } }),
      prisma.certificateTemplate.findMany({ where: { domainId } }),
    ]);
    return {
      ...(domain ? { domain: { dnsName: domain.dnsName, ...(domain.netbiosName ? { netbiosName: domain.netbiosName } : {}), ...(domain.domainSid ? { domainSid: domain.domainSid } : {}), ...(domain.functionalLevel ? { functionalLevel: domain.functionalLevel } : {}) } } : {}),
      domainControllers: dcs.map((d) => ({ hostname: d.hostname, ...(d.dnsName ? { dnsName: d.dnsName } : {}), ipAddresses: d.ipAddresses, ...(d.osName ? { osName: d.osName } : {}), ...(d.osVersion ? { osVersion: d.osVersion } : {}), services: (d.services ?? {}) as Record<string, unknown> })),
      users: users.map((u) => ({
        objectId: u.objectId, samAccountName: u.samAccountName, ...(u.displayName ? { displayName: u.displayName } : {}),
        ...(u.userPrincipalName ? { userPrincipalName: u.userPrincipalName } : {}), enabled: u.enabled,
        isServiceAccount: u.isServiceAccount, passwordNeverExpires: u.passwordNeverExpires,
        passwordNotRequired: u.passwordNotRequired, preauthNotRequired: u.preauthNotRequired,
        spnPresent: u.spnPresent, spns: u.spns, delegationType: u.delegationType as never, delegationTargets: u.delegationTargets,
        ...(u.lastLogonAt ? { lastLogonAt: u.lastLogonAt.toISOString() } : {}),
        ...(u.passwordLastSetAt ? { passwordLastSetAt: u.passwordLastSetAt.toISOString() } : {}),
      })),
      groups: groups.map((g) => ({ objectId: g.objectId, name: g.name, groupScope: g.groupScope as never, groupType: g.groupType as never, privilegeClass: g.privilegeClass as never, memberCount: g.memberCount })),
      computers: computers.map((c) => ({
        objectId: c.objectId, hostname: c.hostname, ...(c.dnsName ? { dnsName: c.dnsName } : {}),
        ...(c.osName ? { osName: c.osName } : {}), ...(c.osVersion ? { osVersion: c.osVersion } : {}),
        enabled: c.enabled, isDomainController: c.isDomainController,
        delegationType: c.delegationType as never, delegationTargets: c.delegationTargets,
      })),
      organizationalUnits: ous.map((o) => ({ objectId: o.objectId, name: o.name, distinguishedName: o.distinguishedName, ...(o.parentRef ? { parentRef: o.parentRef } : {}), linkedGpoIds: o.linkedGpoIds })),
      groupPolicies: gpos.map((g) => ({ objectId: g.objectId, name: g.name, linkedTo: g.linkedTo, securityMetadata: (g.securityMetadata ?? {}) as Record<string, unknown>, delegationMetadata: (g.delegationMetadata ?? {}) as Record<string, unknown>, ...(g.lastModifiedAt ? { lastModifiedAt: g.lastModifiedAt.toISOString() } : {}) })),
      trusts: trusts.map((t) => ({
        targetDomainName: t.targetDomainName, direction: t.direction as never, trustType: t.trustType as never,
        transitive: t.transitive, ...(t.sidFilteringEnabled !== null ? { sidFilteringEnabled: t.sidFilteringEnabled } : {}),
        ...(t.selectiveAuthentication !== null ? { selectiveAuthentication: t.selectiveAuthentication } : {}),
      })),
      relationships: rels.map((r) => ({
        fromType: r.fromType, fromRef: r.fromRef, toType: r.toType, toRef: r.toRef, relationship: r.relationship,
        source: r.source, confidence: r.confidence as never, ...(r.evidenceRef ? { evidenceRef: r.evidenceRef } : {}),
      })),
      smbShares: shares.map((s) => ({
        host: s.host, shareName: s.shareName, accessLevel: s.accessLevel as never,
        ...(s.anonymousAccess !== null ? { anonymousAccess: s.anonymousAccess } : {}),
        ...(s.smbDialect ? { smbDialect: s.smbDialect } : {}),
        ...(s.signingRequired !== null ? { signingRequired: s.signingRequired } : {}), source: s.source,
      })),
      certificateAuthorities: cas.map((c) => ({ name: c.name, ...(c.dnsName ? { dnsName: c.dnsName } : {}), enrollmentServices: (c.enrollmentServices ?? []) as string[], metadata: (c.metadata ?? {}) as Record<string, unknown> })),
      certificateTemplates: templates.map((t) => ({
        name: t.name, ...(t.objectId ? { objectId: t.objectId } : {}), enabled: t.enabled,
        enrollmentPermissions: (t.enrollmentPermissions ?? {}) as Record<string, unknown>,
        subjectConfig: (t.subjectConfig ?? {}) as Record<string, unknown>,
        authenticationEkus: t.authenticationEkus, managerApprovalRequired: t.managerApprovalRequired,
        authorizedSignaturesRequired: t.authorizedSignaturesRequired,
        issuanceRequirements: (t.issuanceRequirements ?? {}) as Record<string, unknown>,
        riskClasses: t.riskClasses,
      })),
    };
  }

  /** Persist one result's directory payload + run the posture analysis
   *  over the persisted inventory (§57–§78). Returns row counts. */
  /** Prompt 18 binary payload persistence (§12–§52): artifact
   *  inventory upserts by identity key (sections by name, functions
   *  by name+address, dependencies by library), the merged hardening
   *  profile, components + SBOM records bound to the artifact
   *  (§26/§27) and dependency→CVE correlation against the LOCAL
   *  intelligence dataset only (§27/§49 — the production dataset is
   *  empty in this build ⇒ zero matches, never invented). Extracted
   *  references persist as DISCOVERED_REFERENCE rows inside the
   *  string inventory — they never expand scope (§31). Secret
   *  candidate rows carry fingerprints only (§30). */
  private async persistBinaryPayload(
    scan: { id: string; workspaceId: string },
    processed: ProcessedResult,
  ): Promise<{ findings: number }> {
    const payload = processed.binary;
    const inventoryCount = payload.sections.length + payload.functions.length + payload.imports.length
      + payload.exports.length + payload.symbols.length + payload.dependencies.length + payload.hardening.length;
    if (inventoryCount === 0) return { findings: 0 };
    const ctx = await this.binaryArtifactForScan(scan.id);
    if (!ctx) return { findings: 0 };
    const { artifact } = ctx;
    const ws = scan.workspaceId;
    for (const s of payload.sections) {
      const data = {
        type: s.type, offset: s.offset !== undefined ? BigInt(Math.trunc(s.offset)) : undefined,
        size: s.size !== undefined ? BigInt(Math.trunc(s.size)) : undefined,
        virtualAddress: s.virtualAddress, permissions: s.permissions, entropy: s.entropy, source: s.source,
      };
      const existing = await prisma.binarySection.findFirst({ where: { artifactId: artifact.id, name: s.name } });
      if (existing) await prisma.binarySection.update({ where: { id: existing.id }, data });
      else await prisma.binarySection.create({ data: { artifactId: artifact.id, workspaceId: ws, name: s.name, ...data } });
    }
    if (payload.hardening.length > 0) {
      const existingProfile = await prisma.binaryHardeningProfile.findUnique({ where: { artifactId: artifact.id } });
      const merged = new Map<string, unknown>();
      for (const h of ((existingProfile?.profile as unknown[]) ?? [])) {
        const rec = h as { name?: string };
        if (rec.name) merged.set(rec.name, h);
      }
      for (const h of payload.hardening) {
        const prev = merged.get(h.name) as { status?: string } | undefined;
        // A concrete status from any tool beats UNKNOWN (§16).
        if (!prev || prev.status === "UNKNOWN" || h.status !== "UNKNOWN") merged.set(h.name, h);
      }
      const profile = [...merged.values()] as never;
      if (existingProfile) await prisma.binaryHardeningProfile.update({ where: { artifactId: artifact.id }, data: { profile, assessedAt: new Date() } });
      else await prisma.binaryHardeningProfile.create({ data: { artifactId: artifact.id, workspaceId: ws, profile } });
    }
    for (const fn of payload.functions) {
      const existing = await prisma.binaryFunction.findFirst({ where: { artifactId: artifact.id, name: fn.name, address: fn.address ?? null } });
      const data = {
        size: fn.size, callingConvention: fn.callingConvention, fingerprint: fn.fingerprint,
        referencesRiskyApi: fn.referencesRiskyApi ?? [], confidence: fn.confidence, source: fn.source,
      };
      if (existing) await prisma.binaryFunction.update({ where: { id: existing.id }, data });
      else await prisma.binaryFunction.create({ data: { artifactId: artifact.id, workspaceId: ws, name: fn.name, address: fn.address, ...data } });
    }
    for (const imp of payload.imports) {
      const existing = await prisma.binaryImport.findFirst({ where: { artifactId: artifact.id, library: imp.library, symbol: imp.symbol } });
      if (!existing) await prisma.binaryImport.create({ data: { artifactId: artifact.id, workspaceId: ws, library: imp.library, symbol: imp.symbol, address: imp.address, source: imp.source } });
    }
    for (const exp of payload.exports) {
      const existing = await prisma.binaryExport.findFirst({ where: { artifactId: artifact.id, symbol: exp.symbol } });
      if (!existing) await prisma.binaryExport.create({ data: { artifactId: artifact.id, workspaceId: ws, symbol: exp.symbol, address: exp.address, type: exp.type, source: exp.source } });
    }
    for (const sym of payload.symbols) {
      const existing = await prisma.binarySymbol.findFirst({ where: { artifactId: artifact.id, name: sym.name } });
      if (!existing) await prisma.binarySymbol.create({ data: { artifactId: artifact.id, workspaceId: ws, name: sym.name, type: sym.type, binding: sym.binding, address: sym.address, source: sym.source } });
    }
    for (const str of payload.strings) {
      const existing = await prisma.binaryString.findFirst({ where: { artifactId: artifact.id, value: str.value, category: str.category, secretFingerprint: str.secretFingerprint ?? null } });
      if (!existing) {
        await prisma.binaryString.create({
          data: {
            artifactId: artifact.id, workspaceId: ws, value: str.value, encoding: str.encoding,
            category: str.category, location: str.location, secretFingerprint: str.secretFingerprint,
            secretType: str.secretType, redactedPreview: str.redactedPreview, source: str.source,
          },
        });
      }
    }
    for (const dep of payload.dependencies) {
      const existing = await prisma.binaryDependency.findFirst({ where: { artifactId: artifact.id, library: dep.library } });
      const data = {
        version: dep.version, path: dep.path, platform: dep.platform, purl: dep.purl, cpe: dep.cpe,
        sourceKind: dep.sourceKind, confidence: dep.confidence, source: dep.source,
      };
      if (existing) await prisma.binaryDependency.update({ where: { id: existing.id }, data });
      else await prisma.binaryDependency.create({ data: { artifactId: artifact.id, workspaceId: ws, library: dep.library, ...data } });
    }
    for (const c of payload.cryptoReferences) {
      const existing = await prisma.binaryCryptoReference.findFirst({ where: { artifactId: artifact.id, kind: c.kind, name: c.name } });
      if (!existing) await prisma.binaryCryptoReference.create({ data: { artifactId: artifact.id, workspaceId: ws, kind: c.kind, name: c.name, source: c.source } });
    }
    // Components + SBOM bound to the artifact (§26/§27).
    for (const c of processed.components) {
      await prisma.softwareComponent.upsert({
        where: { binaryArtifactId_purl: { binaryArtifactId: artifact.id, purl: c.purl } },
        create: {
          binaryArtifactId: artifact.id,
          name: c.name, version: c.version, ecosystem: c.ecosystem, purl: c.purl,
          sourceManifest: c.sourceManifest, scope: c.scope as never,
          dependencyScope: c.dependencyScope as never, licenses: c.licenses ?? [],
        },
        update: { version: c.version, licenses: c.licenses ?? [] },
      });
    }
    if (processed.components.length > 0) {
      const cyclonedx = buildCycloneDxSbom(processed.components, {
        snapshotHash: artifact.sha256, repositoryName: artifact.name, timestamp: new Date().toISOString(),
      });
      const spdx = buildSpdxSbom(processed.components, {
        snapshotHash: artifact.sha256, repositoryName: artifact.name, timestamp: new Date().toISOString(),
      });
      for (const doc of [cyclonedx.sbom, spdx.sbom]) {
        const existing = await prisma.softwareBillOfMaterials.findFirst({ where: { binaryArtifactId: artifact.id, format: doc.format as never } });
        if (!existing) {
          await prisma.softwareBillOfMaterials.create({
            data: {
              binaryArtifactId: artifact.id, scanId: scan.id, format: doc.format as never,
              specVersion: doc.specVersion, checksum: doc.checksum,
              artifactRef: `sbom://binary-artifact/${artifact.id}/${doc.checksum}`,
              componentCount: doc.componentCount,
            },
          });
        }
      }
    }
    // Dependency → CVE correlation vs the LOCAL dataset (§27/§49).
    let intelFindings = 0;
    if (processed.components.length > 0) {
      const names = [...new Set(processed.components.map((c) => c.name.toLowerCase()))];
      const cpes = await prisma.cpeRecord.findMany({
        where: { OR: names.map((n) => ({ canonical: { contains: `:${n}:` } })) },
        take: 500,
      }).catch(() => []);
      if (cpes.length > 0) {
        const cveIds = [...new Set(cpes.flatMap((c) => c.cveIds))];
        const [cves, epssRows, kevRows] = await Promise.all([
          prisma.cveRecord.findMany({ where: { cveId: { in: cveIds } } }),
          prisma.epssRecord.findMany({ where: { cveId: { in: cveIds } }, orderBy: { date: "desc" } }),
          prisma.kevRecord.findMany({ where: { cveId: { in: cveIds } } }),
        ]);
        const dataset = new InMemoryIntelligenceDataset();
        for (const c of cves) {
          const record: Parameters<InMemoryIntelligenceDataset["upsertCve"]>[0] = {
            cveId: c.cveId, description: c.description, cweIds: c.cweIds,
            references: (c.references as { label: string; url: string }[] | null) ?? [], source: c.source,
          };
          if (c.cvssScore != null) {
            record.cvss = { version: (c.cvssVersion ?? "3.1") as CvssRecord["version"], baseScore: c.cvssScore, ...(c.cvssVector ? { vector: c.cvssVector } : {}), source: c.source } as typeof record.cvss;
          }
          dataset.upsertCve(record);
        }
        const seenEpss = new Set<string>();
        for (const e of epssRows) {
          if (seenEpss.has(e.cveId)) continue;
          seenEpss.add(e.cveId);
          dataset.upsertEpss({ cveId: e.cveId, score: e.score, percentile: e.percentile, date: e.date.toISOString().slice(0, 10), source: e.source });
        }
        for (const k of kevRows) dataset.upsertKev({ cveId: k.cveId, source: k.source, ...(k.vendorProject ? { vendorProject: k.vendorProject } : {}), ...(k.product ? { product: k.product } : {}), ...(k.dateAdded ? { dateAdded: k.dateAdded.toISOString().slice(0, 10) } : {}) });
        for (const cpe of cpes) dataset.upsertCpe({ canonical: cpe.canonical, part: cpe.part, vendor: cpe.vendor, product: cpe.product, ...(cpe.version ? { version: cpe.version } : {}), cveIds: cpe.cveIds, source: cpe.source });
        const matches = matchComponentsAgainstIntel(processed.components, dataset);
        const enriched = enrichDependencyFindings(matches, dataset);
        for (const m of enriched) {
          const existingFinding = await prisma.finding.findFirst({ where: { scanId: scan.id, fingerprint: m.sourceFingerprint } });
          if (existingFinding) continue;
          await prisma.finding.create({
            data: {
              workspaceId: ws, scanId: scan.id,
              title: m.title, description: m.description,
              severity: m.severity as never, confidence: m.confidence,
              fingerprint: m.sourceFingerprint, isMock: false,
              status: "OPEN", verificationStatus: "UNVERIFIED",
              sources: [m.sourceTool], vulnClass: "DEPENDENCY_VULNERABILITY",
              cve: m.cve, cwe: m.cwe, cvssScore: m.cvssScore, cvssVector: m.cvssVector,
              componentPurl: m.componentPurl, dependencyScope: m.dependencyScope,
              reachability: "POTENTIAL_EXPOSURE",
              binaryArtifactId: artifact.id, binaryArtifactHash: artifact.sha256,
              binaryFindingType: "BINARY_DEPENDENCY_VULNERABILITY",
              binaryComponent: m.componentPurl,
              binaryReachability: "UNKNOWN", staticConfidence: "MEDIUM",
              binaryFingerprint: binaryFindingFingerprint({
                lineage: `${artifact.format}:${artifact.architecture ?? "unknown"}:${artifact.name}`,
                component: m.componentPurl ?? "dependency", ruleId: "BINARY_DEPENDENCY_VULNERABILITY",
                ...(m.cwe ? { cwe: m.cwe } : {}), findingClass: "BINARY_DEPENDENCY_VULNERABILITY",
                location: m.componentPurl ?? "dependency",
              }),
              evidence: { create: { sourceTool: m.sourceTool, evidenceType: "TEXT", summary: m.evidence } },
              references: { create: m.references.map((url) => ({ type: "OTHER", label: url, url })) },
              history: { create: { workspaceId: ws, event: "CREATED", metadata: { sourceTool: m.sourceTool, origin: "INTEL_MATCH" } as never } },
            },
          });
          intelFindings++;
        }
      }
    }
    await prisma.binaryArtifact.update({
      where: { id: artifact.id },
      data: {
        status: "ANALYZED",
        ...(artifact.format === "UNKNOWN" && payload.format !== "UNKNOWN" ? { format: payload.format } : {}),
        ...(payload.architecture && !artifact.architecture ? { architecture: payload.architecture } : {}),
      },
    }).catch(() => undefined);
    return { findings: intelFindings };
  }

  /** Prompt 17 mobile payload persistence (§20–§52): build inventory
   *  (deep links, components, endpoints, native libraries) upserts by
   *  identity key; build components + SBOM records (§42–§45); platform
   *  posture findings over the merged inventory (stamped, deduped by
   *  canonical fingerprint) and OWASP MASVS control assessments.
   *  Extracted endpoints persist as DISCOVERED_REFERENCE — they never
   *  expand scope (§30). */
  private async persistMobilePayload(
    scan: { id: string; workspaceId: string },
    processed: ProcessedResult,
  ): Promise<{ findings: number }> {
    const payload = processed.mobile;
    const hasPayload = payload.permissions.length + payload.components.length + payload.deepLinks.length
      + payload.endpoints.length + payload.nativeLibraries.length + payload.signing.length > 0;
    if (!hasPayload && processed.components.length === 0) return { findings: 0 };
    const ctx = await this.mobileBuildForScan(scan.id);
    if (!ctx) return { findings: 0 };
    const { app, build } = ctx;
    const scanId = scan.id;
    for (const link of payload.deepLinks) {
      const existing = await prisma.mobileDeepLink.findFirst({
        where: { buildId: build.id, scheme: link.scheme, host: link.host ?? "", pathPrefix: link.pathPrefix ?? "" },
      });
      if (!existing) {
        await prisma.mobileDeepLink.create({
          data: {
            workspaceId: scan.workspaceId, buildId: build.id,
            scheme: link.scheme, host: link.host, pathPrefix: link.pathPrefix,
            autoVerify: link.autoVerify ?? false, source: payload.source,
          },
        });
      }
    }
    for (const component of payload.components) {
      const existing = await prisma.mobileAppComponent.findFirst({
        where: { buildId: build.id, kind: component.kind, name: component.name },
      });
      const data = {
        workspaceId: scan.workspaceId, buildId: build.id,
        kind: component.kind, name: component.name,
        exported: component.exported, permission: component.permission,
        intentActions: component.intentActions ?? [],
      };
      if (existing) await prisma.mobileAppComponent.update({ where: { id: existing.id }, data });
      else await prisma.mobileAppComponent.create({ data });
    }
    for (const endpoint of payload.endpoints) {
      const existing = await prisma.mobileEndpoint.findFirst({ where: { buildId: build.id, url: endpoint.url } });
      if (!existing) {
        await prisma.mobileEndpoint.create({
          data: {
            workspaceId: scan.workspaceId, buildId: build.id, url: endpoint.url,
            host: endpoint.host, kind: endpoint.kind,
            classification: "DISCOVERED_REFERENCE", source: endpoint.source,
          },
        });
      }
    }
    for (const lib of payload.nativeLibraries) {
      const existing = await prisma.mobileNativeLibrary.findFirst({ where: { buildId: build.id, path: lib.path } });
      const data = {
        workspaceId: scan.workspaceId, buildId: build.id, path: lib.path,
        architecture: lib.architecture, sha256: lib.sha256,
        pie: lib.pie, nx: lib.nx, stackCanary: lib.stackCanary,
        relro: lib.relro, stripped: lib.stripped,
      };
      if (existing) await prisma.mobileNativeLibrary.update({ where: { id: existing.id }, data });
      else await prisma.mobileNativeLibrary.create({ data });
    }
    // §42–§45: build components + SBOM records (versions only as
    // reported — never invented).
    if (processed.components.length > 0) {
      for (const c of processed.components) {
        await prisma.softwareComponent.upsert({
          where: { buildId_purl: { buildId: build.id, purl: c.purl } },
          create: {
            buildId: build.id,
            name: c.name, version: c.version, ecosystem: c.ecosystem, purl: c.purl,
            sourceManifest: c.sourceManifest,
            scope: c.scope as never, dependencyScope: c.dependencyScope as never, licenses: c.licenses ?? [],
          },
          update: { version: c.version, licenses: c.licenses ?? [] },
        });
      }
      const cyclonedx = buildCycloneDxSbom(processed.components, {
        snapshotHash: build.artifactHash, repositoryName: app.packageName ?? app.bundleId ?? app.name, timestamp: new Date().toISOString(),
      });
      const spdx = buildSpdxSbom(processed.components, {
        snapshotHash: build.artifactHash, repositoryName: app.packageName ?? app.bundleId ?? app.name, timestamp: new Date().toISOString(),
      });
      for (const doc of [cyclonedx.sbom, spdx.sbom]) {
        const existing = await prisma.softwareBillOfMaterials.findFirst({ where: { buildId: build.id, format: doc.format as never } });
        if (!existing) {
          await prisma.softwareBillOfMaterials.create({
            data: {
              buildId: build.id, scanId, format: doc.format as never,
              specVersion: doc.specVersion, checksum: doc.checksum,
              artifactRef: `sbom://mobile-build/${build.id}/${doc.checksum}`,
              componentCount: doc.componentCount,
            },
          });
        }
      }
    }
    // Platform posture over the merged persisted inventory.
    const inventory = await this.loadMobileInventory(build.id);
    const posture = analyzeMobilePosture(inventory, {
      applicationId: app.id, applicationRef: app.packageName ?? app.bundleId ?? app.name, buildId: build.id,
      buildHash: build.artifactHash, platform: app.platform as "ANDROID" | "IOS",
      environment: app.environment, toolSlug: "mobile-platform-analysis",
    });
    const identity = this.mobileIdentityOf(app, build);
    const stamped = stampMobileFindings(
      processNormalizedResult({
        assets: [], services: [], endpoints: [], technologies: [], findings: posture.findings,
        artifacts: [], metrics: {}, mock: false,
      }, { scopeRules: { includeHosts: [], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] }, toolExecutionId: "platform-mobile-analysis", toolSlug: "mobile-platform-analysis" }).findings,
      identity,
    );
    let created = 0;
    for (const f of stamped) {
      const existing = await prisma.finding.findFirst({ where: { scanId, fingerprint: f.fingerprint } });
      if (existing) continue;
      await prisma.finding.create({
        data: {
          workspaceId: scan.workspaceId, scanId,
          title: f.title, description: f.description, severity: f.severity as never, confidence: f.confidence,
          fingerprint: f.fingerprint, isMock: false, status: "OPEN", verificationStatus: "UNVERIFIED",
          sources: f.sources, ruleId: f.ruleId, cwe: f.cwe, remediation: f.remediation,
          mobileApplicationId: app.id, mobileBuildId: build.id, mobileBuildHash: build.artifactHash,
          mobilePlatform: app.platform, mobileFindingType: f.mobileFindingType as never,
          mobileComponent: f.mobileComponent, owaspMobile: f.owaspMobile, masvsControl: f.masvsControl,
          crossBuildFingerprint: f.crossBuildFingerprint, dynamicConfirmed: false,
          evidence: { create: f.evidenceRows.map((e) => ({ sourceTool: e.sourceTool, evidenceType: "TEXT", summary: e.summary, fingerprint: e.fingerprint })) },
          history: { create: { workspaceId: scan.workspaceId, event: "CREATED", metadata: { sourceTool: f.sourceTool, stage: "MOBILE_MANIFEST_ANALYSIS" } as never } },
        },
      });
      created++;
    }
    for (const a of posture.controlAssessments) {
      const existing = await prisma.controlAssessment.findFirst({
        where: { scanId, frameworkKey: a.frameworkKey, controlId: a.controlId, subjectRef: a.subjectRef },
      });
      if (!existing) {
        await prisma.controlAssessment.create({
          data: {
            workspaceId: scan.workspaceId, scanId, frameworkKey: a.frameworkKey, controlId: a.controlId,
            subjectRef: a.subjectRef, status: a.status as never, evidence: a.evidence,
          },
        });
      }
    }
    return { findings: created };
  }

  /** Prompt 17: rebuild the normalized mobile inventory for a build
   *  from its persisted rows (shared by posture + hooks). The build's
   *  registered analysis artifacts carry the manifest facts (they are
   *  the extraction record); inventory rows carry the rest. */
  private async loadMobileInventory(buildId: string): Promise<NormalizedMobileData> {
    const build = await prisma.mobileBuild.findUnique({ where: { id: buildId } });
    if (!build) return emptyMobileData("mobile-platform-analysis");
    const app = await prisma.mobileApplication.findUnique({ where: { id: build.applicationId } });
    const artifacts = (build.analysisArtifacts ?? {}) as Record<string, unknown>;
    const base = extractMobileArtifacts(artifacts, {
      applicationId: build.applicationId, applicationRef: app?.packageName ?? app?.bundleId ?? app?.name ?? build.id, buildId: build.id,
      buildHash: build.artifactHash, platform: (app?.platform ?? "ANDROID") as "ANDROID" | "IOS",
      environment: app?.environment ?? "PRODUCTION", toolSlug: "mobile-platform-analysis",
    }).data;
    const links = await prisma.mobileDeepLink.findMany({ where: { buildId } });
    const components = await prisma.mobileAppComponent.findMany({ where: { buildId } });
    const endpoints = await prisma.mobileEndpoint.findMany({ where: { buildId } });
    const libs = await prisma.mobileNativeLibrary.findMany({ where: { buildId } });
    return mergeMobileData(base, {
      permissions: [], deepLinks: links.map((l) => ({
        scheme: l.scheme, ...(l.host ? { host: l.host } : {}), ...(l.pathPrefix ? { pathPrefix: l.pathPrefix } : {}),
        autoVerify: l.autoVerify, source: l.source,
      })),
      components: components.map((c) => ({
        kind: c.kind as never, name: c.name, exported: c.exported,
        ...(c.permission ? { permission: c.permission } : {}),
        intentActions: c.intentActions ?? [], source: "mobile-platform-analysis",
      })),
      endpoints: endpoints.map((e) => ({ url: e.url, host: e.host, kind: e.kind as never, classification: "DISCOVERED_REFERENCE" as const, source: e.source })),
      nativeLibraries: libs.map((l) => ({
        path: l.path,
        ...(l.architecture ? { architecture: l.architecture } : {}),
        ...(l.sha256 ? { sha256: l.sha256 } : {}),
        ...(l.pie !== null ? { pie: l.pie } : {}),
        ...(l.nx !== null ? { nx: l.nx } : {}),
        ...(l.stackCanary !== null ? { stackCanary: l.stackCanary } : {}),
        ...(l.relro === "NONE" || l.relro === "PARTIAL" || l.relro === "FULL" ? { relro: l.relro } : {}),
        ...(l.stripped !== null ? { stripped: l.stripped } : {}),
        source: "mobile-platform-analysis",
      })),
      signing: [], sdkInventory: [], source: "mobile-platform-analysis",
    });
  }

  private async persistDirectoryPayload(
    scan: { id: string; workspaceId: string; requestedBy: string; assessment: { targetId: string } },
    processed: ProcessedResult,
  ): Promise<{ users: number; groups: number; computers: number; relationships: number; findings: number }> {
    const workspaceRow = await prisma.workspace.findUnique({ where: { id: scan.workspaceId } });
    const orgId = workspaceRow?.organizationId ?? "";
    const empty = { users: 0, groups: 0, computers: 0, relationships: 0, findings: 0 };
    const payload = processed.directory;
    const hasPayload = payload.users.length + payload.groups.length + payload.computers.length
      + payload.domainControllers.length + payload.relationships.length + payload.smbShares.length
      + payload.certificateAuthorities.length + payload.certificateTemplates.length > 0 || !!payload.snapshot;
    if (!hasPayload) return empty;
    const domain = await prisma.activeDirectoryDomain.findFirst({ where: { workspaceId: scan.workspaceId, targetId: scan.assessment.targetId } });
    if (!domain) return empty;
    const scanId = scan.id;
    const previous = await this.loadDirectoryInventory(domain.id);
    const hasPrevious = previous.users.length + previous.groups.length + previous.computers.length > 0;

    // Domain controllers first (computers reference them by identity).
    for (const dc of payload.domainControllers) {
      const asset = await prisma.asset.findFirst({ where: { targetId: scan.assessment.targetId, host: dc.dnsName ?? dc.hostname } });
      await prisma.domainController.upsert({
        where: { domainId_hostname: { domainId: domain.id, hostname: dc.hostname } },
        create: {
          workspaceId: scan.workspaceId, domainId: domain.id, assetId: asset?.id, hostname: dc.hostname,
          dnsName: dc.dnsName, ipAddresses: dc.ipAddresses, osName: dc.osName, osVersion: dc.osVersion,
          services: dc.services as never,
        },
        update: { dnsName: dc.dnsName, ipAddresses: dc.ipAddresses, osName: dc.osName, osVersion: dc.osVersion, services: dc.services as never, lastSeen: new Date() },
      });
    }
    for (const u of payload.users) {
      await prisma.directoryUser.upsert({
        where: { domainId_objectId: { domainId: domain.id, objectId: u.objectId } },
        create: {
          workspaceId: scan.workspaceId, domainId: domain.id, objectId: u.objectId, samAccountName: u.samAccountName,
          displayName: u.displayName, userPrincipalName: u.userPrincipalName, enabled: u.enabled,
          isServiceAccount: u.isServiceAccount ?? false, passwordNeverExpires: u.passwordNeverExpires ?? false,
          passwordNotRequired: u.passwordNotRequired ?? false, preauthNotRequired: u.preauthNotRequired ?? false,
          spnPresent: u.spnPresent ?? (u.spns?.length ?? 0) > 0, spns: u.spns ?? [],
          delegationType: u.delegationType ?? "NONE", delegationTargets: u.delegationTargets ?? [],
          ...(u.lastLogonAt ? { lastLogonAt: new Date(u.lastLogonAt) } : {}),
          ...(u.passwordLastSetAt ? { passwordLastSetAt: new Date(u.passwordLastSetAt) } : {}),
        },
        update: {
          samAccountName: u.samAccountName, displayName: u.displayName, userPrincipalName: u.userPrincipalName,
          enabled: u.enabled, isServiceAccount: u.isServiceAccount ?? false,
          passwordNeverExpires: u.passwordNeverExpires ?? false, passwordNotRequired: u.passwordNotRequired ?? false,
          preauthNotRequired: u.preauthNotRequired ?? false, spnPresent: u.spnPresent ?? (u.spns?.length ?? 0) > 0,
          spns: u.spns ?? [], delegationType: u.delegationType ?? "NONE", delegationTargets: u.delegationTargets ?? [],
          ...(u.lastLogonAt ? { lastLogonAt: new Date(u.lastLogonAt) } : {}),
          ...(u.passwordLastSetAt ? { passwordLastSetAt: new Date(u.passwordLastSetAt) } : {}),
          lastSeen: new Date(),
        },
      });
    }
    for (const g of payload.groups) {
      await prisma.directoryGroup.upsert({
        where: { domainId_objectId: { domainId: domain.id, objectId: g.objectId } },
        create: {
          workspaceId: scan.workspaceId, domainId: domain.id, objectId: g.objectId, name: g.name,
          groupScope: g.groupScope ?? "GLOBAL", groupType: g.groupType ?? "SECURITY",
          privilegeClass: g.privilegeClass, memberCount: g.memberCount ?? 0,
        },
        update: { name: g.name, privilegeClass: g.privilegeClass, ...(g.memberCount !== undefined ? { memberCount: g.memberCount } : {}), lastSeen: new Date() },
      });
    }
    for (const c of payload.computers) {
      const asset = await prisma.asset.findFirst({ where: { targetId: scan.assessment.targetId, host: c.dnsName ?? c.hostname } });
      await prisma.directoryComputer.upsert({
        where: { domainId_objectId: { domainId: domain.id, objectId: c.objectId } },
        create: {
          workspaceId: scan.workspaceId, domainId: domain.id, assetId: asset?.id, objectId: c.objectId,
          hostname: c.hostname, dnsName: c.dnsName, osName: c.osName, osVersion: c.osVersion, enabled: c.enabled,
          isDomainController: c.isDomainController ?? false, delegationType: c.delegationType ?? "NONE",
          delegationTargets: c.delegationTargets ?? [], unconstrainedDelegation: c.delegationType === "UNCONSTRAINED",
        },
        update: {
          hostname: c.hostname, dnsName: c.dnsName, osName: c.osName, osVersion: c.osVersion, enabled: c.enabled,
          isDomainController: c.isDomainController ?? false, delegationType: c.delegationType ?? "NONE",
          delegationTargets: c.delegationTargets ?? [], unconstrainedDelegation: c.delegationType === "UNCONSTRAINED", lastSeen: new Date(),
        },
      });
    }
    for (const o of payload.organizationalUnits) {
      await prisma.directoryOrganizationalUnit.upsert({
        where: { domainId_objectId: { domainId: domain.id, objectId: o.objectId } },
        create: { workspaceId: scan.workspaceId, domainId: domain.id, objectId: o.objectId, name: o.name, distinguishedName: o.distinguishedName, parentRef: o.parentRef, linkedGpoIds: o.linkedGpoIds },
        update: { name: o.name, distinguishedName: o.distinguishedName, parentRef: o.parentRef, linkedGpoIds: o.linkedGpoIds, lastSeen: new Date() },
      });
    }
    for (const g of payload.groupPolicies) {
      await prisma.groupPolicyObject.upsert({
        where: { domainId_objectId: { domainId: domain.id, objectId: g.objectId } },
        create: {
          workspaceId: scan.workspaceId, domainId: domain.id, objectId: g.objectId, name: g.name, linkedTo: g.linkedTo,
          securityMetadata: g.securityMetadata as never, delegationMetadata: g.delegationMetadata as never,
          ...(g.lastModifiedAt ? { lastModifiedAt: new Date(g.lastModifiedAt) } : {}),
        },
        update: { name: g.name, linkedTo: g.linkedTo, securityMetadata: g.securityMetadata as never, delegationMetadata: g.delegationMetadata as never, lastSeen: new Date() },
      });
    }
    for (const t of payload.trusts) {
      await prisma.directoryTrust.upsert({
        where: { domainId_targetDomainName: { domainId: domain.id, targetDomainName: t.targetDomainName } },
        create: {
          workspaceId: scan.workspaceId, domainId: domain.id, targetDomainName: t.targetDomainName,
          direction: t.direction, trustType: t.trustType, transitive: t.transitive,
          sidFilteringEnabled: t.sidFilteringEnabled, selectiveAuthentication: t.selectiveAuthentication,
        },
        update: { direction: t.direction, trustType: t.trustType, transitive: t.transitive, sidFilteringEnabled: t.sidFilteringEnabled, selectiveAuthentication: t.selectiveAuthentication, lastSeen: new Date() },
      });
    }
    let snapshotId: string | undefined;
    if (payload.snapshot) {
      const snap = await prisma.directorySnapshot.create({
        data: {
          workspaceId: scan.workspaceId, domainId: domain.id, scanId,
          collectionProfile: payload.snapshot.collectionProfile,
          collectorVersions: payload.snapshot.collectorVersions as never,
          objectCounts: payload.snapshot.objectCounts as never,
          relationshipCount: payload.snapshot.relationshipCount,
          snapshotHash: payload.snapshot.snapshotHash,
        },
      });
      snapshotId = snap.id;
      await prisma.auditLog.create({
        data: {
          actorId: scan.requestedBy, organizationId: orgId, workspaceId: scan.workspaceId,
          action: "DIRECTORY_SNAPSHOT_CREATED" as never, resourceType: "ACTIVE_DIRECTORY_DOMAIN", resourceId: domain.id,
          metadata: { scanId, snapshotHash: payload.snapshot.snapshotHash } as never,
        },
      });
    }
    for (const r of payload.relationships) {
      await prisma.directoryRelationship.upsert({
        where: {
          domainId_fromType_fromRef_relationship_toType_toRef: {
            domainId: domain.id, fromType: r.fromType, fromRef: r.fromRef,
            relationship: r.relationship, toType: r.toType, toRef: r.toRef,
          },
        },
        create: {
          workspaceId: scan.workspaceId, domainId: domain.id, snapshotId,
          fromType: r.fromType, fromRef: r.fromRef, toType: r.toType, toRef: r.toRef,
          relationship: r.relationship, source: r.source, confidence: r.confidence, evidenceRef: r.evidenceRef,
        },
        update: { source: r.source, confidence: r.confidence, lastSeen: new Date() },
      });
    }
    for (const s of payload.smbShares) {
      await prisma.smbShare.upsert({
        where: { domainId_host_shareName: { domainId: domain.id, host: s.host, shareName: s.shareName } },
        create: {
          workspaceId: scan.workspaceId, domainId: domain.id, host: s.host, shareName: s.shareName,
          accessLevel: s.accessLevel, anonymousAccess: s.anonymousAccess, smbDialect: s.smbDialect,
          signingRequired: s.signingRequired, source: s.source,
        },
        update: { accessLevel: s.accessLevel, anonymousAccess: s.anonymousAccess, smbDialect: s.smbDialect, signingRequired: s.signingRequired, source: s.source, lastSeen: new Date() },
      });
    }
    const caRowByName = new Map<string, string>();
    for (const ca of payload.certificateAuthorities) {
      const row = await prisma.certificateAuthority.upsert({
        where: { domainId_name: { domainId: domain.id, name: ca.name } },
        create: {
          workspaceId: scan.workspaceId, domainId: domain.id, name: ca.name, dnsName: ca.dnsName,
          enrollmentServices: ca.enrollmentServices as never, metadata: ca.metadata as never,
        },
        update: { dnsName: ca.dnsName, enrollmentServices: ca.enrollmentServices as never, metadata: ca.metadata as never, lastSeen: new Date() },
      });
      caRowByName.set(ca.name, row.id);
    }
    for (const t of payload.certificateTemplates) {
      await prisma.certificateTemplate.upsert({
        where: { domainId_name: { domainId: domain.id, name: t.name } },
        create: {
          workspaceId: scan.workspaceId, domainId: domain.id, caId: t.caName ? caRowByName.get(t.caName) : undefined,
          name: t.name, objectId: t.objectId, enabled: t.enabled ?? true,
          enrollmentPermissions: t.enrollmentPermissions as never, subjectConfig: t.subjectConfig as never,
          authenticationEkus: t.authenticationEkus, managerApprovalRequired: t.managerApprovalRequired ?? false,
          authorizedSignaturesRequired: t.authorizedSignaturesRequired ?? 0,
          issuanceRequirements: t.issuanceRequirements as never, riskClasses: t.riskClasses ?? [],
        },
        update: {
          objectId: t.objectId, enabled: t.enabled ?? true,
          enrollmentPermissions: t.enrollmentPermissions as never, subjectConfig: t.subjectConfig as never,
          authenticationEkus: t.authenticationEkus, managerApprovalRequired: t.managerApprovalRequired ?? false,
          authorizedSignaturesRequired: t.authorizedSignaturesRequired ?? 0,
          issuanceRequirements: t.issuanceRequirements as never, riskClasses: t.riskClasses ?? [], lastSeen: new Date(),
        },
      });
    }
    await prisma.activeDirectoryDomain.update({ where: { id: domain.id }, data: { lastSeen: new Date(), lastAssessmentAt: new Date() } });

    // Drift (§79/§80): diff the pre-collection persisted state against
    // the new persisted state; events are review signals.
    const current = await this.loadDirectoryInventory(domain.id);
    if (hasPrevious) {
      const events = diffDirectorySnapshots(previous, current, domain.dnsName);
      for (const e of events) {
        await prisma.adDriftEvent.create({
          data: { workspaceId: scan.workspaceId, domainId: domain.id, scanId, snapshotId, kind: e.kind, objectRef: e.objectRef, detail: e.detail },
        });
      }
      if (events.length > 0) {
        await prisma.auditLog.create({
          data: {
            actorId: scan.requestedBy, organizationId: orgId, workspaceId: scan.workspaceId,
            action: "AD_DRIFT_DETECTED" as never, resourceType: "ACTIVE_DIRECTORY_DOMAIN", resourceId: domain.id,
            metadata: { scanId, events: events.length } as never,
          },
        });
      }
    }

    // Posture analysis (§57–§78) over the persisted inventory: new
    // findings persist deduped by canonical fingerprint; annotations
    // (privileged flags, explainable risk scores) land on the rows.
    const posture = analyzeDirectoryPosture(current, {
      domainId: domain.id, domainRef: domain.dnsName, toolSlug: "directory-platform-analysis",
    });
    let created = 0;
    for (const f of posture.findings) {
      const existing = await prisma.finding.findFirst({ where: { scanId, fingerprint: f.sourceFingerprint } });
      if (existing) continue;
      await prisma.finding.create({
        data: {
          workspaceId: scan.workspaceId, scanId,
          title: f.title, description: f.description, severity: f.severity as never, confidence: f.confidence,
          fingerprint: f.sourceFingerprint, isMock: false, status: "OPEN", verificationStatus: "UNVERIFIED",
          sources: [f.sourceTool], ruleId: f.ruleId, controlId: f.controlId, remediation: f.remediation,
          host: f.host, directoryDomainId: domain.id, directoryObjectId: f.directoryObjectId,
          evidence: { create: { sourceTool: f.sourceTool, evidenceType: "TEXT", summary: f.evidence ?? "", fingerprint: f.sourceFingerprint } },
          history: { create: { workspaceId: scan.workspaceId, event: "CREATED", metadata: { sourceTool: f.sourceTool, stage: "DIRECTORY_ANALYSIS" } as never } },
        },
      });
      created++;
    }
    for (const a of posture.controlAssessments) {
      const dup = await prisma.controlAssessment.findFirst({ where: { scanId, frameworkKey: a.frameworkKey, controlId: a.controlId, subjectRef: a.subjectRef } });
      if (dup) continue;
      await prisma.controlAssessment.create({
        data: {
          workspaceId: scan.workspaceId, scanId, frameworkKey: a.frameworkKey, controlId: a.controlId,
          subjectRef: a.subjectRef, status: a.status as never, evidence: a.evidence,
        },
      });
    }
    for (const [objectId, ann] of posture.userAnnotations) {
      await prisma.directoryUser.updateMany({
        where: { domainId: domain.id, objectId },
        data: { privileged: ann.privileged, privilegeEvidence: { via: ann.privilegeEvidence } as never, riskScore: ann.riskScore, riskFactors: ann.riskFactors as never },
      });
    }
    for (const [objectId, ann] of posture.computerAnnotations) {
      await prisma.directoryComputer.updateMany({
        where: { domainId: domain.id, objectId },
        data: { riskScore: ann.riskScore, riskFactors: ann.riskFactors as never },
      });
    }
    return {
      users: payload.users.length, groups: payload.groups.length,
      computers: payload.computers.length, relationships: payload.relationships.length,
      findings: created,
    };
  }

  /** Prompt 10 platform hook (§5/§25/§62): canonicalize the scan's CIDR
   *  target, apply the CIDR size policy and persist BOUNDED chunk rows
   *  for checkpointing/distribution — never one row per host. A
   *  hard-denied size records no chunks and reports mode DENIED so the
   *  runner can emit the protected-target event. */
  async expandNetworkTargets(scanId: string): Promise<{ mode: string; hosts: number; chunks: number; totalHosts: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph?.assessment) return null;
    const targetValue = graph.assessment.target.value;
    const verdict = new CidrPolicyService().evaluate(targetValue, { administratorApproved: false });
    if (!verdict) return null; // not a CIDR target — nothing to expand
    if (verdict.approval === "DENY") {
      return { mode: "DENIED", hosts: 0, chunks: 0, totalHosts: verdict.hostCount };
    }
    const expansion = expandCidrTargets(targetValue);
    if (!expansion) return null;
    for (const chunk of expansion.chunks) {
      await prisma.networkScanChunk.upsert({
        where: { scanId_chunkId: { scanId, chunkId: chunk.chunkId } },
        create: {
          workspaceId: graph.workspaceId, scanId, chunkId: chunk.chunkId,
          rangeStart: chunk.rangeStart, rangeEnd: chunk.rangeEnd, hostCount: chunk.hostCount, status: "PENDING",
        },
        update: { rangeStart: chunk.rangeStart, rangeEnd: chunk.rangeEnd, hostCount: chunk.hostCount },
      });
    }
    return expansion.kind === "LIST"
      ? { mode: "LIST", hosts: expansion.hosts.length, chunks: expansion.chunks.length, totalHosts: expansion.hosts.length }
      : { mode: "RANGES", hosts: 0, chunks: expansion.chunks.length, totalHosts: expansion.totalHosts };
  }

  // ---------- Prompt 12 source platform hooks (§19/§96) ----------

  /** SOURCE_ACQUISITION (§10/§96): materialize the scan's immutable
   *  snapshot from the repository's registered content manifest.
   *  Returns null honestly when the repository carries no registered
   *  snapshot content (e.g. a git remote whose clone has not been
   *  provisioned on a source worker) — the runner then fails the stage
   *  instead of inventing a snapshot. Content is NEVER executed (§15):
   *  the manifest is data — file listing + manifest file contents. */
  async acquireSourceSnapshot(scanId: string): Promise<{ snapshotHash: string; files: number; sourceKind: string } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph?.assessment) return null;
    const repo = await prisma.sourceRepository.findFirst({ where: { workspaceId: graph.workspaceId, targetId: graph.assessment.targetId } });
    if (!repo) return null;
    const existing = await prisma.sourceSnapshot.findFirst({ where: { repositoryId: repo.id, scanId } });
    if (existing) return { snapshotHash: existing.snapshotHash, files: existing.fileCount, sourceKind: repo.sourceKind };
    const manifest = repo.snapshotManifest as { files?: { path: string; sizeBytes: number }[]; manifests?: Record<string, string>; commitSha?: string; branch?: string } | null;
    if (!manifest || !Array.isArray(manifest.files)) return null;
    const snapshotHash = createHash("sha256").update(JSON.stringify(manifest)).digest("hex");
    const totalSizeBytes = manifest.files.reduce((sum, f) => sum + (f.sizeBytes ?? 0), 0);
    await prisma.sourceSnapshot.create({
      data: {
        repositoryId: repo.id, scanId,
        snapshotHash, commitSha: manifest.commitSha, branch: manifest.branch,
        sourceKind: repo.sourceKind,
        artifactReference: `snapshots/${repo.id}/${snapshotHash}`,
        fileCount: manifest.files.length, totalSizeBytes: BigInt(totalSizeBytes),
        files: manifest.files as never,
        manifests: (manifest.manifests ?? {}) as never,
      },
    });
    return { snapshotHash, files: manifest.files.length, sourceKind: repo.sourceKind };
  }

  /** LANGUAGE_DETECTION (§27): deterministic classification over the
   *  snapshot's file listing + manifest contents; metadata only. */
  async detectSourceLanguages(scanId: string): Promise<{ languages: number; primaryLanguage?: string; frameworks: number; buildSystems: number } | null> {
    const snap = await prisma.sourceSnapshot.findFirst({ where: { scanId }, orderBy: { createdAt: "desc" } });
    if (!snap) return null;
    const detection = detectRepository(
      (snap.files as never) ?? [],
      (snap.manifests as Record<string, string> | null) ?? {},
    );
    await prisma.sourceSnapshot.update({
      where: { id: snap.id },
      data: {
        languages: detection.languages as never,
        frameworks: detection.frameworks,
        buildSystems: detection.buildSystems,
      },
    });
    return { languages: detection.languages.length, primaryLanguage: detection.primaryLanguage, frameworks: detection.frameworks.length, buildSystems: detection.buildSystems.length };
  }

  /** DEPENDENCY_INVENTORY (§45/§56): parse the snapshot's manifests
   *  (lockfile-first, no installs) into canonical component rows, then
   *  match them against the GOVERNED local intelligence dataset
   *  (Prompt 11). Matches are POTENTIAL_EXPOSURE findings (§73) built
   *  only from what the dataset holds — an empty dataset yields zero
   *  matches and zero findings, honestly (§52). */
  async inventorySourceDependencies(scanId: string): Promise<{ components: number; manifests: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph?.assessment) return null;
    const snap = await prisma.sourceSnapshot.findFirst({ where: { scanId }, orderBy: { createdAt: "desc" } });
    if (!snap) return null;
    const manifests = (snap.manifests as Record<string, string> | null) ?? {};
    const parsed = parseManifests(manifests);
    for (const c of parsed) {
      await prisma.softwareComponent.upsert({
        where: { snapshotId_purl: { snapshotId: snap.id, purl: c.purl } },
        create: {
          snapshotId: snap.id,
          name: c.name, version: c.version, ecosystem: c.ecosystem, purl: c.purl,
          sourceManifest: c.sourceManifest, scope: c.scope,
          dependencyScope: c.dependencyScope, licenses: c.licenses,
          ...(c.supplier ? { supplier: c.supplier } : {}),
        },
        update: { licenses: c.licenses, dependencyScope: c.dependencyScope },
      });
    }
    // Governed-dataset matching: load only the CPE/CVE/EPSS/KEV rows
    // that could match this inventory's component names.
    if (parsed.length > 0) {
      const names = [...new Set(parsed.map((c) => c.name.toLowerCase()))];
      const cpes = await prisma.cpeRecord.findMany({
        where: { OR: names.map((n) => ({ canonical: { contains: `:${n}:` } })) },
        take: 500,
      });
      if (cpes.length > 0) {
        const cveIds = [...new Set(cpes.flatMap((c) => c.cveIds))];
        const [cves, epssRows, kevRows] = await Promise.all([
          prisma.cveRecord.findMany({ where: { cveId: { in: cveIds } } }),
          prisma.epssRecord.findMany({ where: { cveId: { in: cveIds } }, orderBy: { date: "desc" } }),
          prisma.kevRecord.findMany({ where: { cveId: { in: cveIds } } }),
        ]);
        const dataset = new InMemoryIntelligenceDataset();
        for (const c of cves) {
          const record: Parameters<InMemoryIntelligenceDataset["upsertCve"]>[0] = {
            cveId: c.cveId, description: c.description, cweIds: c.cweIds,
            references: (c.references as { label: string; url: string }[] | null) ?? [], source: c.source,
          };
          if (c.cvssScore != null) {
            record.cvss = { version: (c.cvssVersion ?? "3.1") as CvssRecord["version"], baseScore: c.cvssScore, ...(c.cvssVector ? { vector: c.cvssVector } : {}), source: c.source } as typeof record.cvss;
          }
          dataset.upsertCve(record);
        }
        const seenEpss = new Set<string>();
        for (const e of epssRows) {
          if (seenEpss.has(e.cveId)) continue;
          seenEpss.add(e.cveId);
          dataset.upsertEpss({ cveId: e.cveId, score: e.score, percentile: e.percentile, date: e.date.toISOString().slice(0, 10), source: e.source });
        }
        for (const k of kevRows) {
          dataset.upsertKev({ cveId: k.cveId, source: k.source, ...(k.vendorProject ? { vendorProject: k.vendorProject } : {}), ...(k.product ? { product: k.product } : {}), ...(k.dateAdded ? { dateAdded: k.dateAdded.toISOString().slice(0, 10) } : {}) });
        }
        for (const cpe of cpes) {
          dataset.upsertCpe({
            canonical: cpe.canonical, part: cpe.part, vendor: cpe.vendor, product: cpe.product,
            ...(cpe.version ? { version: cpe.version } : {}), cveIds: cpe.cveIds, source: cpe.source,
          });
        }
        const matches = matchComponentsAgainstIntel(parsed, dataset);
        const enriched = enrichDependencyFindings(matches, dataset);
        for (const m of enriched) {
          const existingFinding = await prisma.finding.findFirst({ where: { scanId, fingerprint: m.sourceFingerprint } });
          if (existingFinding) continue;
          await prisma.finding.create({
            data: {
              workspaceId: graph.workspaceId, scanId,
              repositoryId: snap.repositoryId, snapshotId: snap.id,
              title: m.title, description: m.description,
              severity: m.severity as never, confidence: m.confidence,
              fingerprint: m.sourceFingerprint, isMock: false,
              status: "OPEN", verificationStatus: "UNVERIFIED",
              sources: [m.sourceTool], vulnClass: "DEPENDENCY_VULNERABILITY",
              cve: m.cve, cwe: m.cwe, cvssScore: m.cvssScore, cvssVector: m.cvssVector,
              componentPurl: m.componentPurl, dependencyScope: m.dependencyScope,
              reachability: "POTENTIAL_EXPOSURE",
              evidence: { create: { sourceTool: m.sourceTool, evidenceType: "TEXT", summary: m.evidence } },
              references: { create: m.references.map((url) => ({ type: "OTHER", label: url, url })) },
              history: { create: { workspaceId: graph.workspaceId, event: "CREATED", metadata: { sourceTool: m.sourceTool, origin: "INTEL_MATCH" } as never } },
            },
          });
        }
      }
    }
    return { components: parsed.length, manifests: Object.keys(manifests).length };
  }

  /** SBOM_GENERATION (§47): build the CycloneDX document from the
   *  snapshot's component rows; only its reference + checksum persist. */
  async generateSourceSbom(scanId: string): Promise<{ format: string; checksum: string; components: number } | null> {
    const snap = await prisma.sourceSnapshot.findFirst({ where: { scanId }, orderBy: { createdAt: "desc" }, include: { repository: true } });
    if (!snap) return null;
    const rows = await prisma.softwareComponent.findMany({ where: { snapshotId: snap.id } });
    const components = rows.map((r) => ({
      name: r.name, version: r.version ?? undefined, ecosystem: r.ecosystem as never, purl: r.purl,
      sourceManifest: r.sourceManifest, scope: r.scope as never,
      dependencyScope: r.dependencyScope as never, licenses: r.licenses,
      ...(r.supplier ? { supplier: r.supplier } : {}),
    }));
    const { sbom } = buildCycloneDxSbom(components, {
      snapshotHash: snap.snapshotHash, repositoryName: snap.repository.name, timestamp: new Date().toISOString(),
    });
    const sbomData = {
      snapshotId: snap.id, scanId,
      format: "CYCLONEDX_JSON" as never, specVersion: sbom.specVersion,
      checksum: sbom.checksum, artifactRef: `sbom://${snap.id}/${sbom.checksum}`,
      componentCount: sbom.componentCount,
    };
    const existingSbom = await prisma.softwareBillOfMaterials.findFirst({ where: { snapshotId: snap.id, format: "CYCLONEDX_JSON" } });
    if (existingSbom) {
      await prisma.softwareBillOfMaterials.update({ where: { id: existingSbom.id }, data: sbomData });
    } else {
      await prisma.softwareBillOfMaterials.create({ data: sbomData });
    }
    return { format: sbom.format, checksum: sbom.checksum, components: sbom.componentCount };
  }

  /** QUALITY_GATE (§81/§82): classify findings against the previous
   *  snapshot (§79), evaluate the workspace gate policy and record the
   *  verdict. The gate verdict never changes the scan's own status —
   *  it is reported alongside it (§82). */
  async evaluateSourceQualityGate(scanId: string): Promise<{ status: string; failedRules: number; warningRules: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph) return null;
    const snap = await prisma.sourceSnapshot.findFirst({ where: { scanId }, orderBy: { createdAt: "desc" } });
    const rows = await prisma.finding.findMany({ where: { scanId, duplicateOfId: null }, include: { secretMetadata: true } });
    if (rows.length === 0) return null;
    if (snap) {
      const previousRows = await prisma.finding.findMany({
        where: { repositoryId: snap.repositoryId, snapshotId: { not: snap.id }, fingerprint: { not: null } },
        select: { fingerprint: true },
      });
      const previousFingerprints = previousRows.map((r) => r.fingerprint!).filter(Boolean);
      if (previousFingerprints.length > 0) {
        const { statuses } = classifyBaseline(
          rows.map((r) => ({ sourceFingerprint: r.fingerprint ?? r.id })),
          previousFingerprints,
        );
        for (const r of rows) {
          const status = statuses.get(r.fingerprint ?? r.id);
          if (status && status !== r.baselineStatus) {
            await prisma.finding.update({ where: { id: r.id }, data: { baselineStatus: status } });
            r.baselineStatus = status;
          }
        }
      }
    }
    const evaluation = evaluateQualityGate(
      summarizeForQualityGate(rows.map((r) => ({
        severity: r.severity as never, filePath: r.filePath ?? undefined,
        componentPurl: r.componentPurl ?? undefined,
        ...(r.secretMetadata ? { secret: { secretType: r.secretMetadata.secretType } as never } : {}),
        baselineStatus: (r.baselineStatus as never) ?? undefined,
      }))),
      DEFAULT_QUALITY_GATE_POLICY,
    );
    await prisma.qualityGateResult.create({
      data: {
        scanId, snapshotId: snap?.id,
        status: evaluation.status as never,
        policyVersion: DEFAULT_QUALITY_GATE_POLICY.version,
        failedRules: evaluation.failedRules as never,
        warningRules: evaluation.warningRules as never,
        summary: evaluation as never,
      },
    });
    return { status: evaluation.status, failedRules: evaluation.failedRules.length, warningRules: evaluation.warningRules.length };
  }

  // ---------- Prompt 13 cloud-native platform hooks (§5/§75/§78) ----------

  /** IMAGE_RESOLUTION (§5/§78): record the image snapshot this scan
   *  analyzes. The digest comes from the registered image row (written
   *  at registration / by SBOM import / by a previous scan) — registry
   *  tag→digest resolution lands with the registry connectors; until
   *  then an image with no recorded digest resolves tag-only and the
   *  event says so honestly. A changed digest appends a NEW snapshot
   *  (drift) — history is never overwritten. */
  async resolveContainerImage(scanId: string): Promise<{ imageRef: string; digest?: string; drift?: boolean; skipped?: boolean } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph?.assessment) return null;
    const target = graph.assessment.target;
    if (target.type !== "CONTAINER_IMAGE") return { imageRef: "", skipped: true };
    let ref: ReturnType<typeof parseImageReference>;
    try { ref = parseImageReference(target.value); } catch { return null; }
    let image = await prisma.containerImage.findFirst({ where: { workspaceId: graph.workspaceId, targetId: target.id } });
    if (!image) {
      image = await prisma.containerImage.create({
        data: {
          workspaceId: graph.workspaceId, targetId: target.id, reference: target.value,
          registry: ref.registry, repository: ref.repository, tag: ref.tag, digest: ref.digest, source: "TARGET",
        },
      });
    }
    const digest = image.digest ?? ref.digest;
    const previous = await prisma.containerImageSnapshot.findFirst({ where: { imageId: image.id }, orderBy: { capturedAt: "desc" } });
    const drift = !!previous?.digest && !!digest && previous.digest !== "unknown" && previous.digest !== digest;
    if (!previous || previous.digest !== (digest ?? "unknown") || previous.scanId !== scanId) {
      await prisma.containerImageSnapshot.create({
        data: {
          imageId: image.id, scanId, digest: digest ?? "unknown",
          previousDigest: drift ? previous?.digest : undefined, drift,
          config: {} as never, layers: [] as never,
        },
      });
    }
    return { imageRef: target.value, ...(digest ? { digest } : {}), drift };
  }

  /** QUALITY_GATE for cloud-native scans (§75): the container gate
   *  over the scan's canonical findings. KEV membership comes ONLY
   *  from the Phase 11 intelligence tables (§74) — an empty dataset
   *  means no KEV rule can fire, honestly. */
  async evaluateContainerQualityGate(scanId: string): Promise<{ status: string; failedRules: number; warningRules: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph?.assessment) return null;
    const targetType = graph.assessment.target.type;
    if (!["CONTAINER_IMAGE", "KUBERNETES_CLUSTER", "KUBERNETES", "DOCKER_HOST", "DOCKER"].includes(targetType)) return null;
    const rows = await prisma.finding.findMany({ where: { scanId, duplicateOfId: null }, include: { secretMetadata: true } });
    const cveIds = [...new Set(rows.map((r) => r.cve).filter((x): x is string => !!x))];
    const kevRows = cveIds.length > 0 ? await prisma.kevRecord.findMany({ where: { cveId: { in: cveIds } }, select: { cveId: true } }) : [];
    const result = evaluateContainerQualityGate({
      findings: rows.map((r) => ({
        severity: r.severity as never, cve: r.cve ?? undefined, origin: (r.origin as never) ?? undefined,
        ...(r.secretMetadata ? { secret: { secretType: r.secretMetadata.secretType } as never } : {}),
        controlId: r.controlId ?? undefined, resourceKind: r.resourceKind ?? undefined,
      })),
      kevCves: kevRows.map((k) => k.cveId),
    });
    await prisma.qualityGateResult.create({
      data: {
        scanId, status: result.status as never, policyVersion: "container-gate/1.0.0",
        failedRules: result.failedRules as never, warningRules: result.warningRules as never,
        summary: result.summary as never,
      },
    });
    const cloudCtx = await this.loadCloudContext(graph.workspaceId, graph.assessment.targetId, targetType, graph.assessment.target.value);
    if (cloudCtx?.clusterId) {
      await prisma.kubernetesCluster.update({ where: { id: cloudCtx.clusterId }, data: { lastAssessmentAt: new Date() } });
    }
    return { status: result.status, failedRules: result.failedRules.length, warningRules: result.warningRules.length };
  }

  // ---------- Prompt 14 multi-cloud platform hooks (§9/§36–§70) ----------

  /** CLOUD_AUTH (§9–§11): validate the scan's registered account and
   *  issue the job-scoped credential lease. An account without a
   *  credential reference cannot be validated against anything — it
   *  reports NOT_CONFIGURED and the runner fails the scan honestly.
   *  The lease records the reference NAME + lifecycle only (§100). */
  async validateCloudAccount(scanId: string): Promise<{ status: string; provider?: string } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph?.assessment) return null;
    if (!["AWS", "AZURE", "GCP"].includes(graph.assessment.target.type)) return null;
    const account = await prisma.cloudAccount.findFirst({ where: { workspaceId: graph.workspaceId, targetId: graph.assessment.targetId } });
    if (!account) return null;
    if (!account.credentialReference) {
      await prisma.cloudAccount.update({ where: { id: account.id }, data: { status: "NOT_CONFIGURED" } });
      return { status: "NOT_CONFIGURED", provider: account.provider };
    }
    const expiresAt = new Date(Date.now() + 3600 * 1000);
    await prisma.credentialLease.create({
      data: {
        workspaceId: graph.workspaceId, cloudAccountId: account.id, scanId,
        credentialReference: account.credentialReference, purpose: "CLOUD_ASSESSMENT",
        status: "ISSUED", expiresAt,
      },
    });
    await prisma.cloudAccount.update({ where: { id: account.id }, data: { status: "VALIDATED" } });
    await prisma.auditLog.create({
      data: {
        actorId: graph.requestedBy, organizationId: graph.workspace.organizationId, workspaceId: graph.workspaceId,
        action: "CLOUD_CREDENTIAL_VALIDATED" as never, resourceType: "CLOUD_ACCOUNT", resourceId: account.id,
        metadata: { scanId, provider: account.provider } as never,
      },
    });
    return { status: "VALIDATED", provider: account.provider };
  }

  /** Section analysis (§36–§57): run ONE deterministic analyzer over
   *  the scan account's persisted IN_SCOPE inventory and persist its
   *  findings + control assessments. Findings already present in this
   *  scan (same cloud fingerprint — e.g. produced by a CSPM tool) are
   *  skipped here; correlation merges the observations (§60). */
  async analyzeCloudSection(scanId: string, section: string): Promise<{ findings: number; assessments: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph?.assessment) return null;
    const account = await prisma.cloudAccount.findFirst({ where: { workspaceId: graph.workspaceId, targetId: graph.assessment.targetId } });
    if (!account) return null;
    const [resourceRows, identityRows] = await Promise.all([
      prisma.cloudResource.findMany({ where: { cloudAccountId: account.id, scopeStatus: "IN_SCOPE", status: "ACTIVE" } }),
      prisma.cloudIdentity.findMany({ where: { cloudAccountId: account.id } }),
    ]);
    if (resourceRows.length === 0 && identityRows.length === 0) return null;
    const resources: NormalizedCloudResource[] = resourceRows.map((r) => ({
      provider: account.provider as NormalizedCloudResource["provider"],
      resourceType: r.resourceType, providerResourceId: r.providerResourceId, name: r.name,
      ...(r.region ? { region: r.region } : {}), ...(r.zone ? { zone: r.zone } : {}),
      tags: (r.tags ?? {}) as Record<string, string>,
      configuration: (r.configurationMetadata ?? {}) as Record<string, unknown>,
      exposure: r.exposure as NormalizedCloudResource["exposure"],
      source: "persisted-inventory",
    }));
    const identities: NormalizedCloudIdentity[] = identityRows.map((i) => ({
      provider: account.provider as NormalizedCloudIdentity["provider"],
      identityType: i.identityType as NormalizedCloudIdentity["identityType"],
      providerIdentityId: i.providerIdentityId, name: i.name,
      privileged: i.privileged,
      ...(i.privilegeEvidence ? { privilegeEvidence: i.privilegeEvidence as Record<string, unknown> } : {}),
      ...(i.mfaEnabled !== null && i.mfaEnabled !== undefined ? { mfaEnabled: i.mfaEnabled } : {}),
      ...(i.lastUsedAt ? { lastUsedAt: i.lastUsedAt.toISOString() } : {}),
      ...(i.lastSignInAt ? { lastSignInAt: i.lastSignInAt.toISOString() } : {}),
      ...(i.keyAgeDays ? { keyAgeDays: i.keyAgeDays } : {}),
      metadata: (i.metadata ?? {}) as Record<string, unknown>,
    }));
    const ctx = {
      provider: account.provider as "AWS" | "AZURE" | "GCP",
      accountId: account.id, accountRef: account.externalAccountId,
      ...(account.environment ? { environment: account.environment } : {}),
      toolSlug: "cloud-platform-analysis",
    };
    const result =
      section === "IAM_ANALYSIS" ? analyzeIam(identities, ctx)
      : section === "STORAGE_ANALYSIS" ? mergeSections([analyzeStorage(resources, ctx), analyzeDatabases(resources, ctx)])
      : section === "NETWORK_ANALYSIS" ? analyzeNetwork(resources, ctx)
      : section === "ENCRYPTION_ANALYSIS" ? analyzeEncryption(resources, ctx)
      : section === "LOGGING_ANALYSIS" ? analyzeLogging(resources, ctx)
      : null;
    if (!result) return null;
    const resourceRowByProviderId = new Map(resourceRows.map((r) => [r.providerResourceId, r.id]));
    let created = 0;
    for (const f of result.findings) {
      const existing = await prisma.finding.findFirst({ where: { scanId, fingerprint: f.sourceFingerprint } });
      if (existing) continue;
      await prisma.finding.create({
        data: {
          workspaceId: graph.workspaceId, scanId,
          title: f.title, description: f.description, severity: f.severity as never, confidence: f.confidence,
          fingerprint: f.sourceFingerprint, isMock: false, status: "OPEN", verificationStatus: "UNVERIFIED",
          sources: [f.sourceTool], ruleId: f.ruleId, controlId: f.controlId, remediation: f.remediation,
          origin: f.origin, findingClass: f.findingClass, cloudProvider: f.cloudProvider,
          cloudAccountId: account.id,
          cloudResourceId: f.providerResourceId ? resourceRowByProviderId.get(f.providerResourceId) : undefined,
          providerResourceId: f.providerResourceId, cloudRegion: f.cloudRegion,
          evidence: { create: { sourceTool: f.sourceTool, evidenceType: "TEXT", summary: f.evidence ?? "", fingerprint: f.sourceFingerprint } },
          history: { create: { workspaceId: graph.workspaceId, event: "CREATED", metadata: { sourceTool: f.sourceTool, stage: section } as never } },
        },
      });
      created++;
    }
    for (const a of result.controlAssessments) {
      await prisma.controlAssessment.create({
        data: {
          workspaceId: graph.workspaceId, scanId, frameworkKey: a.frameworkKey, controlId: a.controlId,
          subjectRef: a.subjectRef, status: a.status as never, evidence: a.evidence,
        },
      });
    }
    return { findings: created, assessments: result.controlAssessments.length };
  }

  /** CLOUD_COMPLIANCE (§63–§68): assemble the compliance picture —
   *  control assessments already recorded for this scan, drift events
   *  recorded at inventory time, and defensive risk paths built from
   *  evidence-backed graph edges (§66). PASS is evidence only; the
   *  platform never claims certification (§68). */
  async assessCloudCompliance(scanId: string): Promise<{ assessed: number; failed: number; drift: number; riskPaths: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph?.assessment) return null;
    const account = await prisma.cloudAccount.findFirst({ where: { workspaceId: graph.workspaceId, targetId: graph.assessment.targetId } });
    if (!account) return null;
    const [assessments, driftCount, resourceRows, relationshipRows, findingRows] = await Promise.all([
      prisma.controlAssessment.findMany({ where: { scanId } }),
      prisma.cloudDriftEvent.count({ where: { cloudAccountId: account.id, scanId } }),
      prisma.cloudResource.findMany({ where: { cloudAccountId: account.id, scopeStatus: "IN_SCOPE", status: "ACTIVE" } }),
      prisma.cloudRelationship.findMany({ where: { cloudAccountId: account.id } }),
      prisma.finding.findMany({ where: { scanId, duplicateOfId: null }, select: { id: true, fingerprint: true, providerResourceId: true } }),
    ]);
    const resources: NormalizedCloudResource[] = resourceRows.map((r) => ({
      provider: account.provider as NormalizedCloudResource["provider"],
      resourceType: r.resourceType, providerResourceId: r.providerResourceId, name: r.name,
      ...(r.region ? { region: r.region } : {}),
      tags: (r.tags ?? {}) as Record<string, string>,
      configuration: (r.configurationMetadata ?? {}) as Record<string, unknown>,
      exposure: r.exposure as NormalizedCloudResource["exposure"], source: "persisted-inventory",
    }));
    const paths = buildCloudRiskPaths({
      resources,
      relationships: relationshipRows.map((r) => ({
        fromType: r.fromType, fromRef: r.fromRef, toType: r.toType, toRef: r.toRef,
        relationship: r.relationship, ...(r.evidence ? { evidence: r.evidence } : {}),
      })),
      findings: findingRows.map((f) => ({
        title: "", description: "", severity: "LOW" as const, confidence: 0, references: [], sourceTool: "cloud",
        sourceFingerprint: f.fingerprint ?? f.id, providerResourceId: f.providerResourceId ?? undefined,
      })),
    });
    let riskPaths = 0;
    for (const p of paths) {
      const existing = await prisma.cloudRiskPath.findFirst({ where: { cloudAccountId: account.id, scanId, title: p.title } });
      if (existing) continue;
      const findingIds = findingRows.filter((f) => p.findingFingerprints.includes(f.fingerprint ?? "")).map((f) => f.id);
      await prisma.cloudRiskPath.create({
        data: {
          workspaceId: graph.workspaceId, cloudAccountId: account.id, scanId,
          title: p.title, steps: p.steps as never, confidence: p.confidence, findingIds,
        },
      });
      riskPaths++;
    }
    await prisma.cloudAccount.update({ where: { id: account.id }, data: { lastAssessmentAt: new Date() } });
    return {
      assessed: assessments.length,
      failed: assessments.filter((a) => a.status === "FAIL").length,
      drift: driftCount, riskPaths,
    };
  }

  /** QUALITY_GATE for cloud scans (§70): the cloud gate over the
   *  scan's canonical findings + observed audit-logging state. A
   *  failed gate is a recorded RESULT, never a pipeline failure. */
  async evaluateCloudQualityGate(scanId: string): Promise<{ status: string; failedRules: number; warningRules: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph?.assessment) return null;
    if (!["AWS", "AZURE", "GCP"].includes(graph.assessment.target.type)) return null;
    const account = await prisma.cloudAccount.findFirst({ where: { workspaceId: graph.workspaceId, targetId: graph.assessment.targetId } });
    if (!account) return null;
    const [rows, resourceRows] = await Promise.all([
      prisma.finding.findMany({ where: { scanId, duplicateOfId: null } }),
      prisma.cloudResource.findMany({ where: { cloudAccountId: account.id, scopeStatus: "IN_SCOPE", status: "ACTIVE" } }),
    ]);
    const resourceByProviderId = new Map(resourceRows.map((r) => [r.providerResourceId, r]));
    const result = evaluateCloudSecurityGate({
      findings: rows.map((r) => ({
        severity: r.severity, findingClass: r.findingClass ?? undefined,
        exposureClass: (r.providerResourceId ? resourceByProviderId.get(r.providerResourceId)?.exposure : undefined) as never,
        resourceType: r.providerResourceId ? resourceByProviderId.get(r.providerResourceId)?.resourceType : undefined,
        kevListed: r.kevListed,
      })),
      auditLoggingEnabled: auditLoggingEnabled(resourceRows.map((r) => ({
        provider: account.provider as NormalizedCloudResource["provider"],
        resourceType: r.resourceType, providerResourceId: r.providerResourceId, name: r.name,
        tags: {}, configuration: (r.configurationMetadata ?? {}) as Record<string, unknown>,
        exposure: r.exposure as NormalizedCloudResource["exposure"], source: "persisted-inventory",
      }))),
    });
    await prisma.qualityGateResult.create({
      data: {
        scanId, status: result.status as never, policyVersion: "cloud-gate-v1",
        failedRules: result.failedRules as never, warningRules: result.warningRules as never,
        summary: result as never,
      },
    });
    return { status: result.status, failedRules: result.failedRules.length, warningRules: result.warningRules.length };
  }

  /** Prompt 14: the CLOUD_INVENTORY stage narrows its connector
   *  candidates to the registered account's provider (§16–§18). */
  async cloudScanProvider(scanId: string): Promise<string | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph?.assessment) return null;
    const account = await prisma.cloudAccount.findFirst({ where: { workspaceId: graph.workspaceId, targetId: graph.assessment.targetId } });
    return account?.provider ?? null;
  }

  // ── Prompt 15 platform hooks (§9/§32/§34/§70) ──────────────────────

  /** DOMAIN_DISCOVERY (§9/§12): validate the registered domain + issue
   *  the job-scoped credential lease (reference only, TTL ≤ 3600s). An
   *  unregistered domain or a profile without a credential reference
   *  is honestly NOT_CONFIGURED — the DAG fails the scan, never fakes. */
  async validateDirectoryDomain(scanId: string): Promise<{ status: string; domainRef?: string } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph?.assessment) return null;
    if (!["ACTIVE_DIRECTORY", "ACTIVE_DIRECTORY_DOMAIN", "ACTIVE_DIRECTORY_FOREST", "DOMAIN_CONTROLLER", "LDAP_DIRECTORY"].includes(graph.assessment.target.type)) return null;
    const domain = await prisma.activeDirectoryDomain.findFirst({
      where: { workspaceId: graph.workspaceId, targetId: graph.assessment.targetId },
      include: { credentialProfile: true },
    });
    if (!domain) return null;
    const reference = domain.credentialProfile?.credentialReference;
    if (!reference) {
      await prisma.activeDirectoryDomain.update({ where: { id: domain.id }, data: { status: "NOT_CONFIGURED" } });
      return { status: "NOT_CONFIGURED", domainRef: domain.dnsName };
    }
    await prisma.credentialLease.create({
      data: {
        workspaceId: graph.workspaceId, directoryDomainId: domain.id, scanId,
        credentialReference: reference, purpose: "DIRECTORY_ASSESSMENT",
        status: "ISSUED", expiresAt: new Date(Date.now() + 3600 * 1000),
      },
    });
    await prisma.activeDirectoryDomain.update({ where: { id: domain.id }, data: { status: "VALIDATED" } });
    return { status: "VALIDATED", domainRef: domain.dnsName };
  }

  /** The scan's registered domain row (shared by the AD hooks). */
  private async directoryDomainForScan(scanId: string) {
    const graph = await loadScanGraph(scanId);
    if (!graph?.assessment) return null;
    const domain = await prisma.activeDirectoryDomain.findFirst({ where: { workspaceId: graph.workspaceId, targetId: graph.assessment.targetId } });
    return domain ? { graph, domain } : null;
  }

  /** LDAP_POSTURE (§70/§71): run the LDAP/DC analyzer slice over the
   *  persisted inventory and report the section's findings. The full
   *  posture findings were persisted at collection time (deduped by
   *  fingerprint); this hook counts the LDAP-family evidence. */
  async analyzeDirectoryLdapPosture(scanId: string): Promise<{ findings: number; assessments: number } | null> {
    const ctx = await this.directoryDomainForScan(scanId);
    if (!ctx) return null;
    const data = await this.loadDirectoryInventory(ctx.domain.id);
    if (data.domainControllers.length === 0) return null;
    const findings = analyzeLdapPosture(data, { domainId: ctx.domain.id, domainRef: ctx.domain.dnsName, toolSlug: "directory-platform-analysis" });
    let present = 0;
    for (const f of findings) {
      const existing = await prisma.finding.findFirst({ where: { scanId, fingerprint: f.sourceFingerprint } });
      if (existing) { present++; continue; }
      await prisma.finding.create({
        data: {
          workspaceId: ctx.graph.workspaceId, scanId,
          title: f.title, description: f.description, severity: f.severity as never, confidence: f.confidence,
          fingerprint: f.sourceFingerprint, isMock: false, status: "OPEN", verificationStatus: "UNVERIFIED",
          sources: [f.sourceTool], ruleId: f.ruleId, controlId: f.controlId, remediation: f.remediation,
          host: f.host, directoryDomainId: ctx.domain.id, directoryObjectId: f.directoryObjectId,
          evidence: { create: { sourceTool: f.sourceTool, evidenceType: "TEXT", summary: f.evidence ?? "", fingerprint: f.sourceFingerprint } },
          history: { create: { workspaceId: ctx.graph.workspaceId, event: "CREATED", metadata: { sourceTool: f.sourceTool, stage: "LDAP_POSTURE" } as never } },
        },
      });
      present++;
    }
    const assessments = await prisma.controlAssessment.count({ where: { scanId } });
    return { findings: present, assessments };
  }

  /** GRAPH_COLLECTION (§32/§65): build the identity graph over the
   *  persisted inventory — counts + privileged principals + the drift
   *  events this scan recorded at collection time. */
  async buildDirectoryGraph(scanId: string): Promise<{ nodes: number; edges: number; privileged: number; drift: number } | null> {
    const ctx = await this.directoryDomainForScan(scanId);
    if (!ctx) return null;
    const data = await this.loadDirectoryInventory(ctx.domain.id);
    if (data.users.length + data.groups.length + data.computers.length === 0) return null;
    const graph = buildIdentityGraph(data, ctx.domain.dnsName);
    const resolution = resolveNestedGroups(graph, data.groups);
    const privileged = privilegedPrincipals(data, graph, resolution);
    const drift = await prisma.adDriftEvent.count({ where: { domainId: ctx.domain.id, scanId } });
    if (privileged.size > 0) {
      await prisma.auditLog.create({
        data: {
          actorId: ctx.graph.requestedBy, organizationId: ctx.graph.workspace.organizationId, workspaceId: ctx.graph.workspaceId,
          action: "PRIVILEGED_IDENTITY_DETECTED" as never, resourceType: "ACTIVE_DIRECTORY_DOMAIN", resourceId: ctx.domain.id,
          metadata: { scanId, privileged: privileged.size } as never,
        },
      });
    }
    return { nodes: graph.nodes.size, edges: graph.edges.length, privileged: privileged.size, drift };
  }

  /** ATTACK_PATH_ANALYSIS (§34–§37): model defensive attack paths over
   *  the persisted graph and record them as analysis results. Paths
   *  are NEVER executed and never labelled COMPROMISED (§35). */
  async analyzeAttackPaths(scanId: string): Promise<{ paths: number; findings: number } | null> {
    const ctx = await this.directoryDomainForScan(scanId);
    if (!ctx) return null;
    const data = await this.loadDirectoryInventory(ctx.domain.id);
    if (data.relationships.length === 0) return null;
    const graph = buildIdentityGraph(data, ctx.domain.dnsName);
    const resolution = resolveNestedGroups(graph, data.groups);
    const paths = findAttackPaths(data, graph, resolution, {}, ctx.domain.dnsName);
    let created = 0;
    for (const p of paths) {
      const existing = await prisma.adAttackPath.findFirst({ where: { domainId: ctx.domain.id, scanId, title: p.title } });
      if (existing) continue;
      await prisma.adAttackPath.create({
        data: {
          workspaceId: ctx.graph.workspaceId, domainId: ctx.domain.id, scanId,
          title: p.title, steps: p.steps as never, status: p.status, confidence: p.confidence,
          riskScore: p.riskScore, riskFactors: p.riskFactors as never,
        },
      });
      created++;
    }
    if (created > 0) {
      await prisma.auditLog.create({
        data: {
          actorId: ctx.graph.requestedBy, organizationId: ctx.graph.workspace.organizationId, workspaceId: ctx.graph.workspaceId,
          action: "AD_ATTACK_PATH_DETECTED" as never, resourceType: "ACTIVE_DIRECTORY_DOMAIN", resourceId: ctx.domain.id,
          metadata: { scanId, paths: created } as never,
        },
      });
    }
    const total = await prisma.adAttackPath.count({ where: { domainId: ctx.domain.id, scanId } });
    return { paths: total, findings: 0 };
  }

  // ── Prompt 17 platform hooks (§5/§6/§10/§90/§92) ──────────────────

  /** MOBILE_ARTIFACT_INTAKE (§5/§6): validate the registered build —
   *  the artifact hash IS the build identity; the upload-time intake
   *  verdict (format + archive security) is recorded on the build
   *  row. An unregistered build is honestly NOT_CONFIGURED — the DAG
   *  fails the scan, never fakes. */
  async validateMobileBuild(scanId: string): Promise<{ buildHash: string; platform: string; artifactFormat: string } | null> {
    const ctx = await this.mobileBuildForScan(scanId);
    if (!ctx) return null;
    return { buildHash: ctx.build.artifactHash, platform: ctx.app.platform, artifactFormat: ctx.build.artifactFormat };
  }

  /** MOBILE_METADATA_EXTRACTION (§6/§20): run the platform extraction
   *  over the build's registered analysis artifacts — manifest/plist
   *  parse, endpoint/secret/code-pattern analysis, SDK inventory, SCA
   *  — and persist through the ordinary result path (stamping,
   *  inventory upserts, posture). Nothing is executed. */
  async extractMobileMetadata(scanId: string): Promise<{ permissions: number; components: number; endpoints: number; secrets: number; componentsScanned: number } | null> {
    const ctx = await this.mobileBuildForScan(scanId);
    if (!ctx) return null;
    const { app, build } = ctx;
    const artifacts = (build.analysisArtifacts ?? {}) as Record<string, unknown>;
    if (Object.keys(artifacts).length === 0) return null;
    const extracted = extractMobileArtifacts(artifacts, {
      applicationId: app.id, applicationRef: app.packageName ?? app.bundleId ?? app.name, buildId: build.id,
      buildHash: build.artifactHash, platform: app.platform as "ANDROID" | "IOS",
      environment: app.environment, toolSlug: "mobile-platform-analysis",
    });
    const processedExtracted = processNormalizedResult({
      assets: [], services: [], endpoints: [], technologies: [], findings: extracted.findings,
      artifacts: [], metrics: {}, mock: false,
      components: extracted.components, mobile: extracted.data,
    }, { scopeRules: { includeHosts: [], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] }, toolExecutionId: "platform-mobile-metadata", toolSlug: "mobile-platform-analysis" });
    await this.persistResult(scanId, "platform-mobile-metadata", processedExtracted);
    return {
      permissions: extracted.data.permissions.length,
      components: extracted.data.components.length,
      endpoints: extracted.data.endpoints.length,
      secrets: extracted.findings.filter((f) => f.mobileFindingType === "MOBILE_SECRET").length,
      componentsScanned: extracted.components.length,
    };
  }

  /** MOBILE_MANIFEST_ANALYSIS (§20–§41): posture over the persisted
   *  build inventory — findings were persisted at collection time
   *  (deduped by canonical fingerprint); this hook reports the
   *  section's findings + MASVS assessments. */
  async analyzeMobileManifest(scanId: string): Promise<{ findings: number; assessments: number } | null> {
    const ctx = await this.mobileBuildForScan(scanId);
    if (!ctx) return null;
    const findings = await prisma.finding.count({ where: { scanId, mobileBuildId: ctx.build.id } });
    const assessments = await prisma.controlAssessment.count({ where: { scanId, frameworkKey: "OWASP_MASVS" } });
    if (findings === 0 && assessments === 0) return null;
    return { findings, assessments };
  }

  /** QUALITY_GATE — mobile gate (§90): no Critical findings, no
   *  verified secrets, no KEV dependencies, no critical exported-
   *  component issue, no critical network-security misconfiguration.
   *  KEV membership comes from the local intelligence dataset (empty
   *  in this build ⇒ no KEV matches — honest, never invented). */
  async evaluateMobileQualityGate(scanId: string): Promise<{ status: string; failedRules: number; warningRules: number } | null> {
    const ctx = await this.mobileBuildForScan(scanId);
    if (!ctx) return null;
    const rows = await prisma.finding.findMany({
      where: { scanId, duplicateOfId: null },
      include: { secretMetadata: true },
    });
    if (rows.length === 0) return null;
    const dataset = new InMemoryIntelligenceDataset();
    const isKevListed = (cve: string) => dataset.getKev(cve) !== undefined;
    const summary = summarizeMobileForGate(rows.map((r) => ({
      severity: r.severity,
      ...(r.mobileFindingType ? { mobileFindingType: r.mobileFindingType } : {}),
      ...(r.ruleId ? { ruleId: r.ruleId } : {}),
      ...(r.secretMetadata ? { secretVerified: r.secretMetadata.verificationStatus === "VERIFIED_ACTIVE" } : {}),
      ...(r.cve ? { kevListed: isKevListed(r.cve) } : {}),
    })));
    const evaluation = evaluateMobileSecurityGate(summary);
    await prisma.qualityGateResult.create({
      data: {
        scanId, buildId: ctx.build.id,
        policyVersion: "mobile-gate-v1", status: evaluation.status as never,
        summary: summary as never,
        failedRules: evaluation.failedRules, warningRules: evaluation.warningRules,
      },
    });
    await prisma.auditLog.create({
      data: {
        actorId: ctx.graph.requestedBy, organizationId: ctx.graph.workspace.organizationId, workspaceId: ctx.graph.workspaceId,
        action: "MOBILE_STATIC_SCAN_COMPLETED" as never, resourceType: "MOBILE_BUILD", resourceId: ctx.build.id,
        metadata: { scanId, gateStatus: evaluation.status } as never,
      },
    });
    return { status: evaluation.status, failedRules: evaluation.failedRules.length, warningRules: evaluation.warningRules.length };
  }

  /** BINARY_ARTIFACT_INTAKE (§3/§6): the scan's registered artifact
   *  is the intake verdict — identity + format recorded at
   *  registration. No artifact ⇒ NOT_CONFIGURED (the runner fails the
   *  scan honestly). */
  async validateBinaryArtifact(scanId: string): Promise<{ artifactHash: string; format: string } | null> {
    const ctx = await this.binaryArtifactForScan(scanId);
    if (!ctx) return null;
    return { artifactHash: ctx.artifact.sha256, format: ctx.artifact.format };
  }

  /** BINARY_METADATA_EXTRACTION (§12–§50): run the platform static
   *  analysis over the artifact's registered header segment — header
   *  parsing, hardening, string inventory, secret candidates, crypto
   *  inventory, dependency inventory — and persist through the
   *  ordinary result path. PURE PARSING: the segment is data; nothing
   *  is executed, loaded or mapped as code (§8/§100). */
  async extractBinaryMetadata(scanId: string): Promise<{ sections: number; functions: number; dependencies: number; secrets: number; componentsScanned: number } | null> {
    const ctx = await this.binaryArtifactForScan(scanId);
    if (!ctx) return null;
    const { artifact } = ctx;
    const artifacts = (artifact.analysisArtifacts ?? {}) as Record<string, unknown>;
    const segmentB64 = typeof artifacts.headerSegmentBase64 === "string" ? artifacts.headerSegmentBase64 : undefined;
    if (!segmentB64) return null;
    const segment = Buffer.from(segmentB64, "base64");
    if (segment.length === 0 || segment.length > 1024 * 1024) return null;
    const report = parseBinaryHeaders(segment);
    const sectionOf = (offset: number) => report.sections.find((s) => offset >= s.offset && offset < s.offset + s.size)?.name;
    const strings = extractBinaryStrings(segment, { source: "binary-platform-analysis", sectionOf });
    const analysis = analyzeBinaryPlatform({
      artifactName: artifact.name, sha256: artifact.sha256,
      ...(artifact.sha1 ? { sha1: artifact.sha1 } : {}),
      sizeBytes: Number(artifact.sizeBytes),
      report, strings, environment: artifact.environment,
    });
    const processedExtracted = processNormalizedResult({
      assets: [], services: [], endpoints: [], technologies: [], findings: analysis.findings,
      artifacts: [], metrics: {}, mock: false,
      components: analysis.components, binary: analysis.data,
    }, { scopeRules: { includeHosts: [], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] }, toolExecutionId: "platform-binary-metadata", toolSlug: "binary-platform-analysis" });
    await this.persistResult(scanId, "platform-binary-metadata", processedExtracted);
    return {
      sections: analysis.data.sections.length,
      functions: analysis.data.functions.length,
      dependencies: analysis.data.dependencies.length,
      secrets: analysis.findings.filter((f) => f.binaryFindingType === "BINARY_SECRET").length,
      componentsScanned: analysis.components.length,
    };
  }

  /** DEPENDENCY_INVENTORY for binary profiles (§25–§27): the
   *  persisted dependency inventory of the scan's artifact. */
  async inventoryBinaryDependencies(scanId: string): Promise<{ components: number } | null> {
    const ctx = await this.binaryArtifactForScan(scanId);
    if (!ctx) return null;
    const deps = await prisma.binaryDependency.count({ where: { artifactId: ctx.artifact.id } });
    if (deps === 0) return null;
    const components = await prisma.softwareComponent.count({ where: { binaryArtifactId: ctx.artifact.id } });
    return { components };
  }

  /** SBOM_GENERATION for binary profiles (§27): the artifact's SBOM
   *  was generated at payload persistence; this hook reports it (and
   *  generates from persisted components when a payload arrived
   *  without one). */
  async generateBinarySbom(scanId: string): Promise<{ format: string; checksum: string; components: number } | null> {
    const ctx = await this.binaryArtifactForScan(scanId);
    if (!ctx) return null;
    const existing = await prisma.softwareBillOfMaterials.findFirst({
      where: { binaryArtifactId: ctx.artifact.id, format: "CYCLONEDX_JSON" },
      orderBy: { createdAt: "desc" },
    });
    if (existing) return { format: existing.format, checksum: existing.checksum, components: existing.componentCount };
    const rows = await prisma.softwareComponent.findMany({ where: { binaryArtifactId: ctx.artifact.id } });
    if (rows.length === 0) return null;
    const components = rows.map((r) => ({
      name: r.name, ...(r.version ? { version: r.version } : {}), ecosystem: r.ecosystem, purl: r.purl,
      sourceManifest: r.sourceManifest, scope: r.scope as never, dependencyScope: r.dependencyScope as never,
      licenses: r.licenses, ...(r.supplier ? { supplier: r.supplier } : {}),
    }));
    const doc = buildCycloneDxSbom(components, {
      snapshotHash: ctx.artifact.sha256, repositoryName: ctx.artifact.name, timestamp: new Date().toISOString(),
    }).sbom;
    await prisma.softwareBillOfMaterials.create({
      data: {
        binaryArtifactId: ctx.artifact.id, scanId, format: doc.format as never,
        specVersion: doc.specVersion, checksum: doc.checksum,
        artifactRef: `sbom://binary-artifact/${ctx.artifact.id}/${doc.checksum}`,
        componentCount: doc.componentCount,
      },
    });
    return { format: doc.format, checksum: doc.checksum, components: doc.componentCount };
  }

  /** BINARY_DEBUG_SESSION (§64–§74): evaluate the governed session
   *  for the scan's artifact. No session ⇒ null (the runner records
   *  the stage as skipped/NOT_CONFIGURED). An eligible session
   *  without a provisioned lab transport reports NOT_PROVISIONED —
   *  in this build no debugger transport exists, so no session ever
   *  fabricates a run (§72). A kill switch terminates eligibility. */
  async evaluateBinaryDebugSession(scanId: string): Promise<{ status: string; reason?: string } | null> {
    const ctx = await this.binaryArtifactForScan(scanId);
    if (!ctx) return null;
    const session = await prisma.binaryDebugSession.findFirst({
      where: { workspaceId: ctx.graph.workspaceId, artifactId: ctx.artifact.id },
      orderBy: { createdAt: "desc" },
    });
    if (!session) return null;
    if (session.status === "BLOCKED") return { status: "BLOCKED", reason: "session blocked by policy" };
    const switches = this.activeKillSwitches
      ? await this.activeKillSwitches({ organizationId: ctx.graph.workspace.organizationId, workspaceId: ctx.graph.workspaceId, scanId, targetId: ctx.graph.assessment.targetId, sessionId: session.id }).catch(() => [])
      : [];
    const decision = evaluateBinaryDebugPolicy({
      environment: ctx.artifact.environment,
      artifactAuthorized: true,
      targetVerified: ctx.graph.assessment.target.verified,
      requestedBy: session.requestedBy,
      ...(session.approvedBy ? { approvedBy: session.approvedBy } : {}),
      // Eligibility is a POLICY question; transport provisioning is
      // resolved separately below — no BINARY_DYNAMIC_LAB transport
      // is provisioned in this build, so an ELIGIBLE session reports
      // NOT_PROVISIONED (§72).
      workerCapabilityPresent: true,
      killSwitchActive: switches.length > 0,
      operations: (session.operations as { operation: string }[]) ?? [],
    });
    if (decision.decision === "BLOCKED") {
      await prisma.binaryDebugSession.update({ where: { id: session.id }, data: { status: "BLOCKED", policyDecision: decision as never } }).catch(() => undefined);
      return { status: "BLOCKED", reason: decision.reasons[0] ?? "policy" };
    }
    if (decision.decision === "PENDING_APPROVAL") return { status: "PENDING_APPROVAL", reason: decision.reasons[0] ?? "approval" };
    await prisma.binaryDebugSession.update({ where: { id: session.id }, data: { status: "NOT_PROVISIONED", policyDecision: decision as never } }).catch(() => undefined);
    return { status: "NOT_PROVISIONED", reason: "eligible session, but no BINARY_DYNAMIC_LAB debugger transport is provisioned in this build (§72)" };
  }

  /** QUALITY_GATE — binary gate (§63): fails on any Critical binary
   *  finding, any embedded-secret finding, or any KEV-listed
   *  dependency finding. */
  async evaluateBinaryQualityGate(scanId: string): Promise<{ status: string; failedRules: number; warningRules: number } | null> {
    const ctx = await this.binaryArtifactForScan(scanId);
    if (!ctx) return null;
    const rows = await prisma.finding.findMany({ where: { scanId, duplicateOfId: null } });
    if (rows.length === 0) return null;
    const failed: string[] = [];
    const warnings: string[] = [];
    if (rows.some((r) => r.binaryArtifactId === ctx.artifact.id && r.severity === "CRITICAL")) failed.push("NO_CRITICAL_BINARY_FINDINGS");
    if (rows.some((r) => r.binaryFindingType === "BINARY_SECRET")) failed.push("NO_EMBEDDED_SECRETS");
    if (rows.some((r) => r.binaryFindingType === "BINARY_DEPENDENCY_VULNERABILITY" && r.kevListed)) failed.push("NO_KEV_DEPENDENCIES");
    if (rows.some((r) => r.binaryFindingType === "BINARY_HARDENING_FINDING" && r.severity === "HIGH")) warnings.push("HARDENING_GAPS_REVIEWED");
    const status = failed.length > 0 ? "FAILED" : warnings.length > 0 ? "PASSED_WITH_WARNINGS" : "PASSED";
    await prisma.qualityGateResult.create({
      data: {
        scanId, policyVersion: "binary-gate-v1", status: status as never,
        summary: { failedRules: failed, warningRules: warnings } as never,
        failedRules: failed as never, warningRules: warnings as never,
      },
    });
    await prisma.auditLog.create({
      data: {
        actorId: ctx.graph.requestedBy, organizationId: ctx.graph.workspace.organizationId, workspaceId: ctx.graph.workspaceId,
        action: "BINARY_STATIC_SCAN_COMPLETED" as never, resourceType: "BINARY_ARTIFACT", resourceId: ctx.artifact.id,
        metadata: { scanId, gateStatus: status } as never,
      },
    }).catch(() => undefined);
    return { status, failedRules: failed.length, warningRules: warnings.length };
  }

  /** NORMALIZATION stage hook (§45/§46): counts from persisted findings. */
  async summarizeFindings(scanId: string): Promise<Record<string, unknown> | null> {
    const rows = await prisma.finding.findMany({ where: { scanId }, select: { severity: true } });
    if (rows.length === 0) return null;
    const bySeverity: Record<string, number> = {};
    for (const r of rows) bySeverity[r.severity] = (bySeverity[r.severity] ?? 0) + 1;
    return { totalFindings: rows.length, bySeverity };
  }

  /** CORRELATION stage hook (§18–§22): canonicalize the scan's findings.
   *  Duplicates are marked duplicateOfId=canonical and their evidence rows
   *  are re-homed to the canonical finding — evidence is NEVER deleted
   *  (§20). Canonical rows absorb merged sources/confidence/risk. */
  async correlateScanFindings(scanId: string): Promise<{ canonical: number; duplicates: number; stats: Record<string, unknown> } | null> {
    const rows = await prisma.finding.findMany({
      where: { scanId },
      include: { evidence: true, references: true, asset: { select: { criticality: true } }, secretMetadata: true },
      orderBy: { createdAt: "asc" },
    });
    if (rows.length === 0) return null;
    const processed: ProcessedFinding[] = rows.map((r) => ({
      title: r.title, description: r.description, severity: r.severity, confidence: r.confidence,
      host: r.host ?? undefined, endpoint: r.endpoint ?? undefined, fingerprint: r.fingerprint ?? r.id,
      isMock: r.isMock, sourceTool: r.evidence[0]?.sourceTool ?? "unknown", toolExecutionId: r.toolExecutionId ?? "",
      evidenceSummary: r.evidence[0]?.summary ?? "",
      vulnClass: r.vulnClass ?? undefined, sources: r.sources,
      evidenceRows: r.evidence.map((e) => ({ sourceTool: e.sourceTool, summary: e.summary ?? "", fingerprint: e.fingerprint ?? undefined, matchedAt: e.matchedAt ?? undefined })),
      references: r.references.map((x) => ({ type: x.type, label: x.label, url: x.url })),
      cve: r.cve ?? undefined, cwe: r.cwe ?? undefined, owaspCategory: r.owaspCategory ?? undefined,
      cvssScore: r.cvssScore ?? undefined, cvssVector: r.cvssVector ?? undefined,
      port: r.port ?? undefined, protocol: r.protocol ?? undefined, parameter: r.parameter ?? undefined,
      technicalImpact: r.technicalImpact ?? undefined, businessImpact: r.businessImpact ?? undefined,
      remediation: r.remediation ?? undefined,
      // Prompt 12: source fields ride along so source findings route to
      // the line-stable source correlation engine (§64–§68).
      filePath: r.filePath ?? undefined, startLine: r.startLine ?? undefined, endLine: r.endLine ?? undefined,
      startColumn: r.startColumn ?? undefined, endColumn: r.endColumn ?? undefined,
      ruleId: r.ruleId ?? undefined,
      codeFlow: (r.codeFlow as ProcessedFinding["codeFlow"]) ?? undefined,
      componentPurl: r.componentPurl ?? undefined,
      fixedVersion: r.fixedVersion ?? undefined,
      dependencyScope: r.dependencyScope ?? undefined,
      reachability: r.reachability ?? undefined,
      reviewStatus: r.reviewStatus ?? undefined,
      baselineStatus: r.baselineStatus ?? undefined,
      // Prompt 13: cloud-native fields ride along so cloud findings
      // route to the cloud correlation partition (§95) with their
      // static/live origins preserved (§103).
      origin: r.origin ?? undefined, imageDigest: r.imageDigest ?? undefined, imageRef: r.imageRef ?? undefined,
      clusterRef: r.clusterRef ?? undefined, namespace: r.namespace ?? undefined,
      resourceKind: r.resourceKind ?? undefined, resourceName: r.resourceName ?? undefined,
      containerName: r.containerName ?? undefined, controlId: r.controlId ?? undefined,
      // Prompt 14: cloud fields ride along so cloud findings route to
      // the cloud correlation partition with cloud fingerprints (§61)
      // and IaC/live identity (§62) intact.
      findingClass: r.findingClass ?? undefined, cloudProvider: r.cloudProvider ?? undefined,
      cloudAccountId: r.cloudAccountId ?? undefined, providerResourceId: r.providerResourceId ?? undefined,
      cloudRegion: r.cloudRegion ?? undefined,
      ...(r.secretMetadata ? {
        secret: {
          secretType: r.secretMetadata.secretType,
          detector: r.secretMetadata.detector,
          commitSha: r.secretMetadata.commitSha ?? undefined,
          fingerprint: r.secretMetadata.fingerprint,
          redactedPreview: r.secretMetadata.redactedPreview ?? undefined,
          verificationStatus: r.secretMetadata.verificationStatus,
        },
      } : {}),
    }));
    const criticality = rows.find((r) => r.asset)?.asset?.criticality ?? "UNSPECIFIED";
    const { findings: canonical, stats } = correlateProcessedFindings(processed, { assetCriticality: criticality, maxFindings: 1000 });
    // Each canonical finding's evidence rows carry the SOURCE fingerprints
    // of its member rows (correlateProcessedFindings preserves them), so
    // members map back to persisted rows deterministically.
    const rowByFingerprint = new Map(rows.map((r) => [r.fingerprint ?? r.id, r]));
    let duplicates = 0;
    for (const c of canonical) {
      const memberFingerprints = c.evidenceRows.map((e) => e.fingerprint).filter((x): x is string => !!x);
      const memberRows = memberFingerprints.map((fp) => rowByFingerprint.get(fp)).filter((r): r is NonNullable<typeof r> => !!r);
      const primaryRow = memberRows[0];
      if (!primaryRow) continue;
      await prisma.finding.update({
        where: { id: primaryRow.id },
        data: {
          fingerprint: c.fingerprint, sources: c.sources, confidence: c.confidence,
          confidenceBand: c.confidenceBand, verificationStatus: (c.verificationStatus ?? "UNVERIFIED") as never,
          riskScore: c.riskScore, riskBand: c.riskBand, riskExplanation: (c.riskExplanation ?? undefined) as never,
          severity: c.severity as never,
          cve: c.cve ?? primaryRow.cve,
          cwe: c.cwe ?? primaryRow.cwe,
          cvssScore: c.cvssScore ?? primaryRow.cvssScore, remediation: c.remediation ?? primaryRow.remediation,
        },
      });
      // Prompt 11 §59–§64: record one OBSERVATION per (source tool,
      // source fingerprint) — the canonical finding accumulates scanner
      // observations across scans instead of spawning duplicates (§62).
      // Observed severities are the SOURCE severities: conflicts between
      // scanners are preserved here, never averaged away (§63).
      for (const member of memberRows) {
        for (const e of member.evidence) {
          await prisma.findingObservation.upsert({
            where: { findingId_sourceTool_sourceFingerprint: { findingId: primaryRow.id, sourceTool: e.sourceTool, sourceFingerprint: e.fingerprint ?? member.fingerprint ?? member.id } },
            create: {
              findingId: primaryRow.id, workspaceId: member.workspaceId, scanId,
              sourceTool: e.sourceTool, sourceFingerprint: e.fingerprint ?? member.fingerprint ?? member.id,
              severity: member.severity, summary: e.summary ?? undefined,
            },
            update: { observedAt: new Date(), severity: member.severity, scanId },
          });
        }
      }
      // Re-home duplicate evidence + mark duplicates (§20: never delete).
      for (const member of memberRows.slice(1)) {
        await prisma.findingEvidence.updateMany({ where: { findingId: member.id }, data: { findingId: primaryRow.id } });
        await prisma.finding.update({ where: { id: member.id }, data: { duplicateOfId: primaryRow.id } });
        await prisma.findingHistory.create({ data: { findingId: member.id, workspaceId: member.workspaceId, event: "CORRELATED", metadata: { canonicalFindingId: primaryRow.id } as never } });
        duplicates++;
      }
      if (c.sources.length > 1) {
        await prisma.findingHistory.create({ data: { findingId: primaryRow.id, workspaceId: primaryRow.workspaceId, event: "CORRELATED", metadata: { sources: c.sources } as never } });
      }
    }
    return { canonical: canonical.length, duplicates, stats: stats as unknown as Record<string, unknown> };
  }

  /** RISK stage hook (§34/§35): recompute risk for canonical findings
   *  (duplicates keep pointing at their canonical row). */
  async recalculateFindingRisk(scanId: string): Promise<{ updated: number } | null> {
    const rows = await prisma.finding.findMany({ where: { scanId, duplicateOfId: null }, include: { asset: { select: { criticality: true } } } });
    if (rows.length === 0) return null;
    // Prompt 11 §35/§37: Risk Engine V2 — enrichment comes ONLY from the
    // governed local intelligence tables; when they hold nothing for a
    // CVE, the finding keeps its V1-derived score with NO intel factors
    // (never invented, §87). The intelligence snapshot used is recorded
    // on every finding (§31).
    const cveIds = [...new Set(rows.map((r) => r.cve).filter((x): x is string => !!x))];
    const dataset = new InMemoryIntelligenceDataset();
    if (cveIds.length > 0) {
      const [cves, epss, kevs] = await Promise.all([
        prisma.cveRecord.findMany({ where: { cveId: { in: cveIds } } }),
        prisma.epssRecord.findMany({ where: { cveId: { in: cveIds } }, orderBy: { date: "desc" } }),
        prisma.kevRecord.findMany({ where: { cveId: { in: cveIds } } }),
      ]);
      for (const c of cves) {
        const record: Parameters<InMemoryIntelligenceDataset["upsertCve"]>[0] = {
          cveId: c.cveId, description: c.description, cweIds: c.cweIds,
          references: (c.references as { label: string; url: string }[] | null) ?? [], source: c.source,
        };
        if (c.cvssScore != null) {
          record.cvss = { baseScore: c.cvssScore, version: (c.cvssVersion ?? "3.1") as "3.1", source: c.source, ...(c.cvssVector ? { vector: c.cvssVector } : {}) } as typeof record.cvss;
        }
        dataset.upsertCve(record);
      }
      const seenEpss = new Set<string>();
      for (const e of epss) {
        if (seenEpss.has(e.cveId)) continue;
        seenEpss.add(e.cveId);
        dataset.upsertEpss({ cveId: e.cveId, score: e.score, percentile: e.percentile, date: e.date.toISOString().slice(0, 10), source: e.source });
      }
      for (const k of kevs) {
        dataset.upsertKev({ cveId: k.cveId, source: k.source, ...(k.dateAdded ? { dateAdded: k.dateAdded.toISOString().slice(0, 10) } : {}), ...(k.vendorProject ? { vendorProject: k.vendorProject } : {}), ...(k.product ? { product: k.product } : {}), ...(k.requiredAction ? { requiredAction: k.requiredAction } : {}), ...(k.knownRansomwareUse ? { knownRansomwareUse: k.knownRansomwareUse } : {}) });
      }
    }
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, select: { workspaceId: true } });
    const policyRow = scan ? await prisma.remediationSlaPolicy.findFirst({ where: { workspaceId: scan.workspaceId }, orderBy: [{ isDefault: "desc" }, { createdAt: "asc" }] }) : null;
    const policy = policyRow
      ? { id: policyRow.id, name: policyRow.name, rules: (policyRow.rules as { byPriority?: never; bySeverity?: never }) ?? {} }
      : DEFAULT_SLA_POLICY;
    let updated = 0;
    for (const r of rows) {
      const enrichment = enrichFinding({ cve: r.cve ?? undefined, cwe: r.cwe ?? undefined, cpe: r.cpe ?? undefined, cvssScore: r.cvssScore ?? undefined }, dataset);
      const exploitRefs = await prisma.exploitReference.count({ where: { findingId: r.id } });
      const risk = computeRiskV2({
        severity: r.severity as never, cvssScore: enrichment.cvss.effectiveScore ?? r.cvssScore ?? undefined,
        confidence: r.confidence,
        assetCriticality: (r.asset?.criticality ?? "UNSPECIFIED") as never,
        verificationStatus: r.verificationStatus as never,
        enrichment, exploitReferenceExists: exploitRefs > 0 || r.exploitRefExists,
        ageDays: Math.max(0, Math.floor((Date.now() - r.firstSeen.getTime()) / 86400_000)),
      });
      const dueAt = r.dueAt ?? computeDueAt(policy as never, {
        priority: risk.priority, severity: r.severity, createdAt: r.createdAt,
        confirmedAt: r.lifecycleStatus !== "NEW" ? r.reviewedAt : undefined,
      });
      await prisma.finding.update({
        where: { id: r.id },
        data: {
          riskScore: risk.score, riskBand: risk.band,
          riskExplanation: [...risk.baseExplanation, ...risk.factors] as never,
          priority: risk.priority, riskFactors: risk.factors as never, riskCalcVersion: risk.calcVersion,
          intelSnapshot: enrichment.snapshotId as never,
          epssScore: enrichment.epss?.score ?? null, epssPercentile: enrichment.epss?.percentile ?? null,
          kevListed: enrichment.kevListed, intelCvssScore: enrichment.cvss.intelligenceScore ?? null,
          exploitRefExists: exploitRefs > 0 || r.exploitRefExists,
          ...(dueAt ? { dueAt } : {}),
        },
      });
      updated++;
    }
    return { updated };
  }

  // ---------- Prompt 11 retest support (§55–§58) ----------

  /**
   * Prepare a targeted retest execution: build a single-stage child scan
   * (same assessment/target/scope as the original finding's scan) whose
   * only stage re-runs the ORIGINAL tool. Execution then flows through
   * the ordinary StageExecutor, so authorization, scope, policy and
   * budget gates are re-evaluated by construction (§57).
   */
  async prepareRetestExecution(retestId: string): Promise<{ executionId: string; scanId: string; canonicalFingerprint: string; stageId?: string; cloudAnalysisSection?: string; directoryAnalysisSection?: string } | null> {
    const retest = await prisma.retestRequest.findUnique({ where: { id: retestId } });
    if (!retest || retest.status !== "QUEUED") return null;
    const finding = await prisma.finding.findUnique({ where: { id: retest.findingId } });
    if (!finding) return null;
    const graph = await loadScanGraph(finding.scanId);
    if (!graph?.assessment) return null;
    const plan = planRetest({
      fingerprint: finding.fingerprint, host: finding.host, port: finding.port, endpoint: finding.endpoint,
      cve: finding.cve, cwe: finding.cwe, sources: finding.sources,
      checkReference: retest.checkReference, lifecycleStatus: "RETEST_PENDING",
    });
    if (!plan.ok) return null;
    // Prompt 14 §73: cloud findings retest through a targeted
    // read-only cloud chain (auth → provider inventory → the ONE
    // relevant analysis section). The runner executes the inventory
    // stage; this store's analysis hook then produces the section
    // evidence the judgement compares (§58 discipline: a failed stage
    // is never a pass).
    const cloudSecPlan = planCloudRetest({
      cloudProvider: finding.cloudProvider, providerResourceId: finding.providerResourceId, ruleId: finding.ruleId,
    });
    if (cloudSecPlan && finding.fingerprint) {
      const connectorSlug = `${cloudSecPlan.provider.toLowerCase()}-inventory`;
      const scopeParseCloud = scopeRulesSchema.safeParse(graph.assessment.scope?.rules ?? {});
      const childCloud = await prisma.scan.create({
        data: { workspaceId: finding.workspaceId, assessmentId: graph.assessmentId, requestedBy: retest.requestedBy, status: "QUEUED" },
      });
      const cloudStagePlans = cloudSecPlan.stages.map((type) => ({
        id: type, type, name: type === cloudSecPlan.analysisSection ? "Targeted Cloud Retest Analysis" : type,
        description: "Prompt 14 §73 targeted cloud retest: re-check the specific resource and control only.",
        requiredCapabilities: [], dependencies: [] as string[],
        selectedAdapters: type === "CLOUD_INVENTORY"
          ? [{ slug: connectorSlug, adapterId: connectorSlug, name: connectorSlug, riskLevel: "LOW", preference: "REQUIRED", simulation: false, reason: "provider inventory connector (§73)" }]
          : [],
        weight: 10, timeoutSeconds: 1800, failureStrategy: "FAIL_STAGE_CONTINUE", networkCapable: false, status: "QUEUED",
      }));
      await prisma.scanPlan.create({
        data: {
          scanId: childCloud.id, assessmentId: graph.assessmentId, profile: "CUSTOM",
          plan: {
            scanId: childCloud.id, assessmentId: graph.assessmentId, targetId: graph.assessment.targetId,
            workspaceId: finding.workspaceId, organizationId: graph.workspace.organizationId,
            profile: "CUSTOM", targetType: graph.assessment.target.type, targetValue: graph.assessment.target.value,
            targetHost: finding.host ?? "", scope: scopeParseCloud.success ? scopeParseCloud.data : {},
            stages: cloudStagePlans, dependencies: {}, selectedTools: [connectorSlug],
            policySnapshot: { targetVerified: graph.assessment.target.verified, assessmentApproved: graph.assessment.status === "APPROVED", executableSlugs: [connectorSlug], simulation: false },
          } as never,
          policySnapshot: { retest: true, retestId, cloudRetest: true } as never,
        },
      });
      for (const stage of cloudStagePlans) {
        await prisma.scanStage.create({
          data: { scanId: childCloud.id, type: stage.type as never, status: "QUEUED", dependencies: [], weight: stage.weight, metadata: { retestId } as never },
        });
      }
      const execution = await this.ensureExecution(childCloud.id, "CLOUD_INVENTORY", connectorSlug, 1);
      await prisma.retestRequest.update({
        where: { id: retestId },
        data: { status: "RUNNING", scanId: childCloud.id, startedAt: new Date() },
      });
      return {
        executionId: execution.id, scanId: childCloud.id,
        canonicalFingerprint: finding.fingerprint, stageId: "CLOUD_INVENTORY",
        cloudAnalysisSection: cloudSecPlan.analysisSection,
      };
    }
    // Prompt 15 §84: directory findings retest through a targeted
    // READ-ONLY re-check — a fresh collection in the original stage
    // family (or the dedicated LDAP posture section). Credentials are
    // never involved; the judgement discipline is §58 (a failed stage
    // is never a pass).
    if (finding.directoryDomainId && finding.fingerprint) {
      const adPlan = planAdRetest({ ruleId: finding.ruleId ?? undefined, sourceTool: retest.sourceTool });
      const stageType = adPlan.section ? "DIRECTORY_INVENTORY" : adPlan.stageType;
      const slug = adPlan.adapterSlug ?? "ldap-directory-connector";
      const scopeParseAd = scopeRulesSchema.safeParse(graph.assessment.scope?.rules ?? {});
      const childAd = await prisma.scan.create({
        data: { workspaceId: finding.workspaceId, assessmentId: graph.assessmentId, requestedBy: retest.requestedBy, status: "QUEUED" },
      });
      const stagePlanAd = {
        id: stageType, type: stageType, name: "Targeted AD Retest",
        description: "Prompt 15 §84 targeted directory retest: read-only re-query of the affected object only.",
        requiredCapabilities: [], dependencies: [] as string[],
        selectedAdapters: [{ slug, adapterId: slug, name: slug, riskLevel: "LOW", preference: "REQUIRED", simulation: false, reason: "targeted AD retest (§84)" }],
        weight: 100, timeoutSeconds: 1800, failureStrategy: "FAIL_STAGE_CONTINUE", networkCapable: false, status: "QUEUED",
      };
      await prisma.scanPlan.create({
        data: {
          scanId: childAd.id, assessmentId: graph.assessmentId, profile: "CUSTOM",
          plan: {
            scanId: childAd.id, assessmentId: graph.assessmentId, targetId: graph.assessment.targetId,
            workspaceId: finding.workspaceId, organizationId: graph.workspace.organizationId,
            profile: "CUSTOM", targetType: graph.assessment.target.type, targetValue: graph.assessment.target.value,
            targetHost: finding.host ?? graph.assessment.target.value, scope: scopeParseAd.success ? scopeParseAd.data : {},
            stages: [stagePlanAd], dependencies: {}, selectedTools: [slug],
            policySnapshot: { targetVerified: graph.assessment.target.verified, assessmentApproved: graph.assessment.status === "APPROVED", executableSlugs: [slug], simulation: false },
          } as never,
          policySnapshot: { retest: true, retestId, adRetest: true } as never,
        },
      });
      await prisma.scanStage.create({
        data: { scanId: childAd.id, type: stageType as never, status: "QUEUED", dependencies: [], weight: 100, metadata: { retestId } as never },
      });
      const execution = await this.ensureExecution(childAd.id, stageType, slug, 1);
      await prisma.retestRequest.update({
        where: { id: retestId },
        data: { status: "RUNNING", scanId: childAd.id, startedAt: new Date() },
      });
      return {
        executionId: execution.id, scanId: childAd.id,
        canonicalFingerprint: finding.fingerprint, stageId: stageType,
        ...(adPlan.section ? { directoryAnalysisSection: adPlan.section } : {}),
      };
    }
    // Prompt 17 §89: mobile findings retest BUILD-OVER-BUILD — the
    // child scan runs the targeted static check in its original stage
    // family; the store resolves the application's LATEST build (the
    // fixed Build B) for the child scan, and judgement compares the
    // CROSS-BUILD fingerprint (§51), which deliberately excludes the
    // build hash. A failed stage is never a pass (§58 discipline).
    if (finding.mobileBuildId && finding.crossBuildFingerprint) {
      const mobilePlan = planMobileRetest({
        ...(finding.ruleId ? { ruleId: finding.ruleId } : {}),
        sourceTool: retest.sourceTool,
        ...(finding.mobileFindingType ? { mobileFindingType: finding.mobileFindingType } : {}),
      });
      const scopeParseMobile = scopeRulesSchema.safeParse(graph.assessment.scope?.rules ?? {});
      const childMobile = await prisma.scan.create({
        data: { workspaceId: finding.workspaceId, assessmentId: graph.assessmentId, requestedBy: retest.requestedBy, status: "QUEUED" },
      });
      const stagePlanMobile = {
        id: mobilePlan.stageType, type: mobilePlan.stageType, name: "Targeted Mobile Retest",
        description: "Prompt 17 §89 targeted mobile retest: re-run the original static check against the NEW build only.",
        requiredCapabilities: [], dependencies: [] as string[],
        selectedAdapters: [{ slug: mobilePlan.adapterSlug, adapterId: mobilePlan.adapterSlug, name: mobilePlan.adapterSlug, riskLevel: "LOW", preference: "REQUIRED", simulation: false, reason: mobilePlan.reason }],
        weight: 100, timeoutSeconds: 1800, failureStrategy: "FAIL_STAGE_CONTINUE", networkCapable: false, status: "QUEUED",
      };
      await prisma.scanPlan.create({
        data: {
          scanId: childMobile.id, assessmentId: graph.assessmentId, profile: "CUSTOM",
          plan: {
            scanId: childMobile.id, assessmentId: graph.assessmentId, targetId: graph.assessment.targetId,
            workspaceId: finding.workspaceId, organizationId: graph.workspace.organizationId,
            profile: "CUSTOM", targetType: graph.assessment.target.type, targetValue: graph.assessment.target.value,
            targetHost: graph.assessment.target.value, scope: scopeParseMobile.success ? scopeParseMobile.data : {},
            stages: [stagePlanMobile], dependencies: {}, selectedTools: [mobilePlan.adapterSlug],
            policySnapshot: { targetVerified: graph.assessment.target.verified, assessmentApproved: graph.assessment.status === "APPROVED", executableSlugs: [mobilePlan.adapterSlug], simulation: false },
          } as never,
          policySnapshot: { retest: true, retestId, mobileRetest: true } as never,
        },
      });
      await prisma.scanStage.create({
        data: { scanId: childMobile.id, type: mobilePlan.stageType as never, status: "QUEUED", dependencies: [], weight: 100, metadata: { retestId } as never },
      });
      const execution = await this.ensureExecution(childMobile.id, mobilePlan.stageType, mobilePlan.adapterSlug, 1);
      await prisma.retestRequest.update({
        where: { id: retestId },
        data: { status: "RUNNING", scanId: childMobile.id, startedAt: new Date() },
      });
      return {
        executionId: execution.id, scanId: childMobile.id,
        canonicalFingerprint: finding.crossBuildFingerprint, stageId: mobilePlan.stageType,
      };
    }
    // Prompt 18: binary findings retest ARTIFACT-OVER-ARTIFACT — the
    // child scan runs the targeted static check in its original
    // stage family against the target's CURRENT artifact (the fixed
    // build), and judgement compares the §57 binary fingerprint,
    // which deliberately excludes the artifact hash. A failed stage
    // is never a pass (§58 discipline).
    if (finding.binaryArtifactId && finding.binaryFingerprint) {
      const binaryPlan = planBinaryRetest({
        ...(finding.ruleId ? { ruleId: finding.ruleId } : {}),
        sourceTool: retest.sourceTool,
        ...(finding.binaryFindingType ? { binaryFindingType: finding.binaryFindingType } : {}),
      });
      const scopeParseBinary = scopeRulesSchema.safeParse(graph.assessment.scope?.rules ?? {});
      const childBinary = await prisma.scan.create({
        data: { workspaceId: finding.workspaceId, assessmentId: graph.assessmentId, requestedBy: retest.requestedBy, status: "QUEUED" },
      });
      const stagePlanBinary = {
        id: binaryPlan.stageType, type: binaryPlan.stageType, name: "Targeted Binary Retest",
        description: "Prompt 18 targeted binary retest: re-run the original static check against the NEW artifact only. The artifact is parsed, never executed.",
        requiredCapabilities: [], dependencies: [] as string[],
        selectedAdapters: [{ slug: binaryPlan.adapterSlug, adapterId: binaryPlan.adapterSlug, name: binaryPlan.adapterSlug, riskLevel: "LOW", preference: "REQUIRED", simulation: false, reason: binaryPlan.reason }],
        weight: 100, timeoutSeconds: 1800, failureStrategy: "FAIL_STAGE_CONTINUE", networkCapable: false, status: "QUEUED",
      };
      await prisma.scanPlan.create({
        data: {
          scanId: childBinary.id, assessmentId: graph.assessmentId, profile: "CUSTOM",
          plan: {
            scanId: childBinary.id, assessmentId: graph.assessmentId, targetId: graph.assessment.targetId,
            workspaceId: finding.workspaceId, organizationId: graph.workspace.organizationId,
            profile: "CUSTOM", targetType: graph.assessment.target.type, targetValue: graph.assessment.target.value,
            targetHost: graph.assessment.target.value, scope: scopeParseBinary.success ? scopeParseBinary.data : {},
            stages: [stagePlanBinary], dependencies: {}, selectedTools: [binaryPlan.adapterSlug],
            policySnapshot: { targetVerified: graph.assessment.target.verified, assessmentApproved: graph.assessment.status === "APPROVED", executableSlugs: [binaryPlan.adapterSlug], simulation: false },
          } as never,
          policySnapshot: { retest: true, retestId, binaryRetest: true } as never,
        },
      });
      await prisma.scanStage.create({
        data: { scanId: childBinary.id, type: binaryPlan.stageType as never, status: "QUEUED", dependencies: [], weight: 100, metadata: { retestId } as never },
      });
      const execution = await this.ensureExecution(childBinary.id, binaryPlan.stageType, binaryPlan.adapterSlug, 1);
      await prisma.retestRequest.update({
        where: { id: retestId },
        data: { status: "RUNNING", scanId: childBinary.id, startedAt: new Date() },
      });
      return {
        executionId: execution.id, scanId: childBinary.id,
        canonicalFingerprint: finding.binaryFingerprint, stageId: binaryPlan.stageType,
      };
    }
    // Prompt 13 §77: cloud-native findings retest in their original
    // stage kind; everything else keeps the Prompt 11 stage.
    const cloudRetest = finding.origin ? planCloudNativeRetest({ origin: finding.origin, sourceTool: retest.sourceTool, controlId: finding.controlId ?? undefined }) : null;
    const retestStage = cloudRetest?.stageType ?? "SAFE_VULNERABILITY_SCAN";
    const child = await prisma.scan.create({
      data: { workspaceId: finding.workspaceId, assessmentId: graph.assessmentId, requestedBy: retest.requestedBy, status: "QUEUED" },
    });
    const stagePlan = {
      id: retestStage, type: retestStage, name: "Targeted Retest",
      description: "Prompt 11 §56 targeted retest: re-run the original detection only.",
      requiredCapabilities: [], dependencies: [], selectedAdapters: [{
        slug: retest.sourceTool, adapterId: retest.sourceTool, name: retest.sourceTool,
        riskLevel: "MODERATE", preference: "REQUIRED", simulation: false, reason: "original detection tool (§56)",
      }],
      weight: 100, timeoutSeconds: 1800, failureStrategy: "FAIL_STAGE_CONTINUE", networkCapable: !cloudRetest, status: "QUEUED",
    };
    const scopeParse = scopeRulesSchema.safeParse(graph.assessment.scope?.rules ?? {});
    await prisma.scanPlan.create({
      data: {
        scanId: child.id, assessmentId: graph.assessmentId, profile: "CUSTOM",
        plan: {
          scanId: child.id, assessmentId: graph.assessmentId, targetId: graph.assessment.targetId,
          workspaceId: finding.workspaceId, organizationId: graph.workspace.organizationId,
          profile: "CUSTOM", targetType: graph.assessment.target.type, targetValue: graph.assessment.target.value,
          targetHost: finding.host ?? "", scope: scopeParse.success ? scopeParse.data : {},
          stages: [stagePlan], dependencies: {}, selectedTools: [retest.sourceTool],
          policySnapshot: { targetVerified: graph.assessment.target.verified, assessmentApproved: graph.assessment.status === "APPROVED", executableSlugs: [retest.sourceTool], simulation: false },
        } as never,
        policySnapshot: { retest: true, retestId } as never,
      },
    });
    await prisma.scanStage.create({
      data: { scanId: child.id, type: retestStage as never, status: "QUEUED", dependencies: [], weight: 100, metadata: { retestId } as never },
    });
    const execution = await this.ensureExecution(child.id, retestStage, retest.sourceTool, 1);
    await prisma.retestRequest.update({
      where: { id: retestId },
      data: { status: "RUNNING", scanId: child.id, startedAt: new Date() },
    });
    return { executionId: execution.id, scanId: child.id, canonicalFingerprint: plan.plan.canonicalFingerprint, stageId: retestStage };
  }

  /** Canonical fingerprints the retest scan actually produced. */
  async retestScanFingerprints(scanId: string): Promise<string[]> {
    const rows = await prisma.finding.findMany({ where: { scanId }, select: { fingerprint: true, crossBuildFingerprint: true, binaryFingerprint: true } });
    // Prompt 17 §89/§51: mobile retests compare CROSS-BUILD keys —
    // both identities are offered; other families match on fingerprint.
    // Prompt 18: binary retests compare the §57 binary fingerprint
    // (cross-artifact by construction) the same way.
    return rows.flatMap((r) => [r.fingerprint, r.crossBuildFingerprint, r.binaryFingerprint]).filter((x): x is string => !!x);
  }

  /**
   * Apply a retest outcome (§55/§58): RESOLVED closes the finding;
   * REOPENED returns it to the remediation workflow (CONFIRMED — the
   * issue demonstrably persists) with recurrence incremented; FAILED
   * leaves the finding untouched in RETEST_PENDING (a retest that could
   * not run is never a pass). Both evidence sets are preserved.
   */
  async completeRetest(retestId: string, outcome: "RESOLVED" | "REOPENED" | "FAILED", detail: string): Promise<void> {
    const retest = await prisma.retestRequest.findUnique({ where: { id: retestId } });
    if (!retest) return;
    const finding = await prisma.finding.findUnique({ where: { id: retest.findingId } });
    await prisma.retestRequest.update({
      where: { id: retestId },
      data: {
        status: outcome === "FAILED" ? "FAILED" : "COMPLETED",
        ...(outcome === "FAILED" ? {} : { result: outcome }),
        completedAt: new Date(),
        newEvidence: { detail, judgedAt: new Date().toISOString() } as never,
      },
    });
    if (!finding || outcome === "FAILED") return;
    if (outcome === "RESOLVED") {
      await prisma.finding.update({
        where: { id: finding.id },
        data: { lifecycleStatus: "RESOLVED", status: "RESOLVED", resolvedAt: new Date() },
      });
    } else {
      await prisma.finding.update({
        where: { id: finding.id },
        data: {
          lifecycleStatus: "CONFIRMED", status: "CONFIRMED", reopenedAt: new Date(),
          recurrenceCount: finding.recurrenceCount + 1, resolvedAt: null,
        },
      });
    }
    await prisma.findingHistory.create({
      data: {
        findingId: finding.id, workspaceId: finding.workspaceId,
        event: outcome === "RESOLVED" ? "RESOLVED" : "REOPENED",
        metadata: { retestId, via: "targeted-retest", detail } as never,
      },
    });
    await prisma.auditLog.create({
      data: {
        actorId: retest.requestedBy, organizationId: undefined, workspaceId: finding.workspaceId,
        action: "RETEST_COMPLETED" as never, resourceType: "VULNERABILITY", resourceId: finding.id,
        metadata: { retestId, outcome } as never,
      },
    });
  }

  // ---------- Prompt 16: controlled validation store (§12/§13) ----------
  // The runner re-checks everything against this trusted state; queue
  // payloads carry only the request id (§14 pattern from Prompt 4).

  async prepareValidationExecution(requestId: string, workerId: string) {
    const request = await prisma.validationRequest.findUnique({
      where: { id: requestId },
      include: {
        finding: true,
        approvals: { where: { decision: "APPROVED" }, orderBy: { createdAt: "desc" }, take: 1 },
      },
    });
    if (!request || request.status !== "APPROVED") return null;
    if (request.expiresAt && request.expiresAt.getTime() <= Date.now()) {
      await prisma.validationRequest.update({ where: { id: requestId }, data: { status: "EXPIRED" } });
      return null;
    }
    const finding = request.finding;
    const target = await prisma.target.findUnique({ where: { id: request.targetId } });
    const scan = await prisma.scan.findUnique({ where: { id: finding.scanId }, include: { assessment: true } });
    const workspace = await prisma.workspace.findUnique({ where: { id: request.workspaceId } });
    const asset = finding.assetId ? await prisma.asset.findUnique({ where: { id: finding.assetId } }) : null;
    const policyRow = await prisma.validationPolicy.findUnique({ where: { workspaceId: request.workspaceId } });
    const snapshot = (request.authorizationSnapshot ?? {}) as { authorizationExpiresAt?: string };
    const plan = request.plan as unknown as import("@dsrclone/security-sdk").ValidationPlan;
    const session = await prisma.validationSession.create({
      data: {
        requestId, workspaceId: request.workspaceId, workerId, validatorSlug: request.validatorSlug,
        toolSlug: request.toolSlug, status: "RUNNING", startedAt: new Date(), budget: request.budget as never,
      },
    });
    await prisma.validationRequest.update({ where: { id: requestId }, data: { status: "RUNNING" } });
    await prisma.auditLog.create({
      data: {
        actorId: request.requestedBy, organizationId: workspace?.organizationId, workspaceId: request.workspaceId,
        action: "VALIDATION_STARTED" as never, resourceType: "ValidationRequest", resourceId: requestId,
        metadata: { sessionId: session.id, validator: request.validatorSlug, riskClass: request.riskClass } as never,
      },
    });
    const approval = request.approvals[0];
    return {
      requestId, sessionId: session.id, workspaceId: request.workspaceId,
      ...(workspace?.organizationId ? { organizationId: workspace.organizationId } : {}),
      findingId: finding.id,
      finding: {
        id: finding.id, title: finding.title, fingerprint: finding.fingerprint, vulnClass: finding.vulnClass,
        cwe: finding.cwe, cve: finding.cve, host: finding.host, port: finding.port, endpoint: finding.endpoint,
        sources: finding.sources, assetCriticality: asset?.criticality ?? null,
        repositoryId: finding.repositoryId, filePath: finding.filePath, ruleId: finding.ruleId,
        componentPurl: finding.componentPurl, imageDigest: finding.imageDigest, clusterRef: finding.clusterRef,
        cloudProvider: finding.cloudProvider, cloudResourceId: finding.cloudResourceId,
        directoryDomainId: finding.directoryDomainId, directoryObjectId: finding.directoryObjectId,
      },
      targetId: request.targetId, scanId: finding.scanId,
      validatorSlug: request.validatorSlug, riskClass: request.riskClass as never,
      plan, planHash: request.planHash,
      parameters: (request.parameters ?? {}) as Record<string, string | number | boolean>,
      requestedBy: request.requestedBy,
      environment: (request.environment === "LAB" ? "LAB" : "PRODUCTION") as "PRODUCTION" | "LAB",
      policy: {
        productionPolicy: (policyRow?.productionPolicy === "SAFE_AND_LOW_IMPACT_WITH_APPROVAL" ? "SAFE_AND_LOW_IMPACT_WITH_APPROVAL" : "SAFE_ONLY") as "SAFE_ONLY" | "SAFE_AND_LOW_IMPACT_WITH_APPROVAL",
        separationOfDuties: policyRow?.separationOfDuties ?? true,
        allowIntrusiveInLab: policyRow?.allowIntrusiveInLab ?? false,
        allowedValidators: policyRow?.allowedValidators ?? [],
      },
      ...(asset?.criticality ? { assetCriticality: asset.criticality } : {}),
      authorization: {
        // Live state wins over the snapshot (§8): a target unverified or
        // an assessment un-approved since the request voids execution.
        targetVerified: Boolean(target?.verified),
        assessmentApproved: scan?.assessment?.status === "APPROVED",
        ...(snapshot.authorizationExpiresAt ? { expiresAt: snapshot.authorizationExpiresAt } : {}),
      },
      scopeRules: scopeRulesSchema.parse(request.scopeSnapshot ?? {}),
      approval: approval
        ? {
            approverId: approval.approverId, decision: approval.decision, planHash: approval.planHash,
            targetId: request.targetId, findingId: request.findingId, validatorSlug: request.validatorSlug,
            expiresAt: approval.expiresAt.toISOString(),
          }
        : null,
    };
  }

  async activeKillSwitches(_ctx: import("@dsrclone/security-sdk").KillSwitchContext) {
    const rows = await prisma.validationKillSwitch.findMany({ where: { active: true } });
    return rows.map((r) => ({
      level: r.level, organizationId: r.organizationId, workspaceId: r.workspaceId, scopeRef: r.scopeRef, active: r.active,
    }));
  }

  async recordValidationEvidence(sessionId: string, evidence: import("@dsrclone/security-sdk").SanitizedEvidence[]): Promise<void> {
    const session = await prisma.validationSession.findUnique({ where: { id: sessionId }, include: { request: true } });
    if (!session) return;
    for (const e of evidence) {
      await prisma.validationEvidence.create({
        data: {
          requestId: session.requestId, sessionId, workspaceId: session.workspaceId,
          findingId: session.request.findingId, type: e.type as never, summary: e.summary,
          content: (e.content ?? undefined) as never, checksum: e.checksum, sourceTool: e.sourceTool,
        },
      });
    }
  }

  async completeValidation(sessionId: string, outcome: import("@dsrclone/security-sdk").ValidationOutcome, detail: string, consumption: import("@dsrclone/security-sdk").BudgetConsumption): Promise<void> {
    const session = await prisma.validationSession.findUnique({ where: { id: sessionId }, include: { request: { include: { finding: true } } } });
    if (!session) return;
    const requestStatus = outcome === "REPRODUCED" || outcome === "FIXED" ? "SUCCEEDED" : outcome === "VALIDATION_BLOCKED" ? "BLOCKED" : "INCONCLUSIVE";
    await prisma.validationSession.update({
      where: { id: sessionId },
      data: { status: requestStatus, endedAt: new Date(), budgetConsumed: consumption as never, terminationReason: detail },
    });
    await prisma.validationRequest.update({
      where: { id: session.requestId },
      data: { status: requestStatus as never, outcome },
    });
    const update = confidenceUpdateForOutcome(outcome);
    await prisma.finding.update({
      where: { id: session.request.findingId },
      data: {
        validationConfidence: update.validationConfidence,
        ...(update.verificationStatus ? { verificationStatus: update.verificationStatus } : {}),
        lastValidatedAt: new Date(update.lastValidatedAt),
      },
    });
    await prisma.findingHistory.create({
      data: {
        findingId: session.request.findingId, workspaceId: session.workspaceId, event: "VALIDATED",
        metadata: { validationRequestId: session.requestId, sessionId, outcome, detail, note: update.note } as never,
      },
    });
    await prisma.auditLog.create({
      data: {
        actorId: session.request.requestedBy, workspaceId: session.workspaceId,
        action: "VALIDATION_COMPLETED" as never, resourceType: "ValidationRequest", resourceId: session.requestId,
        metadata: { sessionId, outcome, validator: session.validatorSlug } as never,
      },
    });
  }

  async blockValidation(sessionId: string, reasonCode: string, message: string): Promise<void> {
    const session = await prisma.validationSession.findUnique({ where: { id: sessionId }, include: { request: true } });
    if (!session) return;
    await prisma.validationSession.update({
      where: { id: sessionId },
      data: { status: "BLOCKED", endedAt: new Date(), terminationReason: `${reasonCode}: ${message}` },
    });
    await prisma.validationRequest.update({
      where: { id: session.requestId },
      data: { status: "BLOCKED", outcome: "VALIDATION_BLOCKED", policyReason: `${reasonCode}: ${message}` },
    });
    await prisma.auditLog.create({
      data: {
        actorId: session.request.requestedBy, workspaceId: session.workspaceId,
        action: "VALIDATION_BLOCKED" as never, resourceType: "ValidationRequest", resourceId: session.requestId,
        metadata: { sessionId, reasonCode, message } as never,
      },
    });
  }

  async cancelValidation(sessionId: string, reason: string): Promise<void> {
    const session = await prisma.validationSession.findUnique({ where: { id: sessionId }, include: { request: true } });
    if (!session) return;
    await prisma.validationSession.update({
      where: { id: sessionId },
      data: { status: "CANCELLED", endedAt: new Date(), terminationReason: reason },
    });
    await prisma.validationRequest.update({ where: { id: session.requestId }, data: { status: "CANCELLED" } });
    await prisma.auditLog.create({
      data: {
        actorId: session.request.requestedBy, workspaceId: session.workspaceId,
        action: "VALIDATION_CANCELLED" as never, resourceType: "ValidationRequest", resourceId: session.requestId,
        metadata: { sessionId, reason, via: "kill-switch" } as never,
      },
    });
  }

  async failValidation(sessionId: string, terminationReason: string, message: string): Promise<void> {
    const session = await prisma.validationSession.findUnique({ where: { id: sessionId }, include: { request: true } });
    if (!session) return;
    await prisma.validationSession.update({
      where: { id: sessionId },
      data: { status: "FAILED", endedAt: new Date(), terminationReason: `${terminationReason}: ${message}` },
    });
    await prisma.validationRequest.update({
      where: { id: session.requestId },
      data: { status: "FAILED", outcome: "INCONCLUSIVE" },
    });
    await prisma.auditLog.create({
      data: {
        actorId: session.request.requestedBy, workspaceId: session.workspaceId,
        action: "VALIDATION_COMPLETED" as never, resourceType: "ValidationRequest", resourceId: session.requestId,
        metadata: { sessionId, result: "FAILED", terminationReason, message } as never,
      },
    });
  }

  async resolveHost(host: string): Promise<string[]> {
    const { lookup } = await import("node:dns/promises");
    const records = await lookup(host, { all: true });
    return records.map((r) => r.address);
  }

  // ---------- Prompt 9 platform-stage hooks ----------

  /** API_DISCOVERY hook (§5): counts of the consolidated API inventory
   *  for this scan's target. */
  async consolidateApiServices(scanId: string): Promise<{ services: number; endpoints: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph) return null;
    const assets = await prisma.asset.findMany({ where: { targetId: graph.assessment.targetId }, select: { id: true } });
    if (assets.length === 0) return null;
    const ids = assets.map((a) => a.id);
    const [services, endpoints] = await Promise.all([
      prisma.apiService.count({ where: { assetId: { in: ids } } }),
      prisma.endpoint.count({ where: { assetId: { in: ids } } }),
    ]);
    if (services === 0 && endpoints === 0) return null;
    return { services, endpoints };
  }

  /** SPEC_IMPORT hook (§6): what the guarded import store holds for
   *  this target. */
  async summarizeApiSpecifications(scanId: string): Promise<{ specifications: number; operations: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph) return null;
    const specs = await prisma.apiSpecification.findMany({
      where: { targetId: graph.assessment.targetId },
      select: { operationCount: true },
    });
    if (specs.length === 0) return null;
    return { specifications: specs.length, operations: specs.reduce((n, s) => n + (s.operationCount ?? 0), 0) };
  }

  /** AUTH_MAPPING hook (§19–§21): registered contexts + services with a
   *  declared authentication type. References only — no secret is
   *  resolved or used here. */
  async mapApiAuthentication(scanId: string): Promise<{ contexts: number; servicesWithAuth: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph) return null;
    const assets = await prisma.asset.findMany({ where: { targetId: graph.assessment.targetId }, select: { id: true } });
    const [contexts, servicesWithAuth] = await Promise.all([
      prisma.apiAuthContext.count({ where: { workspaceId: graph.workspaceId } }),
      assets.length === 0 ? Promise.resolve(0) : prisma.apiService.count({
        where: { assetId: { in: assets.map((a) => a.id) }, authenticationType: { notIn: ["NONE"] }, NOT: { authenticationType: null } },
      }),
    ]);
    if (contexts === 0 && servicesWithAuth === 0) return null;
    return { contexts, servicesWithAuth };
  }

  /** JWT_ANALYSIS hook (§22–§25): resolve the workspace's registered
   *  credential REFERENCES (API auth contexts + session profiles) inside
   *  this trusted boundary; values that parse as JWTs are inspected.
   *  Only fingerprints + redacted metadata persist — the token itself is
   *  dropped when this function returns. Findings flow into the scan's
   *  finding set ahead of NORMALIZATION/CORRELATION. */
  async analyzeJwtProfiles(scanId: string): Promise<{ tokens: number; findings: number } | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph) return null;
    const budget = clampDiscoveryBudget();
    const [contexts, sessions] = await Promise.all([
      prisma.apiAuthContext.findMany({ where: { workspaceId: graph.workspaceId }, select: { credentialReference: true } }),
      prisma.sessionProfile.findMany({ where: { workspaceId: graph.workspaceId }, select: { credentialReference: true } }),
    ]);
    const references = [...new Set([...contexts, ...sessions].map((r) => r.credentialReference).filter((v): v is string => !!v))];
    if (references.length === 0) return null;
    const resolver = new EnvSecretResolver();
    const tokens: string[] = [];
    for (const reference of references) {
      if (tokens.length >= budget.maxJwtTokensAnalyzed) break;
      const value = await resolver.resolve(reference).catch(() => undefined);
      // A resolved value is a candidate ONLY when it is JWT-shaped; any
      // other secret (passwords, API keys) is never inspected or stored.
      if (value && value.split(".").length === 3) tokens.push(value);
    }
    if (tokens.length === 0) return null;
    const adapter = new JwtToolAdapter();
    const parsed = adapter.inspectTokens({ tokens, host: hostOf(graph.assessment.target.value) });
    const normalized = await adapter.normalize(parsed);
    // Persist profiles (deduped per scan+fingerprint).
    for (const p of normalized.jwtProfiles ?? []) {
      const existing = await prisma.jwtProfile.findFirst({ where: { scanId, fingerprint: p.fingerprint } });
      if (existing) continue;
      await prisma.jwtProfile.create({
        data: {
          workspaceId: graph.workspaceId, scanId, targetId: graph.assessment.targetId,
          fingerprint: p.fingerprint, algorithm: p.algorithm, tokenType: p.tokenType, keyId: p.keyId,
          issuer: p.issuer, audience: p.audience ?? [], source: p.source, host: p.host, endpoint: p.endpoint,
          lifetimeSeconds: p.lifetimeSeconds, claimsSummary: p.claimsSummary as never,
          ...(p.expiresAt ? { expiresAt: new Date(p.expiresAt) } : {}),
          ...(p.notBefore ? { notBefore: new Date(p.notBefore) } : {}),
          ...(p.issuedAt ? { issuedAt: new Date(p.issuedAt) } : {}),
        },
      });
    }
    // Persist findings through the same normalized shape the tool
    // stages produce (fingerprint + evidence + history), ahead of the
    // NORMALIZATION stage. toolExecutionId stays null: platform stage.
    let findings = 0;
    for (const f of normalized.findings) {
      const v = f as typeof f & { vulnClass?: string; evidenceDetail?: { checkId?: string; metadata?: Record<string, string> } };
      const asset = f.host ? await prisma.asset.findFirst({ where: { targetId: graph.assessment.targetId, host: f.host } }) : null;
      await prisma.finding.create({
        data: {
          workspaceId: graph.workspaceId, scanId, assetId: asset?.id,
          title: f.title, description: f.description, severity: f.severity as never, confidence: f.confidence,
          host: f.host, endpoint: f.endpoint, fingerprint: f.sourceFingerprint, isMock: false,
          toolExecutionId: null, status: "OPEN", verificationStatus: "UNVERIFIED",
          vulnClass: v.vulnClass, sources: [f.sourceTool], cwe: f.cwe, owaspCategory: f.owaspCategory,
          remediation: f.remediation,
          evidence: {
            create: [{
              sourceTool: f.sourceTool, evidenceType: "TEXT", summary: f.evidence ?? "",
              fingerprint: f.sourceFingerprint, metadata: (v.evidenceDetail?.metadata ?? undefined) as never,
            }],
          },
          history: { create: { workspaceId: graph.workspaceId, event: "CREATED", metadata: { sourceTool: f.sourceTool, stage: "JWT_ANALYSIS" } as never } },
        },
      });
      findings++;
    }
    return { tokens: (normalized.jwtProfiles ?? []).length, findings };
  }

  /** WEBSOCKET_INVENTORY hook (§31/§32): counts from this scan's
   *  persisted WebSocket inventory. */
  async inventoryWebSockets(scanId: string): Promise<{ webSockets: number; authenticated: number } | null> {
    const rows = await prisma.webSocketEndpoint.findMany({ where: { scanId }, select: { authPresent: true } });
    if (rows.length === 0) return null;
    return { webSockets: rows.length, authenticated: rows.filter((r) => r.authPresent).length };
  }

  async recordDeadLetter(entry: { jobId: string; queue: string; scanId: string; stageId: string; executionId: string; errorCategory: string; errorMessage: string; attempts: number }): Promise<void> {
    await prisma.deadLetterJob.create({ data: entry });
  }

  async isCancelled(scanId: string): Promise<boolean> {
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, select: { status: true } });
    return scan?.status === "CANCELLED" || scan?.status === "CANCELLING";
  }

  async isPaused(scanId: string): Promise<boolean> {
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, select: { status: true } });
    return scan?.status === "PAUSED" || scan?.status === "PAUSING";
  }

  // ---------- ScanRunStore ----------
  async loadScanRun(scanId: string): Promise<ScanRunRecord | null> {
    const graph = await loadScanGraph(scanId);
    if (!graph?.plan || !graph.assessment) return null;
    const scopeParse = scopeRulesSchema.safeParse(graph.assessment.scope?.rules ?? {});
    const target = graph.assessment.target;
    return {
      plan: graph.plan.plan as unknown as ScanPlan,
      scanStatus: graph.status,
      progress: graph.progress,
      gate: {
        auth: {
          organizationId: graph.workspace.organizationId,
          workspaceId: graph.workspaceId,
          targetId: target.id,
          targetOrganizationId: graph.workspace.organizationId,
          assessmentId: graph.assessmentId,
          scanId,
          verificationStatus: target.verified ? "VERIFIED" : "PENDING",
          approvalStatus: graph.assessment.status === "APPROVED" ? "APPROVED" : "PENDING",
          requestedBy: graph.requestedBy,
        },
        targetHost: hostOf(target.value),
        scopeRules: scopeParse.success ? scopeParse.data : { includeHosts: [], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
        targetExists: true,
        targetWorkspaceId: graph.workspaceId,
        workspaceId: graph.workspaceId,
        targetVerified: target.verified,
        assessmentApproved: graph.assessment.status === "APPROVED",
        scopeValid: scopeParse.success,
      },
    };
  }

  async stageStatuses(scanId: string): Promise<Map<string, string>> {
    const stages = await prisma.scanStage.findMany({ where: { scanId } });
    return new Map(stages.map((s) => [s.type as string, s.status as string]));
  }

  async updateScan(scanId: string, patch: Record<string, unknown>): Promise<void> {
    await prisma.scan.update({ where: { id: scanId }, data: patch as never });
  }

  async updateStage(scanId: string, stageType: string, patch: Record<string, unknown>): Promise<void> {
    await prisma.scanStage.updateMany({ where: { scanId, type: stageType as never }, data: patch as never });
  }

  async ensureExecution(scanId: string, stageType: string, adapterSlug: string, attempt: number): Promise<{ id: string; status: string }> {
    // Slug-scoped key (Prompt 5): multi-adapter stages get one execution
    // per adapter instead of colliding on the stage-only key.
    const key = idempotencyKey(scanId, stageType, attempt, adapterSlug);
    const existing = await prisma.toolExecution.findUnique({ where: { idempotencyKey: key } });
    if (existing) return { id: existing.id, status: existing.status };
    const tool = await prisma.tool.findUnique({ where: { slug: adapterSlug } });
    if (!tool) throw new Error(`Tool catalog row missing for adapter ${adapterSlug}`);
    const adapter = await prisma.toolAdapter.findFirst({ where: { toolId: tool.id }, orderBy: { createdAt: "asc" } });
    const stage = await prisma.scanStage.findFirst({ where: { scanId, type: stageType as never } });
    const created = await prisma.toolExecution.create({
      data: {
        scanId, scanStageId: stage?.id, toolId: tool.id, toolAdapterId: adapter?.id,
        idempotencyKey: key, attempt, status: "QUEUED",
      },
    });
    return { id: created.id, status: created.status };
  }

  async markReportPending(scanId: string): Promise<void> {
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, select: { workspaceId: true, requestedBy: true } });
    if (!scan) return;
    const existing = await prisma.report.findFirst({ where: { scanId, status: "PENDING" } });
    if (!existing) {
      await prisma.report.create({
        data: { workspaceId: scan.workspaceId, scanId, format: "PDF", status: "PENDING", generatedBy: scan.requestedBy },
      });
    }
  }
}
