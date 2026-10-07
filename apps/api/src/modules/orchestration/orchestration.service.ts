import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  API_SLUGS, CODE_SLUGS, INERT_CONNECTOR_DEPS, INERT_KUBERNETES_DEPS, LocalEchoAdapter, MockSecurityAdapter, NETWORK_SLUGS, PROXY_SLUGS, RECON_SLUGS, ToolRegistry, VULN_SCANNER_SLUGS, VULN_SLUGS, WEB_DISCOVERY_SLUGS,
  apiHealthBySlug, binaryHealthRecord, cloudNativeHealthBySlug, cloudSecHealthBySlug, codeHealthBySlug, directoryHealthRecord, mobileHealthBySlug, networkHealthBySlug, proxyHealthBySlug, reconHealthBySlug, registerApiAdapters, registerBinaryAdapters, registerCloudNativeAdapters, registerCloudSecAdapters, registerCodeAdapters, registerDirectoryAdapters, registerMobileAdapters, registerNetworkAdapters, registerProxyAdapters, registerReconAdapters, registerVulnAdapters, registerWebDiscoveryAdapters, vulnHealthBySlug,
  type ScannerInstanceRecord,
} from "@dsrclone/security-sdk";
import { scopeRulesSchema, type ScopeRules } from "@dsrclone/validation";
import { assertScanTransition, type ScanStatus } from "@dsrclone/types";
import {
  buildScanPlan, evaluateAuthorizationGate, makeEvent, type ScanPlan,
} from "@dsrclone/orchestration";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";
import { QueueService } from "../../queue/queue.service";
import { ScanEventsService } from "./scan-events.service";

/** Executable adapters: the simulation pair plus the Prompt 5 recon
 *  adapters. Real adapters are selected only when their health probe passes
 *  on this host; otherwise the stage falls back to the labelled simulation
 *  adapter (Prompt 5 §39/§56) — never to a fake "real" run. */
export const EXECUTABLE_SLUGS = ["mock", "local-echo", ...RECON_SLUGS, ...WEB_DISCOVERY_SLUGS, ...VULN_SLUGS, ...PROXY_SLUGS, ...API_SLUGS, ...NETWORK_SLUGS, ...VULN_SCANNER_SLUGS, ...CODE_SLUGS];

export function hostOf(value: string): string {
  try {
    if (value.includes("://")) return new URL(value).hostname;
  } catch { /* fall through */ }
  return value.split("/")[0]!.split(":")[0]!.toLowerCase();
}

interface LoadedAssessment {
  assessment: {
    id: string; workspaceId: string; profile: string; status: string; scopeId: string | null;
    target: { id: string; type: string; value: string; verified: boolean };
    scope: { rules: unknown } | null;
  };
  workspaceId: string;
  scopeRules: ScopeRules;
  scopeValid: boolean;
}

/**
 * Orchestration service (Prompt 4 §2–§4, §46–§47): turns an authorized
 * assessment into an immutable ScanPlan + persisted Scan, then queues the
 * scan-orchestration job. The API NEVER executes tools and NEVER accepts
 * tool commands from clients — request bodies carry no adapter input at all.
 */
@Injectable()
export class OrchestrationService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly queue: QueueService,
    private readonly events: ScanEventsService,
  ) {}

  private registryCache: { registry: ToolRegistry; healthBySlug: Record<string, string> } | undefined;

  private registry(): ToolRegistry {
    if (!this.registryCache) {
      const registry = new ToolRegistry();
      registry.register(new MockSecurityAdapter());
      registry.register(new LocalEchoAdapter());
      registerReconAdapters(registry);
      registerWebDiscoveryAdapters(registry);
      registerVulnAdapters(registry);
      // Prompt 8: proxy connectors register with an EMPTY instance
      // snapshot on purpose — plan-time health for them is derived from
      // the caller's registered ScannerInstance rows (scannerHealth
      // below), never from a process-global guess (§53/§66).
      registerProxyAdapters(registry);
      // Prompt 9: API adapters (Kiterunner / Schemathesis / InQL /
      // GraphQLmap + jwt_tool inspection) join plan-time selection.
      registerApiAdapters(registry);
      // Prompt 10: network adapters (Nmap / Naabu / RustScan / Masscan /
      // Netdiscover / arp-scan / tcpdump / tshark) join plan-time
      // selection for the network profiles.
      registerNetworkAdapters(registry);
      // Prompt 12: source code security adapters (Semgrep / CodeQL /
      // Bandit / Brakeman / SpotBugs / Gitleaks / TruffleHog /
      // Dependency-Check / Grype + the SonarQube connector with inert
      // deps) join plan-time selection for the source profiles.
      registerCodeAdapters(registry, undefined, INERT_CONNECTOR_DEPS);
      // Prompt 13: cloud-native adapters (Trivy / Syft / Checkov /
      // Kubescape / kube-hunter + INTERNAL_PRIVILEGED Docker Bench /
      // kube-bench) and the Kubernetes connector with inert deps join
      // plan-time selection; connector health derives from the
      // workspace's registered clusters (kubernetesHealth below).
      registerCloudNativeAdapters(registry, undefined, INERT_KUBERNETES_DEPS);
      // Prompt 14: cloud-security adapters (provider inventory
      // connectors with inert deps / Prowler / ScoutSuite / Steampipe /
      // CloudMapper / ROADtools imports) join plan-time selection for
      // the cloud profiles. Connectors report NOT_CONFIGURED at plan
      // time — per-account configuration resolves in the worker (§9).
      // Pacu has NO adapter (§34): its health is a governed DISABLED
      // constant in cloudSecHealthBySlug, never a probe.
      registerCloudSecAdapters(registry);
      // Prompt 15: directory adapters (connectors with inert deps /
      // governed AD CLI tools) join plan-time selection for the AD
      // profiles. Connectors report NOT_CONFIGURED at plan time —
      // per-domain configuration resolves in the DIRECTORY_ANALYSIS
      // worker (§15). Offensive tools have NO adapter (§51–§56):
      // their health is a governed DISABLED constant in
      // directoryHealthRecord, never a probe.
      registerDirectoryAdapters(registry);
      // Prompt 17: mobile adapters (MobSF connector / JADX / apktool /
      // Ghidra + the controlled-lab ADB / mitmproxy adapters) join
      // plan-time selection for the mobile profiles. Connectors and
      // lab adapters report NOT_CONFIGURED at plan time — instance /
      // session configuration resolves in the mobile workers (§14/
      // §58). Frida/Objection have NO adapter (§69–§74): their health
      // is a governed DISABLED / APPROVAL_REQUIRED constant in
      // mobileHealthBySlug, never a probe.
      // Prompt 18: binary adapters (checksec / radare2 / the extended
      // dual-mode Ghidra) join plan-time selection for the binary
      // profiles. Registered BEFORE the mobile family so the extended
      // Ghidra owns the shared slug — the mobile registration skips
      // it, and mobile plans keep working because the dual-mode
      // adapter delegates mobile configurations unchanged (§18).
      // IDA/Binary Ninja are connectors (§96) and GDB/pwndbg/Cutter
      // are governed descriptors: their health is a governed constant
      // in binaryHealthRecord, never a probe.
      registerBinaryAdapters(registry);
      registerMobileAdapters(registry);
      // Plan-time health (§39): synchronous PATH probe of this host. The
      // worker re-checks availability at execution time on ITS host.
      this.registryCache = { registry, healthBySlug: { ...reconHealthBySlug(registry.list()), ...vulnHealthBySlug(registry.list()), ...apiHealthBySlug(registry.list()), ...networkHealthBySlug(registry.list()), ...codeHealthBySlug(registry.list()), ...cloudNativeHealthBySlug(registry.list()), ...cloudSecHealthBySlug(registry.list()), ...directoryHealthRecord(registry.list()), ...mobileHealthBySlug(registry.list()), ...binaryHealthRecord(registry.list()) } };
    }
    return this.registryCache.registry;
  }

  private healthBySlug(): Record<string, string> {
    this.registry();
    return this.registryCache!.healthBySlug;
  }

  /** Prompt 8 plan-time connector health (§53/§66): the workspace's (and
   *  org-wide) registered scanner instances decide — no rows means
   *  NOT_CONFIGURED for every product and the passive stage plans with an
   *  empty selection instead of a simulated scanner. */
  private async scannerHealth(workspaceId: string, organizationId: string): Promise<Record<string, string>> {
    const rows = await this.prisma.scannerInstance.findMany({
      where: { organizationId, OR: [{ workspaceId }, { workspaceId: null }] },
      include: { tool: { select: { slug: true } } },
      orderBy: { createdAt: "asc" },
    });
    const records = (rows as unknown as Array<Record<string, unknown>>).map((r) => ({
      toolSlug: (r.tool as { slug: string }).slug,
      enabled: r.enabled as boolean,
      healthStatus: r.healthStatus as string,
    }));
    return proxyHealthBySlug(records as unknown as ScannerInstanceRecord[]);
  }

  /** Prompt 13 plan-time Kubernetes connector health (§34/§93): the
   *  connector is selectable exactly when the workspace has at least
   *  one registered cluster connection — otherwise NOT_CONFIGURED and
   *  the inventory stage plans empty instead of simulated. */
  private async kubernetesHealth(workspaceId: string): Promise<Record<string, string>> {
    const delegate = (this.prisma as unknown as { kubernetesCluster?: { count: (args: unknown) => Promise<number> } }).kubernetesCluster;
    const count = delegate ? await delegate.count({ where: { workspaceId } }).catch(() => 0) : 0;
    return { "kubernetes-connector": count > 0 ? "HEALTHY" : "NOT_CONFIGURED" };
  }

  private async load(user: RequestUser, assessmentId: string): Promise<LoadedAssessment> {
    const workspace = await resolveWorkspace(this.prisma, user);
    const assessment = await this.prisma.assessment.findFirst({
      where: { id: assessmentId, workspaceId: workspace.id },
      include: { target: true, scope: true },
    });
    if (!assessment) throw new NotFoundException("Assessment not found");
    const scopeParse = scopeRulesSchema.safeParse(assessment.scope?.rules ?? {});
    return {
      assessment: assessment as unknown as LoadedAssessment["assessment"],
      workspaceId: workspace.id,
      scopeRules: scopeParse.success ? scopeParse.data : { includeHosts: [], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
      scopeValid: scopeParse.success,
    };
  }

  private async buildPlan(loaded: LoadedAssessment, scanId: string, user: RequestUser): Promise<ScanPlan> {
    const { assessment } = loaded;
    const target = assessment.target;
    const scannerHealth = await this.scannerHealth(loaded.workspaceId, user.organizationId);
    const kubernetesHealth = await this.kubernetesHealth(loaded.workspaceId);
    const { plan } = buildScanPlan({
      scanId,
      assessmentId: assessment.id,
      targetId: target.id,
      workspaceId: loaded.workspaceId,
      organizationId: user.organizationId,
      profile: assessment.profile as never,
      targetType: target.type as never,
      targetValue: target.value,
      targetHost: hostOf(target.value),
      scope: loaded.scopeRules,
      targetVerified: target.verified,
      assessmentApproved: assessment.status === "APPROVED",
      registry: this.registry(),
      selection: { executableSlugs: EXECUTABLE_SLUGS, healthBySlug: { ...this.healthBySlug(), ...scannerHealth, ...kubernetesHealth } },
    });
    return plan;
  }

  /** PLAN PREVIEW (§46): builds and returns the plan. Persists NOTHING and
   *  executes NOTHING. */
  async previewPlan(user: RequestUser, assessmentId: string) {
    const loaded = await this.load(user, assessmentId);
    const plan = await this.buildPlan(loaded, "preview", user);
    return {
      profile: plan.profile,
      targetType: plan.targetType,
      stages: plan.stages.map((s) => ({
        type: s.type, name: s.name, dependencies: s.dependencies,
        requiredCapabilities: s.requiredCapabilities,
        selectedAdapters: s.selectedAdapters,
        riskLevels: [...new Set(s.selectedAdapters.map((a) => a.riskLevel))],
        approvalRequired: s.selectedAdapters.some((a) => a.riskLevel === "INTRUSIVE" || a.riskLevel === "RESTRICTED"),
        timeoutSeconds: s.timeoutSeconds, weight: s.weight, networkCapable: s.networkCapable,
      })),
      dependencies: plan.dependencies,
      capabilities: [...new Set(plan.stages.flatMap((s) => s.requiredCapabilities))],
      selectedTools: plan.selectedTools,
      simulation: plan.policySnapshot.simulation,
      estimatedLimits: { maxConcurrency: 4, stageTimeoutSeconds: Math.max(...plan.stages.map((s) => s.timeoutSeconds)) },
      executesScan: false,
    };
  }

  /** START SCAN (§47): authorize → verify → gate → plan → persist → queue. */
  async startScan(user: RequestUser, assessmentId: string) {
    const loaded = await this.load(user, assessmentId);
    const { assessment } = loaded;
    const target = assessment.target;

    const gate = evaluateAuthorizationGate({
      auth: {
        organizationId: user.organizationId, workspaceId: loaded.workspaceId, targetId: target.id,
        targetOrganizationId: user.organizationId, assessmentId: assessment.id, scanId: "pending",
        verificationStatus: target.verified ? "VERIFIED" : "PENDING",
        approvalStatus: assessment.status === "APPROVED" ? "APPROVED" : "PENDING",
        requestedBy: user.id,
      },
      targetHost: hostOf(target.value),
      scopeRules: loaded.scopeRules,
      targetExists: true,
      targetWorkspaceId: loaded.workspaceId,
      workspaceId: loaded.workspaceId,
      targetVerified: target.verified,
      assessmentApproved: assessment.status === "APPROVED",
      scopeValid: loaded.scopeValid,
    });
    if (!gate.allowed) {
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId: loaded.workspaceId,
        action: gate.reasonCode === "TARGET_OUT_OF_SCOPE" ? "SCOPE_VIOLATION" : "POLICY_DENIED",
        resourceType: "Assessment", resourceId: assessment.id,
        metadata: { reasonCode: gate.reasonCode },
      });
      throw new BadRequestException(`Scan refused: ${gate.message} (${gate.reasonCode})`);
    }

    const scan = await this.prisma.scan.create({
      data: { workspaceId: loaded.workspaceId, assessmentId: assessment.id, status: "CREATED", requestedBy: user.id },
    });
    const plan = await this.buildPlan(loaded, scan.id, user);
    await this.prisma.scanPlan.create({
      data: { scanId: scan.id, assessmentId: assessment.id, profile: assessment.profile as never, planVersion: plan.planVersion, plan: plan as never, policySnapshot: plan.policySnapshot as never },
    });
    await this.prisma.scanStage.createMany({
      data: plan.stages.map((s) => ({
        scanId: scan.id, type: s.type as never,
        status: (s.dependencies.length === 0 ? "READY" : "BLOCKED") as never,
        dependencies: s.dependencies, weight: s.weight,
        metadata: { selectedAdapters: s.selectedAdapters, failureStrategy: s.failureStrategy } as never,
      })),
    });
    await this.prisma.scan.update({ where: { id: scan.id }, data: { status: "QUEUED" } });
    await this.events.record(makeEvent(scan.id, loaded.workspaceId, "scan.created", { profile: plan.profile }));
    await this.events.record(makeEvent(scan.id, loaded.workspaceId, "scan.queued", { simulation: plan.policySnapshot.simulation }));
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: loaded.workspaceId, action: "SCAN_PLANNED", resourceType: "Scan", resourceId: scan.id });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: loaded.workspaceId, action: "SCAN_REQUESTED", resourceType: "Scan", resourceId: scan.id });
    // Prompt 10 §85: network-profile scans carry the network audit
    // actions too (request + scope validation) — counts/ids only.
    if (plan.profile.startsWith("NETWORK_")) {
      await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: loaded.workspaceId, action: "NETWORK_SCAN_REQUESTED", resourceType: "Scan", resourceId: scan.id, metadata: { profile: plan.profile } });
      await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: loaded.workspaceId, action: "NETWORK_SCOPE_VALIDATED", resourceType: "Scan", resourceId: scan.id });
      if (plan.profile === "NETWORK_INTERNAL") {
        await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: loaded.workspaceId, action: "INTERNAL_SCAN_APPROVED", resourceType: "Scan", resourceId: scan.id, metadata: { basis: "assessment approval + verified target (internal engagement)" } });
      }
    }
    const enqueued = await this.queue.enqueueScanOrchestration({ scanId: scan.id, workspaceId: loaded.workspaceId });
    return { scanId: scan.id, status: "QUEUED", plan, queueEnqueued: enqueued, simulation: plan.policySnapshot.simulation };
  }

  /** SCAN DETAILS (§48) with counts — tenant-scoped by workspace. */
  async getScanDetails(user: RequestUser, scanId: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const scan = await this.prisma.scan.findFirst({
      where: { id: scanId, workspaceId: workspace.id },
      include: {
        stages: true,
        // Executions carry their tool identity so the Live Scan view can
        // show WHICH adapter ran, its status and its metrics (§42).
        executions: { include: { tool: { select: { slug: true, name: true } } }, orderBy: { createdAt: "asc" } },
        assessment: { include: { target: true } },
      },
    });
    if (!scan) throw new NotFoundException("Scan not found");
    const safe = async <T>(fn: () => Promise<T>, fallback: T): Promise<T> => {
      try { return await fn(); } catch { return fallback; }
    };
    const [findingCounts, assetCount, workers] = await Promise.all([
      safe(() => this.prisma.finding.groupBy({ by: ["severity"], where: { scanId }, _count: true }), []),
      safe(() => this.prisma.asset.count({ where: { targetId: scan.assessment.targetId } }), 0),
      safe(() => this.prisma.workerNode.findMany({ orderBy: { lastHeartbeat: "desc" }, take: 5 }), []),
    ]);
    const severityCounts: Record<string, number> = {};
    for (const row of findingCounts as Array<{ severity: string; _count: number }>) severityCounts[row.severity] = row._count;
    return { ...scan, findingCounts: severityCounts, assetCount, workers };
  }

  /** ADMIN OPERATIONS (§63): queue/worker/failed-job/stale-scan visibility.
   *  Controller restricts this to OWNER/ADMIN — ordinary users never see it. */
  async opsOverview(user: RequestUser) {
    void user;
    const staleBefore = new Date(Date.now() - 10 * 60 * 1000);
    const [workers, deadLetters, staleScans, running, queued] = await Promise.all([
      this.prisma.workerNode.findMany({ orderBy: { lastHeartbeat: "desc" }, take: 20 }),
      this.prisma.deadLetterJob.findMany({ orderBy: { createdAt: "desc" }, take: 20 }),
      this.prisma.scan.findMany({ where: { status: { in: ["RUNNING", "PREPARING"] as never }, updatedAt: { lt: staleBefore } }, take: 20 }),
      this.prisma.scan.count({ where: { status: "RUNNING" as never } }),
      this.prisma.scan.count({ where: { status: { in: ["CREATED", "QUEUED"] as never } } }),
    ]);
    return { workers, failedJobs: deadLetters, staleScans, counts: { running, queued } };
  }

  /** Pause (§27): stop scheduling new work. Running mock executions are not
   *  frozen mid-flight — the runner observes PAUSED between stages. */
  async pauseScan(user: RequestUser, scanId: string) {
    return this.transition(user, scanId, ["RUNNING", "QUEUED", "PREPARING"], "PAUSED", "SCAN_PAUSED", "scan.paused");
  }

  /** Resume (§27): gates are RE-EVALUATED before anything is scheduled again. */
  async resumeScan(user: RequestUser, scanId: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const scan = await this.prisma.scan.findFirst({ where: { id: scanId, workspaceId: workspace.id }, include: { assessment: { include: { target: true, scope: true } } } });
    if (!scan) throw new NotFoundException("Scan not found");
    try {
      assertScanTransition(scan.status as ScanStatus, "RUNNING");
    } catch {
      throw new BadRequestException(`Scan in status ${scan.status} cannot be resumed`);
    }
    const scopeParse = scopeRulesSchema.safeParse(scan.assessment.scope?.rules ?? {});
    const gate = evaluateAuthorizationGate({
      auth: {
        organizationId: user.organizationId, workspaceId: workspace.id, targetId: scan.assessment.target.id,
        targetOrganizationId: user.organizationId, assessmentId: scan.assessment.id, scanId,
        verificationStatus: scan.assessment.target.verified ? "VERIFIED" : "PENDING",
        approvalStatus: scan.assessment.status === "APPROVED" ? "APPROVED" : "PENDING",
        requestedBy: user.id,
      },
      targetHost: hostOf(scan.assessment.target.value),
      scopeRules: scopeParse.success ? scopeParse.data : { includeHosts: [], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
      targetExists: true, targetWorkspaceId: workspace.id, workspaceId: workspace.id,
      targetVerified: scan.assessment.target.verified,
      assessmentApproved: scan.assessment.status === "APPROVED",
      scopeValid: scopeParse.success,
    });
    if (!gate.allowed) throw new BadRequestException(`Resume refused: ${gate.message} (${gate.reasonCode})`);
    const updated = await this.prisma.scan.update({ where: { id: scanId }, data: { status: "QUEUED" } });
    await this.events.record(makeEvent(scanId, workspace.id, "scan.resumed", {}));
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id, action: "SCAN_RESUMED", resourceType: "Scan", resourceId: scanId });
    await this.queue.enqueueScanOrchestration({ scanId, workspaceId: workspace.id });
    return updated;
  }

  /** Cancel (§26): idempotent. Scan → CANCELLING → CANCELLED; pending stages
   *  are cancelled/skipped; the worker observes CANCELLED and stops. */
  async cancelScan(user: RequestUser, scanId: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const scan = await this.prisma.scan.findFirst({ where: { id: scanId, workspaceId: workspace.id } });
    if (!scan) throw new NotFoundException("Scan not found");
    if (scan.status === "CANCELLED") return scan; // idempotent (§26)
    try {
      assertScanTransition(scan.status as ScanStatus, "CANCELLING");
    } catch {
      throw new BadRequestException(`Scan in status ${scan.status} cannot be cancelled`);
    }
    await this.prisma.scan.update({ where: { id: scanId }, data: { status: "CANCELLING" } });
    await this.prisma.scanStage.updateMany({
      where: { scanId, status: { in: ["PENDING", "BLOCKED", "READY", "QUEUED"] as never } },
      data: { status: "CANCELLED" },
    });
    const updated = await this.prisma.scan.update({ where: { id: scanId }, data: { status: "CANCELLED", completedAt: new Date() } });
    await this.events.record(makeEvent(scanId, workspace.id, "scan.cancelled", {}));
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id, action: "SCAN_CANCELLED", resourceType: "Scan", resourceId: scanId });
    return updated;
  }

  /** Emergency stop = cancel with an explicit audit marker. Same converging
   *  semantics; distinct audit action intent via metadata. */
  async emergencyStop(user: RequestUser, scanId: string) {
    const result = await this.cancelScan(user, scanId);
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: result.workspaceId, action: "SCAN_CANCELLED", resourceType: "Scan", resourceId: scanId, metadata: { emergencyStop: true } });
    return result;
  }

  private async transition(user: RequestUser, scanId: string, _from: string[], to: ScanStatus, auditAction: string, eventType: "scan.paused") {
    const workspace = await resolveWorkspace(this.prisma, user);
    const scan = await this.prisma.scan.findFirst({ where: { id: scanId, workspaceId: workspace.id } });
    if (!scan) throw new NotFoundException("Scan not found");
    try {
      assertScanTransition(scan.status as ScanStatus, to);
    } catch {
      throw new BadRequestException(`Scan in status ${scan.status} cannot transition to ${to}`);
    }
    const updated = await this.prisma.scan.update({ where: { id: scanId }, data: { status: to } });
    await this.events.record(makeEvent(scanId, workspace.id, eventType, {}));
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id, action: auditAction, resourceType: "Scan", resourceId: scanId });
    return updated;
  }
}
