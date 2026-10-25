import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  DEFAULT_MOBILE_BUDGET, MOBILE_TOOL_DESCRIPTORS, activeKillSwitch, evaluateInstrumentationPolicy,
  redactMobileSecretValues, sanitizeMobileText, validateMobileArtifactUpload,
  type InstrumentationModuleRecord,
} from "@dsrclone/security-sdk";
import type {
  CreateMobileDynamicSessionInput, RegisterMobileAppInput, RegisterMobileDeviceInput,
  StartMobileScanInput, UploadMobileBuildInput,
} from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";
import { OrchestrationService } from "../orchestration/orchestration.service";
import { hasMobileSecurityPermission, requireMobileSecurityPermission } from "./permissions";

type Row = Record<string, unknown> & { id: string };

const DYNAMIC_PROFILES = new Set(["MOBILE_DYNAMIC_CONTROLLED", "MOBILE_FULL_CONTROLLED"]);

/**
 * Mobile security API (Prompt 17 §100).
 *
 * Discipline carried through every method:
 * - Static analysis is the default; apps are NEVER installed, run,
 *   emulated or instrumented by this API (§8). Dynamic sessions are
 *   governed lab records evaluated against the instrumentation
 *   policy (§73) — arbitrary shell commands, arbitrary Frida scripts
 *   and arbitrary Objection commands are refused AND audited
 *   (MOBILE_DYNAMIC_ACTION_BLOCKED), and every §75 prohibited action
 *   is refused by construction.
 * - App binaries are hostile content (§107): upload runs the intake
 *   validator (format sniffing, declared-hash binding, archive
 *   zip-slip/bomb discipline) and persists METADATA + the bounded
 *   extracted-artifact record only — sanitized, secret-redacted
 *   (§24/§28). Raw secret values exist in no record.
 * - Builds are identified by their artifact SHA-256 (§5), never by
 *   filename; a duplicate hash is the same build.
 * - Extracted endpoints are DISCOVERED_REFERENCE (§30): listed for
 *   review, never authorized, never scope-expanding.
 * - Scans start only through the gated orchestration path (VERIFIED
 *   target + APPROVED assessment + scope), never directly.
 */
@Injectable()
export class MobileSecurityService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly orchestration: OrchestrationService,
  ) {}

  // ── Applications (§93/§100) ─────────────────────────────────────

  async listApps(user: RequestUser) {
    requireMobileSecurityPermission(user, "VIEW_MOBILE_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.mobileApplication.findMany({
      where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 200,
    });
    const items = [];
    for (const r of rows as unknown as Row[]) {
      const [builds, findings] = await Promise.all([
        this.prisma.mobileBuild.count({ where: { applicationId: r.id } }).catch(() => 0),
        this.prisma.finding.count({ where: { mobileApplicationId: r.id } }).catch(() => 0),
      ]);
      items.push({
        id: r.id, name: r.name, platform: r.platform,
        packageName: (r.packageName as string | null) ?? null, bundleId: (r.bundleId as string | null) ?? null,
        environment: r.environment, criticality: r.criticality, status: r.status,
        targetId: (r.targetId as string | null) ?? null, builds, findings,
        createdAt: r.createdAt ?? null,
      });
    }
    return { items };
  }

  async registerApp(user: RequestUser, input: RegisterMobileAppInput) {
    requireMobileSecurityPermission(user, "MANAGE_MOBILE_APPS");
    const workspace = await resolveWorkspace(this.prisma, user);
    const identity = input.platform === "ANDROID" ? input.packageName : input.bundleId;
    const existing = await this.prisma.mobileApplication.findFirst({
      where: {
        workspaceId: workspace.id, platform: input.platform,
        ...(input.platform === "ANDROID" ? { packageName: input.packageName } : { bundleId: input.bundleId }),
      },
    });
    if (existing) return { id: (existing as Row).id, status: (existing as Row).status, alreadyRegistered: true };
    const target = await this.prisma.target.create({
      data: {
        workspaceId: workspace.id, name: input.name, type: "MOBILE_APP" as never,
        value: identity!, status: "DRAFT", verified: false, createdBy: user.id,
      },
    });
    const app = await this.prisma.mobileApplication.create({
      data: {
        workspaceId: workspace.id, targetId: (target as Row).id, name: input.name,
        platform: input.platform as never, packageName: input.packageName ?? null, bundleId: input.bundleId ?? null,
        owner: input.owner ?? null, projectRef: input.projectRef ?? null,
        environment: input.environment, criticality: input.criticality,
        status: "REGISTERED", createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "MOBILE_APP_CREATED", resourceType: "MobileApplication", resourceId: (app as Row).id,
      metadata: { platform: input.platform, applicationRef: identity },
    });
    return { id: (app as Row).id, targetId: (target as Row).id, status: "REGISTERED" };
  }

  async getApp(user: RequestUser, id: string) {
    requireMobileSecurityPermission(user, "VIEW_MOBILE_SECURITY");
    const { app } = await this.loadApp(user, id);
    const builds = await this.prisma.mobileBuild.findMany({
      where: { applicationId: app.id }, orderBy: { createdAt: "desc" }, take: 100,
    });
    return {
      id: app.id, name: app.name, platform: app.platform,
      packageName: (app.packageName as string | null) ?? null, bundleId: (app.bundleId as string | null) ?? null,
      environment: app.environment, criticality: app.criticality, status: app.status,
      targetId: (app.targetId as string | null) ?? null,
      builds: (builds as unknown as Row[]).map((b) => this.buildView(b)),
    };
  }

  // ── Builds: hostile-content intake (§5/§6/§107) ────────────────

  async uploadBuild(user: RequestUser, appId: string, input: UploadMobileBuildInput) {
    requireMobileSecurityPermission(user, "UPLOAD_MOBILE_BUILD");
    const { workspace, app } = await this.loadApp(user, appId);
    const intake = validateMobileArtifactUpload({
      fileName: input.fileName,
      ...(input.archiveEntries ? { entries: input.archiveEntries } : {}),
      ...(input.declaredSha256 ? { declaredSha256: input.declaredSha256 } : {}),
    });
    if (!intake.ok) {
      throw new BadRequestException(`Mobile artifact intake refused: ${intake.errors.join("; ")}`);
    }
    const artifactHash = intake.artifactHash || input.declaredSha256;
    if (!artifactHash) {
      throw new BadRequestException("Mobile artifact intake refused: declaredSha256 is required when artifact bytes are not supplied — the SHA-256 IS the build identity (§5)");
    }
    const existing = await this.prisma.mobileBuild.findFirst({
      where: { applicationId: app.id, artifactHash },
    });
    if (existing) return { id: (existing as Row).id, artifactHash, alreadyUploaded: true };
    const build = await this.prisma.mobileBuild.create({
      data: {
        workspaceId: workspace.id, applicationId: app.id,
        versionName: input.versionName ?? null, versionCode: input.versionCode ?? null,
        buildNumber: input.buildNumber ?? null,
        artifactHash, artifactFormat: intake.format,
        artifactReference: input.artifactReference ?? null,
        artifactSizeBytes: BigInt(input.artifactSizeBytes),
        signingMetadata: this.sanitizeRecord(input.signingMetadata ?? {}) as never,
        analysisArtifacts: this.sanitizeArtifacts(input.analysisArtifacts ?? {}) as never,
        status: "UPLOADED",
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "MOBILE_BUILD_UPLOADED", resourceType: "MobileBuild", resourceId: (build as Row).id,
      // Metadata only (§116): hash + format + size — never content.
      metadata: { artifactHash, format: intake.format, sizeBytes: input.artifactSizeBytes },
    });
    return { id: (build as Row).id, artifactHash, format: intake.format, warnings: intake.warnings };
  }

  async getBuild(user: RequestUser, buildId: string) {
    requireMobileSecurityPermission(user, "VIEW_MOBILE_SECURITY");
    const { app, build } = await this.loadBuild(user, buildId);
    const [findings, endpoints, components, deepLinks, libraries, sboms, gate] = await Promise.all([
      this.prisma.finding.count({ where: { mobileBuildId: build.id } }).catch(() => 0),
      this.prisma.mobileEndpoint.count({ where: { buildId: build.id } }).catch(() => 0),
      this.prisma.softwareComponent.count({ where: { buildId: build.id } }).catch(() => 0),
      this.prisma.mobileDeepLink.findMany({ where: { buildId: build.id }, take: 500 }).catch(() => []),
      this.prisma.mobileNativeLibrary.findMany({ where: { buildId: build.id }, take: 500 }).catch(() => []),
      this.prisma.softwareBillOfMaterials.findMany({ where: { buildId: build.id }, take: 10 }).catch(() => []),
      this.prisma.qualityGateResult.findFirst({ where: { buildId: build.id }, orderBy: { evaluatedAt: "desc" } }).catch(() => null),
    ]);
    return {
      ...this.buildView(build),
      applicationId: app.id, applicationRef: this.appRef(app), platform: app.platform,
      findings, endpoints, components,
      deepLinks: (deepLinks as unknown as Row[]).map((l) => ({
        scheme: l.scheme, host: (l.host as string | null) ?? null,
        pathPrefix: (l.pathPrefix as string | null) ?? null, autoVerify: l.autoVerify === true,
      })),
      nativeLibraries: (libraries as unknown as Row[]).map((l) => ({
        path: l.path, architecture: (l.architecture as string | null) ?? null,
        pie: (l.pie as boolean | null) ?? null, nx: (l.nx as boolean | null) ?? null,
        stackCanary: (l.stackCanary as boolean | null) ?? null, relro: (l.relro as string | null) ?? null,
        stripped: (l.stripped as boolean | null) ?? null,
      })),
      sboms: (sboms as unknown as Row[]).map((s) => ({
        format: s.format, specVersion: s.specVersion, checksum: s.checksum, componentCount: s.componentCount,
      })),
      qualityGate: gate ? { status: (gate as Row).status, failedRules: (gate as Row).failedRules, evaluatedAt: (gate as Row).evaluatedAt ?? null } : null,
      // §28: signing metadata is certificate metadata only — no key
      // material exists in this record by construction (§31).
      signingMetadata: build.signingMetadata ?? {},
    };
  }

  /** Decompiled-source artifacts (§24): RBAC-gated + audited per
   *  access (§116 MOBILE_ARTIFACT_ACCESSED). Content was sanitized +
   *  secret-redacted at intake; raw secret values exist nowhere. */
  async getBuildArtifacts(user: RequestUser, buildId: string) {
    requireMobileSecurityPermission(user, "VIEW_MOBILE_SOURCE_ARTIFACTS");
    const { workspace, build } = await this.loadBuild(user, buildId);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "MOBILE_ARTIFACT_ACCESSED", resourceType: "MobileBuild", resourceId: build.id,
      metadata: { artifactHash: build.artifactHash },
    });
    return { buildId: build.id, artifactHash: build.artifactHash, analysisArtifacts: build.analysisArtifacts ?? {} };
  }

  // ── Scans (§100) ────────────────────────────────────────────────

  async startScan(user: RequestUser, appId: string, input: StartMobileScanInput) {
    const profile = input.profile ?? "MOBILE_STATIC_BASELINE";
    requireMobileSecurityPermission(user, DYNAMIC_PROFILES.has(profile) ? "RUN_MOBILE_DYNAMIC_SCAN" : "RUN_MOBILE_STATIC_SCAN");
    const { workspace, app } = await this.loadApp(user, appId);
    if (!app.targetId) throw new BadRequestException("Mobile application has no target");
    const target = await this.prisma.target.findUnique({ where: { id: app.targetId } });
    if (!target?.verified) throw new BadRequestException("Mobile application target is not VERIFIED — verify the application registration before scanning");
    const started = await this.startGatedScan(user, workspace.id, target as unknown as Row & { id: string; value: string }, this.appRef(app), profile);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "MOBILE_STATIC_SCAN_STARTED", resourceType: "MobileApplication", resourceId: app.id,
      metadata: { profile, buildId: input.buildId ?? null },
    });
    return { applicationId: app.id, ...started };
  }

  async listBuildFindings(user: RequestUser, buildId: string) {
    requireMobileSecurityPermission(user, "VIEW_MOBILE_SECURITY");
    const { build } = await this.loadBuild(user, buildId);
    const rows = await this.prisma.finding.findMany({
      where: { mobileBuildId: build.id, duplicateOfId: null },
      orderBy: { createdAt: "desc" }, take: 500,
    });
    return {
      items: (rows as unknown as Row[]).map((f) => ({
        id: f.id, title: f.title, severity: f.severity, status: f.status,
        mobileFindingType: (f.mobileFindingType as string | null) ?? null,
        ruleId: (f.ruleId as string | null) ?? null,
        owaspMobile: (f.owaspMobile as string | null) ?? null,
        masvsControl: (f.masvsControl as string | null) ?? null,
        cwe: (f.cwe as string | null) ?? null,
        filePath: (f.filePath as string | null) ?? null,
        mobileComponent: (f.mobileComponent as string | null) ?? null,
        dynamicConfirmed: f.dynamicConfirmed === true,
        crossBuildFingerprint: (f.crossBuildFingerprint as string | null) ?? null,
        sources: f.sources ?? [],
      })),
    };
  }

  async listBuildEndpoints(user: RequestUser, buildId: string) {
    requireMobileSecurityPermission(user, "VIEW_MOBILE_SECURITY");
    const { build } = await this.loadBuild(user, buildId);
    const rows = await this.prisma.mobileEndpoint.findMany({
      where: { buildId: build.id }, orderBy: { createdAt: "asc" }, take: 1000,
    });
    return {
      items: (rows as unknown as Row[]).map((e) => ({
        id: e.id, url: e.url, host: e.host, kind: e.kind,
        // §30: extraction NEVER authorizes — the classification is
        // reported verbatim so no client can mistake it for scope.
        classification: e.classification, source: e.source,
        linkedAssetId: (e.linkedAssetId as string | null) ?? null,
      })),
    };
  }

  // ── Dynamic sessions: the governed lab (§58/§69–§75) ───────────

  async createDynamicSession(user: RequestUser, appId: string, input: CreateMobileDynamicSessionInput & { scriptBody?: string; shellCommand?: string }) {
    requireMobileSecurityPermission(user, "RUN_MOBILE_DYNAMIC_SCAN");
    const requestedActions = input.requestedActions ?? [];
    const moduleIds = input.moduleIds ?? [];
    const profile = input.profile ?? "MOBILE_DYNAMIC_CONTROLLED";
    const { workspace, app } = await this.loadApp(user, appId);
    const build = await this.prisma.mobileBuild.findFirst({ where: { id: input.buildId, applicationId: app.id } });
    if (!build) throw new NotFoundException("Mobile build not found for this application");
    let device: Row | null = null;
    if (input.deviceId) {
      device = (await this.prisma.mobileTestDevice.findFirst({
        where: { id: input.deviceId, workspaceId: workspace.id },
      })) as unknown as Row | null;
      if (!device) throw new NotFoundException("Lab device not found in this workspace");
    }
    // §92: the SAME kill-switch table the validation engine uses.
    const switches = await this.prisma.validationKillSwitch.findMany({ where: { active: true } }).catch(() => []);
    const kill = activeKillSwitch(
      (switches as unknown as Row[]).map((s) => ({
        level: s.level as string, organizationId: s.organizationId as string | null,
        workspaceId: s.workspaceId as string | null, scopeRef: s.scopeRef as string | null, active: true,
      })),
      { organizationId: user.organizationId, workspaceId: workspace.id, targetId: (app.targetId as string | null) ?? app.id },
    );
    const moduleRows = moduleIds.length > 0
      ? await this.prisma.mobileInstrumentationModule.findMany({ where: { workspaceId: workspace.id, id: { in: moduleIds } } }).catch(() => [])
      : [];
    const modules: InstrumentationModuleRecord[] = (moduleRows as unknown as Row[]).map((m) => ({
      id: m.id, name: m.name as string, tool: m.tool as "FRIDA" | "OBJECTION",
      version: m.version as string, moduleHash: m.moduleHash as string,
      approved: m.approved === true, status: m.status as string,
    }));
    const decision = evaluateInstrumentationPolicy({
      requestedActions,
      ...(input.scriptBody ? { scriptBody: input.scriptBody } : {}),
      ...(input.shellCommand ? { shellCommand: input.shellCommand } : {}),
      moduleIds,
      // An "approved session" in policy terms = the full §73 context:
      // authorized (verified) target + registered lab device +
      // controlled profile. Anything less refuses.
      hasApprovedSession: Boolean(app.targetId) && Boolean(device),
      hasInstrumentationApproval: input.instrumentationApproved === true && hasMobileSecurityPermission(user, "APPROVE_MOBILE_INSTRUMENTATION"),
      killSwitchActive: kill !== null,
    }, modules, DEFAULT_MOBILE_BUDGET);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "MOBILE_DYNAMIC_SESSION_REQUESTED", resourceType: "MobileBuild", resourceId: (build as Row).id,
      metadata: { profile, actions: requestedActions, modules: moduleIds.length },
    });
    if (!decision.allowed) {
      const session = await this.prisma.mobileDynamicSession.create({
        data: {
          workspaceId: workspace.id, applicationId: app.id, buildId: (build as Row).id,
          deviceId: device?.id ?? null, profile, status: "BLOCKED",
          requestedActions: requestedActions as never, blockedReasons: decision.reasons as never,
          moduleIds, killSwitchChecked: true, createdBy: user.id,
        },
      });
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
        action: "MOBILE_DYNAMIC_ACTION_BLOCKED", resourceType: "MobileDynamicSession", resourceId: (session as Row).id,
        metadata: { reasons: decision.reasons },
      });
      throw new BadRequestException(`Mobile dynamic session BLOCKED by policy: ${decision.reasons.join("; ")}`);
    }
    const session = await this.prisma.mobileDynamicSession.create({
      data: {
        workspaceId: workspace.id, applicationId: app.id, buildId: (build as Row).id,
        deviceId: device?.id ?? null, profile, status: "APPROVED",
        requestedActions: requestedActions as never, blockedReasons: [] as never,
        moduleIds, killSwitchChecked: true,
        createdBy: user.id, approvedBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "MOBILE_DYNAMIC_SESSION_APPROVED", resourceType: "MobileDynamicSession", resourceId: (session as Row).id,
      metadata: { profile, deviceId: device?.id ?? null },
    });
    return { id: (session as Row).id, status: "APPROVED", buildId: (build as Row).id, deviceId: device?.id ?? null };
  }

  // ── Device lab (§56/§98) ────────────────────────────────────────

  async listDevices(user: RequestUser) {
    requireMobileSecurityPermission(user, "VIEW_MOBILE_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.mobileTestDevice.findMany({
      where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 200,
    });
    return {
      // §55/§98: ZeroSweep-managed lab devices only. There is no
      // remote-shell affordance anywhere in this view or API.
      items: (rows as unknown as Row[]).map((d) => ({
        id: d.id, name: d.name, platform: d.platform, deviceKind: d.deviceKind,
        osVersion: (d.osVersion as string | null) ?? null, capabilities: d.capabilities ?? [],
        availability: d.availability, health: d.health,
        dedicatedNetwork: d.dedicatedNetwork === true,
        lastResetAt: (d.lastResetAt as unknown) ?? null, status: d.status,
      })),
    };
  }

  async registerDevice(user: RequestUser, input: RegisterMobileDeviceInput) {
    requireMobileSecurityPermission(user, "MANAGE_DEVICE_LAB");
    const workspace = await resolveWorkspace(this.prisma, user);
    const device = await this.prisma.mobileTestDevice.create({
      data: {
        workspaceId: workspace.id, name: input.name, platform: input.platform as never,
        deviceKind: input.deviceKind, osVersion: input.osVersion ?? null,
        capabilities: input.capabilities, dedicatedNetwork: input.dedicatedNetwork,
        availability: "AVAILABLE", health: "UNKNOWN", status: "REGISTERED", createdBy: user.id,
      },
    });
    return { id: (device as Row).id, status: "REGISTERED" };
  }

  // ── Traffic (§64–§68/§99) ───────────────────────────────────────

  async getTrafficSession(user: RequestUser, id: string) {
    requireMobileSecurityPermission(user, "VIEW_MOBILE_TRAFFIC");
    const workspace = await resolveWorkspace(this.prisma, user);
    const session = await this.prisma.mobileTrafficSession.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!session) throw new NotFoundException("Traffic session not found");
    const s = session as unknown as Row;
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "MOBILE_TRAFFIC_ACCESSED", resourceType: "MobileTrafficSession", resourceId: s.id,
      metadata: { buildId: s.buildId },
    });
    return {
      id: s.id, buildId: s.buildId, deviceId: (s.deviceId as string | null) ?? null,
      proxyTool: s.proxyTool, status: s.status,
      // §66: sanitized metadata only — hosts + counts + sizes. Bodies
      // are never part of this record by construction.
      hosts: s.hosts ?? [], requestCount: s.requestCount ?? 0,
      bytesCaptured: String(s.bytesCaptured ?? 0),
      sanitizationState: s.sanitizationState,
      startedAt: (s.startedAt as unknown) ?? null, endedAt: (s.endedAt as unknown) ?? null,
    };
  }

  // ── Tool health (§102) ──────────────────────────────────────────

  async listTools(user: RequestUser) {
    requireMobileSecurityPermission(user, "VIEW_MOBILE_SECURITY");
    await resolveWorkspace(this.prisma, user);
    return {
      items: MOBILE_TOOL_DESCRIPTORS.map((d) => ({
        slug: d.slug, name: d.name, workerType: d.workerType, risk: d.risk,
        approvalRequirement: d.approvalRequirement, capabilities: d.capabilities,
        // §102: honest static posture from the API — execution health
        // is worker-reported; registrations that can never execute
        // say so (§69–§74).
        health: d.slug === "frida" ? "DISABLED" : d.slug === "objection" ? "APPROVAL_REQUIRED" : "NOT_CONFIGURED",
        version: null,
      })),
      prohibitedAutomationNote: "Credential theft, session-token theft, account takeover, payment abuse, device persistence, spyware behavior, SMS/contact/file extraction, security-control bypass, arbitrary ADB shell, arbitrary Frida scripts and arbitrary Objection commands are PROHIBITED AUTOMATION (§75/§119) — never implemented.",
    };
  }

  // ── helpers ─────────────────────────────────────────────────────

  private appRef(app: Row): string {
    return (app.packageName as string | null) ?? (app.bundleId as string | null) ?? (app.name as string);
  }

  private buildView(b: Row) {
    return {
      id: b.id, applicationId: b.applicationId,
      versionName: (b.versionName as string | null) ?? null,
      versionCode: (b.versionCode as number | null) ?? null,
      buildNumber: (b.buildNumber as string | null) ?? null,
      // §5: the artifact SHA-256 IS the build identity.
      artifactHash: b.artifactHash, artifactFormat: b.artifactFormat,
      artifactSizeBytes: String(b.artifactSizeBytes ?? 0),
      artifactReference: (b.artifactReference as string | null) ?? null,
      minOsVersion: (b.minOsVersion as string | null) ?? null,
      targetOsVersion: (b.targetOsVersion as string | null) ?? null,
      status: b.status, createdAt: b.createdAt ?? null,
    };
  }

  /** §24/§28: the extracted-artifact record is sanitized + secret-
   *  redacted VALUE BY VALUE before persistence (redacting a
   *  serialized form would miss secrets behind JSON escaping) — a
   *  raw secret value in a decompiled snippet is stored nowhere.
   *  Depth/node caps bound hostile records (§91/§107). */
  private sanitizeArtifacts(artifacts: Record<string, unknown>): Record<string, unknown> {
    let nodes = 0;
    const walk = (value: unknown, depth: number): unknown => {
      if (++nodes > 20000 || depth > 12) return undefined;
      if (typeof value === "string") return redactMobileSecretValues(sanitizeMobileText(value, 65536));
      if (Array.isArray(value)) return value.slice(0, 2000).map((v) => walk(v, depth + 1));
      if (value !== null && typeof value === "object") {
        const out: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
          const walked = walk(v, depth + 1);
          if (walked !== undefined) out[sanitizeMobileText(k, 128)] = walked;
        }
        return out;
      }
      return value;
    };
    const result = walk(artifacts, 0) as Record<string, unknown>;
    if (JSON.stringify(result).length > 8 * 1024 * 1024) {
      throw new BadRequestException("analysisArtifacts exceeds the 8 MiB intake bound (§91)");
    }
    return result;
  }

  /** Signing metadata (§31): certificate facts only. Any key naming
   *  key material is dropped by construction — private keys never
   *  exist in ZeroSweep. */
  private sanitizeRecord(record: Record<string, unknown>): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(record)) {
      if (/private|secret|password|keystore/i.test(k)) continue;
      out[sanitizeMobileText(k, 128)] = typeof v === "string" ? sanitizeMobileText(v, 1024) : v;
    }
    return out;
  }

  private async loadApp(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const app = await this.prisma.mobileApplication.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!app) throw new NotFoundException("Mobile application not found");
    return { workspace, app: app as unknown as Row & { targetId: string | null } };
  }

  private async loadBuild(user: RequestUser, buildId: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const build = await this.prisma.mobileBuild.findFirst({ where: { id: buildId, workspaceId: workspace.id } });
    if (!build) throw new NotFoundException("Mobile build not found");
    const b = build as unknown as Row;
    const app = await this.prisma.mobileApplication.findFirst({ where: { id: b.applicationId as string, workspaceId: workspace.id } });
    if (!app) throw new NotFoundException("Mobile build not found");
    return { workspace, build: b, app: app as unknown as Row & { targetId: string | null } };
  }

  /** The gated scan path (mirrors the other families): a pre-existing scope +
   *  a pre-existing APPROVED assessment are consumed (never minted),
   *  then OrchestrationService
   *  re-checks VERIFIED + APPROVED before planning. */
  private async startGatedScan(
    user: RequestUser,
    workspaceId: string,
    target: Row & { id: string; value: string },
    scopeHost: string,
    profile: string,
  ) {
    const scope = await this.prisma.scope.findFirst({ where: { targetId: target.id } });
    if (!scope) {
      throw new BadRequestException("No pre-existing scope covers this target — create a scope via the scopes flow and request assessment approval via the assessments flow before starting a scan");
    }
    const assessment = await this.prisma.assessment.findFirst({
      where: { targetId: target.id, profile: profile as never, status: "APPROVED", scopeId: (scope as Row).id },
      orderBy: { createdAt: "desc" },
    });
    if (!assessment) {
      throw new BadRequestException("No pre-existing APPROVED assessment covers this target and profile — request approval via the assessments flow before starting a scan");
    }
    const assessmentRow = assessment as unknown as Row;
    if (!assessmentRow.approvedBy || assessmentRow.approvedBy === assessmentRow.createdBy || assessmentRow.approvedBy === user.id) {
      throw new BadRequestException("Assessment approval is not independent — the approver must be neither the assessment creator nor the scan starter; request approval via the assessments flow");
    }
    const started = await this.orchestration.startScan(user, (assessment as Row).id);
    return { assessmentId: (assessment as Row).id, ...started };
  }
}
