import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  buildMobileAnalysisPlan, compareBuildFindings, computeBinaryCoverage, computeMobileCoverage,
  detectProtectionEvidence, evaluateAdbOperation, evaluateFridaScriptRequest, evaluateObjectionWorkflow,
  guardMobileAiRequest, mobbinProfileDefinition, mobbinReportDefinition, planMobileNlQuery,
  planMobileRetest, redactTrafficBody, redactTrafficHeaders, type CarryForwardFindingRef,
} from "@zerosweep/security-sdk";
import type { CreateMobileDynamicSessionInput, UploadMobileBuildInput } from "@zerosweep/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";
import { MobileSecurityService } from "../mobile-security/mobile-security.service";
import { BinarySecurityService } from "../binary-security/binary-security.service";
import { requireMobileBinaryV2Permission } from "./permissions";

type Row = Record<string, unknown> & { id: string };

/** V2 profile → the V1 gated-scan profile that executes it. The V2
 *  profile set (§15) is a planning/governance layer; execution stays
 *  on the Prompt 17/18 gated engines — nothing new executes here. */
const SCAN_PROFILE_MAP: Record<string, string> = {
  MOBILE_STATIC: "MOBILE_STATIC_BASELINE",
  MOBILE_STANDARD: "MOBILE_STATIC_COMPREHENSIVE",
  ANDROID_STATIC: "MOBILE_STATIC_BASELINE",
  IOS_STATIC: "MOBILE_STATIC_BASELINE",
  ANDROID_DYNAMIC_SAFE: "MOBILE_STATIC_BASELINE",
  IOS_DYNAMIC_SAFE: "MOBILE_STATIC_BASELINE",
  TARGETED_MOBILE_VERIFICATION: "MOBILE_STATIC_BASELINE",
};

/**
 * Mobile & Binary Security V2 API (Prompt 35 §133).
 *
 * Discipline: this module DEEPENS Prompts 17/18 — intake, scans,
 * dynamic sessions and binary analysis all delegate to the V1
 * governed services. What V2 adds is the plan layer (§13), the
 * device-authorization gate (§72–§74), the ADB/Frida/Objection
 * policy surface (§75–§84), traffic-capture governance (§88–§93),
 * version lineage (§105–§108), coverage snapshots (§121–§126),
 * report definitions (§127) and the guarded NL surface (§129–§132).
 * Nothing here installs, runs, emulates or executes an artifact.
 */
@Injectable()
export class MobileBinaryV2Service {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly mobile: MobileSecurityService,
    private readonly binary: BinarySecurityService,
  ) {}

  // ── Artifacts (§6/§133) ─────────────────────────────────────────

  async uploadArtifact(user: RequestUser, appId: string, input: UploadMobileBuildInput) {
    requireMobileBinaryV2Permission(user, "UPLOAD_MOBILE_ARTIFACT");
    const result = await this.mobile.uploadBuild(user, appId, input);
    const workspace = await resolveWorkspace(this.prisma, user);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "MOBILE_ARTIFACT_UPLOADED", resourceType: "MobileBuild", resourceId: result.id,
      metadata: { artifactHash: result.artifactHash ?? null, format: result.format ?? null },
    });
    return result;
  }

  async getArtifact(user: RequestUser, artifactId: string) {
    requireMobileBinaryV2Permission(user, "VIEW_MOBILE_SECURITY");
    return this.mobile.getBuild(user, artifactId);
  }

  // ── Analysis plans (§13/§133) ───────────────────────────────────

  async analyzeArtifact(user: RequestUser, artifactId: string, input: { profile?: string; deviceId?: string; trafficAnalysis?: boolean }) {
    requireMobileBinaryV2Permission(user, "RUN_MOBILE_STATIC_ANALYSIS");
    const profile = input.profile ?? "MOBILE_STANDARD";
    if (!mobbinProfileDefinition(profile)) throw new BadRequestException(`Unknown V2 analysis profile: ${profile}`);
    const { workspace, app, build } = await this.loadBuild(user, artifactId);
    let device: Row | null = null;
    if (input.deviceId) {
      device = (await this.prisma.mobileTestDevice.findFirst({
        where: { id: input.deviceId, workspaceId: workspace.id },
      })) as unknown as Row | null;
      if (!device) throw new NotFoundException("Lab device not found in this workspace");
    }
    const approvedModules = await this.prisma.mobileInstrumentationModule.count({
      where: { workspaceId: workspace.id, approved: true, status: "APPROVED" },
    }).catch(() => 0);
    const plan = buildMobileAnalysisPlan({
      profile, platform: (app.platform as string) as "ANDROID" | "IOS",
      artifactHash: build.artifactHash as string,
      authorizationId: (app.targetId as string | null) ?? null,
      device: device ? {
        id: device.id, deviceType: (device.deviceType as string) ?? "ANDROID_EMULATOR",
        authorizationStatus: (device.authorizationStatus as string) ?? "NOT_AUTHORIZED",
        availability: (device.availability as string) ?? "AVAILABLE",
      } : null,
      approvedModuleCount: approvedModules,
      trafficAnalysis: input.trafficAnalysis === true,
    });
    const planRow = await this.prisma.mobileAnalysisPlan.create({
      data: {
        workspaceId: workspace.id, applicationId: app.id, buildId: build.id,
        profile: plan.profile, platform: plan.platform, authorizationId: plan.authorizationId,
        staticModules: plan.staticModules as never, dynamicModules: plan.dynamicModules as never,
        dynamicGate: plan.dynamicGate, dynamicGateReasons: plan.dynamicGateReasons as never,
        deviceId: plan.deviceProfile?.deviceId ?? null, trafficAnalysis: plan.trafficAnalysis,
        limits: plan.limits as never, verificationPolicy: plan.verificationPolicy,
        status: "PLANNED", createdBy: user.id,
      },
    });
    // Execution rides the V1 gated scan path (VERIFIED target +
    // APPROVED assessment + scope) — the plan never bypasses it.
    const scanProfile = SCAN_PROFILE_MAP[profile] ?? "MOBILE_STATIC_BASELINE";
    const started = await this.mobile.startScan(user, app.id, { profile: scanProfile as never, buildId: build.id });
    await this.prisma.mobileAnalysisPlan.update({
      where: { id: (planRow as Row).id }, data: { status: "SCAN_STARTED", scanId: (started as unknown as Row).scanId ?? null },
    }).catch(() => undefined);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "MOBILE_STATIC_ANALYSIS_STARTED", resourceType: "MobileAnalysisPlan", resourceId: (planRow as Row).id,
      metadata: { profile, dynamicGate: plan.dynamicGate, artifactHash: build.artifactHash },
    });
    return {
      planId: (planRow as Row).id, profile, platform: plan.platform,
      staticModules: plan.staticModules, dynamicModules: plan.dynamicModules,
      dynamicGate: plan.dynamicGate, dynamicGateReasons: plan.dynamicGateReasons,
      trafficAnalysis: plan.trafficAnalysis, verificationPolicy: plan.verificationPolicy,
      scan: started,
    };
  }

  // ── Dynamic analysis (§71–§87/§133/§135) ────────────────────────

  async requestDynamicAnalysis(user: RequestUser, artifactId: string, input: CreateMobileDynamicSessionInput & { scriptBody?: string; shellCommand?: string }) {
    requireMobileBinaryV2Permission(user, "RUN_MOBILE_DYNAMIC_ANALYSIS");
    const { workspace, app, build } = await this.loadBuild(user, artifactId);
    // §72–§74/§151: the device must be an explicitly AUTHORIZED lab
    // device of this workspace — registration alone is not
    // authorization. Checked BEFORE delegating to the V1 policy.
    if (input.deviceId) {
      const device = (await this.prisma.mobileTestDevice.findFirst({
        where: { id: input.deviceId, workspaceId: workspace.id },
      })) as unknown as Row | null;
      if (!device) throw new NotFoundException("Lab device not found in this workspace");
      if ((device.authorizationStatus as string) !== "AUTHORIZED") {
        await this.prisma.mobileDynamicSession.create({
          data: {
            workspaceId: workspace.id, applicationId: app.id, buildId: build.id,
            deviceId: device.id, profile: input.profile ?? "MOBILE_DYNAMIC_CONTROLLED",
            status: "BLOCKED", requestedActions: (input.requestedActions ?? []) as never,
            blockedReasons: ["DEVICE_NOT_AUTHORIZED: dynamic analysis requires an explicitly authorized test device (§72–§74)"] as never,
            moduleIds: input.moduleIds ?? [], killSwitchChecked: true, createdBy: user.id,
          },
        }).catch(() => undefined);
        await this.audit.record({
          actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
          action: "MOBILE_DYNAMIC_ACTION_BLOCKED", resourceType: "MobileBuild", resourceId: build.id,
          metadata: { reason: "DEVICE_NOT_AUTHORIZED", deviceId: device.id },
        });
        throw new BadRequestException("Mobile dynamic analysis BLOCKED: device is not an AUTHORIZED test device (§72–§74/§151)");
      }
    }
    const session = await this.mobile.createDynamicSession(user, app.id, { ...input, buildId: build.id });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "MOBILE_DYNAMIC_ANALYSIS_STARTED", resourceType: "MobileDynamicSession", resourceId: (session as Row).id,
      metadata: { buildId: build.id, deviceId: input.deviceId ?? null },
    });
    // §87: cleanup contract is part of the session record — device
    // release + temporary-data removal + proxy clearing are tracked,
    // never assumed.
    return { ...session, cleanup: { required: true, state: "PENDING", steps: ["STOP_APP", "REMOVE_TEMP_TEST_DATA", "REVOKE_TEMP_SECRETS", "RELEASE_DEVICE", "CLEAR_PROXY_CONFIGURATION"] } };
  }

  async getDynamicSession(user: RequestUser, sessionId: string) {
    requireMobileBinaryV2Permission(user, "VIEW_MOBILE_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const s = (await this.prisma.mobileDynamicSession.findFirst({
      where: { id: sessionId, workspaceId: workspace.id },
    })) as unknown as Row | null;
    if (!s) throw new NotFoundException("Dynamic session not found");
    const traffic = await this.prisma.mobileTrafficSession.findMany({
      where: { buildId: s.buildId as string, workspaceId: workspace.id }, take: 50,
    }).catch(() => []);
    return {
      id: s.id, applicationId: s.applicationId, buildId: s.buildId,
      deviceId: (s.deviceId as string | null) ?? null, profile: s.profile, status: s.status,
      requestedActions: s.requestedActions ?? [], blockedReasons: s.blockedReasons ?? [],
      moduleIds: s.moduleIds ?? [], killSwitchChecked: s.killSwitchChecked === true,
      cleanupState: s.cleanupState, startedAt: (s.startedAt as unknown) ?? null, endedAt: (s.endedAt as unknown) ?? null,
      trafficSessions: (traffic as unknown as Row[]).map((t) => ({ id: t.id, proxyTool: t.proxyTool, status: t.status, requestCount: t.requestCount ?? 0 })),
    };
  }

  // ── Runtime policy surface (§75–§84) ────────────────────────────

  async evaluateAdb(user: RequestUser, operation: string) {
    requireMobileBinaryV2Permission(user, "RUN_APPROVED_RUNTIME_INSTRUMENTATION");
    const verdict = evaluateAdbOperation(operation);
    const workspace = await resolveWorkspace(this.prisma, user);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: verdict.allowed ? "MOBILE_INSTRUMENTATION_STARTED" : "MOBILE_DYNAMIC_ACTION_BLOCKED",
      resourceType: "MobileTestDevice", resourceId: "adb-policy",
      metadata: { operation: verdict.operation, allowed: verdict.allowed, reasons: verdict.reasons },
    });
    if (!verdict.allowed) throw new BadRequestException(`ADB operation REJECTED: ${verdict.reasons.join("; ")}`);
    return { operation: verdict.operation, allowed: true, execution: "POLICY_ONLY — operations execute only inside an approved dynamic session on an authorized device (§75)" };
  }

  async registerInstrumentationScript(user: RequestUser, input: {
    name: string; tool: string; version: string; purpose?: string; platform?: string;
    riskClassification?: string; moduleHash: string; scriptBody?: string;
  }) {
    requireMobileBinaryV2Permission(user, "RUN_APPROVED_RUNTIME_INSTRUMENTATION");
    // §79/§152: an inline script body is not a registration shape.
    if (input.scriptBody) throw new BadRequestException("Frida/Objection registration REJECTED: arbitrary script bodies are never accepted — register the reviewed artifact by hash (§79/§80)");
    const verdict = evaluateFridaScriptRequest({
      registryEntry: {
        id: input.name, version: input.version, purpose: input.purpose ?? "",
        platform: input.platform ?? "", riskClass: input.riskClassification ?? "",
        hash: input.moduleHash, reviewStatus: "REGISTERED",
      },
    });
    // Registration itself only requires completeness; APPROVED is a
    // separate review act. Incompleteness is refused outright.
    const incomplete = verdict.reasons.filter((r) => r.startsWith("INCOMPLETE") || r.startsWith("INVALID") || r.startsWith("UNKNOWN"));
    if (incomplete.length > 0) throw new BadRequestException(`Script registration REJECTED: ${incomplete.join("; ")}`);
    const workspace = await resolveWorkspace(this.prisma, user);
    const existing = await this.prisma.mobileInstrumentationModule.findFirst({
      where: { workspaceId: workspace.id, name: input.name, version: input.version },
    });
    if (existing) return { id: (existing as Row).id, status: (existing as Row).status, alreadyRegistered: true };
    const row = await this.prisma.mobileInstrumentationModule.create({
      data: {
        workspaceId: workspace.id, name: input.name, tool: input.tool, version: input.version,
        purpose: input.purpose ?? null, platform: input.platform ?? null,
        moduleHash: input.moduleHash, riskClassification: input.riskClassification ?? "REVIEW_REQUIRED",
        capability: "DYNAMIC_INSTRUMENTATION", approved: false, status: "REGISTERED", createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "RUNTIME_INSTRUMENTATION_STARTED", resourceType: "MobileInstrumentationModule", resourceId: (row as Row).id,
      metadata: { event: "SCRIPT_REGISTERED", tool: input.tool, purpose: input.purpose ?? null, reviewStatus: "REGISTERED" },
    });
    return { id: (row as Row).id, status: "REGISTERED", approved: false, note: "Registered for review — a script runs only after approval (§80/§152)" };
  }

  async checkObjectionWorkflow(user: RequestUser, workflow: string) {
    requireMobileBinaryV2Permission(user, "RUN_APPROVED_RUNTIME_INSTRUMENTATION");
    const verdict = evaluateObjectionWorkflow(workflow);
    if (!verdict.allowed) throw new BadRequestException(`Objection workflow REJECTED: ${verdict.reasons.join("; ")}`);
    return { workflow, allowed: true, execution: "POLICY_ONLY — workflows execute only inside an approved dynamic session (§83)" };
  }

  // ── Traffic capture (§88–§93) ───────────────────────────────────

  async startTrafficCapture(user: RequestUser, artifactId: string, input: { proxyTool?: string; deviceId?: string }) {
    requireMobileBinaryV2Permission(user, "VIEW_MOBILE_TRAFFIC");
    const { workspace, build } = await this.loadBuild(user, artifactId);
    const proxyTool = input.proxyTool ?? "MITMPROXY";
    if (!["MITMPROXY", "BURP_SUITE"].includes(proxyTool)) throw new BadRequestException(`Unsupported proxy provider: ${proxyTool}`);
    const row = await this.prisma.mobileTrafficSession.create({
      data: {
        workspaceId: workspace.id, buildId: build.id, deviceId: input.deviceId ?? null,
        proxyTool, status: "REQUESTED", hosts: [] as never, requestCount: 0,
        bytesCaptured: BigInt(0), sanitizationState: "PENDING", createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "MOBILE_TRAFFIC_CAPTURE_STARTED", resourceType: "MobileTrafficSession", resourceId: (row as Row).id,
      metadata: { buildId: build.id, proxyTool, scope: "AUTHORIZED_TEST_APP_ONLY (§90)", redaction: "§91 headers/fields redacted before persistence" },
    });
    return { id: (row as Row).id, status: "REQUESTED", proxyTool, buildId: build.id };
  }

  /** §91/§154: redaction preview — proves the redactor over caller-
   *  supplied synthetic records without persisting anything. */
  async previewTrafficRedaction(user: RequestUser, input: { headers?: { name: string; value: string }[]; body?: string }) {
    requireMobileBinaryV2Permission(user, "VIEW_MOBILE_TRAFFIC");
    return {
      headers: redactTrafficHeaders(input.headers ?? []),
      body: input.body ? redactTrafficBody(input.body) : null,
      persisted: false,
    };
  }

  // ── Findings (§133) ─────────────────────────────────────────────

  async listMobileFindings(user: RequestUser) {
    requireMobileBinaryV2Permission(user, "VIEW_MOBILE_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.finding.findMany({
      where: { workspaceId: workspace.id, sourceDomain: "MOBILE", duplicateOfId: null },
      orderBy: { createdAt: "desc" }, take: 500,
    }).catch(() => []);
    return {
      items: (rows as unknown as Row[]).map((f) => ({
        id: f.id, title: f.title, severity: f.severity, status: f.status,
        mobileApplicationId: (f.mobileApplicationId as string | null) ?? null,
        mobileBuildId: (f.mobileBuildId as string | null) ?? null,
        ruleId: (f.ruleId as string | null) ?? null, cwe: (f.cwe as string | null) ?? null,
        owaspMobile: (f.owaspMobile as string | null) ?? null, masvsControl: (f.masvsControl as string | null) ?? null,
        crossBuildFingerprint: (f.crossBuildFingerprint as string | null) ?? null,
        dynamicConfirmed: f.dynamicConfirmed === true,
      })),
    };
  }

  // ── Version lineage (§105–§108) ─────────────────────────────────

  async compareVersions(user: RequestUser, appId: string, input: { fromBuildId: string; toBuildId: string }) {
    requireMobileBinaryV2Permission(user, "VIEW_MOBILE_SECURITY");
    const { workspace, app } = await this.loadApp(user, appId);
    const from = await this.loadBuildRow(workspace.id, app.id, input.fromBuildId);
    const to = await this.loadBuildRow(workspace.id, app.id, input.toBuildId);
    const [prevFindings, curFindings, olderBuilds] = await Promise.all([
      this.findingsOfBuild(from.id), this.findingsOfBuild(to.id),
      this.prisma.mobileBuild.findMany({ where: { applicationId: app.id, workspaceId: workspace.id } }),
    ]);
    // Regression evidence: fingerprints seen in builds OLDER than
    // `from` but absent from `from` itself (§157).
    const fromFps = new Set(prevFindings.map((f) => f.crossBuildFingerprint).filter(Boolean));
    const earlierAbsent = new Set<string>();
    for (const b of olderBuilds as unknown as Row[]) {
      if (b.id === from.id || b.id === to.id) continue;
      if (new Date(b.createdAt as string).getTime() >= new Date(from.createdAt as string).getTime()) continue;
      for (const f of await this.findingsOfBuild(b.id)) {
        if (f.crossBuildFingerprint && !fromFps.has(f.crossBuildFingerprint)) earlierAbsent.add(f.crossBuildFingerprint);
      }
    }
    const result = compareBuildFindings({ previous: prevFindings, current: curFindings, earlierAbsent });
    const lineage = await this.prisma.applicationVersionLineage.create({
      data: {
        workspaceId: workspace.id, applicationId: app.id,
        fromBuildId: from.id, toBuildId: to.id, summary: result.summary as never, comparedBy: user.id,
      },
    });
    for (const e of result.entries) {
      await this.prisma.mobileFindingCarryForward.create({
        data: {
          workspaceId: workspace.id, lineageId: (lineage as Row).id,
          crossBuildFingerprint: e.crossBuildFingerprint, classification: e.classification,
          fromFindingId: e.fromFindingId, toFindingId: e.toFindingId,
          ruleId: e.ruleId, title: e.title, severity: e.severity,
        },
      }).catch(() => undefined);
    }
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "MOBILE_FINDING_VERIFIED", resourceType: "ApplicationVersionLineage", resourceId: (lineage as Row).id,
      metadata: { event: "VERSION_COMPARISON", summary: result.summary, note: "FIXED_CANDIDATE entries require Prompt 31 targeted verification — comparison never closes a finding (§107/§108)" },
    });
    return {
      lineageId: (lineage as Row).id, applicationId: app.id,
      fromBuildId: from.id, toBuildId: to.id, summary: result.summary,
      entries: result.entries.map((e) => ({
        ...e,
        // §107: the verification path for a candidate — the P31
        // targeted retest plan for its rule against the NEW build.
        retestPlan: e.classification === "FIXED_CANDIDATE" ? planMobileRetest({ ruleId: e.ruleId ?? undefined }) : null,
      })),
    };
  }

  async listLineage(user: RequestUser, appId: string) {
    requireMobileBinaryV2Permission(user, "VIEW_MOBILE_SECURITY");
    const { workspace } = await this.loadApp(user, appId);
    const rows = await this.prisma.applicationVersionLineage.findMany({
      where: { applicationId: appId, workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 100,
    }).catch(() => []);
    return { items: (rows as unknown as Row[]).map((r) => ({ id: r.id, fromBuildId: r.fromBuildId, toBuildId: r.toBuildId, summary: r.summary ?? {}, createdAt: r.createdAt ?? null })) };
  }

  // ── Coverage (§121–§126) ────────────────────────────────────────

  async getMobileCoverage(user: RequestUser, artifactId: string) {
    requireMobileBinaryV2Permission(user, "VIEW_MOBILE_SECURITY");
    const { workspace, build } = await this.loadBuild(user, artifactId);
    const artifacts = (build.analysisArtifacts as Record<string, unknown> | null) ?? {};
    const [components, endpoints, libraries, trafficCount, dynamicCount, findings] = await Promise.all([
      this.prisma.mobileAppComponent.count({ where: { buildId: build.id } }).catch(() => 0),
      this.prisma.mobileEndpoint.count({ where: { buildId: build.id } }).catch(() => 0),
      this.prisma.mobileNativeLibrary.findMany({ where: { buildId: build.id }, take: 500 }).catch(() => []),
      this.prisma.mobileTrafficSession.count({ where: { buildId: build.id } }).catch(() => 0),
      this.prisma.mobileDynamicSession.count({ where: { buildId: build.id, status: "COMPLETED" } }).catch(() => 0),
      this.prisma.finding.count({ where: { mobileBuildId: build.id } }).catch(() => 0),
    ]);
    void endpoints;
    const protection = detectProtectionEvidence({
      stripped: (libraries as unknown as Row[]).some((l) => l.stripped === true),
    });
    const coverage = computeMobileCoverage({
      hasManifest: Boolean(artifacts.manifestText || artifacts.infoPlist || artifacts.networkSecurityConfig),
      permissionCount: Array.isArray(artifacts.permissions) ? artifacts.permissions.length : 0,
      componentCount: components, codeRuleFindingCount: findings,
      hasDecompiledEvidence: Boolean(artifacts.decompiledSnippets || artifacts.codeSnippets),
      componentInventoryCount: await this.prisma.softwareComponent.count({ where: { buildId: build.id } }).catch(() => 0),
      secretScanRan: build.status === "ANALYZED",
      nativeLibraryCount: (libraries as unknown as Row[]).length,
      dynamicModulesRun: dynamicCount > 0 ? ["RUNTIME_OBSERVATION"] : [],
      trafficSessionCount: trafficCount,
      symbolsAvailable: !(libraries as unknown as Row[]).some((l) => l.stripped === true),
      obfuscation: protection.obfuscation, packing: protection.packing,
    });
    const row = await this.prisma.mobileSecurityCoverage.create({
      data: {
        workspaceId: workspace.id, buildId: build.id, dimensions: coverage.dimensions as never,
        completion: coverage.completion, obfuscation: coverage.obfuscation as never, packing: coverage.packing as never,
      },
    });
    return { id: (row as Row).id, buildId: build.id, ...coverage };
  }

  async getBinaryCoverage(user: RequestUser, artifactId: string) {
    requireMobileBinaryV2Permission(user, "VIEW_BINARY_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const artifact = (await this.prisma.binaryArtifact.findFirst({
      where: { id: artifactId, workspaceId: workspace.id },
    })) as unknown as Row | null;
    if (!artifact) throw new NotFoundException("Binary artifact not found");
    const [imports, exportsCount, strings, functions, deps, hardening] = await Promise.all([
      this.prisma.binaryImport.count({ where: { artifactId } }).catch(() => 0),
      this.prisma.binaryExport.count({ where: { artifactId } }).catch(() => 0),
      this.prisma.binaryString.count({ where: { artifactId } }).catch(() => 0),
      this.prisma.binaryFunction.count({ where: { artifactId } }).catch(() => 0),
      this.prisma.binaryDependency.count({ where: { artifactId } }).catch(() => 0),
      this.prisma.binaryHardeningProfile.findFirst({ where: { artifactId } }).catch(() => null),
    ]);
    const coverage = computeBinaryCoverage({
      formatParsed: (artifact.format as string) !== "UNKNOWN",
      hasHardeningProfile: Boolean(hardening),
      importCount: imports, exportCount: exportsCount, stringCount: strings,
      functionCount: functions, dependencyCount: deps,
      // §64: licensed decompilers are capability-detected; absent
      // here, so the gap is recorded — the pipeline continues.
      decompilationAvailable: false,
      decompilationUnavailableReason: "decompilation capability NOT_CONFIGURED in this environment (§64) — recorded as a gap, pipeline continues",
    });
    const row = await this.prisma.binarySecurityCoverage.create({
      data: { workspaceId: workspace.id, artifactId, dimensions: coverage.dimensions as never, completion: coverage.completion },
    });
    return { id: (row as Row).id, artifactId, ...coverage };
  }

  // ── Binary surface (§133) ───────────────────────────────────────

  async listBinaryArtifacts(user: RequestUser) {
    requireMobileBinaryV2Permission(user, "VIEW_BINARY_SECURITY");
    return this.binary.listArtifacts(user);
  }

  async getBinaryArtifact(user: RequestUser, artifactId: string) {
    requireMobileBinaryV2Permission(user, "VIEW_BINARY_SECURITY");
    return this.binary.getArtifact(user, artifactId);
  }

  async analyzeBinary(user: RequestUser, artifactId: string, input: { profile?: string }) {
    requireMobileBinaryV2Permission(user, "RUN_BINARY_ANALYSIS");
    const profile = input.profile ?? "BINARY_STATIC";
    if (!mobbinProfileDefinition(profile)) throw new BadRequestException(`Unknown V2 analysis profile: ${profile}`);
    const workspace = await resolveWorkspace(this.prisma, user);
    const artifact = (await this.prisma.binaryArtifact.findFirst({
      where: { id: artifactId, workspaceId: workspace.id },
    })) as unknown as Row | null;
    if (!artifact) throw new NotFoundException("Binary artifact not found");
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "BINARY_ANALYSIS_STARTED", resourceType: "BinaryArtifact", resourceId: artifactId,
      metadata: { profile, sha256: artifact.sha256 },
    });
    const scanProfile = profile === "BINARY_HARDENING" ? "BINARY_HARDENING_ANALYSIS" : "BINARY_STATIC_ANALYSIS";
    const started = await this.binary.startScan(user, artifactId, { profile: scanProfile as never });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "BINARY_ANALYSIS_COMPLETED", resourceType: "BinaryArtifact", resourceId: artifactId,
      metadata: { profile, event: "SCAN_START_RECORDED" },
    });
    return { artifactId, profile, scan: started };
  }

  // ── Reports & AI (§127–§132) ────────────────────────────────────

  async getReportDefinition(user: RequestUser, kind: string) {
    requireMobileBinaryV2Permission(user, "EXPORT_MOBILE_REPORT");
    const def = mobbinReportDefinition(kind);
    if (!def) throw new BadRequestException(`Unknown mobile/binary report kind: ${kind}`);
    return { ...def, substrate: "Prompt 20 SecurityReport/ReportSnapshot — immutable, redacted (§128)" };
  }

  async nlQuery(user: RequestUser, text: string) {
    requireMobileBinaryV2Permission(user, "VIEW_MOBILE_SECURITY");
    const guard = guardMobileAiRequest(text);
    if (!guard.allowed) return { refused: true, category: guard.category, refusal: guard.refusal, executed: false };
    const plan = planMobileNlQuery(text);
    return { refused: false, plan, executed: false as const, note: "Deterministic plan over governed records — answers cite stored findings only (§129)" };
  }

  // ── helpers ─────────────────────────────────────────────────────

  private async loadApp(user: RequestUser, appId: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const app = (await this.prisma.mobileApplication.findFirst({
      where: { id: appId, workspaceId: workspace.id },
    })) as unknown as Row | null;
    if (!app) throw new NotFoundException("Mobile application not found");
    return { workspace, app };
  }

  private async loadBuild(user: RequestUser, buildId: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const build = (await this.prisma.mobileBuild.findFirst({
      where: { id: buildId, workspaceId: workspace.id },
    })) as unknown as Row | null;
    if (!build) throw new NotFoundException("Mobile artifact (build) not found");
    const app = (await this.prisma.mobileApplication.findFirst({
      where: { id: build.applicationId as string, workspaceId: workspace.id },
    })) as unknown as Row | null;
    if (!app) throw new NotFoundException("Mobile application not found");
    return { workspace, app, build };
  }

  private async loadBuildRow(workspaceId: string, appId: string, buildId: string) {
    const build = (await this.prisma.mobileBuild.findFirst({
      where: { id: buildId, applicationId: appId, workspaceId },
    })) as unknown as Row | null;
    if (!build) throw new NotFoundException("Build not found for this application");
    return build;
  }

  private async findingsOfBuild(buildId: string): Promise<CarryForwardFindingRef[]> {
    const rows = await this.prisma.finding.findMany({
      where: { mobileBuildId: buildId, duplicateOfId: null }, take: 2000,
    }).catch(() => []);
    return (rows as unknown as Row[])
      .filter((f) => typeof f.crossBuildFingerprint === "string" && f.crossBuildFingerprint)
      .map((f) => ({
        crossBuildFingerprint: f.crossBuildFingerprint as string,
        findingId: f.id, ruleId: (f.ruleId as string | null) ?? null,
        title: f.title as string, severity: f.severity as string, status: f.status as string,
      }));
  }
}
