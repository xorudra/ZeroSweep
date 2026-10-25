import {
  BadRequestException, ConflictException, Inject, Injectable, NotFoundException,
} from "@nestjs/common";
import {
  NETWORK_PROFILE_KEYS, NETWORK_TOOL_CAPABILITIES, assessExposure, buildNetworkScopeSnapshot,
  clampNetworkVaptBudget, compareNetworkSnapshots, decideDiscoveredHost,
  evaluateCredentialedScan, evaluateMasscanGate, evaluateMetasploitVerification,
  evaluateNetworkPreflight, evaluatePacketCapture, groundedNetworkAnswer,
  networkProfileDefinition, networkToolCapability, networkToolHealthView,
  normalizeNetworkTarget, parseCidr, planNetworkVerification, resolvePortSet,
  scannerLogicalProfile, selectNseScriptsV2, workloadClassOf,
  type NetworkAuthorizationFacts, type NetworkVaptProfileKey,
} from "@zerosweep/security-sdk";
import { AuditService } from "../audit/audit.service";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { resolveWorkspace } from "../../common/tenant";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { requireNetworkPermission, networkPermissionsFor, type NetworkPermission } from "./permissions";

type AuthUser = RequestUser;
type Headers = Record<string, string | string[] | undefined>;

const ENVIRONMENTS = ["PRODUCTION", "STAGING", "DEVELOPMENT", "TEST", "INTERNAL_LAB", "UNKNOWN"];
const CRITICALITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNSPECIFIED"];
const TARGET_TYPES = ["IP", "CIDR", "HOSTNAME", "AUTHORIZED_ASSET_GROUP"];
const GROUP_LABEL_RE = /^[A-Za-z0-9][A-Za-z0-9-_ ]{1,63}$/;

/**
 * Network VAPT V2 (Prompt 33). Deepens the Prompt 10 engine on the same
 * governance chain as Prompt 32's web VAPT: a V2 target exists only
 * under a VERIFIED parent target + an APPROVED assessment (the
 * authorization record); preflight decides on real authorization facts
 * while reachability/worker transports report NOT_CONFIGURED (never
 * assumed); plans freeze an immutable scope snapshot with clamped
 * budgets, the §27 Masscan gate and the §37 NSE policy evaluated in the
 * open; scans materialize only on a READY preflight — which this
 * deployment honestly never produces, so no scan is ever fabricated.
 */
@Injectable()
export class NetworkVaptService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly auditService: AuditService,
  ) {}

  private ws(user: AuthUser, headers: Headers) {
    return resolveWorkspace(this.prisma, user, headers["x-workspace-id"] as string | undefined);
  }

  private async audit(workspaceId: string, user: AuthUser, action: string, entityType: string, entityId: string, metadata?: Record<string, unknown>): Promise<void> {
    await this.auditService
      .record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: action as never, resourceType: entityType, resourceId: entityId,
        ...(metadata ? { metadata } : {}),
      })
      .catch(() => undefined);
  }

  private has(user: AuthUser, permission: NetworkPermission): boolean {
    try { requireNetworkPermission(user, permission); return true; } catch { return false; }
  }

  mePermissions(user: AuthUser) {
    return { role: user.role, permissions: networkPermissionsFor(user.role) };
  }

  /* ------------------------------- targets (§3–§7) ------------------------------- */

  async listTargets(user: AuthUser, headers: Headers) {
    requireNetworkPermission(user, "VIEW_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    return this.prisma.networkVaptTarget.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" } });
  }

  private async targetOr404(workspaceId: string, id: string) {
    const target = await this.prisma.networkVaptTarget.findFirst({ where: { id, workspaceId } });
    if (!target) throw new NotFoundException("Network VAPT target not found");
    return target;
  }

  async createTarget(user: AuthUser, headers: Headers, body: Record<string, unknown>) {
    requireNetworkPermission(user, "MANAGE_NETWORK_TARGETS");
    const workspace = await this.ws(user, headers);
    const parent = await this.prisma.target.findFirst({ where: { id: String(body.targetId ?? ""), workspaceId: workspace.id } });
    if (!parent) throw new NotFoundException("Parent target not found in this workspace");
    const asset = await this.prisma.asset.findFirst({ where: { id: String(body.assetId ?? ""), workspaceId: workspace.id } });
    if (!asset) throw new NotFoundException("Asset not found in this workspace");
    if (parent.verified !== true) {
      throw new BadRequestException("Parent target must be VERIFIED before a network VAPT target can be created (§7) — ownership verification precedes any active network operation");
    }
    const assessment = body.assessmentId
      ? await this.prisma.assessment.findFirst({ where: { id: String(body.assessmentId), workspaceId: workspace.id } })
      : await this.prisma.assessment.findFirst({ where: { workspaceId: workspace.id, targetId: parent.id, status: "APPROVED" } });
    if (!assessment) throw new BadRequestException("An APPROVED assessment (the authorization record) is required before a network target can be created (§7)");
    if (assessment.status !== "APPROVED") throw new BadRequestException(`Assessment is ${assessment.status}, not APPROVED — no authorization exists for active network operations (§7)`);
    // Approval independence (security audit 2026-10-16 run-2): a
    // self-approved assessment is not an authorization record.
    if (!assessment.approvedBy || assessment.approvedBy === assessment.createdBy) {
      throw new BadRequestException("Assessment approval must be independent: recorded, and granted by someone other than its creator (§7)");
    }

    const requestedType = String(body.targetType ?? "");
    if (requestedType && !TARGET_TYPES.includes(requestedType)) throw new BadRequestException(`targetType must be one of ${TARGET_TYPES.join(", ")} (§4)`);

    let targetType: string;
    let targetValue: string;
    if (requestedType === "AUTHORIZED_ASSET_GROUP") {
      const label = String(body.targetValue ?? body.groupLabel ?? "").trim();
      if (!GROUP_LABEL_RE.test(label)) throw new BadRequestException("Asset-group label is invalid — letters, digits, dashes, underscores and spaces only (§138)");
      await this.resolveGroupMembers(workspace.id, body.memberAssetIds);
      targetType = "AUTHORIZED_ASSET_GROUP";
      targetValue = label;
    } else {
      const raw = String(body.targetValue ?? parent.value ?? "");
      const normalized = normalizeNetworkTarget(raw, { internalAuthorized: body.internalEngagementApproved === true });
      if (!normalized.ok || !normalized.target) {
        throw new BadRequestException(`Target refused: ${normalized.detail ?? normalized.reason} (§5/§6)`);
      }
      if (requestedType && normalized.target.type !== requestedType) {
        throw new BadRequestException(`Declared targetType ${requestedType} does not match the normalized value type ${normalized.target.type} (§6)`);
      }
      targetType = normalized.target.type;
      targetValue = normalized.target.value;
    }

    const profileKey = NETWORK_PROFILE_KEYS.includes(String(body.scanProfileId ?? "") as NetworkVaptProfileKey)
      ? String(body.scanProfileId) : "NETWORK_SAFE";
    const row = await this.prisma.networkVaptTarget.create({
      data: {
        organizationId: user.organizationId, workspaceId: workspace.id,
        assetId: asset.id, targetId: parent.id,
        targetType, targetValue, authorizationId: assessment.id,
        environment: ENVIRONMENTS.includes(String(body.environment)) ? String(body.environment) : "PRODUCTION",
        criticality: CRITICALITIES.includes(String(body.criticality)) ? String(body.criticality) : "UNSPECIFIED",
        scanProfileId: profileKey, status: "ACTIVE", createdById: user.id,
      },
    });
    await this.audit(workspace.id, user, "NETWORK_TARGET_CREATED", "NetworkVaptTarget", row.id, {
      targetType, targetValue, profile: profileKey,
      internalEngagementAsserted: body.internalEngagementApproved === true,
    });
    return row;
  }

  async getTarget(user: AuthUser, headers: Headers, id: string) {
    requireNetworkPermission(user, "VIEW_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    const target = await this.targetOr404(workspace.id, id);
    const [preflights, plans, observations] = await Promise.all([
      this.prisma.networkVaptPreflightResult.findMany({ where: { workspaceId: workspace.id, targetId: id }, orderBy: { createdAt: "desc" }, take: 5 }),
      this.prisma.networkVaptScanPlan.findMany({ where: { workspaceId: workspace.id, targetId: id }, orderBy: { createdAt: "desc" }, take: 10 }),
      this.prisma.networkHostObservation.findMany({ where: { workspaceId: workspace.id }, orderBy: { lastSeenAt: "desc" }, take: 25 }),
    ]);
    return { target, preflights, plans, observations };
  }

  /** Group membership is resolved from REAL workspace assets, every
   *  time — a member id outside the workspace fails the request (§4). */
  private async resolveGroupMembers(workspaceId: string, memberAssetIds: unknown): Promise<Array<{ id: string; host: string; ip?: string | null }>> {
    const ids = Array.isArray(memberAssetIds) ? memberAssetIds.map(String) : [];
    if (ids.length === 0) throw new BadRequestException("AUTHORIZED_ASSET_GROUP targets require memberAssetIds — group membership is explicit, never inferred (§4)");
    const assets = await this.prisma.asset.findMany({ where: { workspaceId, id: { in: ids } } });
    if (assets.length !== ids.length) throw new BadRequestException("Every memberAssetId must be an asset in this workspace (§4/§156)");
    return assets;
  }

  /** The frozen-scope inputs for a target (§10/§11). */
  private async scopeForTarget(workspaceId: string, target: { targetType: string; targetValue: string }, memberAssetIds?: unknown) {
    if (target.targetType === "CIDR") {
      const info = parseCidr(target.targetValue);
      return { hosts: [] as string[], cidrs: [target.targetValue], hostCount: info?.hostCount ?? 0 };
    }
    if (target.targetType === "AUTHORIZED_ASSET_GROUP") {
      const members = await this.resolveGroupMembers(workspaceId, memberAssetIds);
      const hosts = [...new Set(members.map((a) => (a.ip ?? a.host).toLowerCase()))];
      return { hosts, cidrs: [] as string[], hostCount: hosts.length };
    }
    return { hosts: [target.targetValue], cidrs: [] as string[], hostCount: 1 };
  }

  private async authorizationFacts(workspaceId: string, target: { targetId: string; authorizationId: string; scanProfileId: string }): Promise<NetworkAuthorizationFacts> {
    const parent = await this.prisma.target.findFirst({ where: { id: target.targetId, workspaceId } });
    const assessment = await this.prisma.assessment.findFirst({ where: { id: target.authorizationId, workspaceId } });
    const verification = await this.prisma.targetVerification.findFirst({ where: { targetId: target.targetId }, orderBy: { createdAt: "desc" } });
    return {
      targetVerified: parent?.verified === true,
      authorizationExists: !!assessment,
      authorizationActive: assessment?.status === "APPROVED",
      authorizationExpired: verification?.expiresAt ? new Date(verification.expiresAt as Date).getTime() < Date.now() : false,
      targetCoveredByScope: !!assessment && assessment.targetId === target.targetId,
      toolAllowed: true, // profile tools are the governed catalog; per-tool gates (Masscan/NSE) are evaluated at plan time
      profileAllowed: NETWORK_PROFILE_KEYS.includes(target.scanProfileId as NetworkVaptProfileKey),
    };
  }

  /* ------------------------------- preflight (§8/§9) ------------------------------- */

  async runPreflight(user: AuthUser, headers: Headers, targetId: string, body: Record<string, unknown> = {}) {
    requireNetworkPermission(user, "RUN_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    const target = await this.targetOr404(workspace.id, targetId);
    const profile = networkProfileDefinition((target.scanProfileId ?? "NETWORK_SAFE") as NetworkVaptProfileKey);
    const facts = await this.authorizationFacts(workspace.id, target);
    // Re-normalization of an EXISTING target: creation was the gate for
    // internal ranges (asserted by a lead under an APPROVED assessment);
    // preflight re-verifies the live authorization records above.
    const syntax = target.targetType === "AUTHORIZED_ASSET_GROUP"
      ? { ok: true as const }
      : normalizeNetworkTarget(target.targetValue, { internalAuthorized: true });
    let hostCount = 0;
    try { hostCount = (await this.scopeForTarget(workspace.id, target, body.memberAssetIds)).hostCount; } catch { hostCount = 0; }

    let masscanApproved = false;
    if (body.masscanRequested === true) {
      const gate = evaluateMasscanGate({
        explicitlyRequested: true,
        highThroughputPermission: this.has(user, "RUN_HIGH_THROUGHPUT_PORT_SCAN"),
        platformPermission: typeof body.platformPermissionRef === "string" && String(body.platformPermissionRef).length > 0,
        scopeHostCount: hostCount,
        scopePortCount: resolvePortSet(profile.portPolicy).ports.length,
        ...(typeof body.masscanRate === "number" ? { requestedRate: body.masscanRate } : {}),
      });
      masscanApproved = gate.approved;
    }

    const result = evaluateNetworkPreflight({
      targetSyntaxOk: syntax.ok,
      ...(!syntax.ok && "detail" in syntax ? { targetSyntaxDetail: String((syntax as { detail?: string }).detail ?? "") } : {}),
      scopeHostCount: hostCount,
      budgetMaxHosts: profile.defaultBudget.maxHosts,
      authorization: facts,
      transport: "NOT_CONFIGURED",
      requiredTools: profile.toolSlugs,
      ...(body.masscanRequested === true ? { masscanRequested: true, masscanApproved } : {}),
      rateWithinPolicy: typeof body.requestedRatePerSecond === "number" ? body.requestedRatePerSecond <= 10_000 : true,
    });
    const row = await this.prisma.networkVaptPreflightResult.create({
      data: {
        workspaceId: workspace.id, targetId, status: result.status,
        checks: result.checks as never, probeTransport: "NOT_CONFIGURED", createdById: user.id,
      },
    });
    await this.audit(workspace.id, user, "NETWORK_PREFLIGHT_COMPLETED", "NetworkVaptTarget", targetId, { status: result.status });
    return row;
  }

  /* ------------------------------- plans (§10–§18, §27, §37) ------------------------------- */

  async createPlan(user: AuthUser, headers: Headers, targetId: string, body: Record<string, unknown>) {
    requireNetworkPermission(user, "RUN_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    const target = await this.targetOr404(workspace.id, targetId);
    const profileKey = (NETWORK_PROFILE_KEYS.includes(String(body.profileKey ?? "") as NetworkVaptProfileKey)
      ? String(body.profileKey) : target.scanProfileId) as NetworkVaptProfileKey;
    if (profileKey === "NETWORK_VULNERABILITY") requireNetworkPermission(user, "RUN_NETWORK_VULNERABILITY_SCAN");
    if (profileKey === "TARGETED_SERVICE_VERIFICATION") requireNetworkPermission(user, "RUN_TARGETED_NETWORK_VERIFICATION");
    const definition = networkProfileDefinition(profileKey);
    const blockedItems: Array<{ item: string; reason: string }> = [];

    const requested = (body.budget && typeof body.budget === "object" ? body.budget : {}) as Record<string, number>;
    const { budget, clampedFields } = clampNetworkVaptBudget(requested, definition.defaultBudget);

    // Port policy (§30–§32): FULL_TCP without a recorded policy grant
    // falls back in the open; UDP stays off unless the profile/body
    // deliberately enables a bounded set.
    const requestedPolicy = (body.portPolicy && typeof body.portPolicy === "object" ? body.portPolicy : {}) as Record<string, unknown>;
    const portPolicy = {
      set: (typeof requestedPolicy.set === "string" ? requestedPolicy.set : definition.portPolicy.set) as never,
      ...(Array.isArray(requestedPolicy.customPorts) ? { customPorts: requestedPolicy.customPorts.map(Number) } : definition.portPolicy.customPorts ? { customPorts: definition.portPolicy.customPorts } : {}),
      udpEnabled: typeof requestedPolicy.udpEnabled === "boolean" ? requestedPolicy.udpEnabled : definition.portPolicy.udpEnabled,
      ...(definition.portPolicy.udpPorts ? { udpPorts: definition.portPolicy.udpPorts } : {}),
      fullTcpApproved: body.fullTcpPolicyGrant === true,
    };
    const { ports, fullTcpGranted } = resolvePortSet(portPolicy);
    if (portPolicy.set === "FULL_TCP" && !fullTcpGranted) {
      blockedItems.push({ item: "FULL_TCP", reason: "Full TCP range requires an explicit profile/policy grant — never derived automatically (§31); fell back to the COMMON set" });
    }
    if (ports.length > budget.maxPortsPerHost) {
      blockedItems.push({ item: "PORT_POLICY", reason: `Port policy spans ${ports.length} ports — above the per-host budget of ${budget.maxPortsPerHost}; the worker enforces the budget (§17)` });
    }

    // NSE policy V2 (§37/§38): blocked categories are refused in the
    // open and recorded on the plan; the exact selected set is frozen.
    const nse = selectNseScriptsV2({
      profileKey,
      ...(Array.isArray(body.nseScripts) ? { requestedScriptIds: body.nseScripts.map(String) } : {}),
      ...(Array.isArray(body.approvedReviewScriptIds) ? { approvedReviewIds: body.approvedReviewScriptIds.map(String) } : {}),
      ...(Array.isArray(body.vulnApprovedAllowlist) ? { vulnApprovedAllowlist: body.vulnApprovedAllowlist.map(String) } : {}),
      vulnerabilityScanPermission: this.has(user, "RUN_NETWORK_VULNERABILITY_SCAN"),
    });
    for (const b of nse.blocked) blockedItems.push({ item: `NSE:${b.id}`, reason: b.reason });

    // Masscan gate (§27): never a default tool; the gate verdict is a
    // plan record, and a refused gate never adds the tool.
    const tools = [...definition.toolSlugs];
    let masscanLimits: unknown;
    if (body.masscanRequested === true) {
      const scope = await this.scopeForTarget(workspace.id, target, body.memberAssetIds);
      const gate = evaluateMasscanGate({
        explicitlyRequested: true,
        highThroughputPermission: this.has(user, "RUN_HIGH_THROUGHPUT_PORT_SCAN"),
        platformPermission: typeof body.platformPermissionRef === "string" && String(body.platformPermissionRef).length > 0,
        scopeHostCount: scope.hostCount, scopePortCount: ports.length,
        ...(typeof body.masscanRate === "number" ? { requestedRate: body.masscanRate } : {}),
      });
      if (gate.approved) { tools.push("masscan"); masscanLimits = gate.limits; }
      else blockedItems.push({ item: "MASSCAN", reason: `MASSCAN_NOT_APPROVED — ${gate.reasons.join("; ")}` });
    }

    // Credentialed scanning (§60–§63): reference-only, single-recipient
    // injection plan; refusals are recorded, never worked around.
    let credentialedInjection: unknown;
    if (body.credentialedScan && typeof body.credentialedScan === "object") {
      requireNetworkPermission(user, "RUN_CREDENTIALLED_NETWORK_SCAN");
      const cs = body.credentialedScan as Record<string, unknown>;
      const reference = String(cs.credentialReference ?? "");
      const cred = reference
        ? await this.prisma.credential.findFirst({ where: { workspaceId: workspace.id, name: reference } })
          ?? await this.prisma.credential.findFirst({ where: { workspaceId: workspace.id, id: reference } })
        : null;
      const verdict = evaluateCredentialedScan(
        {
          credentialReference: reference,
          targetScanner: String(cs.targetScanner ?? ""),
          otherScanners: tools.filter((t) => t !== String(cs.targetScanner ?? "")),
          ...(typeof cs.validationAttempts === "number" ? { validationAttempts: cs.validationAttempts } : {}),
        },
        { credentialedPermission: true, credentialExists: !!cred },
      );
      if (verdict.allowed) credentialedInjection = verdict.injectionPlan;
      else blockedItems.push({ item: "CREDENTIALED_SCAN", reason: verdict.reasons.join("; ") });
    }

    // Immutable scope snapshot (§11): frozen from the target + explicit
    // exclusions. CIDRs are stored as scope entries alongside hosts.
    const scope = await this.scopeForTarget(workspace.id, target, body.memberAssetIds);
    const exclusions = Array.isArray(body.exclusions) ? body.exclusions.map(String) : [];
    const snapshotData = buildNetworkScopeSnapshot({ hosts: scope.hosts, cidrs: scope.cidrs, exclusions });
    const snapshot = await this.prisma.scanScopeSnapshot.create({
      data: { workspaceId: workspace.id, origins: [], hosts: [...snapshotData.hosts, ...snapshotData.cidrs], exclusions: snapshotData.exclusions, hash: snapshotData.hash },
    });

    const vulnerabilityScanners = definition.vulnScannerProfile
      ? [
          { product: "GREENBONE", slug: "greenbone-openvas", logicalProfile: scannerLogicalProfile("GREENBONE", profileKey) },
          { product: "NESSUS", slug: "nessus-professional", logicalProfile: scannerLogicalProfile("NESSUS", profileKey) },
        ].filter((s) => s.logicalProfile)
      : [];

    const plan = await this.prisma.networkVaptScanPlan.create({
      data: {
        workspaceId: workspace.id, targetId, profile: profileKey,
        stages: definition.stages as never, tools: tools as never,
        portPolicy: { ...portPolicy, resolvedPortCount: ports.length, fullTcpGranted } as never,
        rateLimits: { maxRatePerSecond: budget.maxRatePerSecond, maxConcurrency: budget.maxConcurrency, ...(masscanLimits ? { masscan: masscanLimits } : {}) } as never,
        timeouts: { maxDurationSeconds: budget.maxDurationSeconds } as never,
        serviceDetection: true,
        vulnerabilityScanners: vulnerabilityScanners as never,
        verificationPolicy: { methods: ["PORT_RECHECK", "SERVICE_VERSION_RECHECK", "TLS_RECHECK", "CONFIGURATION_RECHECK", "TARGETED_VULN_RESCAN"], minimalScope: true, ...(credentialedInjection ? { credentialedInjection } : {}) } as never,
        estimatedWorkloadClass: workloadClassOf(budget, scope.hostCount),
        budget: { ...budget, clampedFields } as never,
        scopeSnapshotId: snapshot.id,
        scriptsUsed: nse.selected as never,
        blockedItems: blockedItems as never,
        status: "PLANNED", createdById: user.id,
      },
    });
    await this.prisma.scanScopeSnapshot.update({ where: { id: snapshot.id }, data: { planId: plan.id } });
    await this.audit(workspace.id, user, "NETWORK_SCAN_PLANNED", "NetworkVaptScanPlan", plan.id, { profile: profileKey, tools: tools.length, blockedItems: blockedItems.length });
    return {
      plan, scopeSnapshot: { id: snapshot.id, hash: snapshot.hash, hosts: snapshotData.hosts, cidrs: snapshotData.cidrs },
      blockedItems,
      budgetNotice: clampedFields.length > 0 ? `Budget clamped to the platform ceiling (§18): ${clampedFields.join(", ")}` : undefined,
    };
  }

  async listPlans(user: AuthUser, headers: Headers, targetId: string) {
    requireNetworkPermission(user, "VIEW_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    await this.targetOr404(workspace.id, targetId);
    return this.prisma.networkVaptScanPlan.findMany({ where: { workspaceId: workspace.id, targetId }, orderBy: { createdAt: "desc" } });
  }

  /* ------------------------------- scans (§13/§14) ------------------------------- */

  async startScan(user: AuthUser, headers: Headers, targetId: string, body: Record<string, unknown>) {
    requireNetworkPermission(user, "RUN_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    const target = await this.targetOr404(workspace.id, targetId);
    let plan = body.planId
      ? await this.prisma.networkVaptScanPlan.findFirst({ where: { id: String(body.planId), workspaceId: workspace.id, targetId } })
      : null;
    if (body.planId && !plan) throw new NotFoundException("Scan plan not found for this target");
    if (!plan) {
      const created = await this.createPlan(user, headers, targetId, { profileKey: target.scanProfileId, ...(body.memberAssetIds ? { memberAssetIds: body.memberAssetIds } : {}) });
      plan = created.plan;
    }
    if (plan.status === "STARTED") throw new ConflictException("This plan already has a started scan");
    if (plan.profile === "NETWORK_VULNERABILITY") requireNetworkPermission(user, "RUN_NETWORK_VULNERABILITY_SCAN");
    // Preflight gate (§8/§9): a scan materializes ONLY on READY /
    // READY_WITH_WARNINGS. The network probe transport is NOT_CONFIGURED
    // in this deployment, so the honest outcome is a BLOCKED plan — no
    // canonical Scan is fabricated.
    const preflight = await this.runPreflight(user, headers, targetId, body);
    if (preflight.status !== "READY" && preflight.status !== "READY_WITH_WARNINGS") {
      await this.prisma.networkVaptScanPlan.update({ where: { id: plan.id }, data: { status: "BLOCKED" } });
      throw new BadRequestException(`Scan blocked by preflight: ${preflight.status} — see the preflight checks (network probe transport is NOT_CONFIGURED in this deployment; reachability is never assumed, §8)`);
    }
    const scan = await this.prisma.scan.create({
      data: { workspaceId: workspace.id, assessmentId: target.authorizationId, status: "QUEUED", requestedBy: user.id },
    });
    await this.prisma.networkVaptScanPlan.update({ where: { id: plan.id }, data: { status: "STARTED", scanId: scan.id } });
    await this.audit(workspace.id, user, "NETWORK_SCAN_STARTED", "Scan", scan.id, { planId: plan.id, profile: plan.profile });
    return { scan, planId: plan.id, preflightStatus: preflight.status };
  }

  async listScans(user: AuthUser, headers: Headers) {
    requireNetworkPermission(user, "VIEW_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    return this.prisma.networkVaptScanPlan.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 100 });
  }

  async getScan(user: AuthUser, headers: Headers, scanId: string) {
    requireNetworkPermission(user, "VIEW_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    const plan = await this.prisma.networkVaptScanPlan.findFirst({ where: { workspaceId: workspace.id, scanId } });
    const scan = await this.prisma.scan.findFirst({ where: { id: scanId, workspaceId: workspace.id } });
    if (!scan && !plan) throw new NotFoundException("Scan not found");
    const coverage = await this.prisma.networkVaptCoverage.findFirst({ where: { workspaceId: workspace.id, scanId } });
    return { scan, plan, coverage: coverage ?? this.emptyCoverage(scanId) };
  }

  async cancelScan(user: AuthUser, headers: Headers, scanId: string) {
    requireNetworkPermission(user, "RUN_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    const plan = await this.prisma.networkVaptScanPlan.findFirst({ where: { workspaceId: workspace.id, scanId } });
    if (!plan) throw new NotFoundException("No V2 plan is attached to this scan");
    const updated = await this.prisma.networkVaptScanPlan.update({ where: { id: plan.id }, data: { status: "CANCELLED" } });
    await this.audit(workspace.id, user, "NETWORK_SCAN_CANCELLED", "Scan", scanId, { planId: plan.id });
    return updated;
  }

  /** §121–§123: unrun coverage is nulls + named limitations — never a
   *  fabricated 100%. */
  private emptyCoverage(scanId: string) {
    return {
      scanId, authorizedHosts: 0, discoveredHosts: 0, scannedHosts: 0,
      portCoverage: null, serviceCoverage: null, vulnScannerCoverage: null, credentialedCoverage: null,
      limitations: ["No coverage record exists for this scan — nothing has run in this deployment (network transports NOT_CONFIGURED), so coverage is unknown, not complete (§123)"],
      completion: "COMPLETED_WITH_GAPS",
    };
  }

  async coverage(user: AuthUser, headers: Headers) {
    requireNetworkPermission(user, "VIEW_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    const rows = await this.prisma.networkVaptCoverage.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 25 });
    return { coverage: rows, note: "Coverage is computed from recorded runs only; gaps are limitations, never silent (§121–§123)" };
  }

  /* ------------------------------- hosts & topology (§19–§42, §94–§100) ------------------------------- */

  async listHosts(user: AuthUser, headers: Headers, query: Record<string, string | undefined> = {}) {
    requireNetworkPermission(user, "VIEW_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    const assets = await this.prisma.asset.findMany({ where: { workspaceId: workspace.id }, include: { services: true }, orderBy: { createdAt: "desc" }, take: 500 });
    const segments = await this.prisma.networkSegment.findMany({ where: { workspaceId: workspace.id } });
    const zoneFor = (asset: { network?: string | null }) => segments.find((s: { cidr: string }) => asset.network && s.cidr === asset.network)?.zone ?? "UNKNOWN";
    let hosts = assets.map((a: { id: string; host: string; ip?: string | null; osHint?: string | null; network?: string | null; criticality?: string; services: Array<{ port: number; name?: string | null; state?: string | null }> }) => {
      const open = (a.services ?? []).filter((s) => !s.state || s.state === "OPEN");
      const sensitive = open.map((s) => ({ port: s.port, exposure: assessExposure({ zone: zoneFor(a) as never, port: s.port, ...(s.name ? { service: s.name } : {}) }) }));
      return {
        id: a.id, host: a.host, ip: a.ip ?? null, osHint: a.osHint ?? null, network: a.network ?? null,
        zone: zoneFor(a), criticality: a.criticality ?? "UNSPECIFIED",
        openServices: open.length,
        internetExposedSensitive: sensitive.filter((s) => s.exposure.sensitiveServicePubliclyExposed).length,
      };
    });
    if (query.zone) hosts = hosts.filter((h: { zone: string }) => h.zone === query.zone);
    if (query.q) { const q = query.q.toLowerCase(); hosts = hosts.filter((h: { host: string; ip?: string | null }) => h.host.toLowerCase().includes(q) || (h.ip ?? "").includes(q)); }
    return hosts;
  }

  async getHost(user: AuthUser, headers: Headers, id: string) {
    requireNetworkPermission(user, "VIEW_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    const asset = await this.prisma.asset.findFirst({ where: { id, workspaceId: workspace.id }, include: { services: true } });
    if (!asset) throw new NotFoundException("Host not found");
    const observations = await this.prisma.networkHostObservation.findMany({ where: { workspaceId: workspace.id, assetId: id }, orderBy: { lastSeenAt: "desc" } });
    const osObservations = await this.prisma.osFingerprintObservation.findMany({ where: { workspaceId: workspace.id, assetId: id }, orderBy: { observedAt: "desc" } });
    const findings = await this.prisma.finding.findMany({ where: { assetId: id }, orderBy: { createdAt: "desc" }, take: 100 });
    const services = (asset.services ?? []).map((s: { port: number; name?: string | null; product?: string | null; version?: string | null; state?: string | null; protocol: string }) => ({
      ...s,
      exposure: assessExposure({ zone: "UNKNOWN", port: s.port, ...(s.name ? { service: s.name } : {}) }),
      verification: planNetworkVerification({ host: asset.host, port: s.port, ...(s.name ? { kind: s.name } : {}) }),
    }));
    return { host: asset, services, observations, osObservations, findings };
  }

  /** §12/§21: ingest a discovered-host observation — recorded as a
   *  CANDIDATE when outside the supplied snapshot; never scanned. */
  async recordDiscovery(user: AuthUser, headers: Headers, body: Record<string, unknown>) {
    requireNetworkPermission(user, "RUN_NETWORK_DISCOVERY");
    const workspace = await this.ws(user, headers);
    const snapshot = buildNetworkScopeSnapshot({
      hosts: Array.isArray(body.snapshotHosts) ? body.snapshotHosts.map(String) : [],
      cidrs: Array.isArray(body.snapshotCidrs) ? body.snapshotCidrs.map(String) : [],
      exclusions: Array.isArray(body.snapshotExclusions) ? body.snapshotExclusions.map(String) : [],
    });
    const ip = String(body.ip ?? "");
    const decision = decideDiscoveredHost(snapshot, ip, { recordCandidates: body.recordCandidates !== false });
    if (decision.membership === "INVALID") throw new BadRequestException("ip must be a valid IP literal (§138)");
    if (decision.membership === "EXCLUDED" || (!decision.scannable && !decision.recordCandidate)) {
      return { decision, recorded: false };
    }
    const row = await this.prisma.networkHostObservation.create({
      data: {
        workspaceId: workspace.id, ip,
        ...(typeof body.hostname === "string" ? { hostname: body.hostname } : {}),
        ...(typeof body.macAddress === "string" ? { macAddress: body.macAddress } : {}),
        ...(typeof body.vendorHint === "string" ? { vendorHint: body.vendorHint } : {}),
        discoveryMethod: typeof body.discoveryMethod === "string" ? body.discoveryMethod : "IMPORT",
        hostStatus: typeof body.hostStatus === "string" ? body.hostStatus : "UNKNOWN",
        scopeStatus: decision.scannable ? "IN_SCOPE" : "CANDIDATE",
        confidence: typeof body.confidence === "number" ? body.confidence : 0.5,
      },
    });
    await this.audit(workspace.id, user, "NETWORK_HOST_DISCOVERED", "NetworkHostObservation", row.id, { ip, scopeStatus: row.scopeStatus, scannable: decision.scannable });
    return { decision, recorded: true, observation: row };
  }

  /* ------------------------------- segments, baselines, drift (§94–§107) ------------------------------- */

  async listSegments(user: AuthUser, headers: Headers) {
    requireNetworkPermission(user, "VIEW_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    return this.prisma.networkSegment.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" } });
  }

  async createSegment(user: AuthUser, headers: Headers, body: Record<string, unknown>) {
    requireNetworkPermission(user, "MANAGE_NETWORK_PROFILES");
    const workspace = await this.ws(user, headers);
    const cidr = String(body.cidr ?? "");
    if (!parseCidr(cidr)) throw new BadRequestException("Segment cidr must be a valid CIDR (§95)");
    const zones = ["INTERNET", "DMZ", "INTERNAL", "RESTRICTED", "MANAGEMENT", "UNKNOWN"];
    const row = await this.prisma.networkSegment.create({
      data: {
        workspaceId: workspace.id, name: String(body.name ?? "segment"), cidr,
        environment: typeof body.environment === "string" ? body.environment : "PRODUCTION",
        zone: zones.includes(String(body.zone)) ? String(body.zone) : "UNKNOWN",
        criticality: CRITICALITIES.includes(String(body.criticality)) ? String(body.criticality) : "MEDIUM",
        ...(typeof body.owner === "string" ? { owner: body.owner } : {}),
        createdById: user.id,
      },
    });
    return row;
  }

  async createBaseline(user: AuthUser, headers: Headers, body: Record<string, unknown>) {
    requireNetworkPermission(user, "MANAGE_NETWORK_PROFILES");
    const workspace = await this.ws(user, headers);
    const segmentId = typeof body.segmentId === "string" ? body.segmentId : undefined;
    const latest = await this.prisma.networkBaseline.findFirst({
      where: { workspaceId: workspace.id, ...(segmentId ? { segmentId } : { segmentId: null }) },
      orderBy: { version: "desc" },
    });
    const hosts = Array.isArray(body.hosts) ? body.hosts : [];
    const { createHash } = await import("node:crypto");
    const hash = createHash("sha256").update(JSON.stringify(hosts)).digest("hex");
    const row = await this.prisma.networkBaseline.create({
      data: {
        workspaceId: workspace.id, ...(segmentId ? { segmentId } : {}),
        version: (latest?.version ?? 0) + 1, hosts: hosts as never, hash, createdById: user.id,
      },
    });
    return row;
  }

  async listDrift(user: AuthUser, headers: Headers) {
    requireNetworkPermission(user, "VIEW_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    return this.prisma.networkDriftEvent.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 100 });
  }

  /** Compare a fresh posture against the latest baseline (§101–§103)
   *  and persist the drift events. */
  async computeDrift(user: AuthUser, headers: Headers, body: Record<string, unknown>) {
    requireNetworkPermission(user, "RUN_NETWORK_DISCOVERY");
    const workspace = await this.ws(user, headers);
    const baseline = await this.prisma.networkBaseline.findFirst({ where: { workspaceId: workspace.id }, orderBy: { version: "desc" } });
    if (!baseline) throw new BadRequestException("No baseline exists yet — create one before drift can be computed (§104)");
    const current = Array.isArray(body.hosts) ? (body.hosts as never[]) : [];
    const events = compareNetworkSnapshots(
      { version: baseline.version, capturedAt: new Date(baseline.createdAt as Date).toISOString(), hosts: (baseline.hosts ?? []) as never },
      current as never,
    );
    const rows = [];
    for (const event of events) {
      rows.push(await this.prisma.networkDriftEvent.create({
        data: {
          workspaceId: workspace.id, baselineId: baseline.id, host: event.host,
          kind: event.kind, detail: event.detail, riskSignal: event.riskSignal, signalReason: event.signalReason,
        },
      }));
      await this.audit(workspace.id, user, "NETWORK_DRIFT_DETECTED", "NetworkDriftEvent", baseline.id, { host: event.host, kind: event.kind, riskSignal: event.riskSignal });
    }
    return { baselineVersion: baseline.version, events: rows };
  }

  /* ------------------------------- packet captures (§83–§93) ------------------------------- */

  async createPacketCapture(user: AuthUser, headers: Headers, body: Record<string, unknown>) {
    requireNetworkPermission(user, "CREATE_PACKET_CAPTURE");
    const workspace = await this.ws(user, headers);
    const verdict = evaluatePacketCapture({
      interfaceReference: String(body.interfaceReference ?? ""),
      interfaceAuthorized: body.interfaceAuthorized === true,
      durationSeconds: Number(body.durationSeconds ?? 0),
      sizeLimitBytes: Number(body.sizeLimitBytes ?? 0),
      ...(typeof body.filter === "string" ? { filter: body.filter } : {}),
      callerCanCreate: true,
      storageQuotaBytes: Number(body.storageQuotaBytes ?? 10_737_418_240),
      storageUsedBytes: Number(body.storageUsedBytes ?? 0),
    });
    if (!verdict.allowed) {
      throw new BadRequestException(`Packet capture refused: ${verdict.reasons.join("; ")} (§84/§87)`);
    }
    const row = await this.prisma.networkPacketCaptureJob.create({
      data: {
        workspaceId: workspace.id,
        ...(typeof body.targetId === "string" ? { targetId: body.targetId } : {}),
        interfaceReference: String(body.interfaceReference),
        ...(typeof body.filter === "string" ? { filter: body.filter } : {}),
        durationSeconds: verdict.effective!.durationSeconds,
        sizeLimitBytes: verdict.effective!.sizeLimitBytes,
        status: "REQUESTED", transport: "NOT_CONFIGURED", createdById: user.id,
      },
    });
    await this.audit(workspace.id, user, "PACKET_CAPTURE_STARTED", "NetworkPacketCaptureJob", row.id, { transport: "NOT_CONFIGURED", note: "Capture requested; no capture transport is wired in this deployment — the job is recorded, not executed (§85)" });
    return { ...row, note: "Capture transport is NOT_CONFIGURED in this deployment: the request is recorded with its bounds; no traffic is captured or fabricated (§85/§88)" };
  }

  async listPacketCaptures(user: AuthUser, headers: Headers) {
    requireNetworkPermission(user, "VIEW_PACKET_CAPTURE");
    const workspace = await this.ws(user, headers);
    return this.prisma.networkPacketCaptureJob.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 100 });
  }

  async getPacketCapture(user: AuthUser, headers: Headers, id: string) {
    requireNetworkPermission(user, "VIEW_PACKET_CAPTURE");
    const workspace = await this.ws(user, headers);
    const row = await this.prisma.networkPacketCaptureJob.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!row) throw new NotFoundException("Packet capture not found");
    return row;
  }

  /* ------------------------------- exploit refs + Metasploit policy (§72–§82) ------------------------------- */

  async listExploitReferences(user: AuthUser, headers: Headers, query: Record<string, string | undefined>) {
    requireNetworkPermission(user, "VIEW_NETWORK_VAPT");
    await this.ws(user, headers);
    const rows = await this.prisma.defensiveExploitReference.findMany({ take: 100 });
    const filtered = query.cve
      ? rows.filter((r: { cveIds: unknown }) => Array.isArray(r.cveIds) && (r.cveIds as string[]).includes(query.cve!.toUpperCase()))
      : query.product
        ? rows.filter((r: { affectedProduct: string }) => r.affectedProduct.toLowerCase().includes(query.product!.toLowerCase()))
        : rows;
    return {
      datasetState: rows.length === 0 ? "EMPTY" : "POPULATED",
      note: "Defensive metadata only (§72–§74): references inform prioritization; nothing here downloads, compiles or executes exploit code",
      references: filtered.map((r: { referenceId: string; title: string; affectedProduct: string; cveIds: unknown; source: string; referenceUrl: string }) => ({
        referenceId: r.referenceId, title: r.title, affectedProduct: r.affectedProduct,
        cveIds: r.cveIds, source: r.source, referenceUrl: r.referenceUrl,
        meaning: "PUBLIC_EXPLOIT_REFERENCE_EXISTS", executable: false,
      })),
    };
  }

  async requestMetasploitVerification(user: AuthUser, headers: Headers, body: Record<string, unknown>) {
    requireNetworkPermission(user, "RUN_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    const host = String(body.host ?? "");
    let hostInScope = false;
    let snapshotHash: string | undefined;
    if (typeof body.planId === "string") {
      const plan = await this.prisma.networkVaptScanPlan.findFirst({ where: { id: body.planId, workspaceId: workspace.id } });
      if (plan?.scopeSnapshotId) {
        const snapshot = await this.prisma.scanScopeSnapshot.findFirst({ where: { id: plan.scopeSnapshotId } });
        if (snapshot) {
          snapshotHash = snapshot.hash as string;
          const entries = (snapshot.hosts ?? []) as string[];
          hostInScope = entries.some((e) => e.toLowerCase() === host.toLowerCase());
        }
      }
    }
    const verdict = evaluateMetasploitVerification({
      moduleId: String(body.moduleId ?? ""),
      targetHost: host,
      findingId: String(body.findingId ?? ""),
      ...(typeof body.intentDescription === "string" ? { intentDescription: body.intentDescription } : {}),
      ...(typeof body.payloadRequested === "string" ? { payloadRequested: body.payloadRequested } : {}),
      controlledVerificationPermission: this.has(user, "RUN_CONTROLLED_METASPLOIT_VERIFICATION"),
      hostAuthorized: body.hostAuthorized === true,
      hostInScope,
    });
    const row = await this.prisma.metasploitVerificationRequest.create({
      data: {
        workspaceId: workspace.id,
        ...(typeof body.targetId === "string" ? { targetId: body.targetId } : {}),
        findingId: String(body.findingId ?? ""), host, moduleId: String(body.moduleId ?? ""),
        decision: verdict.decision, reasons: verdict.reasons as never, transport: verdict.transport,
        requestedById: user.id,
      },
    });
    await this.audit(workspace.id, user, "CONTROLLED_METASPLOIT_VERIFICATION_REQUESTED", "MetasploitVerificationRequest", row.id, { decision: verdict.decision, moduleId: row.moduleId, ...(snapshotHash ? { snapshotHash } : {}) });
    return { request: row, verdict };
  }

  /* ------------------------------- tool health, reports, AI (§120–§126, §132) ------------------------------- */

  async toolHealth(user: AuthUser, headers: Headers) {
    requireNetworkPermission(user, "VIEW_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    void workspace;
    let toolRows: Array<{ slug: string; enabled: boolean; healthStatus: string }> = [];
    try {
      const rows = await this.prisma.tool.findMany({});
      toolRows = rows.map((r: { slug: string; enabled?: boolean; healthStatus?: string }) => ({ slug: r.slug, enabled: r.enabled ?? false, healthStatus: r.healthStatus ?? "NOT_CONFIGURED" }));
    } catch { toolRows = []; }
    const bySlug = new Map(toolRows.map((r) => [r.slug, r]));
    return Object.keys(NETWORK_TOOL_CAPABILITIES).map((slug) => networkToolHealthView(bySlug.get(slug), networkToolCapability(slug)));
  }

  async reportSummary(user: AuthUser, headers: Headers) {
    requireNetworkPermission(user, "EXPORT_NETWORK_REPORT");
    const workspace = await this.ws(user, headers);
    const [targets, plans, hosts, drift, captures] = await Promise.all([
      this.prisma.networkVaptTarget.count({ where: { workspaceId: workspace.id } }),
      this.prisma.networkVaptScanPlan.count({ where: { workspaceId: workspace.id } }),
      this.prisma.asset.count({ where: { workspaceId: workspace.id } }),
      this.prisma.networkDriftEvent.count({ where: { workspaceId: workspace.id } }),
      this.prisma.networkPacketCaptureJob.count({ where: { workspaceId: workspace.id } }),
    ]);
    const types = [
      "Network VAPT Report", "Infrastructure Vulnerability Report", "Network Exposure Report",
      "Network Drift Report", "Network Verification Report", "Executive Infrastructure Security Report",
    ];
    return {
      reports: types.map((name) => ({
        name,
        sections: ["scope", "authorization", "methodology", "tools + versions", "network coverage", "host coverage", "port/service inventory", "findings", "CVE intelligence", "risk", "evidence (sanitized, §134/§135)", "limitations", "remediation", "verification"],
      })),
      facts: { targets, plans, hosts, driftEvents: drift, packetCaptures: captures },
      note: "Report content derives from recorded evidence only; banners are classification-redacted before inclusion (§135). Rendering engines live in the Prompt 20 reporting module.",
    };
  }

  async aiSuggest(user: AuthUser, headers: Headers, body: Record<string, unknown>) {
    requireNetworkPermission(user, "VIEW_NETWORK_VAPT");
    const workspace = await this.ws(user, headers);
    const question = String(body.question ?? body.prompt ?? "");
    const [targets, assets, drift] = await Promise.all([
      this.prisma.networkVaptTarget.count({ where: { workspaceId: workspace.id } }),
      this.prisma.asset.findMany({ where: { workspaceId: workspace.id }, include: { services: true }, take: 500 }),
      this.prisma.networkDriftEvent.count({ where: { workspaceId: workspace.id } }),
    ]);
    let openServices = 0;
    let sensitiveExposed = 0;
    for (const a of assets as Array<{ services: Array<{ port: number; name?: string | null; state?: string | null }> }>) {
      for (const s of a.services ?? []) {
        if (s.state && s.state !== "OPEN") continue;
        openServices += 1;
        if (assessExposure({ zone: "UNKNOWN", port: s.port, ...(s.name ? { service: s.name } : {}) }).sensitiveServicePubliclyExposed) sensitiveExposed += 1;
      }
    }
    const findings = await this.prisma.finding.findMany({ where: { workspaceId: workspace.id }, take: 500 });
    const criticalFindings = (findings as Array<{ severity: string }>).filter((f) => f.severity === "CRITICAL").length;
    const kevFindings = (findings as Array<{ kevListed?: boolean }>).filter((f) => f.kevListed === true).length;
    const answer = groundedNetworkAnswer(question, {
      targets, hostsDiscovered: assets.length, openServices, sensitiveExposed,
      criticalFindings, kevFindings, driftEvents: drift, openLimitations: [],
    });
    return { answer: answer.text, ...(answer.refused ? { refused: answer.refused } : {}), executes: false };
  }
}
