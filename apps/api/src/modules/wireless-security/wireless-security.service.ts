import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  DEFAULT_WIRELESS_BUDGET, WIRELESS_TOOL_DESCRIPTORS, captureHeaderSanity,
  createWirelessAdapters, evaluateActiveToolRequest, evaluateWirelessLabPolicy,
  maskMacAddress, normalizeBssid, sanitizeSsid, sanitizeWirelessText,
  validateWirelessCaptureUpload, wirelessHealthBySlug,
} from "@dsrclone/security-sdk";
import type {
  ApproveWirelessCaptureInput, CreateApprovedWirelessProfileInput,
  CreateWirelessEnvironmentInput, RegisterWirelessSensorInput,
  RequestWirelessLabValidationInput, StartWirelessScanInput, UploadWirelessCaptureInput,
} from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";
import { OrchestrationService } from "../orchestration/orchestration.service";
import { hasWirelessSecurityPermission, requireWirelessSecurityPermission } from "./permissions";

type Row = Record<string, unknown> & { id: string };

/**
 * Wireless security API (Prompt 19 §77).
 *
 * Discipline carried through every method:
 * - PASSIVE ONLY (§1/§99): nothing here transmits, associates,
 *   probes, deauthenticates, captures handshakes on demand or cracks
 *   keys. There is NO endpoint accepting a raw wireless command, a
 *   deauthentication request, arbitrary aircrack arguments, an
 *   arbitrary tshark filter, Wifite/hcxdumptool commands or a shell
 *   command (§78). Command-shaped lab requests are refused AND
 *   audited (§93).
 * - Observed wireless data is untrusted input (§92): SSIDs are
 *   sanitized at intake; observed networks NEVER become verified
 *   targets and never expand scope (§94) — the only target an
 *   environment owns is its own registration target, created
 *   UNVERIFIED and verified through the ordinary target flow.
 * - Captures are hostile content (§26–§30/§84): format is proven
 *   from magic bytes, the size budget refuses before parsing, the
 *   SHA-256 is the identity, raw references are permission-gated
 *   and every raw read is audited. Authentication material found in
 *   captures is counted, never stored (§67).
 * - Stations are pseudonymized (§9/§90): ordinary views carry the
 *   HMAC fingerprint only; BSSIDs are masked in ordinary AP views
 *   (§73) unless the caller holds VIEW_RAW_WIRELESS_CAPTURES.
 * - Scans start only through the gated orchestration path (VERIFIED
 *   target + APPROVED assessment + scope), never directly.
 * - Live RF needs dedicated sensor hardware (§13/§14): sensors are
 *   registered records; nothing here fabricates observations.
 */
@Injectable()
export class WirelessSecurityService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly orchestration: OrchestrationService,
  ) {}

  // ── Environments (§3/§4) ─────────────────────────────────────────

  async listEnvironments(user: RequestUser) {
    requireWirelessSecurityPermission(user, "VIEW_WIRELESS_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.wirelessEnvironment.findMany({
      where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 200,
    });
    const items = [];
    for (const r of rows as unknown as Row[]) {
      const [accessPoints, sensors, captures, events] = await Promise.all([
        this.prisma.wirelessAccessPoint.count({ where: { environmentId: r.id } }).catch(() => 0),
        this.prisma.wirelessSensor.count({ where: { environmentId: r.id } }).catch(() => 0),
        this.prisma.wirelessCapture.count({ where: { environmentId: r.id } }).catch(() => 0),
        this.prisma.wirelessSecurityEvent.count({ where: { environmentId: r.id } }).catch(() => 0),
      ]);
      items.push({ ...this.environmentView(r), counts: { accessPoints, sensors, captures, events } });
    }
    return { items };
  }

  async createEnvironment(user: RequestUser, input: CreateWirelessEnvironmentInput) {
    requireWirelessSecurityPermission(user, "MANAGE_WIRELESS_ENVIRONMENTS");
    const workspace = await resolveWorkspace(this.prisma, user);
    const name = sanitizeWirelessText(input.name, 255);
    const env = await this.prisma.wirelessEnvironment.create({
      data: {
        workspaceId: workspace.id, name,
        locationLabel: input.locationLabel ? sanitizeWirelessText(input.locationLabel, 255) : null,
        environment: input.environment ?? "CORPORATE",
        criticality: input.criticality ?? "MEDIUM",
        status: "ACTIVE", createdBy: user.id,
      },
    });
    const envRow = env as unknown as Row;
    if (input.scope) {
      await this.prisma.wirelessScope.create({
        data: {
          environmentId: envRow.id,
          bssidAllowlist: (input.scope.bssidAllowlist ?? []).map((b) => normalizeBssid(b) ?? b).slice(0, 500),
          ssidAllowlist: (input.scope.ssidAllowlist ?? []).map((s) => sanitizeSsid(s).ssid).slice(0, 500),
          channelAllowlist: input.scope.channelAllowlist ?? [],
          frequencyBands: input.scope.frequencyBands ?? [],
          maxCaptureDurationSeconds: input.scope.maxCaptureDurationSeconds ?? 3600,
          approvedInterfaces: input.scope.approvedInterfaces ?? [],
        },
      });
    }
    // The environment's own registration target (§94): created
    // UNVERIFIED — observed networks never become targets, and this
    // target is verified only through the ordinary target flow.
    // Its value binds the environment id for worker resolution.
    await this.prisma.target.create({
      data: {
        workspaceId: workspace.id, name, type: "WIRELESS_LAB" as never,
        value: envRow.id, status: "DRAFT", verified: false, createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "WIRELESS_ENVIRONMENT_CREATED", resourceType: "WirelessEnvironment", resourceId: envRow.id,
      metadata: { environment: input.environment ?? "CORPORATE" },
    });
    return this.environmentView(envRow);
  }

  async getEnvironment(user: RequestUser, id: string) {
    requireWirelessSecurityPermission(user, "VIEW_WIRELESS_SECURITY");
    const { workspace, environment } = await this.loadEnvironment(user, id);
    void workspace;
    const scope = await this.prisma.wirelessScope.findFirst({ where: { environmentId: id } });
    const [accessPoints, stations, sensors, captures, events, drift] = await Promise.all([
      this.prisma.wirelessAccessPoint.count({ where: { environmentId: id } }).catch(() => 0),
      this.prisma.wirelessStation.count({ where: { environmentId: id } }).catch(() => 0),
      this.prisma.wirelessSensor.count({ where: { environmentId: id } }).catch(() => 0),
      this.prisma.wirelessCapture.count({ where: { environmentId: id } }).catch(() => 0),
      this.prisma.wirelessSecurityEvent.count({ where: { environmentId: id } }).catch(() => 0),
      this.prisma.wirelessDriftEvent.count({ where: { environmentId: id } }).catch(() => 0),
    ]);
    return {
      ...this.environmentView(environment),
      scope: scope ? this.scopeView(scope as unknown as Row) : null,
      counts: { accessPoints, stations, sensors, captures, events, drift },
    };
  }

  // ── Scans (§15/§62): gated orchestration only ────────────────────

  async startScan(user: RequestUser, id: string, input: StartWirelessScanInput) {
    requireWirelessSecurityPermission(user, "RUN_PASSIVE_WIRELESS_SCAN");
    const profile = input.profile ?? "WIRELESS_PASSIVE_BASELINE";
    const { workspace, environment } = await this.loadEnvironment(user, id);
    const target = await this.prisma.target.findFirst({
      where: { workspaceId: workspace.id, type: "WIRELESS_LAB" as never, value: id },
    });
    if (!target) throw new BadRequestException("Wireless environment has no registration target");
    const targetRow = target as unknown as Row & { verified?: boolean };
    if (!targetRow.verified) {
      throw new BadRequestException("Wireless environment target is not VERIFIED — verify the environment registration before scanning");
    }
    const started = await this.startGatedScan(user, workspace.id, targetRow as Row & { id: string; value: string }, environment.name as string, profile);
    const scope = await this.prisma.wirelessScope.findFirst({ where: { environmentId: id } });
    await this.prisma.wirelessScanSession.create({
      data: {
        workspaceId: workspace.id, environmentId: id, scanId: (started as { scanId?: string }).scanId ?? null,
        profile, scopeSnapshot: (scope ? this.scopeView(scope as unknown as Row) : {}) as never,
        channels: ((scope as unknown as Row | null)?.channelAllowlist as number[] | undefined) ?? [],
        status: "RUNNING", budget: DEFAULT_WIRELESS_BUDGET as never,
      },
    }).catch(() => undefined);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "WIRELESS_SCAN_STARTED", resourceType: "WirelessEnvironment", resourceId: id,
      metadata: { profile },
    });
    return { environmentId: id, ...started };
  }

  // ── Access points (§6/§73) ───────────────────────────────────────

  async listAccessPoints(user: RequestUser, environmentId?: string) {
    requireWirelessSecurityPermission(user, "VIEW_WIRELESS_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const elevated = hasWirelessSecurityPermission(user, "VIEW_RAW_WIRELESS_CAPTURES");
    const rows = await this.prisma.wirelessAccessPoint.findMany({
      where: { workspaceId: workspace.id, ...(environmentId ? { environmentId } : {}) },
      orderBy: { lastSeen: "desc" }, take: 500,
    });
    return { items: (rows as unknown as Row[]).map((r) => this.accessPointView(r, elevated)) };
  }

  async getAccessPoint(user: RequestUser, id: string) {
    requireWirelessSecurityPermission(user, "VIEW_WIRELESS_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const elevated = hasWirelessSecurityPermission(user, "VIEW_RAW_WIRELESS_CAPTURES");
    const row = await this.prisma.wirelessAccessPoint.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!row) throw new NotFoundException("Wireless access point not found");
    const ap = row as unknown as Row;
    const [observations, stations, history, findings] = await Promise.all([
      this.prisma.wirelessObservation.findMany({ where: { accessPointId: id }, orderBy: { timestamp: "desc" }, take: 100 }).catch(() => []),
      this.prisma.wirelessStation.findMany({ where: { accessPointId: id }, take: 100 }).catch(() => []),
      this.prisma.wirelessAccessPointHistory.findMany({ where: { accessPointId: id }, orderBy: { observedAt: "desc" }, take: 50 }).catch(() => []),
      this.prisma.finding.findMany({ where: { wirelessAccessPointId: id, duplicateOfId: null }, take: 100 }).catch(() => []),
    ]);
    return {
      ...this.accessPointView(ap, elevated),
      // §90: stations are ALWAYS pseudonymized in API views — the
      // raw address is never selected into a response.
      stations: (stations as unknown as Row[]).map((s) => ({
        addressFingerprint: s.addressFingerprint, associatedBssid: elevated ? s.associatedBssid : maskMacAddress((s.associatedBssid as string) ?? ""),
        signalDbm: s.signalDbm ?? null, firstSeen: s.firstSeen ?? null, lastSeen: s.lastSeen ?? null,
      })),
      observations: (observations as unknown as Row[]).map((o) => ({
        timestamp: o.timestamp ?? null, channel: o.channel ?? null, signalDbm: o.signalDbm ?? null,
        securityMode: o.securityMode, source: o.source,
      })),
      history: (history as unknown as Row[]).map((h) => ({
        ssid: h.ssid, channel: h.channel ?? null, securityMode: h.securityMode,
        authentication: h.authentication ?? null, approvedStatus: h.approvedStatus, observedAt: h.observedAt ?? null,
      })),
      findings: (findings as unknown as Row[]).map((f) => ({
        id: f.id, title: f.title, severity: f.severity, status: f.status,
        wirelessFindingType: f.wirelessFindingType ?? null, wirelessFingerprint: f.wirelessFingerprint ?? null,
      })),
    };
  }

  // ── Sensors (§11/§12) ────────────────────────────────────────────

  async listSensors(user: RequestUser) {
    requireWirelessSecurityPermission(user, "VIEW_WIRELESS_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.wirelessSensor.findMany({
      where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 200,
    });
    return { items: (rows as unknown as Row[]).map((r) => this.sensorView(r)) };
  }

  async registerSensor(user: RequestUser, input: RegisterWirelessSensorInput) {
    requireWirelessSecurityPermission(user, "MANAGE_WIRELESS_SENSORS");
    const workspace = await resolveWorkspace(this.prisma, user);
    if (input.environmentId) await this.loadEnvironment(user, input.environmentId);
    const sensor = await this.prisma.wirelessSensor.create({
      data: {
        workspaceId: workspace.id, environmentId: input.environmentId ?? null,
        name: sanitizeWirelessText(input.name, 255),
        host: input.host ? sanitizeWirelessText(input.host, 255) : null,
        adapter: input.adapter ? sanitizeWirelessText(input.adapter, 255) : null,
        driver: input.driver ? sanitizeWirelessText(input.driver, 255) : null,
        interfaceName: input.interfaceName ?? null,
        supportedBands: input.supportedBands ?? [],
        monitorModeCapable: input.monitorModeCapable ?? false,
        health: "UNKNOWN", status: "REGISTERED",
      },
    });
    const row = sensor as unknown as Row;
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "WIRELESS_SENSOR_REGISTERED", resourceType: "WirelessSensor", resourceId: row.id,
      metadata: { monitorModeCapable: input.monitorModeCapable ?? false },
    });
    return this.sensorView(row);
  }

  async approveSensor(user: RequestUser, id: string) {
    requireWirelessSecurityPermission(user, "MANAGE_WIRELESS_SENSORS");
    const workspace = await resolveWorkspace(this.prisma, user);
    const sensor = await this.prisma.wirelessSensor.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!sensor) throw new NotFoundException("Wireless sensor not found");
    const s = sensor as unknown as Row;
    // §12: approval binds the sensor to an APPROVED interface of its
    // environment's scope — an unlisted interface cannot be approved.
    if (s.environmentId) {
      const scope = await this.prisma.wirelessScope.findFirst({ where: { environmentId: s.environmentId as string } });
      const approvedInterfaces = ((scope as unknown as Row | null)?.approvedInterfaces as string[] | undefined) ?? [];
      if (approvedInterfaces.length > 0 && !(s.interfaceName && approvedInterfaces.includes(s.interfaceName as string))) {
        throw new BadRequestException("Sensor interface is not in the environment's approved interface list (§12)");
      }
    }
    const updated = await this.prisma.wirelessSensor.update({ where: { id }, data: { status: "ACTIVE" } });
    return this.sensorView(updated as unknown as Row);
  }

  // ── Captures (§26–§30) ───────────────────────────────────────────

  async uploadCapture(user: RequestUser, input: UploadWirelessCaptureInput) {
    requireWirelessSecurityPermission(user, "UPLOAD_WIRELESS_CAPTURE");
    const { workspace } = await this.loadEnvironment(user, input.environmentId);
    const content = Buffer.from(input.contentBase64, "base64");
    const intake = validateWirelessCaptureUpload({
      name: input.name, sizeBytes: content.length, content,
      ...(input.expectedSha256 ? { declaredSha256: input.expectedSha256 } : {}),
    });
    if (!intake.accepted || !intake.sha256 || !intake.format) {
      throw new BadRequestException(`Wireless capture intake refused: ${intake.reason}`);
    }
    const sanity = captureHeaderSanity(content);
    if (!sanity.ok) {
      throw new BadRequestException(`Wireless capture intake refused: ${sanity.reason}`);
    }
    const existing = await this.prisma.wirelessCapture.findFirst({
      where: { workspaceId: workspace.id, sha256: intake.sha256 },
    });
    if (existing) return { id: (existing as Row).id, sha256: intake.sha256, alreadyRegistered: true };
    // Raw bytes are NOT persisted by this API — the row carries the
    // hash identity + metadata; bytes live behind the artifact
    // reference in protected storage (§29). Analysis payloads the
    // worker registers later are bounded + sanitized (§26).
    const capture = await this.prisma.wirelessCapture.create({
      data: {
        workspaceId: workspace.id, environmentId: input.environmentId, sensorId: input.sensorId ?? null,
        name: sanitizeWirelessText(input.name, 255), sha256: intake.sha256, format: intake.format,
        sizeBytes: BigInt(content.length), channels: [],
        artifactReference: input.artifactReference ?? null,
        status: "PENDING", sanitizationStatus: "SANITIZED", createdBy: user.id,
        analysisArtifacts: { intake: { format: intake.format, headerSanity: "OK" } } as never,
      },
    });
    const row = capture as unknown as Row;
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "WIRELESS_CAPTURE_UPLOADED", resourceType: "WirelessCapture", resourceId: row.id,
      metadata: { format: intake.format, sizeBytes: content.length },
    });
    return { id: row.id, sha256: intake.sha256, format: intake.format, status: "PENDING" };
  }

  async getCapture(user: RequestUser, id: string) {
    requireWirelessSecurityPermission(user, "VIEW_WIRELESS_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const capture = await this.prisma.wirelessCapture.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!capture) throw new NotFoundException("Wireless capture not found");
    const c = capture as unknown as Row;
    const elevated = hasWirelessSecurityPermission(user, "VIEW_RAW_WIRELESS_CAPTURES");
    if (elevated) {
      // §30: every raw capture access is audited.
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
        action: "WIRELESS_CAPTURE_ACCESSED", resourceType: "WirelessCapture", resourceId: id,
        metadata: { format: c.format },
      });
    }
    return {
      id: c.id, environmentId: c.environmentId, name: c.name, sha256: c.sha256, format: c.format,
      sizeBytes: String(c.sizeBytes ?? 0), status: c.status, sanitizationStatus: c.sanitizationStatus,
      channels: c.channels ?? [], createdAt: c.createdAt ?? null,
      // The raw artifact reference is an elevated datum (§30).
      artifactReference: elevated ? ((c.artifactReference as string | null) ?? null) : null,
      analysisArtifacts: c.analysisArtifacts ?? null,
    };
  }

  async approveCapture(user: RequestUser, id: string, input: ApproveWirelessCaptureInput) {
    requireWirelessSecurityPermission(user, "MANAGE_WIRELESS_POLICIES");
    const workspace = await resolveWorkspace(this.prisma, user);
    const capture = await this.prisma.wirelessCapture.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!capture) throw new NotFoundException("Wireless capture not found");
    const status = input.decision === "APPROVE" ? "APPROVED" : "REJECTED";
    await this.prisma.wirelessCapture.update({ where: { id }, data: { status } });
    return { id, status };
  }

  // ── Approved profiles (§43) ──────────────────────────────────────

  async listApprovedProfiles(user: RequestUser, environmentId: string) {
    requireWirelessSecurityPermission(user, "VIEW_WIRELESS_SECURITY");
    await this.loadEnvironment(user, environmentId);
    const rows = await this.prisma.approvedWirelessProfile.findMany({
      where: { environmentId }, orderBy: { createdAt: "desc" }, take: 200,
    });
    return { items: (rows as unknown as Row[]).map((r) => this.approvedProfileView(r)) };
  }

  async createApprovedProfile(user: RequestUser, input: CreateApprovedWirelessProfileInput) {
    requireWirelessSecurityPermission(user, "MANAGE_APPROVED_APS");
    const { workspace } = await this.loadEnvironment(user, input.environmentId);
    void workspace;
    const profile = await this.prisma.approvedWirelessProfile.create({
      data: {
        workspaceId: (await resolveWorkspace(this.prisma, user)).id, environmentId: input.environmentId,
        ssid: sanitizeSsid(input.ssid).ssid,
        bssid: input.bssid ? (normalizeBssid(input.bssid) ?? input.bssid) : null,
        securityMode: input.securityMode, authentication: input.authentication ?? null,
        allowedChannels: input.allowedChannels ?? [], allowedBands: input.allowedBands ?? [],
      },
    });
    const row = profile as unknown as Row;
    return this.approvedProfileView(row);
  }

  // ── Events + drift (§47/§56) ─────────────────────────────────────

  async listEvents(user: RequestUser, environmentId?: string) {
    requireWirelessSecurityPermission(user, "VIEW_WIRELESS_EVENTS");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.wirelessSecurityEvent.findMany({
      where: { workspaceId: workspace.id, ...(environmentId ? { environmentId } : {}) },
      orderBy: { timestamp: "desc" }, take: 500,
    });
    return {
      items: (rows as unknown as Row[]).map((r) => ({
        id: r.id, environmentId: r.environmentId, type: r.type, timestamp: r.timestamp ?? null,
        bssid: r.bssid ? maskMacAddress(r.bssid as string) : null, confidence: r.confidence,
        evidenceSummary: r.evidenceSummary, source: r.source,
      })),
    };
  }

  async listDrift(user: RequestUser, environmentId?: string) {
    requireWirelessSecurityPermission(user, "VIEW_WIRELESS_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.wirelessDriftEvent.findMany({
      where: { workspaceId: workspace.id, ...(environmentId ? { environmentId } : {}) },
      orderBy: { detectedAt: "desc" }, take: 500,
    });
    return {
      items: (rows as unknown as Row[]).map((r) => ({
        id: r.id, environmentId: r.environmentId, kind: r.kind, bssid: maskMacAddress(r.bssid as string),
        ssid: r.ssid, field: r.field, fromValue: r.fromValue ?? null, toValue: r.toValue ?? null,
        securityDowngrade: r.securityDowngrade, detectedAt: r.detectedAt ?? null,
      })),
    };
  }

  // ── Lab validation (§65/§66/§93) ────────────────────────────────

  async requestLabValidation(user: RequestUser, input: RequestWirelessLabValidationInput) {
    requireWirelessSecurityPermission(user, "REQUEST_WIRELESS_LAB_VALIDATION");
    const { workspace, environment } = await this.loadEnvironment(user, input.environmentId);
    // §78/§93: command-shaped content is refused + audited — never
    // executed, never persisted as an instruction.
    const commandCarried = [input.deauthCommand, input.shellCommand, input.rawCommand]
      .some((v) => typeof v === "string" && v.trim().length > 0);
    if (commandCarried) {
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
        action: "WIRELESS_ACTIVE_TOOL_BLOCKED", resourceType: "WirelessEnvironment", resourceId: input.environmentId,
        metadata: { reason: "COMMAND_SHAPED_REQUEST" },
      });
      throw new BadRequestException("Wireless lab validation refused: command-shaped content is not accepted (§78) — requests are typed and governed");
    }
    // §64/§93: active tools are blocked for every profile in this
    // build — the request is refused + audited.
    if (input.requestedTool) {
      const decision = evaluateActiveToolRequest({ slug: input.requestedTool, profile: "WIRELESS_LAB_VALIDATION" });
      if (!decision.allowed) {
        await this.audit.record({
          actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
          action: "WIRELESS_ACTIVE_TOOL_BLOCKED", resourceType: "WirelessEnvironment", resourceId: input.environmentId,
          metadata: { tool: input.requestedTool, reasonCode: decision.reasonCode ?? "WIRELESS_ACTIVE_TOOL_BLOCKED" },
        });
        throw new BadRequestException(`Wireless lab validation refused: ${decision.reason}`);
      }
    }
    const decision = evaluateWirelessLabPolicy({
      environmentKind: environment.environment as string,
      // Dedicated test AP/clients + separate approval are §65 facts
      // the platform records through the lab workflow; none are
      // recorded by this request alone, so the gate reports them
      // unmet rather than assuming them.
      dedicatedTestAp: false, dedicatedTestClients: false,
      ...(environment.authorizationId ? { authorizationId: environment.authorizationId as string } : {}),
      approved: false,
      requestedDurationSeconds: input.requestedDurationSeconds ?? 1800,
      killSwitchEngaged: false,
      syntheticCredentialsOnly: input.syntheticDataOnly !== false,
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "WIRELESS_LAB_VALIDATION_REQUESTED", resourceType: "WirelessEnvironment", resourceId: input.environmentId,
      metadata: { status: decision.status },
    });
    return {
      environmentId: input.environmentId, status: decision.status,
      ...(decision.status === "BLOCKED" ? { reasonCode: decision.reasonCode } : {}),
      reasons: decision.reasons,
      note: "Lab validation never transmits in this build: the WIRELESS_LAB_VALIDATION transport is deliberately unwired (§65).",
    };
  }

  // ── Tool health (§80) ────────────────────────────────────────────

  async listTools(user: RequestUser) {
    requireWirelessSecurityPermission(user, "VIEW_WIRELESS_SECURITY");
    await resolveWorkspace(this.prisma, user);
    const health = await wirelessHealthBySlug(createWirelessAdapters());
    return {
      items: WIRELESS_TOOL_DESCRIPTORS.map((d) => ({
        slug: d.slug, name: d.name, kind: d.kind, workerType: d.workerType,
        riskLevel: d.riskLevel, classification: d.classification,
        requiresApproval: d.requiresApproval, capabilities: d.capabilities, note: d.note,
        // §80: honest posture — executing adapters probe their
        // binary; the Kismet instance reports NOT_CONFIGURED;
        // governed descriptors report their non-executing state.
        health: health[d.slug]?.status ?? "NOT_CONFIGURED",
        detail: health[d.slug]?.detail ?? null,
      })),
      prohibitedAutomationNote: "Deauthentication/disassociation, handshake triggering, key or handshake cracking, rogue-AP creation, jamming and client connection attempts are PROHIBITED AUTOMATION (§99) — never implemented. DSRclone wireless work is passive observation and offline capture analysis only.",
    };
  }

  // ── helpers ──────────────────────────────────────────────────────

  private async loadEnvironment(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const environment = await this.prisma.wirelessEnvironment.findFirst({
      where: { id, workspaceId: workspace.id },
    });
    if (!environment) throw new NotFoundException("Wireless environment not found");
    return { workspace, environment: environment as unknown as Row };
  }

  private environmentView(r: Row) {
    return {
      id: r.id, name: r.name, locationLabel: (r.locationLabel as string | null) ?? null,
      environment: r.environment, criticality: r.criticality, status: r.status,
      authorizationId: (r.authorizationId as string | null) ?? null, createdAt: r.createdAt ?? null,
    };
  }

  private scopeView(r: Row) {
    return {
      bssidAllowlist: r.bssidAllowlist ?? [], ssidAllowlist: r.ssidAllowlist ?? [],
      channelAllowlist: r.channelAllowlist ?? [], frequencyBands: r.frequencyBands ?? [],
      maxCaptureDurationSeconds: r.maxCaptureDurationSeconds ?? 3600,
      approvedInterfaces: r.approvedInterfaces ?? [],
    };
  }

  private accessPointView(r: Row, elevated: boolean) {
    return {
      id: r.id, environmentId: r.environmentId,
      // §73: ordinary views mask the device part of the BSSID.
      bssid: elevated ? r.bssid : maskMacAddress(r.bssid as string),
      ssid: r.ssid, ssidHidden: r.ssidHidden, vendor: (r.vendor as string | null) ?? null,
      channel: r.channel ?? null, frequencyMhz: r.frequencyMhz ?? null, band: (r.band as string | null) ?? null,
      securityMode: r.securityMode, encryption: (r.encryption as string | null) ?? null,
      authentication: (r.authentication as string | null) ?? null, pmf: r.pmf,
      wpsAdvertised: r.wpsAdvertised, signalDbm: r.signalDbm ?? null,
      approvedStatus: r.approvedStatus, firstSeen: r.firstSeen ?? null, lastSeen: r.lastSeen ?? null,
    };
  }

  private sensorView(r: Row) {
    return {
      id: r.id, environmentId: (r.environmentId as string | null) ?? null, name: r.name,
      host: (r.host as string | null) ?? null, adapter: (r.adapter as string | null) ?? null,
      driver: (r.driver as string | null) ?? null, interfaceName: (r.interfaceName as string | null) ?? null,
      supportedBands: r.supportedBands ?? [], monitorModeCapable: r.monitorModeCapable,
      // §80: sensor health is reported, never fabricated — a sensor
      // with no provisioned transport reports UNKNOWN.
      health: r.health, status: r.status, lastSeen: r.lastSeen ?? null,
    };
  }

  private approvedProfileView(r: Row) {
    return {
      id: r.id, environmentId: r.environmentId, ssid: r.ssid, bssid: (r.bssid as string | null) ?? null,
      securityMode: r.securityMode, authentication: (r.authentication as string | null) ?? null,
      allowedChannels: r.allowedChannels ?? [], allowedBands: r.allowedBands ?? [],
    };
  }

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
