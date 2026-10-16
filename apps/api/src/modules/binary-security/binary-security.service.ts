import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  BINARY_TOOL_DESCRIPTORS, activeKillSwitch, binaryHealthBySlug, diffBinaryArtifacts,
  evaluateBinaryDebugPolicy, parseBinaryHeaders, sanitizeMobileText, validateBinaryArtifactUpload,
  validateDebugOperations, type NormalizedBinaryData,
} from "@dsrclone/security-sdk";
import type {
  ApproveBinaryDebugSessionInput, CreateBinaryDebugSessionInput, CreateBinaryDiffInput,
  RegisterBinaryArtifactInput, StartBinaryScanInput,
} from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";
import { OrchestrationService } from "../orchestration/orchestration.service";
import { requireBinarySecurityPermission } from "./permissions";

type Row = Record<string, unknown> & { id: string };

/**
 * Binary security API (Prompt 18 §92).
 *
 * Discipline carried through every method:
 * - Binaries are hostile content and are NEVER executed, loaded,
 *   debugged or emulated by this API (§8/§100). Registration is
 *   metadata + a bounded header segment for platform PARSING; the
 *   identity is the SHA-256 (§3) and the format comes from MAGIC
 *   BYTES, never the file name (§5/§102).
 * - Secrets found in binaries persist as type + fingerprint +
 *   redacted preview only (§30 — the worker/SDK discipline); raw
 *   artifact reads are audited per access (§84).
 * - Extracted URLs/domains are DISCOVERED_REFERENCE (§31): listed,
 *   never authorized, never scope-expanding, never scanned.
 * - Debug sessions are governed records evaluated against the §64
 *   policy: LAB only, separate approver, kill-switch checked, typed
 *   operations only. Command/script-shaped requests are refused AND
 *   audited (BINARY_DEBUG_ACTION_BLOCKED, §114). No debugger
 *   transport is provisioned in this build, so an eligible session
 *   honestly reports NOT_PROVISIONED at run time (§72) — it never
 *   fabricates a debugging run.
 * - Scans start only through the gated orchestration path (VERIFIED
 *   target + APPROVED assessment + scope), never directly.
 */
@Injectable()
export class BinarySecurityService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly orchestration: OrchestrationService,
  ) {}

  // ── Artifacts: hostile-content intake (§3/§5/§6) ───────────────

  async listArtifacts(user: RequestUser) {
    requireBinarySecurityPermission(user, "VIEW_BINARY_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.binaryArtifact.findMany({
      where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 200,
    });
    const items = [];
    for (const r of rows as unknown as Row[]) {
      const findings = await this.prisma.finding.count({ where: { binaryArtifactId: r.id, duplicateOfId: null } }).catch(() => 0);
      items.push({ ...this.artifactView(r), findings });
    }
    return { items };
  }

  async registerArtifact(user: RequestUser, input: RegisterBinaryArtifactInput) {
    requireBinarySecurityPermission(user, "UPLOAD_BINARY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const segment = input.headerSegmentBase64 ? Buffer.from(input.headerSegmentBase64, "base64") : undefined;
    if (segment && segment.length > 1024 * 1024) {
      throw new BadRequestException("Binary intake refused: header segment exceeds the 1 MiB bound (§12)");
    }
    const intake = validateBinaryArtifactUpload({
      name: input.name,
      source: input.source ?? "UPLOAD",
      sizeBytes: input.sizeBytes,
      declaredSha256: input.sha256,
      ...(input.declaredFormat ? { declaredFormat: input.declaredFormat } : {}),
      ...(segment ? { magicPrefix: segment.subarray(0, 16) } : {}),
    });
    if (!intake.accepted) {
      throw new BadRequestException(`Binary artifact intake refused: ${intake.reason}`);
    }
    // §3: the SHA-256 IS the artifact identity — the same hash in a
    // workspace is the same physical artifact (tenant references are
    // preserved by returning the existing row).
    const existing = await this.prisma.binaryArtifact.findFirst({
      where: { workspaceId: workspace.id, sha256: input.sha256 },
    });
    if (existing) return { id: (existing as Row).id, sha256: input.sha256, alreadyRegistered: true };
    // Header facts come from PARSING the segment — never executed.
    const report = segment ? parseBinaryHeaders(segment) : null;
    const format = report && report.format !== "UNKNOWN" ? report.format : intake.detectedFormat !== "UNKNOWN" ? intake.detectedFormat : (input.declaredFormat ?? "UNKNOWN");
    const target = await this.prisma.target.create({
      data: {
        workspaceId: workspace.id, name: input.name, type: "BINARY" as never,
        value: input.name, status: "DRAFT", verified: false, createdBy: user.id,
      },
    });
    const analysisArtifacts: Record<string, unknown> = {};
    if (input.headerSegmentBase64) analysisArtifacts.headerSegmentBase64 = input.headerSegmentBase64;
    if (input.recordedOutputs) analysisArtifacts.recordedOutputs = this.sanitizeRecorded(input.recordedOutputs);
    if (report) {
      analysisArtifacts.headerReport = {
        format: report.format, architecture: report.architecture ?? null,
        bits: report.bitness ?? null, entryPoint: report.entryPoint ?? null,
        compilerHints: report.compilerHints ?? [],
      };
    }
    const artifact = await this.prisma.binaryArtifact.create({
      data: {
        workspaceId: workspace.id, targetId: (target as Row).id,
        mobileBuildId: input.mobileBuildId ?? null, containerImageId: input.containerImageId ?? null,
        name: input.name, source: input.source as never,
        artifactReference: input.artifactReference ?? null,
        sha256: input.sha256, sha1: input.sha1 ?? null,
        sizeBytes: BigInt(input.sizeBytes),
        format, architecture: report?.architecture ?? null,
        bitness: report?.bitness ?? null, endianness: report?.endianness ?? null,
        environment: input.environment, status: "REGISTERED",
        analysisArtifacts: analysisArtifacts as never, createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "BINARY_UPLOADED", resourceType: "BinaryArtifact", resourceId: (artifact as Row).id,
      // Metadata only (§120): hash + format + size — never content.
      metadata: { sha256: input.sha256, format, sizeBytes: input.sizeBytes, source: input.source },
    });
    return { id: (artifact as Row).id, targetId: (target as Row).id, sha256: input.sha256, format, status: "REGISTERED" };
  }

  async getArtifact(user: RequestUser, id: string) {
    requireBinarySecurityPermission(user, "VIEW_BINARY_SECURITY");
    const { workspace, artifact } = await this.loadArtifact(user, id);
    // §84: raw artifact record access is audited EVERY time.
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "BINARY_ARTIFACT_ACCESSED", resourceType: "BinaryArtifact", resourceId: artifact.id,
      metadata: { sha256: artifact.sha256 },
    });
    const [sections, functions, imports, exportsCount, dependencies, hardening, findings, sessions, sboms] = await Promise.all([
      this.prisma.binarySection.findMany({ where: { artifactId: artifact.id }, take: 200 }).catch(() => []),
      this.prisma.binaryFunction.count({ where: { artifactId: artifact.id } }).catch(() => 0),
      this.prisma.binaryImport.count({ where: { artifactId: artifact.id } }).catch(() => 0),
      this.prisma.binaryExport.count({ where: { artifactId: artifact.id } }).catch(() => 0),
      this.prisma.binaryDependency.findMany({ where: { artifactId: artifact.id }, take: 200 }).catch(() => []),
      this.prisma.binaryHardeningProfile.findUnique({ where: { artifactId: artifact.id } }).catch(() => null),
      this.prisma.finding.findMany({ where: { binaryArtifactId: artifact.id, duplicateOfId: null }, orderBy: { createdAt: "desc" }, take: 200 }).catch(() => []),
      this.prisma.binaryDebugSession.findMany({ where: { artifactId: artifact.id }, orderBy: { createdAt: "desc" }, take: 50 }).catch(() => []),
      this.prisma.softwareBillOfMaterials.findMany({ where: { binaryArtifactId: artifact.id } }).catch(() => []),
    ]);
    return {
      ...this.artifactView(artifact),
      sections: (sections as unknown as Row[]).map((s) => ({
        name: s.name, type: (s.type as string | null) ?? null,
        size: String(s.size ?? 0), permissions: (s.permissions as string | null) ?? null,
        entropy: (s.entropy as number | null) ?? null, source: s.source,
      })),
      counts: { functions, imports, exports: exportsCount },
      dependencies: (dependencies as unknown as Row[]).map((d) => this.dependencyView(d)),
      hardening: hardening ? ((hardening as Row).profile as unknown[]) : [],
      findings: (findings as unknown as Row[]).map((f) => this.findingView(f)),
      debugSessions: (sessions as unknown as Row[]).map((s) => this.sessionView(s)),
      sboms: (sboms as unknown as Row[]).map((s) => ({
        id: s.id, format: s.format, specVersion: s.specVersion,
        checksum: s.checksum, componentCount: s.componentCount,
      })),
    };
  }

  async listFunctions(user: RequestUser, id: string) {
    // §89: the function/decompilation explorer is a restricted view.
    requireBinarySecurityPermission(user, "VIEW_BINARY_DECOMPILATION");
    const { workspace, artifact } = await this.loadArtifact(user, id);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "BINARY_DECOMPILATION_ACCESSED", resourceType: "BinaryArtifact", resourceId: artifact.id,
      metadata: { view: "functions" },
    });
    const rows = await this.prisma.binaryFunction.findMany({
      where: { artifactId: artifact.id }, orderBy: { name: "asc" }, take: 1000,
    });
    return {
      items: (rows as unknown as Row[]).map((f) => ({
        id: f.id, name: f.name, address: (f.address as string | null) ?? null,
        size: (f.size as number | null) ?? null,
        callingConvention: (f.callingConvention as string | null) ?? null,
        fingerprint: (f.fingerprint as string | null) ?? null,
        referencesRiskyApi: (f.referencesRiskyApi as string[] | null) ?? [],
        confidence: (f.confidence as number | null) ?? null, source: f.source,
      })),
      // §89: bounded inventory only — there is no unlimited
      // decompiler dump endpoint.
      bounded: true,
    };
  }

  async listDependencies(user: RequestUser, id: string) {
    requireBinarySecurityPermission(user, "VIEW_BINARY_SECURITY");
    const { artifact } = await this.loadArtifact(user, id);
    const [deps, components] = await Promise.all([
      this.prisma.binaryDependency.findMany({ where: { artifactId: artifact.id }, take: 500 }),
      this.prisma.softwareComponent.findMany({ where: { binaryArtifactId: artifact.id }, take: 500 }).catch(() => []),
    ]);
    return {
      items: (deps as unknown as Row[]).map((d) => this.dependencyView(d)),
      components: (components as unknown as Row[]).map((c) => ({
        id: c.id, name: c.name, version: (c.version as string | null) ?? null,
        ecosystem: c.ecosystem, purl: c.purl, licenses: c.licenses ?? [],
      })),
    };
  }

  async getHardening(user: RequestUser, id: string) {
    requireBinarySecurityPermission(user, "VIEW_BINARY_SECURITY");
    const { artifact } = await this.loadArtifact(user, id);
    const profile = await this.prisma.binaryHardeningProfile.findUnique({ where: { artifactId: artifact.id } }).catch(() => null);
    return {
      artifactId: artifact.id, format: artifact.format,
      // §16: a mitigation state is an OBSERVATION with evidence —
      // PASS-equivalent claims are never made from headers alone.
      profile: profile ? ((profile as Row).profile as unknown[]) : [],
      assessedAt: profile ? ((profile as Row).assessedAt ?? null) : null,
    };
  }

  // ── Scans (§92) ─────────────────────────────────────────────────

  async startScan(user: RequestUser, id: string, input: StartBinaryScanInput) {
    requireBinarySecurityPermission(user, "RUN_BINARY_STATIC_SCAN");
    const profile = input.profile ?? "BINARY_BASELINE";
    const { workspace, artifact } = await this.loadArtifact(user, id);
    if (!artifact.targetId) throw new BadRequestException("Binary artifact has no target");
    const target = await this.prisma.target.findUnique({ where: { id: artifact.targetId } });
    if (!target?.verified) throw new BadRequestException("Binary artifact target is not VERIFIED — verify the artifact registration before scanning");
    const started = await this.startGatedScan(user, workspace.id, target as unknown as Row & { id: string; value: string }, artifact.name, profile);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "BINARY_STATIC_SCAN_STARTED", resourceType: "BinaryArtifact", resourceId: artifact.id,
      metadata: { profile, sha256: artifact.sha256 },
    });
    return { artifactId: artifact.id, ...started };
  }

  // ── Diffs (§53–§55) ─────────────────────────────────────────────

  async createDiff(user: RequestUser, input: CreateBinaryDiffInput) {
    requireBinarySecurityPermission(user, "CREATE_BINARY_DIFF");
    const { workspace } = await this.loadArtifact(user, input.baseArtifactId);
    const base = await this.loadArtifact(user, input.baseArtifactId);
    const targetArt = await this.loadArtifact(user, input.targetArtifactId);
    const [baseData, targetData] = await Promise.all([
      this.loadInventory(base.artifact), this.loadInventory(targetArt.artifact),
    ]);
    const [baseFindings, targetFindings] = await Promise.all([
      this.prisma.finding.findMany({ where: { binaryArtifactId: base.artifact.id, duplicateOfId: null } }).catch(() => []),
      this.prisma.finding.findMany({ where: { binaryArtifactId: targetArt.artifact.id, duplicateOfId: null } }).catch(() => []),
    ]);
    const vulnDeps = new Set((targetFindings as unknown as Row[])
      .filter((f) => f.binaryFindingType === "BINARY_DEPENDENCY_VULNERABILITY")
      .map((f) => (f.binaryComponent as string | null) ?? ""));
    const result = diffBinaryArtifacts(baseData, targetData, {
      vulnerableDependency: (dep) => vulnDeps.has(dep.purl ?? "") || [...vulnDeps].some((p) => p.includes(dep.library)),
      resolvedFindingFingerprints: new Set((baseFindings as unknown as Row[]).map((f) => (f.binaryFingerprint as string | null) ?? "").filter(Boolean)),
      targetFindingFingerprints: new Set((targetFindings as unknown as Row[]).map((f) => (f.binaryFingerprint as string | null) ?? "").filter(Boolean)),
    });
    const diff = await this.prisma.binaryDiff.create({
      data: {
        workspaceId: workspace.id, baseArtifactId: base.artifact.id, targetArtifactId: targetArt.artifact.id,
        summary: result.summary as never, regressions: result.regressions as never,
        detail: result as never, createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "BINARY_DIFF_CREATED", resourceType: "BinaryDiff", resourceId: (diff as Row).id,
      metadata: { base: base.artifact.sha256, target: targetArt.artifact.sha256, regressions: result.regressions.length },
    });
    return { id: (diff as Row).id, summary: result.summary, regressions: result.regressions };
  }

  async getDiff(user: RequestUser, id: string) {
    requireBinarySecurityPermission(user, "VIEW_BINARY_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const diff = await this.prisma.binaryDiff.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!diff) throw new NotFoundException("Binary diff not found");
    const d = diff as unknown as Row;
    return {
      id: d.id, baseArtifactId: d.baseArtifactId, targetArtifactId: d.targetArtifactId,
      summary: d.summary, regressions: d.regressions, detail: d.detail, createdAt: d.createdAt ?? null,
    };
  }

  // ── Debug sessions: the governed lab (§64–§74) ────────────────

  async createDebugSession(user: RequestUser, artifactId: string, input: CreateBinaryDebugSessionInput) {
    requireBinarySecurityPermission(user, "REQUEST_BINARY_DEBUG");
    const { workspace, artifact } = await this.loadArtifact(user, artifactId);
    const operations = input.operations ?? [];
    // §93/§114: command/script-shaped content is refused + audited —
    // it is never executed and never persisted as an instruction.
    const commandCarried = [input.gdbCommand, input.shellCommand, input.scriptBody, input.r2Command]
      .some((v) => typeof v === "string" && v.trim().length > 0);
    const opsCheck = validateDebugOperations(operations as never);
    const switches = await this.prisma.validationKillSwitch.findMany({ where: { active: true } }).catch(() => []);
    const kill = activeKillSwitch(
      (switches as unknown as Row[]).map((s) => ({
        level: s.level as string, organizationId: s.organizationId as string | null,
        workspaceId: s.workspaceId as string | null, scopeRef: s.scopeRef as string | null, active: true,
      })),
      { organizationId: user.organizationId, workspaceId: workspace.id, targetId: (artifact.targetId as string | null) ?? artifact.id },
    );
    const target = artifact.targetId
      ? await this.prisma.target.findUnique({ where: { id: artifact.targetId } }).catch(() => null)
      : null;
    const decision = evaluateBinaryDebugPolicy({
      environment: artifact.environment,
      artifactAuthorized: true,
      targetVerified: (target as unknown as Row | null)?.verified === true,
      requestedBy: user.id,
      // Eligibility at request time; transport provisioning resolves
      // at run time to NOT_PROVISIONED (§72) — see class doc.
      workerCapabilityPresent: true,
      killSwitchActive: kill !== null,
      ...(input.timeoutSeconds ? { timeoutSeconds: input.timeoutSeconds } : {}),
      ...(input.networkPolicy ? { networkPolicy: input.networkPolicy } : {}),
      operations: operations as never,
    });
    const blocked = commandCarried || !opsCheck.ok || decision.decision === "BLOCKED";
    const session = await this.prisma.binaryDebugSession.create({
      data: {
        workspaceId: workspace.id, artifactId: artifact.id,
        status: blocked ? "BLOCKED" : "REQUESTED",
        requestedBy: user.id,
        operations: operations as never,
        policyDecision: {
          ...decision,
          ...(commandCarried ? { commandCarried: true } : {}),
          ...(!opsCheck.ok ? { operationsRefused: opsCheck.refused } : {}),
        } as never,
        networkPolicy: input.networkPolicy ?? "NO_NETWORK",
        timeoutSeconds: input.timeoutSeconds ?? 1800,
        killSwitchChecked: true,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "BINARY_DEBUG_REQUESTED", resourceType: "BinaryDebugSession", resourceId: (session as Row).id,
      metadata: { artifactId: artifact.id, operations: operations.length, environment: artifact.environment },
    });
    if (blocked) {
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
        action: "BINARY_DEBUG_ACTION_BLOCKED", resourceType: "BinaryDebugSession", resourceId: (session as Row).id,
        metadata: {
          reason: commandCarried ? "command/script-shaped content carried (§93)" : !opsCheck.ok ? opsCheck.refused : decision.reasons[0] ?? "policy",
        },
      });
    }
    return { id: (session as Row).id, status: (session as Row).status, decision: decision.decision, reasons: decision.reasons };
  }

  async approveDebugSession(user: RequestUser, sessionId: string, input: ApproveBinaryDebugSessionInput) {
    requireBinarySecurityPermission(user, "APPROVE_BINARY_DEBUG");
    const workspace = await resolveWorkspace(this.prisma, user);
    const session = await this.prisma.binaryDebugSession.findFirst({ where: { id: sessionId, workspaceId: workspace.id } });
    if (!session) throw new NotFoundException("Binary debug session not found");
    const s = session as unknown as Row;
    if (s.status !== "REQUESTED") throw new BadRequestException(`Debug session is ${s.status} — only REQUESTED sessions can be decided`);
    // §67 separation of duties: the requester never approves their own.
    if (s.requestedBy === user.id) {
      throw new BadRequestException("Separation of duties: the requester cannot approve their own debug session (§67)");
    }
    const status = input.decision === "APPROVE" ? "APPROVED" : "BLOCKED";
    await this.prisma.binaryDebugSession.update({
      where: { id: sessionId },
      data: { status, approvedBy: user.id },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "BINARY_DEBUG_APPROVED", resourceType: "BinaryDebugSession", resourceId: sessionId,
      metadata: { decision: input.decision, ...(input.note ? { note: input.note } : {}) },
    });
    return { id: sessionId, status };
  }

  async getDebugSession(user: RequestUser, sessionId: string) {
    requireBinarySecurityPermission(user, "VIEW_BINARY_DEBUG_EVIDENCE");
    const workspace = await resolveWorkspace(this.prisma, user);
    const session = await this.prisma.binaryDebugSession.findFirst({ where: { id: sessionId, workspaceId: workspace.id } });
    if (!session) throw new NotFoundException("Binary debug session not found");
    return this.sessionView(session as unknown as Row);
  }

  // ── Tool health (§95/§96) ───────────────────────────────────────

  async listTools(user: RequestUser) {
    requireBinarySecurityPermission(user, "VIEW_BINARY_SECURITY");
    await resolveWorkspace(this.prisma, user);
    const health = await binaryHealthBySlug([]);
    return {
      items: BINARY_TOOL_DESCRIPTORS.map((d) => ({
        slug: d.slug, name: d.name, workerType: d.workerType, risk: d.risk,
        approvalRequirement: d.approvalRequirement, capabilities: d.capabilities, license: d.license,
        // §95/§96: honest posture — executing adapters report
        // worker-side at runtime; connectors report license state;
        // governed descriptors report their non-executing state.
        health: health[d.slug]?.status ?? "NOT_CONFIGURED",
        detail: health[d.slug]?.detail ?? null,
      })),
      prohibitedAutomationNote: "Exploit generation, weaponized proof-of-concepts, shellcode, ROP chains, malware creation, payload injection, credential dumping, process injection, persistence, privilege escalation, sandbox escape and AV/EDR evasion are PROHIBITED AUTOMATION (§78/§123) — never implemented. Binaries are never executed by DSRclone.",
    };
  }

  // ── helpers ─────────────────────────────────────────────────────

  private artifactView(a: Row) {
    return {
      id: a.id, name: a.name, source: a.source,
      sha256: a.sha256, sha1: (a.sha1 as string | null) ?? null,
      sizeBytes: String(a.sizeBytes ?? 0),
      format: a.format, architecture: (a.architecture as string | null) ?? null,
      bits: (a.bitness as number | null) ?? null,
      environment: a.environment, status: a.status,
      targetId: (a.targetId as string | null) ?? null,
      artifactReference: (a.artifactReference as string | null) ?? null,
      createdAt: a.createdAt ?? null,
    };
  }

  private dependencyView(d: Row) {
    return {
      id: d.id, library: d.library, version: (d.version as string | null) ?? null,
      purl: (d.purl as string | null) ?? null, cpe: (d.cpe as string | null) ?? null,
      sourceKind: d.sourceKind, confidence: (d.confidence as number | null) ?? null, source: d.source,
    };
  }

  private findingView(f: Row) {
    return {
      id: f.id, title: f.title, severity: f.severity, status: f.status,
      binaryFindingType: (f.binaryFindingType as string | null) ?? null,
      ruleId: (f.ruleId as string | null) ?? null,
      cwe: (f.cwe as string | null) ?? null, cve: (f.cve as string | null) ?? null,
      binaryComponent: (f.binaryComponent as string | null) ?? null,
      binaryReachability: (f.binaryReachability as string | null) ?? null,
      binaryFingerprint: (f.binaryFingerprint as string | null) ?? null,
      staticConfidence: (f.staticConfidence as string | null) ?? null,
      sources: f.sources ?? [],
    };
  }

  private sessionView(s: Row) {
    return {
      id: s.id, artifactId: s.artifactId, status: s.status,
      requestedBy: s.requestedBy, approvedBy: (s.approvedBy as string | null) ?? null,
      operations: s.operations ?? [], networkPolicy: s.networkPolicy,
      timeoutSeconds: s.timeoutSeconds, // §89-like: NO unrestricted console exists — sessions are records.
      createdAt: s.createdAt ?? null,
    };
  }

  /** Recorded outputs registered at intake are sanitized value by
   *  value before persistence (§30 discipline) — a raw secret in a
   *  recorded output is stored nowhere. Depth/node caps bound hostile
   *  records. */
  private sanitizeRecorded(record: Record<string, unknown>): Record<string, unknown> {
    let nodes = 0;
    const walk = (value: unknown, depth: number): unknown => {
      if (++nodes > 5000 || depth > 8) return undefined;
      if (typeof value === "string") return sanitizeMobileText(value, 32768);
      if (Array.isArray(value)) return value.slice(0, 500).map((v) => walk(v, depth + 1));
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
    return walk(record, 0) as Record<string, unknown>;
  }

  private async loadArtifact(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const artifact = await this.prisma.binaryArtifact.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!artifact) throw new NotFoundException("Binary artifact not found");
    return { workspace, artifact: artifact as unknown as Row & { targetId: string | null; sha256: string; environment: string; format: string; name: string } };
  }

  /** Persisted inventory → the SDK diff input shape (§53). */
  private async loadInventory(artifact: Row): Promise<NormalizedBinaryData> {
    const [sections, functions, imports, exportsRows, symbols, dependencies, profile] = await Promise.all([
      this.prisma.binarySection.findMany({ where: { artifactId: artifact.id } }).catch(() => []),
      this.prisma.binaryFunction.findMany({ where: { artifactId: artifact.id } }).catch(() => []),
      this.prisma.binaryImport.findMany({ where: { artifactId: artifact.id } }).catch(() => []),
      this.prisma.binaryExport.findMany({ where: { artifactId: artifact.id } }).catch(() => []),
      this.prisma.binarySymbol.findMany({ where: { artifactId: artifact.id } }).catch(() => []),
      this.prisma.binaryDependency.findMany({ where: { artifactId: artifact.id } }).catch(() => []),
      this.prisma.binaryHardeningProfile.findUnique({ where: { artifactId: artifact.id } }).catch(() => null),
    ]);
    return {
      sha256: artifact.sha256 as string,
      format: (artifact.format as NormalizedBinaryData["format"]) ?? "UNKNOWN",
      ...(artifact.architecture ? { architecture: artifact.architecture as string } : {}),
      compilerHints: [],
      sections: (sections as unknown as Row[]).map((s) => ({
        name: s.name as string, type: (s.type as string | null) ?? undefined,
        offset: Number(s.offset ?? 0), size: Number(s.size ?? 0),
        permissions: (s.permissions as string | null) ?? undefined, source: s.source as string,
      })),
      hardening: profile ? ((profile as Row).profile as NormalizedBinaryData["hardening"]) : [],
      functions: (functions as unknown as Row[]).map((f) => ({
        name: f.name as string, address: (f.address as string | null) ?? undefined,
        fingerprint: (f.fingerprint as string | null) ?? undefined,
        confidence: (f.confidence as number | null) ?? 0.5, source: f.source as string,
      })),
      imports: (imports as unknown as Row[]).map((i) => ({ library: i.library as string, symbol: i.symbol as string, source: i.source as string })),
      exports: (exportsRows as unknown as Row[]).map((e) => ({ symbol: e.symbol as string, source: e.source as string })),
      symbols: (symbols as unknown as Row[]).map((s) => ({ name: s.name as string, source: s.source as string })),
      dependencies: (dependencies as unknown as Row[]).map((d) => ({
        library: d.library as string, version: (d.version as string | null) ?? undefined,
        purl: (d.purl as string | null) ?? undefined, sourceKind: "DETECTED_LINKED" as const,
        confidence: (d.confidence as number | null) ?? 0.5, source: d.source as string,
      })),
      strings: [], stringsSummary: { total: 0, byCategory: {} },
      cryptoReferences: [], discoveredReferences: [], source: "binary-security-api",
    };
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
