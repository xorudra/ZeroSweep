import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { AD_DISABLED_REGISTRATIONS, isValidCredentialReference, looksLikeSecretValue } from "@dsrclone/security-sdk";
import type { RegisterAdDomainInput, StartAdScanInput } from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";
import { OrchestrationService, hostOf } from "../orchestration/orchestration.service";
import { requireAdSecurityPermission } from "./permissions";

type Row = Record<string, unknown> & { id: string };

/** Slugs that must never be executable (Prompt 15 §51–§56/§120): the
 *  offensive registrations plus every capability the policy names. */
const OFFENSIVE_SLUGS = new Set<string>([
  ...AD_DISABLED_REGISTRATIONS.map((r) => r.slug),
  "certipy", // the FIND-only posture adapter is "certipy-posture"; bare certipy is the offensive tool
]);

/**
 * Active Directory security API (Prompt 15 §100).
 *
 * Discipline carried through every method:
 * - Assessment is DEFENSIVE and READ-ONLY forever (§83/§120): no
 *   method modifies a directory object, and no remediation action
 *   exists — remediation is guidance text on findings only.
 * - Credentials exist ONLY as secret-reference names (§7) — a value
 *   is never accepted (secret-shaped references are refused), never
 *   stored, never returned and never logged. Directory rows hold no
 *   password material by construction (§113).
 * - Domains are verified targets (§3/§4): registration records
 *   identity; scans start only through the gated orchestration path
 *   (VERIFIED target + APPROVED assessment + scope), never directly.
 * - Attack paths are analysis results (§35): modeled over collected
 *   data, never executed, never labelled COMPROMISED.
 * - Raw directory graph access is OWNER/ADMIN and audited per access
 *   (§30/§117 DIRECTORY_ARTIFACT_ACCESSED).
 */
@Injectable()
export class ActiveDirectoryService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly orchestration: OrchestrationService,
  ) {}

  // ── Forests + domains (§90/§100) ───────────────────────────────

  async listForests(user: RequestUser) {
    requireAdSecurityPermission(user, "VIEW_AD_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.activeDirectoryForest.findMany({
      where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 200,
    });
    const items = [];
    for (const r of rows as unknown as Row[]) {
      const domains = await this.prisma.activeDirectoryDomain.count({ where: { forestId: r.id } }).catch(() => 0);
      items.push({ id: r.id, name: r.name, rootDomain: r.rootDomain, functionalLevel: r.functionalLevel ?? null, status: r.assessmentState, domains });
    }
    return { items };
  }

  async listDomains(user: RequestUser) {
    requireAdSecurityPermission(user, "VIEW_AD_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.activeDirectoryDomain.findMany({
      where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 200,
    });
    const items = [];
    for (const r of rows as unknown as Row[]) {
      const [users, computers, paths, drift] = await Promise.all([
        this.prisma.directoryUser.count({ where: { domainId: r.id } }).catch(() => 0),
        this.prisma.directoryComputer.count({ where: { domainId: r.id } }).catch(() => 0),
        this.prisma.adAttackPath.count({ where: { domainId: r.id } }).catch(() => 0),
        this.prisma.adDriftEvent.count({ where: { domainId: r.id } }).catch(() => 0),
      ]);
      items.push({
        id: r.id, dnsName: r.dnsName, netbiosName: r.netbiosName ?? null,
        domainSid: r.domainSid ?? null, functionalLevel: r.functionalLevel ?? null,
        environment: r.environment, criticality: r.criticality, forestId: r.forestId ?? null,
        // §7: the ONLY assessment posture, by design.
        assessmentPolicy: "READ_ONLY", status: r.status,
        lastSeen: r.lastSeen ?? null, lastAssessmentAt: r.lastAssessmentAt ?? null,
        users, computers, attackPaths: paths, driftEvents: drift,
      });
    }
    return { items };
  }

  async registerDomain(user: RequestUser, input: RegisterAdDomainInput) {
    requireAdSecurityPermission(user, "MANAGE_AD_CONNECTIONS");
    const workspace = await resolveWorkspace(this.prisma, user);
    if (input.credentialReference !== undefined) this.assertReferenceName(input.credentialReference);
    const existing = await this.prisma.activeDirectoryDomain.findFirst({
      where: { workspaceId: workspace.id, dnsName: input.dnsName },
    });
    if (existing) return { id: (existing as Row).id, status: (existing as Row).status, alreadyRegistered: true };
    let forestId: string | undefined;
    if (input.forestName) {
      const forest = await this.prisma.activeDirectoryForest.findFirst({
        where: { workspaceId: workspace.id, name: input.forestName },
      });
      if (forest) forestId = (forest as Row).id;
      else {
        const created = await this.prisma.activeDirectoryForest.create({
          data: {
            workspaceId: workspace.id, name: input.forestName,
            rootDomain: input.forestRootDomain ?? input.dnsName,
            assessmentState: "REGISTERED", createdBy: user.id,
          },
        });
        forestId = (created as Row).id;
      }
    }
    const target = await this.prisma.target.create({
      data: {
        workspaceId: workspace.id, name: input.name, type: "ACTIVE_DIRECTORY_DOMAIN" as never,
        value: input.dnsName, status: "DRAFT", verified: false, createdBy: user.id,
      },
    });
    let credentialProfileId: string | undefined;
    if (input.credentialReference || input.credentialProfileName) {
      const profile = await this.prisma.directoryCredentialProfile.create({
        data: {
          workspaceId: workspace.id,
          name: input.credentialProfileName ?? `${input.dnsName} assessment identity`,
          identityKind: input.identityKind ?? "READ_ONLY_DOMAIN",
          ...(input.credentialReference ? { credentialReference: input.credentialReference } : {}),
          status: input.credentialReference ? "CONFIGURED" : "NOT_CONFIGURED",
          createdBy: user.id,
        },
      });
      credentialProfileId = (profile as Row).id;
    }
    const domain = await this.prisma.activeDirectoryDomain.create({
      data: {
        workspaceId: workspace.id, targetId: target.id, ...(forestId ? { forestId } : {}),
        ...(credentialProfileId ? { credentialProfileId } : {}),
        dnsName: input.dnsName,
        ...(input.netbiosName ? { netbiosName: input.netbiosName } : {}),
        ...(input.domainSid ? { domainSid: input.domainSid } : {}),
        ...(input.functionalLevel ? { functionalLevel: input.functionalLevel } : {}),
        environment: input.environment ?? "UNKNOWN", criticality: input.criticality ?? "HIGH",
        // §7/§83: assessment is READ_ONLY by platform design (no column
        // exists because no other posture is representable).
        status: input.credentialReference ? "REGISTERED" : "NOT_CONFIGURED",
        createdBy: user.id,
      },
    });
    for (const dc of input.domainControllers ?? []) {
      await this.prisma.domainController.create({
        data: {
          workspaceId: workspace.id, domainId: domain.id, hostname: dc.hostname,
          dnsName: dc.hostname.includes(".") ? dc.hostname : `${dc.hostname}.${input.dnsName}`,
          ipAddresses: dc.ipAddresses ?? [],
        },
      });
    }
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "AD_DOMAIN_REGISTERED", resourceType: "ActiveDirectoryDomain", resourceId: domain.id,
      metadata: { dnsName: input.dnsName, credentialConfigured: !!input.credentialReference, identityKind: input.identityKind ?? "READ_ONLY_DOMAIN" },
    });
    return { id: domain.id, targetId: target.id, dnsName: input.dnsName, status: domain.status, verified: false };
  }

  private async loadDomain(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const domain = await this.prisma.activeDirectoryDomain.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!domain) throw new NotFoundException("Active Directory domain not found");
    return { workspace, domain: domain as unknown as Row & { targetId: string | null; dnsName: string; credentialProfileId?: string | null; status: string } };
  }

  async getDomain(user: RequestUser, id: string) {
    requireAdSecurityPermission(user, "VIEW_AD_SECURITY");
    const { domain } = await this.loadDomain(user, id);
    const [controllers, trusts, gpos, snapshots, counts] = await Promise.all([
      this.prisma.domainController.findMany({ where: { domainId: id }, take: 100 }),
      this.prisma.directoryTrust.findMany({ where: { domainId: id }, take: 100 }),
      this.prisma.groupPolicyObject.findMany({ where: { domainId: id }, take: 100 }),
      this.prisma.directorySnapshot.findMany({ where: { domainId: id }, orderBy: { capturedAt: "desc" }, take: 5 }),
      Promise.all([
        this.prisma.directoryUser.count({ where: { domainId: id } }).catch(() => 0),
        this.prisma.directoryGroup.count({ where: { domainId: id } }).catch(() => 0),
        this.prisma.directoryComputer.count({ where: { domainId: id } }).catch(() => 0),
        this.prisma.directoryRelationship.count({ where: { domainId: id } }).catch(() => 0),
        this.prisma.adAttackPath.count({ where: { domainId: id } }).catch(() => 0),
        this.prisma.adDriftEvent.count({ where: { domainId: id } }).catch(() => 0),
      ]),
    ]);
    let credentialProfile: { name: string; identityKind: string; credentialReference: string | null; credentialConfigured: boolean } | null = null;
    if (domain.credentialProfileId) {
      const profile = await this.prisma.directoryCredentialProfile.findFirst({ where: { id: domain.credentialProfileId } }).catch(() => null);
      if (profile) {
        const p = profile as unknown as Row;
        credentialProfile = {
          name: p.name as string, identityKind: p.identityKind as string,
          // Reference NAME + posture only — never a credential value (§7).
          credentialReference: (p.credentialReference as string | undefined) ?? null,
          credentialConfigured: typeof p.credentialReference === "string" && (p.credentialReference as string).length > 0,
        };
      }
    }
    return {
      ...domain,
      credentialProfile,
      controllers: (controllers as unknown as Row[]).map((c) => ({
        id: c.id, hostname: c.hostname, dnsName: c.dnsName ?? null, ipAddresses: c.ipAddresses,
        osName: c.osName ?? null, osVersion: c.osVersion ?? null, services: c.services ?? {},
      })),
      trusts: (trusts as unknown as Row[]).map((t) => ({
        id: t.id, targetDomainName: t.targetDomainName, direction: t.direction, trustType: t.trustType,
        transitive: t.transitive, sidFilteringEnabled: t.sidFilteringEnabled ?? null,
        selectiveAuthentication: t.selectiveAuthentication ?? null,
      })),
      groupPolicies: (gpos as unknown as Row[]).map((g) => ({
        id: g.id, name: g.name, linkedTo: g.linkedTo, lastModifiedAt: g.lastModifiedAt ?? null,
      })),
      latestSnapshots: (snapshots as unknown as Row[]).map((s) => ({
        id: s.id, collectionProfile: s.collectionProfile, objectCounts: s.objectCounts,
        relationshipCount: s.relationshipCount, snapshotHash: s.snapshotHash, capturedAt: s.capturedAt,
      })),
      counts: { users: counts[0], groups: counts[1], computers: counts[2], relationships: counts[3], attackPaths: counts[4], driftEvents: counts[5] },
    };
  }

  /** POST /ad/domains/:id/validate (§100): platform-side credential
   *  posture check. The API never holds a credential value, so this
   *  validates the REFERENCE (§7): missing → NOT_CONFIGURED;
   *  secret-shaped → VALIDATION_FAILED; well-formed → VALIDATED for
   *  scan-time use, where the DIRECTORY_ANALYSIS worker re-validates
   *  under a job-scoped lease (§12) before any collection. */
  async validateDomain(user: RequestUser, id: string) {
    requireAdSecurityPermission(user, "MANAGE_AD_CONNECTIONS");
    const { domain } = await this.loadDomain(user, id);
    let reference: string | null = null;
    if (domain.credentialProfileId) {
      const profile = await this.prisma.directoryCredentialProfile.findFirst({ where: { id: domain.credentialProfileId } }).catch(() => null);
      reference = ((profile as unknown as Row | null)?.credentialReference as string | undefined) ?? null;
    }
    let status: string;
    let detail: string;
    if (!reference) {
      status = "NOT_CONFIGURED";
      detail = "No credential reference is configured for this domain — scans report NOT_CONFIGURED (§9)";
    } else if (!isValidCredentialReference(reference) || looksLikeSecretValue(reference)) {
      status = "VALIDATION_FAILED";
      detail = "The stored credential reference is not a valid reference name — a secret value must never be stored here (§7)";
    } else {
      status = "VALIDATED";
      detail = "Credential reference accepted; the DIRECTORY_ANALYSIS worker re-validates the directory identity at scan time under a job-scoped lease (§12)";
    }
    await this.prisma.activeDirectoryDomain.update({ where: { id }, data: { status } });
    return { domainId: id, status, validated: status === "VALIDATED", detail };
  }

  /** §112/§120: a scan request naming an offensive tool is refused
   *  and the attempt is audited (AD_OFFENSIVE_ACTION_BLOCKED) — the
   *  platform has no executable path for these tools at all. */
  async assertNoOffensiveTools(user: RequestUser, domainId: string, requestedTools: string[]): Promise<void> {
    const blocked = requestedTools.filter((t) => OFFENSIVE_SLUGS.has(t));
    if (blocked.length === 0) return;
    const workspace = await resolveWorkspace(this.prisma, user);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "AD_OFFENSIVE_ACTION_BLOCKED", resourceType: "ActiveDirectoryDomain", resourceId: domainId,
      metadata: { blockedTools: blocked },
    });
    throw new BadRequestException(`offensive tools are never executable on this platform (§120): ${blocked.join(", ")}`);
  }

  /** POST /ad/domains/:id/scan (§100): records the engagement
   *  approval for this domain+profile, then starts through the gated
   *  orchestration path — which re-verifies independently. The target
   *  must be VERIFIED first (§3 discipline, as every target kind). */
  async startDomainScan(user: RequestUser, id: string, input: StartAdScanInput) {
    requireAdSecurityPermission(user, "RUN_AD_SCAN");
    const profile = input.profile ?? "AD_BASELINE";
    const { workspace, domain } = await this.loadDomain(user, id);
    if (!domain.targetId) throw new BadRequestException("AD domain has no target");
    const target = await this.prisma.target.findUnique({ where: { id: domain.targetId } });
    if (!target?.verified) throw new BadRequestException("AD domain target is not VERIFIED — verify the domain registration before scanning");
    const started = await this.startGatedScan(user, workspace.id, target as unknown as Row & { id: string; value: string }, domain.dnsName, profile);
    return { domainId: domain.id, ...started };
  }

  // ── Identities (§92–§94/§100) ─────────────────────────────────

  async listUsers(user: RequestUser, query: { domainId?: string; privileged?: boolean; search?: string }) {
    requireAdSecurityPermission(user, "VIEW_AD_IDENTITIES");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.directoryUser.findMany({
      where: {
        workspaceId: workspace.id,
        ...(query.domainId ? { domainId: query.domainId } : {}),
        ...(query.privileged !== undefined ? { privileged: query.privileged } : {}),
        ...(query.search ? { samAccountName: { contains: query.search, mode: "insensitive" } } : {}),
      },
      orderBy: [{ privileged: "desc" }, { samAccountName: "asc" }], take: 500,
    });
    return {
      // §92: identity metadata only — credential MATERIAL is never
      // part of this view; directory rows hold none by construction.
      items: (rows as unknown as Row[]).map((u) => ({
        id: u.id, domainId: u.domainId, objectId: u.objectId, samAccountName: u.samAccountName,
        displayName: u.displayName ?? null, userPrincipalName: u.userPrincipalName ?? null,
        enabled: u.enabled, privileged: u.privileged, privilegeEvidence: u.privilegeEvidence ?? null,
        isServiceAccount: u.isServiceAccount, spnPresent: u.spnPresent, spns: u.spns,
        passwordNeverExpires: u.passwordNeverExpires, passwordNotRequired: u.passwordNotRequired,
        preauthNotRequired: u.preauthNotRequired, delegationType: u.delegationType,
        riskScore: u.riskScore ?? null, riskFactors: u.riskFactors ?? null,
        lastLogonAt: u.lastLogonAt ?? null, passwordLastSetAt: u.passwordLastSetAt ?? null,
      })),
    };
  }

  async getUser(user: RequestUser, id: string) {
    requireAdSecurityPermission(user, "VIEW_AD_IDENTITIES");
    const workspace = await resolveWorkspace(this.prisma, user);
    const row = await this.prisma.directoryUser.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!row) throw new NotFoundException("Directory user not found");
    const u = row as unknown as Row;
    const [memberships, findings] = await Promise.all([
      this.prisma.directoryRelationship.findMany({
        where: { workspaceId: workspace.id, domainId: u.domainId as string, fromRef: u.objectId as string, relationship: "MEMBER_OF" }, take: 200,
      }).catch(() => []),
      this.prisma.finding.findMany({
        where: { workspaceId: workspace.id, directoryObjectId: u.objectId as string, duplicateOfId: null },
        orderBy: { createdAt: "desc" }, take: 100,
      }).catch(() => []),
    ]);
    return {
      ...u,
      memberships: (memberships as unknown as Row[]).map((m) => ({ groupRef: m.toRef, source: m.source, confidence: m.confidence })),
      findings: (findings as unknown as Row[]).map((f) => ({
        id: f.id, title: f.title, severity: f.severity, ruleId: f.ruleId ?? null, status: f.status,
      })),
    };
  }

  async listGroups(user: RequestUser, query: { domainId?: string }) {
    requireAdSecurityPermission(user, "VIEW_AD_IDENTITIES");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.directoryGroup.findMany({
      where: { workspaceId: workspace.id, ...(query.domainId ? { domainId: query.domainId } : {}) },
      orderBy: [{ name: "asc" }], take: 500,
    });
    return {
      items: (rows as unknown as Row[]).map((g) => ({
        id: g.id, domainId: g.domainId, objectId: g.objectId, name: g.name,
        groupScope: g.groupScope, groupType: g.groupType, privilegeClass: g.privilegeClass,
        memberCount: g.memberCount,
      })),
    };
  }

  async getGroup(user: RequestUser, id: string) {
    requireAdSecurityPermission(user, "VIEW_AD_IDENTITIES");
    const workspace = await resolveWorkspace(this.prisma, user);
    const row = await this.prisma.directoryGroup.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!row) throw new NotFoundException("Directory group not found");
    const g = row as unknown as Row;
    const members = await this.prisma.directoryRelationship.findMany({
      where: { workspaceId: workspace.id, domainId: g.domainId as string, toRef: g.objectId as string, relationship: "MEMBER_OF" }, take: 500,
    }).catch(() => []);
    return {
      ...g,
      // Membership is evidence-backed relationship data (§33) —
      // nested membership resolves through the same edges (§65).
      members: (members as unknown as Row[]).map((m) => ({ memberType: m.fromType, memberRef: m.fromRef, source: m.source, confidence: m.confidence })),
    };
  }

  async listComputers(user: RequestUser, query: { domainId?: string }) {
    requireAdSecurityPermission(user, "VIEW_AD_IDENTITIES");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.directoryComputer.findMany({
      where: { workspaceId: workspace.id, ...(query.domainId ? { domainId: query.domainId } : {}) },
      orderBy: [{ hostname: "asc" }], take: 500,
    });
    return {
      items: (rows as unknown as Row[]).map((c) => ({
        id: c.id, domainId: c.domainId, objectId: c.objectId, hostname: c.hostname, dnsName: c.dnsName ?? null,
        osName: c.osName ?? null, osVersion: c.osVersion ?? null, enabled: c.enabled,
        isDomainController: c.isDomainController, delegationType: c.delegationType,
        delegationTargets: c.delegationTargets, riskScore: c.riskScore ?? null, riskFactors: c.riskFactors ?? null,
      })),
    };
  }

  async getComputer(user: RequestUser, id: string) {
    requireAdSecurityPermission(user, "VIEW_AD_IDENTITIES");
    const workspace = await resolveWorkspace(this.prisma, user);
    const row = await this.prisma.directoryComputer.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!row) throw new NotFoundException("Directory computer not found");
    const c = row as unknown as Row;
    const findings = await this.prisma.finding.findMany({
      where: { workspaceId: workspace.id, directoryObjectId: c.objectId as string, duplicateOfId: null },
      orderBy: { createdAt: "desc" }, take: 100,
    }).catch(() => []);
    return {
      ...c,
      findings: (findings as unknown as Row[]).map((f) => ({
        id: f.id, title: f.title, severity: f.severity, ruleId: f.ruleId ?? null, status: f.status,
      })),
    };
  }

  // ── Trusts (§73/§100) ─────────────────────────────────────────

  async listTrusts(user: RequestUser, query: { domainId?: string }) {
    requireAdSecurityPermission(user, "VIEW_AD_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.directoryTrust.findMany({
      where: { workspaceId: workspace.id, ...(query.domainId ? { domainId: query.domainId } : {}) },
      orderBy: { lastSeen: "desc" }, take: 200,
    });
    return {
      items: (rows as unknown as Row[]).map((t) => ({
        id: t.id, domainId: t.domainId, targetDomainName: t.targetDomainName, direction: t.direction,
        trustType: t.trustType, transitive: t.transitive, sidFilteringEnabled: t.sidFilteringEnabled ?? null,
        selectiveAuthentication: t.selectiveAuthentication ?? null,
      })),
    };
  }

  // ── Graph + attack paths (§95/§100) ───────────────────────────

  async getGraph(user: RequestUser, query: { domainId?: string }) {
    requireAdSecurityPermission(user, "VIEW_AD_GRAPH");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.directoryRelationship.findMany({
      where: { workspaceId: workspace.id, ...(query.domainId ? { domainId: query.domainId } : {}) },
      orderBy: { lastSeen: "desc" }, take: 1000,
    });
    return {
      // §33: edges exist only where collected evidence supplied them,
      // each with provenance (source tool + confidence).
      edges: (rows as unknown as Row[]).map((e) => ({
        id: e.id, domainId: e.domainId, fromType: e.fromType, fromRef: e.fromRef,
        toType: e.toType, toRef: e.toRef, relationship: e.relationship,
        source: e.source, confidence: e.confidence, evidenceRef: e.evidenceRef ?? null,
      })),
    };
  }

  /** GET /ad/graph/raw (§30): the RAW directory graph is sensitive —
   *  OWNER/ADMIN (VIEW_RAW_DIRECTORY_GRAPH) and every access is
   *  audited (DIRECTORY_ARTIFACT_ACCESSED). */
  async getRawGraph(user: RequestUser, query: { domainId?: string }) {
    requireAdSecurityPermission(user, "VIEW_RAW_DIRECTORY_GRAPH");
    const workspace = await resolveWorkspace(this.prisma, user);
    const [edges, artifacts] = await Promise.all([
      this.prisma.directoryRelationship.findMany({
        where: { workspaceId: workspace.id, ...(query.domainId ? { domainId: query.domainId } : {}) },
        take: 5000,
      }),
      this.prisma.directoryArtifact.findMany({
        where: { workspaceId: workspace.id, ...(query.domainId ? { domainId: query.domainId } : {}) },
        orderBy: { createdAt: "desc" }, take: 100,
      }).catch(() => []),
    ]);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "DIRECTORY_ARTIFACT_ACCESSED", resourceType: "DirectoryGraph",
      resourceId: query.domainId ?? "workspace",
      metadata: { edges: (edges as unknown[]).length, rawGraph: true },
    });
    return {
      edges: (edges as unknown as Row[]).map((e) => ({ ...e })),
      artifacts: (artifacts as unknown as Row[]).map((a) => ({
        id: a.id, domainId: a.domainId, kind: a.kind, name: a.name, sensitivity: a.sensitivity,
        sizeBytes: a.sizeBytes ?? null, checksum: a.checksum ?? null, createdAt: a.createdAt,
      })),
    };
  }

  async listAttackPaths(user: RequestUser, query: { domainId?: string }) {
    requireAdSecurityPermission(user, "VIEW_AD_ATTACK_PATHS");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.adAttackPath.findMany({
      where: { workspaceId: workspace.id, ...(query.domainId ? { domainId: query.domainId } : {}) },
      orderBy: { createdAt: "desc" }, take: 200,
    });
    return {
      // §35/§75: an attack path is a defensive MODEL computed over
      // collected data — it is never executed, and a path never
      // implies any principal or system is compromised.
      framing: "Attack paths are defensive models over collected directory data. They are never executed, and a path does not imply the principal or any system is compromised.",
      items: (rows as unknown as Row[]).map((p) => ({
        id: p.id, domainId: p.domainId, title: p.title, steps: p.steps, status: p.status,
        confidence: p.confidence, riskScore: p.riskScore, riskFactors: p.riskFactors, createdAt: p.createdAt,
      })),
    };
  }

  // ── AD CS (§96/§100) ──────────────────────────────────────────

  async listAdcs(user: RequestUser, query: { domainId?: string }) {
    requireAdSecurityPermission(user, "VIEW_ADCS");
    const workspace = await resolveWorkspace(this.prisma, user);
    const [cas, templates] = await Promise.all([
      this.prisma.certificateAuthority.findMany({
        where: { workspaceId: workspace.id, ...(query.domainId ? { domainId: query.domainId } : {}) }, take: 200,
      }),
      this.prisma.certificateTemplate.findMany({
        where: { workspaceId: workspace.id, ...(query.domainId ? { domainId: query.domainId } : {}) }, take: 500,
      }),
    ]);
    return {
      // §49/§50: configuration posture only — no exploitation action
      // exists anywhere in this API.
      authorities: (cas as unknown as Row[]).map((c) => ({
        id: c.id, domainId: c.domainId, name: c.name, dnsName: c.dnsName ?? null,
        enrollmentServices: c.enrollmentServices, metadata: c.metadata,
      })),
      templates: (templates as unknown as Row[]).map((t) => ({
        id: t.id, domainId: t.domainId, caId: t.caId ?? null, name: t.name, enabled: t.enabled,
        authenticationEkus: t.authenticationEkus, managerApprovalRequired: t.managerApprovalRequired,
        authorizedSignaturesRequired: t.authorizedSignaturesRequired, riskClasses: t.riskClasses,
      })),
    };
  }

  // ── SMB (§97/§100) ────────────────────────────────────────────

  async listSmb(user: RequestUser, query: { domainId?: string }) {
    requireAdSecurityPermission(user, "VIEW_AD_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.smbShare.findMany({
      where: { workspaceId: workspace.id, ...(query.domainId ? { domainId: query.domainId } : {}) },
      orderBy: { lastSeen: "desc" }, take: 500,
    });
    return {
      // §44/§97: share INVENTORY + permission metadata only — share
      // contents are never browsed, read or downloaded.
      items: (rows as unknown as Row[]).map((s) => ({
        id: s.id, domainId: s.domainId, host: s.host, shareName: s.shareName,
        accessLevel: s.accessLevel, anonymousAccess: s.anonymousAccess ?? null,
        smbDialect: s.smbDialect ?? null, signingRequired: s.signingRequired ?? null, source: s.source,
      })),
    };
  }

  // ── Drift (§98/§100) ──────────────────────────────────────────

  async listDrift(user: RequestUser, query: { domainId?: string; kind?: string }) {
    requireAdSecurityPermission(user, "VIEW_AD_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.adDriftEvent.findMany({
      where: {
        workspaceId: workspace.id,
        ...(query.domainId ? { domainId: query.domainId } : {}),
        ...(query.kind ? { kind: query.kind } : {}),
      },
      orderBy: { detectedAt: "desc" }, take: 500,
    });
    return {
      // §80: a drift event is a review signal, never classified
      // malicious automatically.
      items: (rows as unknown as Row[]).map((d) => ({
        id: d.id, domainId: d.domainId, kind: d.kind, objectRef: d.objectRef ?? null,
        detail: d.detail, detectedAt: d.detectedAt, scanId: d.scanId ?? null,
      })),
    };
  }

  // ── Compliance (§81 — reuses the Phase 13 framework) ──────────

  async listCompliance(user: RequestUser) {
    requireAdSecurityPermission(user, "VIEW_AD_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.controlAssessment.findMany({
      where: { workspaceId: workspace.id, frameworkKey: "MS_AD_BASELINE" },
      orderBy: { assessedAt: "desc" }, take: 500,
    });
    const byStatus: Record<string, number> = {};
    for (const r of rows as unknown as Row[]) byStatus[r.status as string] = (byStatus[r.status as string] ?? 0) + 1;
    return {
      // §81: posture evidence mapped onto the baseline — NEVER a
      // certification claim.
      disclaimer: "Control assessments are posture evidence from governed checks mapped to the Microsoft AD security baseline; they are not a compliance certification.",
      byStatus,
      items: (rows as unknown as Row[]).map((r) => ({
        id: r.id, frameworkKey: r.frameworkKey, controlId: r.controlId, subjectRef: r.subjectRef,
        status: r.status, evidence: r.evidence ?? null, assessedAt: r.assessedAt, scanId: r.scanId ?? null,
      })),
    };
  }

  // ── Helpers ────────────────────────────────────────────────────

  private assertReferenceName(reference: string): void {
    if (looksLikeSecretValue(reference) || !isValidCredentialReference(reference)) {
      throw new BadRequestException("credentialReference must be a secret-manager reference NAME — credential values are never accepted or stored (§7)");
    }
  }

  /** Shared gated scan start (mirrors Prompt 14 discipline). */
  private async startGatedScan(
    user: RequestUser,
    workspaceId: string,
    target: Row & { id: string; value: string },
    scopeHost: string,
    profile: string,
  ) {
    let scope = await this.prisma.scope.findFirst({ where: { targetId: target.id } });
    if (!scope) {
      scope = await this.prisma.scope.create({
        data: {
          workspaceId, targetId: target.id, name: `${scopeHost} directory scope`,
          rules: { includeHosts: [hostOf(target.value)], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] } as never,
        },
      });
    }
    let assessment = await this.prisma.assessment.findFirst({
      where: { targetId: target.id, profile: profile as never, status: "APPROVED" },
      orderBy: { createdAt: "desc" },
    });
    if (!assessment) {
      assessment = await this.prisma.assessment.create({
        data: {
          workspaceId, targetId: target.id, scopeId: (scope as Row).id,
          name: `${scopeHost} — ${profile}`, profile: profile as never,
          status: "APPROVED", createdBy: user.id, approvedBy: user.id,
        },
      });
    }
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "AD_SCAN_STARTED", resourceType: "ActiveDirectoryDomain", resourceId: target.id,
      metadata: { profile, assessmentId: (assessment as Row).id },
    });
    const started = await this.orchestration.startScan(user, (assessment as Row).id);
    return { assessmentId: (assessment as Row).id, ...started };
  }
}
