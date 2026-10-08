import { createHash } from "node:crypto";
import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  projectFindingForClient, clientNotificationText, renderReport, evaluateShareLink, hashShareToken,
  evaluateRemediationTransition, toV2LifecycleState, REMEDIATION_TRANSITIONS,
  type ReportSnapshotDocument,
} from "@dsrclone/security-sdk";

/** Shortest legal path through the Prompt 31 case machine (BFS over
 *  REMEDIATION_TRANSITIONS); null when the target is unreachable. */
export function shortestCasePath(from: string, to: string): string[] | null {
  if (from === to) return [];
  const queue: { state: string; path: string[] }[] = [{ state: from, path: [] }];
  const seen = new Set([from]);
  while (queue.length) {
    const { state, path } = queue.shift()!;
    for (const next of REMEDIATION_TRANSITIONS[state as keyof typeof REMEDIATION_TRANSITIONS] ?? []) {
      if (seen.has(next)) continue;
      const extended = [...path, next];
      if (next === to) return extended;
      seen.add(next);
      queue.push({ state: next, path: extended });
    }
  }
  return null;
}
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { requireV2Permission, requireClientPermission } from "../vulnerability-management/permissions-v2";

/**
 * Prompt 37 §95–§109 client portal.
 *
 * The portal is a HARD tenant boundary. A portal request resolves
 * exactly one ClientPortalUser binding (user → client organization);
 * every object it can reach hangs off engagements of that organization,
 * and findings reach it ONLY through an active ClientFindingPublication
 * (§100). Anything else — unpublished, another client's, another
 * workspace's — is a 404, never a 403 and never a filtered 200 (§144).
 * Internal comments, internal evidence, risk internals and other
 * clients' data have no code path into a portal response (§101):
 * finding payloads are built exclusively by the SDK allowlist
 * projection.
 */
@Injectable()
export class ClientPortalService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  // ---------------- Admin side (§95–§97) ----------------

  async createClient(user: RequestUser, workspaceId: string, input: { name: string; slug: string; contactEmail?: string }) {
    requireV2Permission(user, "MANAGE_CLIENT_ENGAGEMENTS");
    // Prompt 39 RC1 fix (finding RC1-H1): unguarded input.slug.toLowerCase()
    // turned a malformed request body into a 500 TypeError. Invalid input
    // is a 400 here, and the controller validates with zod before this.
    if (typeof input?.name !== "string" || input.name.trim() === "" || typeof input?.slug !== "string" || input.slug.trim() === "") {
      throw new BadRequestException("client name and slug are required");
    }
    const slug = input.slug.toLowerCase().replace(/[^a-z0-9-]/g, "-");
    const existing = await this.prisma.clientOrganization.findFirst({ where: { workspaceId, slug } });
    if (existing) throw new ConflictException(`client slug ${slug} already exists in this workspace (§95)`);
    const row = await this.prisma.clientOrganization.create({
      data: { workspaceId, name: input.name, slug, contactEmail: input.contactEmail, createdBy: user.id },
    });
    return row;
  }

  async listClients(user: RequestUser, workspaceId: string) {
    requireV2Permission(user, "MANAGE_CLIENT_ENGAGEMENTS");
    return this.prisma.clientOrganization.findMany({ where: { workspaceId }, orderBy: { name: "asc" } });
  }

  async createEngagement(user: RequestUser, workspaceId: string, input: {
    clientOrganizationId: string; name: string; scopeSummary?: string; reportVisibility?: string;
  }) {
    requireV2Permission(user, "MANAGE_CLIENT_ENGAGEMENTS");
    if (typeof input?.name !== "string" || input.name.trim() === "" || typeof input?.clientOrganizationId !== "string" || input.clientOrganizationId === "") {
      throw new BadRequestException("engagement name and clientOrganizationId are required");
    }
    const client = await this.prisma.clientOrganization.findFirst({ where: { id: input.clientOrganizationId, workspaceId } });
    if (!client) throw new NotFoundException("client organization not found in this workspace");
    return this.prisma.clientEngagement.create({
      data: {
        workspaceId, clientOrganizationId: client.id, name: input.name,
        reportVisibility: input.reportVisibility ?? "FINALIZED_ONLY",
        createdBy: user.id,
      },
    });
  }

  async listEngagementsAdmin(user: RequestUser, workspaceId: string) {
    requireV2Permission(user, "MANAGE_CLIENT_ENGAGEMENTS");
    return this.prisma.clientEngagement.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" } });
  }

  /** §97: bind an existing user account to exactly one client org with
   *  one of the §128 portal roles. A user already bound elsewhere is
   *  refused — portal identity is singular by design. */
  async bindPortalUser(user: RequestUser, workspaceId: string, input: { userId: string; clientOrganizationId: string; portalRole: string }) {
    requireV2Permission(user, "MANAGE_CLIENT_ENGAGEMENTS");
    if (!["CLIENT_VIEWER", "CLIENT_REMEDIATOR", "CLIENT_MANAGER"].includes(input.portalRole)) {
      throw new BadRequestException(`unknown portal role ${input.portalRole} (§128)`);
    }
    const client = await this.prisma.clientOrganization.findFirst({ where: { id: input.clientOrganizationId, workspaceId } });
    if (!client) throw new NotFoundException("client organization not found in this workspace");
    const account = await this.prisma.user.findFirst({ where: { id: input.userId } });
    if (!account) throw new NotFoundException("user account not found");
    const existing = await this.prisma.clientPortalUser.findFirst({ where: { userId: input.userId } });
    if (existing) throw new ConflictException("this user is already bound to a client organization (§97)");
    return this.prisma.clientPortalUser.create({
      data: { userId: input.userId, clientOrganizationId: client.id, workspaceId: client.workspaceId, portalRole: input.portalRole, createdBy: user.id },
    });
  }

  /** §100: publication is the ONLY way a finding becomes portal-visible. */
  async publishFinding(user: RequestUser, workspaceId: string, engagementId: string, findingId: string) {
    requireV2Permission(user, "MANAGE_CLIENT_ENGAGEMENTS");
    const engagement = await this.prisma.clientEngagement.findFirst({ where: { id: engagementId, workspaceId } });
    if (!engagement) throw new NotFoundException("engagement not found in this workspace");
    const finding = await this.prisma.finding.findFirst({ where: { id: findingId, workspaceId } });
    if (!finding) throw new NotFoundException("finding not found in this workspace");
    const existing = await this.prisma.clientFindingPublication.findFirst({ where: { engagementId, findingId } });
    if (existing && !existing.revokedAt) return existing;
    const publication = existing
      ? await this.prisma.clientFindingPublication.update({ where: { id: existing.id }, data: { revokedAt: null, publishedBy: user.id, publishedAt: new Date() } })
      : await this.prisma.clientFindingPublication.create({ data: { engagementId, findingId, workspaceId: engagement.workspaceId, publishedBy: user.id } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "CLIENT_FINDING_PUBLISHED", resourceType: "Finding", resourceId: findingId, metadata: { engagementId } as never });
    const note = clientNotificationText("finding_published", {
      title: finding.title, severity: finding.severity, status: toV2LifecycleState({ lifecycleStatus: finding.lifecycleStatus }),
    });
    await this.prisma.clientNotification.create({
      data: {
        clientOrganizationId: engagement.clientOrganizationId, engagementId, type: "FINDING_PUBLISHED", findingId: finding.id,
        title: note.title, body: note.body,
      },
    });
    return publication;
  }

  async unpublishFinding(user: RequestUser, workspaceId: string, engagementId: string, findingId: string) {
    requireV2Permission(user, "MANAGE_CLIENT_ENGAGEMENTS");
    const publication = await this.prisma.clientFindingPublication.findFirst({ where: { engagementId, findingId, revokedAt: null } });
    if (!publication) throw new NotFoundException("no active publication for this finding in this engagement");
    const updated = await this.prisma.clientFindingPublication.update({ where: { id: publication.id }, data: { revokedAt: new Date() } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "CLIENT_FINDING_UNPUBLISHED", resourceType: "Finding", resourceId: findingId, metadata: { engagementId } as never });
    return updated;
  }

  // ---------------- Portal side (§98–§109) ----------------

  /** Resolve the caller's portal binding or 404 (never a hint that
   *  the portal exists for other identities). */
  private async portalContext(user: RequestUser) {
    const binding = await this.prisma.clientPortalUser.findFirst({ where: { userId: user.id } });
    if (!binding) throw new NotFoundException("not found");
    requireClientPermission(binding.portalRole, "VIEW_CLIENT_PORTAL");
    return binding;
  }

  private async auditPortal(user: RequestUser, workspaceId: string, action: string, resourceType: string, resourceId: string, metadata?: Record<string, unknown>) {
    const workspace = await this.prisma.workspace.findFirst({ where: { id: workspaceId } });
    await this.audit.record({
      actorId: user.id, organizationId: workspace?.organizationId ?? user.organizationId, workspaceId,
      action: action as never, resourceType, resourceId, metadata: metadata as never,
    });
  }

  private async engagementFor(binding: { clientOrganizationId: string }, engagementId: string) {
    const engagement = await this.prisma.clientEngagement.findFirst({
      where: { id: engagementId, clientOrganizationId: binding.clientOrganizationId },
    });
    if (!engagement) throw new NotFoundException("not found");
    return engagement;
  }

  async dashboard(user: RequestUser) {
    const binding = await this.portalContext(user);
    const engagements = await this.prisma.clientEngagement.findMany({ where: { clientOrganizationId: binding.clientOrganizationId } });
    const engagementIds = engagements.map((e) => e.id);
    const publications = engagementIds.length
      ? await this.prisma.clientFindingPublication.findMany({ where: { engagementId: { in: engagementIds }, revokedAt: null } })
      : [];
    const unread = await this.prisma.clientNotification.count({ where: { clientOrganizationId: binding.clientOrganizationId, readAt: null } });
    if (engagements[0]) {
      await this.auditPortal(user, engagements[0].workspaceId, "CLIENT_PORTAL_ACCESSED", "ClientPortal", binding.clientOrganizationId, { view: "dashboard" });
    }
    return {
      clientOrganizationId: binding.clientOrganizationId, portalRole: binding.portalRole,
      engagements: engagements.length, publishedFindings: publications.length, unreadNotifications: unread,
    };
  }

  async myEngagements(user: RequestUser) {
    const binding = await this.portalContext(user);
    return this.prisma.clientEngagement.findMany({ where: { clientOrganizationId: binding.clientOrganizationId }, orderBy: { createdAt: "desc" } });
  }

  async myFindings(user: RequestUser, engagementId: string) {
    const binding = await this.portalContext(user);
    const engagement = await this.engagementFor(binding, engagementId);
    const publications = await this.prisma.clientFindingPublication.findMany({ where: { engagementId, revokedAt: null } });
    const out = [];
    for (const pub of publications) {
      out.push(await this.projectedFinding(engagement.workspaceId, pub.findingId));
    }
    await this.auditPortal(user, engagement.workspaceId, "CLIENT_PORTAL_ACCESSED", "ClientEngagement", engagementId, { view: "findings" });
    return out.filter(Boolean);
  }

  private async projectedFinding(workspaceId: string, findingId: string) {
    const finding = await this.prisma.finding.findFirst({ where: { id: findingId, workspaceId } });
    if (!finding) return null;
    const [evidence, comments, kase] = await Promise.all([
      this.prisma.findingEvidence.findMany({ where: { findingId } }),
      this.prisma.findingComment.findMany({ where: { findingId } }),
      this.prisma.remediationCase.findFirst({ where: { workspaceId, findingId }, orderBy: { createdAt: "desc" } }),
    ]);
    return projectFindingForClient(
      { ...(finding as object), caseStatus: kase?.status ?? null, caseVerificationState: kase?.verificationState ?? null } as never,
      evidence as never, comments as never,
    );
  }

  async myFinding(user: RequestUser, engagementId: string, findingId: string) {
    const binding = await this.portalContext(user);
    const engagement = await this.engagementFor(binding, engagementId);
    const publication = await this.prisma.clientFindingPublication.findFirst({ where: { engagementId, findingId, revokedAt: null } });
    if (!publication) throw new NotFoundException("not found"); // §144: unpublished == nonexistent
    const projected = await this.projectedFinding(engagement.workspaceId, findingId);
    if (!projected) throw new NotFoundException("not found");
    await this.auditPortal(user, engagement.workspaceId, "CLIENT_PORTAL_ACCESSED", "Finding", findingId, { view: "finding-detail" });
    return projected;
  }

  /** §102: client comments are forced CLIENT visibility — a client can
   *  never author an internal note. */
  async comment(user: RequestUser, engagementId: string, findingId: string, text: string) {
    const binding = await this.portalContext(user);
    requireClientPermission(binding.portalRole, "ADD_CLIENT_COMMENTS");
    const engagement = await this.engagementFor(binding, engagementId);
    const publication = await this.prisma.clientFindingPublication.findFirst({ where: { engagementId, findingId, revokedAt: null } });
    if (!publication) throw new NotFoundException("not found");
    const trimmed = text?.trim();
    if (!trimmed) throw new BadRequestException("comment text is required");
    const row = await this.prisma.findingComment.create({
      data: { findingId, workspaceId: engagement.workspaceId, authorId: user.id, text: trimmed.slice(0, 8000), visibility: "CLIENT", mentions: [] as never },
    });
    await this.auditPortal(user, engagement.workspaceId, "CLIENT_COMMENT_ADDED", "Finding", findingId, { commentId: row.id, via: "portal" });
    return row;
  }

  /**
   * §103/§30: a client fix claim moves the Prompt 31 case to
   * FIX_CLAIMED — and to nothing beyond it. Verified closure exists
   * only on the governed retest path (§30), which this service cannot
   * invoke: there is no code path here to a verification verdict.
   */
  async claimFix(user: RequestUser, engagementId: string, findingId: string, note?: string) {
    const binding = await this.portalContext(user);
    requireClientPermission(binding.portalRole, "CLAIM_FIX");
    const engagement = await this.engagementFor(binding, engagementId);
    const publication = await this.prisma.clientFindingPublication.findFirst({ where: { engagementId, findingId, revokedAt: null } });
    if (!publication) throw new NotFoundException("not found");
    const workspaceId = engagement.workspaceId;
    let kase = await this.prisma.remediationCase.findFirst({ where: { workspaceId, findingId }, orderBy: { createdAt: "desc" } });
    if (!kase) {
      kase = await this.prisma.remediationCase.create({
        data: { organizationId: user.organizationId, workspaceId, findingId, status: "NEW", createdBy: user.id },
      });
    }
    // The governed journey to FIX_CLAIMED runs through the Prompt 31
    // machine (NEW → TRIAGED → IN_PROGRESS → FIX_CLAIMED): walk the
    // shortest legal path, recording every hop. States from which
    // FIX_CLAIMED is unreachable (VERIFIED_FIXED, CLOSED, …) refuse —
    // a client cannot resurrect or re-claim a settled case.
    const path = shortestCasePath(kase.status, "FIX_CLAIMED");
    if (!path) throw new ConflictException(`a fix cannot be claimed while the case is ${kase.status} (§103)`);
    let current = kase.status;
    for (const hop of path) {
      const verdict = evaluateRemediationTransition({
        from: current as never, to: hop as never, viaFixClaim: hop === "FIX_CLAIMED",
      });
      if (!verdict.ok) throw new ConflictException(verdict.error ?? "fix cannot be claimed from the current state (§103)");
      await this.prisma.remediationCase.update({ where: { id: kase.id }, data: { status: hop } });
      await this.prisma.remediationStatusHistory.create({
        data: {
          caseId: kase.id, workspaceId, fromStatus: current, toStatus: hop, actorId: user.id,
          reason: hop === "FIX_CLAIMED" ? (note ?? "client fix claim via portal (§103)") : "progressed to register the client fix claim (§103)",
        },
      });
      current = hop;
    }
    await this.auditPortal(user, workspaceId, "FIX_CLAIMED", "Finding", findingId, { caseId: kase.id, via: "portal" });
    return { caseId: kase.id, status: "FIX_CLAIMED", verifiedClosure: false };
  }

  /** §104: retest requests join the governed queue; the client never
   *  learns, triggers or influences the verification itself. */
  async requestRetest(user: RequestUser, engagementId: string, findingId: string) {
    const binding = await this.portalContext(user);
    requireClientPermission(binding.portalRole, "REQUEST_RETEST");
    const engagement = await this.engagementFor(binding, engagementId);
    const publication = await this.prisma.clientFindingPublication.findFirst({ where: { engagementId, findingId, revokedAt: null } });
    if (!publication) throw new NotFoundException("not found");
    // Delegate to the Prompt 20 unified retest router as the portal user
    // is not a workspace member in the usual sense — the service checks
    // the workspace Role, so perform the equivalent governed write here:
    // a QUEUED RetestRequest, nothing executed, nothing escalated.
    const retest = await this.prisma.retestRequest.create({
      data: { findingId, workspaceId: engagement.workspaceId, requestedBy: user.id, sourceTool: "CLIENT_PORTAL", checkReference: "PORTAL_REQUEST", status: "QUEUED" },
    });
    await this.auditPortal(user, engagement.workspaceId, "VERIFICATION_REQUESTED", "Finding", findingId, { retestId: retest.id, via: "portal" });
    return { retest, status: "QUEUED" };
  }

  /** §105: only FINALIZED reports scoped to this client are listable. */
  async myReports(user: RequestUser, engagementId: string) {
    const binding = await this.portalContext(user);
    const engagement = await this.engagementFor(binding, engagementId);
    const reports = await this.prisma.securityReport.findMany({
      where: {
        workspaceId: engagement.workspaceId, approvalStatus: "ISSUED",
        OR: [{ clientOrganizationId: binding.clientOrganizationId }, { engagementId }],
      },
      orderBy: { finalizedAt: "desc" },
    });
    return reports.map((r) => ({ id: r.id, title: r.title, type: r.type, version: r.version, finalizedAt: r.finalizedAt }));
  }

  async downloadReport(user: RequestUser, engagementId: string, reportId: string, format: "PDF" | "HTML" | "JSON" | "CSV") {
    const binding = await this.portalContext(user);
    requireClientPermission(binding.portalRole, "DOWNLOAD_FINALIZED_REPORTS");
    const engagement = await this.engagementFor(binding, engagementId);
    const report = await this.prisma.securityReport.findFirst({
      where: {
        id: reportId, workspaceId: engagement.workspaceId, approvalStatus: "ISSUED",
        OR: [{ clientOrganizationId: binding.clientOrganizationId }, { engagementId }],
      },
    });
    if (!report) throw new NotFoundException("not found"); // §105/§144
    const version = await this.prisma.reportVersion.findFirst({ where: { reportId, workspaceId: engagement.workspaceId }, orderBy: { finalizedAt: "desc" } });
    const snapshot = version ? null : await this.prisma.reportSnapshot.findFirst({ where: { reportId } });
    const document = (version?.document ?? snapshot?.data) as unknown as ReportSnapshotDocument | undefined;
    if (!document) throw new NotFoundException("not found");
    const rendered = renderReport(document, format);
    const bytes = Buffer.isBuffer(rendered.content) ? rendered.content : Buffer.from(rendered.content as string);
    await this.auditPortal(user, engagement.workspaceId, "REPORT_DOWNLOADED", "SecurityReport", reportId, { format, via: "portal" });
    return { format, contentType: rendered.contentType, checksum: createHash("sha256").update(bytes).digest("hex"), sizeBytes: bytes.length, content: Buffer.isBuffer(rendered.content) ? bytes.toString("base64") : rendered.content, encoding: Buffer.isBuffer(rendered.content) ? "base64" : "utf8" };
  }

  async myNotifications(user: RequestUser) {
    const binding = await this.portalContext(user);
    return this.prisma.clientNotification.findMany({ where: { clientOrganizationId: binding.clientOrganizationId }, orderBy: { createdAt: "desc" }, take: 100 });
  }

  async markNotificationRead(user: RequestUser, notificationId: string) {
    const binding = await this.portalContext(user);
    const row = await this.prisma.clientNotification.findFirst({ where: { id: notificationId, clientOrganizationId: binding.clientOrganizationId } });
    if (!row) throw new NotFoundException("not found");
    return this.prisma.clientNotification.update({ where: { id: notificationId }, data: { readAt: new Date() } });
  }

  /** §149: portal export — client-visible fields of published findings only. */
  async exportFindings(user: RequestUser, engagementId: string) {
    const binding = await this.portalContext(user);
    const findings = await this.myFindings(user, engagementId);
    return { format: "JSON", count: findings.length, findings };
  }

  // ---------------- Secure share links (§106) ----------------

  /** Public resolution: raw token → hash → governed evaluation. The
   *  response renders the frozen finalized version only. */
  async resolveSharedReport(token: string, format: "PDF" | "HTML" | "JSON" | "CSV") {
    const link = await this.prisma.reportShareLink.findFirst({ where: { tokenHash: hashShareToken(token) } });
    if (!link) throw new NotFoundException("not found");
    const verdict = evaluateShareLink(link, new Date());
    if (!verdict.usable) throw new NotFoundException("not found"); // expired/revoked/exhausted are indistinguishable (§106)
    const report = await this.prisma.securityReport.findFirst({ where: { id: link.reportId, workspaceId: link.workspaceId, approvalStatus: "ISSUED" } });
    if (!report) throw new NotFoundException("not found");
    const version = link.reportVersionId
      ? await this.prisma.reportVersion.findFirst({ where: { id: link.reportVersionId, reportId: report.id } })
      : await this.prisma.reportVersion.findFirst({ where: { reportId: report.id }, orderBy: { finalizedAt: "desc" } });
    if (!version) throw new NotFoundException("not found");
    const rendered = renderReport(version.document as unknown as ReportSnapshotDocument, format);
    const bytes = Buffer.isBuffer(rendered.content) ? rendered.content : Buffer.from(rendered.content as string);
    await this.prisma.reportShareLink.update({ where: { id: link.id }, data: { downloadCount: (link.downloadCount ?? 0) + 1 } });
    const workspace = await this.prisma.workspace.findFirst({ where: { id: link.workspaceId } });
    await this.audit.record({
      actorId: "share-link", organizationId: workspace?.organizationId ?? link.workspaceId, workspaceId: link.workspaceId,
      action: "REPORT_SHARED", resourceType: "SecurityReport", resourceId: report.id,
      metadata: { linkId: link.id, format, via: "share-link" } as never,
    });
    return { format, contentType: rendered.contentType, checksum: createHash("sha256").update(bytes).digest("hex"), sizeBytes: bytes.length, content: Buffer.isBuffer(rendered.content) ? bytes.toString("base64") : rendered.content, encoding: Buffer.isBuffer(rendered.content) ? "base64" : "utf8" };
  }
}
