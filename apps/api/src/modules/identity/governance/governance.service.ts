import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import * as bcrypt from "bcryptjs";
import {
  DEFAULT_PASSWORD_POLICY, emailDomain, evaluatePassword, normalizeEmail, randomToken, sha256Hex,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";

/**
 * Identity governance (§60–65, §88, §94–100, §116): organization security
 * policy (with lockout-safe validation), password policy, domain
 * verification, invitations, user directory, access reviews and the
 * privileged-access report. Policy enforcement lives here in services —
 * never only in the UI (§99).
 */
@Injectable()
export class GovernanceService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  /* ------------------------------ organization ---------------------------- */
  async getOrganization(user: RequestUser, organizationId: string) {
    if (organizationId !== user.organizationId) throw new NotFoundException("Organization not found");
    const org = await this.prisma.organization.findUnique({ where: { id: organizationId } });
    if (!org || org.deletedAt) throw new NotFoundException("Organization not found");
    return { id: org.id, name: org.name, slug: org.slug, status: org.status, securityContact: org.securityContact, dataRegion: org.dataRegion, createdAt: org.createdAt };
  }

  /** Suspended organizations must not run scans or automations (§4). */
  async organizationOperational(organizationId: string): Promise<boolean> {
    const org = await this.prisma.organization.findUnique({ where: { id: organizationId } });
    return Boolean(org) && org?.status === "ACTIVE" && !org?.deletedAt;
  }

  /* --------------------------- user directory (§88) ------------------------ */
  async listMembers(user: RequestUser) {
    const memberships = await this.prisma.membership.findMany({ where: { organizationId: user.organizationId }, orderBy: { createdAt: "asc" } });
    const out = [];
    for (const m of memberships) {
      const member = await this.prisma.user.findUnique({ where: { id: m.userId } });
      if (!member) continue;
      const [mfa, passkeys, wm] = await Promise.all([
        this.prisma.mfaMethod.count({ where: { userId: member.id, isActive: true } }),
        this.prisma.webAuthnCredential.count({ where: { userId: member.id } }),
        this.prisma.workspaceMembership.findMany({ where: { userId: member.id, organizationId: user.organizationId, status: "ACTIVE" } }),
      ]);
      // Directory exposes NO sensitive authentication material (§88).
      out.push({
        userId: member.id, email: member.email, displayName: member.name, userStatus: member.status,
        organizationRole: m.role, membershipStatus: m.status, mfaEnrolled: mfa > 0 || passkeys > 0,
        passkeyCount: passkeys, workspaceIds: wm.map((w) => w.workspaceId), lastActive: member.lastLoginAt,
      });
    }
    return out;
  }

  async setMembershipRole(user: RequestUser, targetUserId: string, role: string) {
    const membership = await this.prisma.membership.findFirst({ where: { userId: targetUserId, organizationId: user.organizationId } });
    if (!membership) throw new NotFoundException("Membership not found");
    const updated = await this.prisma.membership.update({ where: { id: membership.id }, data: { role: role as never } });
    return updated;
  }

  async setMembershipStatus(user: RequestUser, targetUserId: string, status: string) {
    const membership = await this.prisma.membership.findFirst({ where: { userId: targetUserId, organizationId: user.organizationId } });
    if (!membership) throw new NotFoundException("Membership not found");
    const updated = await this.prisma.membership.update({ where: { id: membership.id }, data: { status: status as never } });
    if (status === "SUSPENDED" || status === "REVOKED") {
      await this.prisma.userSession.updateMany({ where: { userId: targetUserId, organizationId: user.organizationId, revokedAt: null }, data: { revokedAt: new Date() } });
    }
    return updated;
  }

  /* --------------------------- security policy ---------------------------- */
  async getSecurityPolicy(user: RequestUser) {
    const policy = await this.prisma.organizationSecurityPolicy.findUnique({ where: { organizationId: user.organizationId } });
    return policy ?? {
      organizationId: user.organizationId, mfaRequirement: "OPTIONAL", ssoRequirement: "OPTIONAL",
      passwordLoginAllowed: true, sessionIdleMinutes: 30, sessionAbsoluteMinutes: 720,
      patAllowed: true, scimEnabled: false, jitEnabled: false, stepUpActions: [],
    };
  }

  async updateSecurityPolicy(user: RequestUser, body: Record<string, unknown>) {
    const fields = ["mfaRequirement", "ssoRequirement", "passwordLoginAllowed", "sessionIdleMinutes", "sessionAbsoluteMinutes", "apiKeyMaxLifetimeDays", "patAllowed", "scimEnabled", "jitEnabled", "stepUpActions"];
    const data: Record<string, unknown> = {};
    for (const f of fields) if (body[f] !== undefined) data[f] = body[f];
    // §100: unsafe configurations are refused — SSO_REQUIRED with no
    // working provider and no recovery path is a lockout, not a policy.
    if (data.ssoRequirement === "SSO_REQUIRED") {
      const [providers, breakGlass, domains] = await Promise.all([
        this.prisma.enterpriseSsoProvider.count({ where: { organizationId: user.organizationId, enabled: true } }),
        this.prisma.breakGlassEnrollment.count({ where: { organizationId: user.organizationId, status: "ACTIVE" } }),
        this.prisma.organizationDomain.count({ where: { organizationId: user.organizationId, status: "VERIFIED" } }),
      ]);
      if (providers === 0) throw new BadRequestException("Cannot require SSO: no SSO provider is enabled");
      if (breakGlass === 0 && domains === 0) throw new BadRequestException("Cannot require SSO without a validated recovery path (break-glass enrollment or verified domain)");
    }
    if (data.passwordLoginAllowed === false && data.ssoRequirement !== "SSO_REQUIRED") {
      // Disallowing password login only makes sense with SSO enforcement; keep explicit.
      const current = await this.getSecurityPolicy(user);
      if ((current as Record<string, unknown>).ssoRequirement !== "SSO_REQUIRED") {
        throw new BadRequestException("Password login can only be disabled when SSO is required");
      }
    }
    const existing = await this.prisma.organizationSecurityPolicy.findUnique({ where: { organizationId: user.organizationId } });
    const saved = existing
      ? await this.prisma.organizationSecurityPolicy.update({ where: { organizationId: user.organizationId }, data })
      : await this.prisma.organizationSecurityPolicy.create({ data: { organizationId: user.organizationId, ...data } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "SECURITY_POLICY_CHANGED", resourceType: "OrganizationSecurityPolicy", resourceId: saved.id as string, metadata: { fields: Object.keys(data) } });
    return saved;
  }

  /* ---------------------------- password policy --------------------------- */
  async getPasswordPolicy(user: RequestUser) {
    const policy = await this.prisma.passwordPolicy.findUnique({ where: { organizationId: user.organizationId } });
    return policy ?? { organizationId: user.organizationId, ...DEFAULT_PASSWORD_POLICY };
  }

  async updatePasswordPolicy(user: RequestUser, body: Record<string, unknown>) {
    const data: Record<string, unknown> = {};
    for (const f of ["minLength", "maxLength", "historyCount", "compromisedCheckEnabled"]) if (body[f] !== undefined) data[f] = body[f];
    if (typeof data.minLength === "number" && data.minLength < 8) throw new BadRequestException("Minimum length cannot be below 8");
    const existing = await this.prisma.passwordPolicy.findUnique({ where: { organizationId: user.organizationId } });
    return existing
      ? this.prisma.passwordPolicy.update({ where: { organizationId: user.organizationId }, data })
      : this.prisma.passwordPolicy.create({ data: { organizationId: user.organizationId, ...data } });
  }

  /** Validate a candidate password against the org policy (§21). */
  async assertPasswordAllowed(organizationId: string, password: string) {
    const stored = await this.prisma.passwordPolicy.findUnique({ where: { organizationId } });
    const shape = stored ? { minLength: stored.minLength as number, maxLength: stored.maxLength as number, historyCount: stored.historyCount as number, compromisedCheckEnabled: stored.compromisedCheckEnabled as boolean } : DEFAULT_PASSWORD_POLICY;
    const result = evaluatePassword(password, shape);
    if (!result.ok) throw new BadRequestException(result.failures.join("; "));
  }

  /* ------------------------------ domains --------------------------------- */
  async startDomainVerification(user: RequestUser, domain: string) {
    const clean = domain.trim().toLowerCase();
    if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(clean)) throw new BadRequestException("Invalid domain");
    const existing = await this.prisma.organizationDomain.findFirst({ where: { organizationId: user.organizationId, domain: clean } });
    if (existing) throw new ConflictException("Domain already registered for this organization");
    const token = randomToken(24);
    const record = await this.prisma.organizationDomain.create({
      data: { organizationId: user.organizationId, domain: clean, verificationTokenHash: sha256Hex(token), status: "PENDING" },
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "DOMAIN_VERIFICATION_STARTED", resourceType: "OrganizationDomain", resourceId: record.id as string, metadata: { domain: clean } });
    // The token is shown once so it can be published as a DNS TXT record;
    // only its hash persists (§61).
    return { id: record.id, domain: clean, status: "PENDING", dnsRecord: { type: "TXT", name: `_dsrclone-verify.${clean}`, value: `dsrclone-site-verification=${token}` }, shownOnce: true };
  }

  /** Verify via an injected DNS TXT lookup (fixture in tests). */
  async confirmDomainVerification(user: RequestUser, domainId: string, resolveTxt: (name: string) => Promise<string[][]>) {
    const record = await this.prisma.organizationDomain.findFirst({ where: { id: domainId, organizationId: user.organizationId } });
    if (!record) throw new NotFoundException("Domain not found");
    const records = await resolveTxt(`_dsrclone-verify.${record.domain}`);
    const flat = records.flat().join(" ");
    const expectedPrefix = "dsrclone-site-verification=";
    const presented = flat.split(/\s+/).find((t) => t.startsWith(expectedPrefix))?.slice(expectedPrefix.length);
    if (!presented || sha256Hex(presented) !== record.verificationTokenHash) {
      throw new BadRequestException("Verification token not found in DNS TXT records");
    }
    const updated = await this.prisma.organizationDomain.update({ where: { id: domainId }, data: { status: "VERIFIED", verifiedAt: new Date() } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "DOMAIN_VERIFIED", resourceType: "OrganizationDomain", resourceId: domainId });
    return updated;
  }

  async listDomains(user: RequestUser) {
    return this.prisma.organizationDomain.findMany({ where: { organizationId: user.organizationId } });
  }

  /* ----------------------------- invitations ------------------------------ */
  async createInvitation(user: RequestUser, body: Record<string, unknown>) {
    const email = String(body.email ?? "");
    const normalized = normalizeEmail(email);
    if (!normalized.includes("@")) throw new BadRequestException("A valid email is required");
    const token = randomToken(32);
    const invitation = await this.prisma.organizationInvitation.create({
      data: {
        organizationId: user.organizationId, email, normalizedEmail: normalized,
        role: ((body.role as string) ?? "VIEWER") as never, workspaceIds: (body.workspaceIds as string[]) ?? null,
        tokenHash: sha256Hex(token), status: "PENDING", invitedBy: user.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 3600_000),
      },
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "INVITATION_CREATED", resourceType: "OrganizationInvitation", resourceId: invitation.id as string, metadata: { email: normalized } });
    return { id: invitation.id, email, role: invitation.role, expiresAt: invitation.expiresAt, token, shownOnce: true };
  }

  /** Accept an invitation (§63–65): token is single-use + hashed; expired
   *  invitations can never be accepted. Creates the user if needed. */
  async acceptInvitation(token: string, body: { name?: string; password?: string }) {
    const invitation = await this.prisma.organizationInvitation.findUnique({ where: { tokenHash: sha256Hex(token) } });
    if (!invitation || invitation.status !== "PENDING") throw new BadRequestException("Invitation is invalid or already used");
    if (new Date(invitation.expiresAt as Date).getTime() < Date.now()) {
      await this.prisma.organizationInvitation.update({ where: { id: invitation.id }, data: { status: "EXPIRED" } });
      throw new BadRequestException("Invitation has expired");
    }
    let user = await this.prisma.user.findUnique({ where: { normalizedEmail: invitation.normalizedEmail } });
    if (!user) {
      if (!body.password) throw new BadRequestException("A password is required to create the account");
      await this.assertPasswordAllowed(invitation.organizationId as string, body.password);
      user = await this.prisma.user.create({
        data: {
          email: invitation.email, normalizedEmail: invitation.normalizedEmail, name: body.name ?? invitation.email,
          passwordHash: await bcrypt.hash(body.password, 12), status: "ACTIVE",
        },
      });
    }
    const membership = await this.prisma.membership.findFirst({ where: { userId: user.id, organizationId: invitation.organizationId } });
    if (!membership) {
      await this.prisma.membership.create({
        data: { userId: user.id, organizationId: invitation.organizationId, role: invitation.role as never, status: "ACTIVE", invitedBy: invitation.invitedBy, joinedAt: new Date() },
      });
    }
    for (const workspaceId of ((invitation.workspaceIds as string[]) ?? [])) {
      const existingWm = await this.prisma.workspaceMembership.findFirst({ where: { userId: user.id, workspaceId } });
      if (!existingWm) {
        await this.prisma.workspaceMembership.create({ data: { userId: user.id, workspaceId, organizationId: invitation.organizationId, role: invitation.role, status: "ACTIVE", invitedBy: invitation.invitedBy as string, joinedAt: new Date() } });
      }
    }
    await this.prisma.organizationInvitation.update({ where: { id: invitation.id }, data: { status: "ACCEPTED", acceptedAt: new Date() } });
    await this.audit.record({ actorId: user.id as string, organizationId: invitation.organizationId as string, action: "INVITATION_ACCEPTED", resourceType: "OrganizationInvitation", resourceId: invitation.id as string });
    return { accepted: true, userId: user.id, organizationId: invitation.organizationId };
  }

  /* ----------------------------- access reviews ---------------------------- */
  async createAccessReview(user: RequestUser, body: Record<string, unknown>) {
    const review = await this.prisma.accessReview.create({
      data: { organizationId: user.organizationId, title: String(body.title ?? "Access review"), createdBy: user.id, dueAt: body.dueAt ? new Date(body.dueAt as string) : null, status: "OPEN" },
    });
    // Snapshot privileged subjects (§94): org memberships, workspace
    // memberships, service accounts, API keys.
    const subjects: { subjectType: string; subjectId: string; subjectLabel: string }[] = [];
    const memberships = await this.prisma.membership.findMany({ where: { organizationId: user.organizationId, status: "ACTIVE" } });
    for (const m of memberships) subjects.push({ subjectType: "MEMBERSHIP", subjectId: m.id as string, subjectLabel: `membership:${m.userId}:${m.role}` });
    const accounts = await this.prisma.serviceAccount.findMany({ where: { organizationId: user.organizationId, status: "ACTIVE" } });
    for (const a of accounts) subjects.push({ subjectType: "SERVICE_ACCOUNT", subjectId: a.id as string, subjectLabel: `service-account:${a.name}` });
    const keys = await this.prisma.apiKey.findMany({ where: { organizationId: user.organizationId, revokedAt: null } });
    for (const k of keys) subjects.push({ subjectType: "API_KEY", subjectId: k.id as string, subjectLabel: `api-key:${k.prefix}` });
    for (const s of subjects) await this.prisma.accessReviewItem.create({ data: { reviewId: review.id, ...s } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "ACCESS_REVIEW_CREATED", resourceType: "AccessReview", resourceId: review.id as string, metadata: { items: subjects.length } });
    return { ...review, itemCount: subjects.length };
  }

  async listAccessReviews(user: RequestUser) {
    return this.prisma.accessReview.findMany({ where: { organizationId: user.organizationId }, orderBy: { createdAt: "desc" } });
  }

  async getAccessReview(user: RequestUser, reviewId: string) {
    const review = await this.prisma.accessReview.findFirst({ where: { id: reviewId, organizationId: user.organizationId } });
    if (!review) throw new NotFoundException("Access review not found");
    const items = await this.prisma.accessReviewItem.findMany({ where: { reviewId } });
    return { review, items };
  }

  /** Decisions execute through the normal permission services (§96). */
  async decideAccessReviewItem(user: RequestUser, reviewId: string, itemId: string, decision: string, newRole?: string) {
    const { review, items } = await this.getAccessReview(user, reviewId);
    void review;
    const item = items.find((i) => i.id === itemId);
    if (!item) throw new NotFoundException("Review item not found");
    if (!["KEEP", "REVOKE", "CHANGE_ROLE", "DISABLE"].includes(decision)) throw new BadRequestException("Unknown decision");
    if (decision === "REVOKE" || decision === "DISABLE") {
      if (item.subjectType === "MEMBERSHIP") {
        const membership = await this.prisma.membership.findUnique({ where: { id: item.subjectId } });
        if (membership) {
          await this.prisma.membership.update({ where: { id: item.subjectId }, data: { status: decision === "REVOKE" ? "REVOKED" : "SUSPENDED" } });
          await this.prisma.userSession.updateMany({ where: { userId: membership.userId, revokedAt: null }, data: { revokedAt: new Date() } });
        }
      }
      if (item.subjectType === "SERVICE_ACCOUNT") await this.prisma.serviceAccount.update({ where: { id: item.subjectId }, data: { status: "DISABLED" } });
      if (item.subjectType === "API_KEY") await this.prisma.apiKey.update({ where: { id: item.subjectId }, data: { revokedAt: new Date() } });
    }
    if (decision === "CHANGE_ROLE") {
      if (item.subjectType !== "MEMBERSHIP" || !newRole) throw new BadRequestException("CHANGE_ROLE requires a membership item and a new role");
      await this.prisma.membership.update({ where: { id: item.subjectId }, data: { role: newRole as never } });
    }
    await this.prisma.accessReviewItem.update({ where: { id: itemId }, data: { decision: decision as never, decidedBy: user.id, decidedAt: new Date() } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "ACCESS_REVIEW_DECIDED", resourceType: "AccessReviewItem", resourceId: itemId, metadata: { decision } });
    return { decided: true };
  }

  async completeAccessReview(user: RequestUser, reviewId: string) {
    const { items } = await this.getAccessReview(user, reviewId);
    if (items.some((i) => !i.decision)) throw new BadRequestException("All items must be decided before completing the review");
    const updated = await this.prisma.accessReview.update({ where: { id: reviewId }, data: { status: "COMPLETED", completedAt: new Date() } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "ACCESS_REVIEW_COMPLETED", resourceType: "AccessReview", resourceId: reviewId });
    return updated;
  }

  /* ------------------------- privileged report (§97) ----------------------- */
  async privilegedAccessReport(user: RequestUser) {
    const memberships = await this.prisma.membership.findMany({ where: { organizationId: user.organizationId, status: "ACTIVE" } });
    const privileged = memberships.filter((m) => ["OWNER", "ADMIN", "SECURITY_ADMIN"].includes(m.role as string));
    const accounts = await this.prisma.serviceAccount.findMany({ where: { organizationId: user.organizationId, status: "ACTIVE" } });
    const keys = await this.prisma.apiKey.findMany({ where: { organizationId: user.organizationId, revokedAt: null } });
    const highScope = keys.filter((k) => ((k.scopes as string[]) ?? []).some((s) => s.endsWith(":create-safe") || s.includes("manage")));
    return {
      privilegedMemberships: privileged.map((m) => ({ userId: m.userId, role: m.role })),
      serviceAccounts: accounts.map((a) => ({ id: a.id, name: a.name, scopes: a.scopes })),
      highScopeApiKeys: highScope.map((k) => ({ id: k.id, prefix: k.prefix, scopes: k.scopes })),
    };
  }

  /* --------------------------- observability (§116) ------------------------ */
  async authObservability(user: RequestUser) {
    const events = await this.prisma.authenticationEvent.findMany({ where: { organizationId: user.organizationId }, orderBy: { createdAt: "desc" }, take: 500 });
    const count = (type: string) => events.filter((e) => e.eventType === type).length;
    const activeSessions = await this.prisma.userSession.count({ where: { organizationId: user.organizationId, revokedAt: null } });
    return {
      loginSucceeded: count("LOGIN_SUCCESS") + count("SSO_LOGIN"),
      loginFailed: count("LOGIN_FAILED") + count("SSO_LOGIN_FAILED"),
      mfaEvents: count("MFA_SUCCESS") + count("MFA_FAILED"),
      activeSessions,
      recentEvents: events.slice(0, 25),
    };
  }

  /** Domain-claim safety (§62): verified domains never auto-transfer users. */
  async domainForEmail(email: string): Promise<string | null> {
    return emailDomain(email);
  }
}
