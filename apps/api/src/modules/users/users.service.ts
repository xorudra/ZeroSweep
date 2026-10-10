import {
  BadRequestException, Inject, Injectable, NotFoundException, UnauthorizedException,
} from "@nestjs/common";
import * as bcrypt from "bcryptjs";
import { deleteAccountSchema } from "@dsrclone/validation";
import { GENERIC_AUTH_ERROR, randomToken } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { parseOrThrow } from "../../common/parse";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { AuditService } from "../audit/audit.service";

/**
 * Self-service account rights (Launch Safety F28/F29, DPDP data-subject
 * rights). Both operations are CALLER-SCOPED by construction: the only
 * identity ever used is the authenticated token's user id — no route
 * here accepts a target user id, so one user can never export or delete
 * another user's account through them.
 */
@Injectable()
export class UsersService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  /**
   * F29: everything the platform holds about the caller, as JSON —
   * profile, organization memberships, session metadata (never token
   * hashes) and the caller's own audit-trail entries. The export itself
   * is audited, like every other consequential action.
   */
  async exportMe(user: RequestUser) {
    const profileRow = await this.prisma.user.findUnique({
      where: { id: user.id },
      select: {
        id: true, email: true, name: true, isActive: true, status: true,
        emailVerifiedAt: true, termsAcceptedAt: true, termsVersion: true,
        lastLoginAt: true, createdAt: true, updatedAt: true, deletedAt: true,
      },
    });
    if (!profileRow || profileRow.deletedAt) {
      throw new NotFoundException("Account not found");
    }
    const { deletedAt: _deletedAt, ...profile } = profileRow;
    const [memberships, sessions, auditTrail] = await Promise.all([
      this.prisma.membership.findMany({
        where: { userId: user.id },
        include: { organization: { select: { id: true, name: true, slug: true } } },
      }),
      this.prisma.userSession.findMany({
        where: { userId: user.id },
        orderBy: { createdAt: "desc" },
        select: {
          id: true, organizationId: true, assurance: true, deviceSummary: true,
          createdAt: true, lastSeenAt: true, expiresAt: true, idleExpiresAt: true, revokedAt: true,
        },
      }),
      this.prisma.auditLog.findMany({
        where: { actorId: user.id },
        orderBy: { createdAt: "desc" },
        take: 1000,
        select: {
          id: true, organizationId: true, workspaceId: true, action: true,
          resourceType: true, resourceId: true, metadata: true, ipAddress: true, createdAt: true,
        },
      }),
    ]);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId,
      action: "USER_DATA_EXPORTED", resourceType: "User", resourceId: user.id,
    });
    return {
      exportedAt: new Date().toISOString(),
      profile,
      memberships,
      sessions,
      auditTrail,
    };
  }

  /**
   * F28: password-confirmed self-deletion. Follows the organization
   * lifecycle pattern — deletion is a state change with an audit
   * record, never an inline hard delete: the row is anonymized in
   * place (PII replaced with tombstones, credential replaced with a
   * hash of a random throwaway secret) so tenant audit history keeps
   * its referential integrity while the person's data is gone.
   * Sessions are revoked and memberships removed first. A sole
   * organization OWNER is blocked: they must delete the organization
   * (the §91 lifecycle path) or transfer ownership first, so an org
   * is never left ownerless by an account deletion.
   */
  async deleteMe(user: RequestUser, rawBody: unknown) {
    const data = parseOrThrow(deleteAccountSchema, rawBody);
    const record = await this.prisma.user.findUnique({ where: { id: user.id } });
    if (!record || record.deletedAt) throw new NotFoundException("Account not found");
    const passwordOk = await bcrypt.compare(data.password, record.passwordHash as string);
    if (!passwordOk) throw new UnauthorizedException(GENERIC_AUTH_ERROR);

    const memberships = await this.prisma.membership.findMany({
      where: { userId: user.id, status: "ACTIVE" },
    });
    for (const m of memberships as Array<{ organizationId: string; role: string }>) {
      if (m.role !== "OWNER") continue;
      const activeOwners = await this.prisma.membership.count({
        where: { organizationId: m.organizationId, role: "OWNER", status: "ACTIVE" },
      });
      if (activeOwners <= 1) {
        throw new BadRequestException(
          "You are the only owner of an organization. Delete the organization or transfer ownership to another member before deleting your account.",
        );
      }
    }

    const now = new Date();
    await this.prisma.membership.updateMany({ where: { userId: user.id }, data: { status: "REVOKED" } });
    await this.prisma.userSession.updateMany({
      where: { userId: user.id, revokedAt: null }, data: { revokedAt: now },
    });
    const tombstone = `deleted-${user.id}@deleted.invalid`;
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        email: tombstone,
        normalizedEmail: tombstone,
        name: "Deleted user",
        passwordHash: await bcrypt.hash(randomToken(32), 12),
        isActive: false,
        status: "DEACTIVATED",
        isPlatformAdmin: false,
        deletedAt: now,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId,
      action: "USER_ACCOUNT_DELETED", resourceType: "User", resourceId: user.id,
    });
    return { deleted: true, deletedAt: now };
  }
}
