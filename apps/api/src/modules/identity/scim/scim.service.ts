import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common";
import * as bcrypt from "bcryptjs";
import {
  evaluateScimFilter, normalizeEmail, parseScimFilter, randomToken, sha256Hex, verifyTokenHash, ScimFilterError,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";

/**
 * SCIM 2.0 provisioning (§66–72). Authenticated by a DEDICATED SCIM bearer
 * token (hashed at rest, per-organization — never a user API key, §67).
 * Users/groups are provisioned into the token's organization only; group →
 * role assignment goes through the explicit approved mapping table, so an
 * unmapped IdP group can never grant administrator (§71, §131). Deprovi-
 * sioning disables the user, revokes memberships AND sessions (§69).
 */
@Injectable()
export class ScimService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  /* ------------------------------ token admin ----------------------------- */
  async createOrRotateToken(organizationId: string, actorId: string) {
    const plaintext = `scim_${randomToken(32)}`;
    const prefix = plaintext.slice(0, 12);
    const existing = await this.prisma.scimCredential.findUnique({ where: { organizationId } });
    if (existing) {
      await this.prisma.scimCredential.update({ where: { organizationId }, data: { tokenHash: sha256Hex(plaintext), tokenPrefix: prefix, rotatedAt: new Date() } });
      await this.audit.record({ actorId, organizationId, action: "SCIM_TOKEN_ROTATED", resourceType: "ScimCredential", resourceId: existing.id as string });
    } else {
      await this.prisma.scimCredential.create({ data: { organizationId, tokenHash: sha256Hex(plaintext), tokenPrefix: prefix } });
      await this.audit.record({ actorId, organizationId, action: "SCIM_TOKEN_CREATED", resourceType: "ScimCredential", resourceId: organizationId });
    }
    return { token: plaintext, prefix, shownOnce: true };
  }

  async tokenStatus(organizationId: string) {
    const cred = await this.prisma.scimCredential.findUnique({ where: { organizationId } });
    if (!cred) return { configured: false };
    return { configured: true, prefix: cred.tokenPrefix, createdAt: cred.createdAt, rotatedAt: cred.rotatedAt, lastUsedAt: cred.lastUsedAt };
  }

  /** Authenticate a SCIM request: the token determines the organization.
   *  A token minted for org A can never address org B (no org parameter
   *  exists in SCIM paths) — cross-tenant confusion is structural (§141). */
  async authenticate(authorization: string | undefined): Promise<{ organizationId: string }> {
    if (!authorization?.startsWith("Bearer ")) throw new UnauthorizedException("SCIM bearer token required");
    const token = authorization.slice("Bearer ".length).trim();
    if (!token.startsWith("scim_")) throw new UnauthorizedException("Invalid SCIM token");
    const prefix = token.slice(0, 12);
    const candidates = await this.prisma.scimCredential.findMany({ where: { tokenPrefix: prefix } });
    for (const cred of candidates) {
      if (verifyTokenHash(token, cred.tokenHash as string)) {
        await this.prisma.scimCredential.update({ where: { id: cred.id }, data: { lastUsedAt: new Date() } });
        return { organizationId: cred.organizationId as string };
      }
    }
    throw new UnauthorizedException("Invalid SCIM token");
  }

  /* -------------------------------- users -------------------------------- */
  async createUser(organizationId: string, body: Record<string, unknown>) {
    const userName = String(body.userName ?? "");
    if (!userName.includes("@")) throw new BadRequestException("userName must be an email address");
    const normalized = normalizeEmail(userName);
    const existing = await this.prisma.user.findUnique({ where: { normalizedEmail: normalized } });
    let user = existing;
    if (!user) {
      const unusablePassword = await bcrypt.hash(randomToken(32), 12);
      user = await this.prisma.user.create({
        data: {
          email: userName, normalizedEmail: normalized,
          name: scimDisplayName(body), passwordHash: unusablePassword,
          status: body.active === false ? "DEACTIVATED" : "ACTIVE", isActive: body.active !== false,
        },
      });
    }
    const role = await this.roleForScimGroups(organizationId, body.groups);
    const membership = await this.prisma.membership.findFirst({ where: { userId: user.id, organizationId } });
    if (!membership) {
      await this.prisma.membership.create({ data: { userId: user.id, organizationId, role: (role ?? "VIEWER") as never, status: body.active === false ? "SUSPENDED" : "ACTIVE", joinedAt: new Date() } });
    }
    await this.upsertExternal(organizationId, "USER", user.id as string, (body.externalId as string) ?? null, userName);
    await this.audit.record({ actorId: "scim", organizationId, action: "SCIM_USER_CREATED", resourceType: "User", resourceId: user.id as string });
    return this.presentUser(user, organizationId, body.active !== false);
  }

  async getUser(organizationId: string, id: string) {
    const record = await this.prisma.scimExternalRecord.findFirst({ where: { organizationId, resourceType: "USER", localId: id } });
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user || !record) throw new NotFoundException("SCIM user not found");
    const membership = await this.prisma.membership.findFirst({ where: { userId: id, organizationId } });
    return this.presentUser(user, organizationId, membership?.status === "ACTIVE");
  }

  async listUsers(organizationId: string, filter?: string, startIndex = 1, count = 100) {
    const records = await this.prisma.scimExternalRecord.findMany({ where: { organizationId, resourceType: "USER" } });
    let users: Record<string, unknown>[] = [];
    for (const record of records) {
      const user = await this.prisma.user.findUnique({ where: { id: record.localId } });
      if (!user) continue;
      const membership = await this.prisma.membership.findFirst({ where: { userId: user.id, organizationId } });
      users.push({
        id: user.id, userName: user.email, displayName: user.name, active: membership?.status === "ACTIVE" && user.isActive,
        externalId: record.externalId, emails: [{ value: user.email, primary: true }],
      });
    }
    if (filter) {
      let parsed;
      try { parsed = parseScimFilter(filter); } catch (err) {
        if (err instanceof ScimFilterError) throw new BadRequestException(`Invalid SCIM filter: ${err.message}`);
        throw err;
      }
      users = users.filter((u) => evaluateScimFilter(parsed, u));
    }
    const total = users.length;
    const page = users.slice(Math.max(0, startIndex - 1), Math.max(0, startIndex - 1) + count);
    return { schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], totalResults: total, startIndex, itemsPerPage: page.length, Resources: page.map((u) => this.toScimUser(u)) };
  }

  async updateUser(organizationId: string, id: string, body: Record<string, unknown>) {
    await this.mustFindScimUser(organizationId, id);
    const data: Record<string, unknown> = {};
    const displayName = scimDisplayName(body);
    if (displayName) data.name = displayName;
    if (Object.keys(data).length > 0) await this.prisma.user.update({ where: { id }, data });
    if (body.active !== undefined) {
      if (body.active === false) return this.deactivateUser(organizationId, id);
      await this.prisma.membership.updateMany({ where: { userId: id, organizationId }, data: { status: "ACTIVE" } });
      await this.prisma.user.update({ where: { id }, data: { isActive: true, status: "ACTIVE" } });
    }
    if (body.groups !== undefined) {
      const role = await this.roleForScimGroups(organizationId, body.groups);
      if (role) await this.prisma.membership.updateMany({ where: { userId: id, organizationId }, data: { role: role as never } });
    }
    await this.audit.record({ actorId: "scim", organizationId, action: "SCIM_USER_UPDATED", resourceType: "User", resourceId: id });
    return this.getUser(organizationId, id);
  }

  /** Deprovisioning (§69): disable — never delete — revoke org access,
   *  revoke sessions, preserve audit/history. */
  async deactivateUser(organizationId: string, id: string) {
    const { user } = await this.mustFindScimUser(organizationId, id);
    await this.prisma.user.update({ where: { id }, data: { isActive: false, status: "DEACTIVATED" } });
    await this.prisma.membership.updateMany({ where: { userId: id, organizationId }, data: { status: "REVOKED" } });
    await this.prisma.userSession.updateMany({ where: { userId: id, organizationId, revokedAt: null }, data: { revokedAt: new Date() } });
    await this.prisma.authenticationEvent.create({ data: { userId: id, organizationId, eventType: "SCIM_DEPROVISIONED" } });
    await this.audit.record({ actorId: "scim", organizationId, action: "SCIM_USER_DEACTIVATED", resourceType: "User", resourceId: id });
    return this.presentUser({ ...user, isActive: false }, organizationId, false);
  }

  /* -------------------------------- groups -------------------------------- */
  async upsertGroup(organizationId: string, body: Record<string, unknown>) {
    const displayName = String(body.displayName ?? "");
    if (!displayName) throw new BadRequestException("displayName is required");
    const groupId = (body.id as string) ?? `grp_${sha256Hex(`${organizationId}:${displayName}`).slice(0, 16)}`;
    await this.upsertExternal(organizationId, "GROUP", groupId, (body.externalId as string) ?? null, displayName);
    const members = Array.isArray(body.members) ? (body.members as { value: string }[]) : [];
    const mapping = await this.prisma.scimGroupMapping.findFirst({ where: { organizationId, externalGroup: displayName } });
    if (mapping) {
      for (const member of members) {
        await this.prisma.membership.updateMany({ where: { userId: member.value, organizationId }, data: { role: mapping.organizationRole } });
        if (mapping.workspaceId && mapping.workspaceRole) {
          const existingWm = await this.prisma.workspaceMembership.findFirst({ where: { userId: member.value, workspaceId: mapping.workspaceId } });
          if (!existingWm) {
            await this.prisma.workspaceMembership.create({ data: { userId: member.value, workspaceId: mapping.workspaceId as string, organizationId, role: mapping.workspaceRole, status: "ACTIVE", joinedAt: new Date() } });
          }
        }
      }
    }
    await this.audit.record({ actorId: "scim", organizationId, action: "SCIM_GROUP_UPSERTED", resourceType: "ScimGroup", resourceId: groupId, metadata: { displayName, mapped: Boolean(mapping) } });
    return { id: groupId, displayName, members, mappedRole: mapping?.organizationRole ?? null };
  }

  async listGroups(organizationId: string) {
    const records = await this.prisma.scimExternalRecord.findMany({ where: { organizationId, resourceType: "GROUP" } });
    return { Resources: records.map((r) => ({ id: r.localId, displayName: r.displayName })) };
  }

  /* ------------------------------- mappings ------------------------------- */
  async listMappings(organizationId: string) {
    return this.prisma.scimGroupMapping.findMany({ where: { organizationId } });
  }

  async createMapping(organizationId: string, actorId: string, body: Record<string, unknown>) {
    const externalGroup = String(body.externalGroup ?? "");
    if (!externalGroup) throw new BadRequestException("externalGroup is required");
    const existing = await this.prisma.scimGroupMapping.findFirst({ where: { organizationId, externalGroup } });
    if (existing) throw new ConflictException("A mapping for this group already exists");
    const mapping = await this.prisma.scimGroupMapping.create({
      data: {
        organizationId, externalGroup, organizationRole: ((body.organizationRole as string) ?? "VIEWER") as never,
        workspaceId: (body.workspaceId as string) ?? null, workspaceRole: ((body.workspaceRole as string) ?? null) as never,
      },
    });
    await this.audit.record({ actorId, organizationId, action: "SCIM_GROUP_UPSERTED", resourceType: "ScimGroupMapping", resourceId: mapping.id as string, metadata: { externalGroup, approvedMapping: true } });
    return mapping;
  }

  /** §87/§131: roles come ONLY from the approved mapping table. */
  private async roleForScimGroups(organizationId: string, groupsRaw: unknown): Promise<string | null> {
    if (!Array.isArray(groupsRaw)) return null;
    const names = groupsRaw.map((g) => (g as { display?: string; value?: string }).display ?? (g as { value?: string }).value ?? "").filter(Boolean);
    if (names.length === 0) return null;
    const mappings = await this.prisma.scimGroupMapping.findMany({ where: { organizationId } });
    const order = ["VIEWER", "MEMBER", "ANALYST", "SECURITY_ENGINEER", "SECURITY_ADMIN", "ADMIN", "OWNER"];
    let best: string | null = null;
    for (const m of mappings) {
      if (names.includes(m.externalGroup as string)) {
        const role = m.organizationRole as string;
        if (!best || order.indexOf(role) > order.indexOf(best)) best = role;
      }
    }
    return best;
  }

  private async mustFindScimUser(organizationId: string, id: string) {
    const record = await this.prisma.scimExternalRecord.findFirst({ where: { organizationId, resourceType: "USER", localId: id } });
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user || !record) throw new NotFoundException("SCIM user not found");
    return { user, record };
  }

  private async upsertExternal(organizationId: string, resourceType: string, localId: string, externalId: string | null, displayName: string) {
    const existing = await this.prisma.scimExternalRecord.findFirst({ where: { organizationId, resourceType, localId } });
    if (existing) await this.prisma.scimExternalRecord.update({ where: { id: existing.id }, data: { externalId, displayName } });
    else await this.prisma.scimExternalRecord.create({ data: { organizationId, resourceType, localId, externalId, displayName } });
  }

  private presentUser(user: Record<string, unknown>, _organizationId: string, active: boolean) {
    return this.toScimUser({ id: user.id, userName: user.email, displayName: user.name, active, emails: [{ value: user.email, primary: true }] });
  }

  private toScimUser(u: Record<string, unknown>) {
    return {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      id: u.id, userName: u.userName, displayName: u.displayName, active: u.active,
      emails: u.emails,
    };
  }
}

function scimDisplayName(body: Record<string, unknown>): string {
  if (typeof body.displayName === "string") return body.displayName;
  const name = body.name as { formatted?: string; givenName?: string; familyName?: string } | undefined;
  if (name?.formatted) return name.formatted;
  if (name) return [name.givenName, name.familyName].filter(Boolean).join(" ");
  return "";
}
