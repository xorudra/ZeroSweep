import { BadRequestException, ForbiddenException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  apiKeyUsable, generateApiKey, validateApiScopes,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";

/**
 * Service accounts + API keys (§73–84). Service accounts are non-human,
 * least-privilege, workspace-scoped identities that never inherit user
 * permissions. API keys are high-entropy, shown once, hash-only at rest,
 * typed-scope only, expirable, rotatable and revocable.
 */
@Injectable()
export class KeysService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  /* ---------------------------- service accounts --------------------------- */
  async createServiceAccount(user: RequestUser, body: Record<string, unknown>) {
    const scopes = (body.scopes as string[]) ?? [];
    const check = validateApiScopes(scopes);
    if (!check.ok) throw new BadRequestException(`Invalid API scopes: ${check.invalid.join(", ") || "at least one scope is required"}`);
    let workspaceId: string | null = (body.workspaceId as string) ?? null;
    if (workspaceId) {
      const workspace = await this.prisma.workspace.findFirst({ where: { id: workspaceId, organizationId: user.organizationId, deletedAt: null } });
      if (!workspace) throw new ForbiddenException("Workspace is outside your organization");
    } else workspaceId = null;
    const account = await this.prisma.serviceAccount.create({
      data: { organizationId: user.organizationId, workspaceId, name: String(body.name ?? "service-account"), status: "ACTIVE", scopes, createdBy: user.id },
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "SERVICE_ACCOUNT_CREATED", resourceType: "ServiceAccount", resourceId: account.id as string });
    return this.presentServiceAccount(account);
  }

  async listServiceAccounts(user: RequestUser) {
    const rows = await this.prisma.serviceAccount.findMany({ where: { organizationId: user.organizationId }, orderBy: { createdAt: "desc" } });
    return rows.map((r) => this.presentServiceAccount(r));
  }

  async updateServiceAccount(user: RequestUser, id: string, body: Record<string, unknown>) {
    await this.ownServiceAccount(user, id);
    const data: Record<string, unknown> = {};
    if (body.name !== undefined) data.name = body.name;
    if (body.status !== undefined) {
      if (!["ACTIVE", "DISABLED"].includes(body.status as string)) throw new BadRequestException("status must be ACTIVE or DISABLED");
      data.status = body.status;
    }
    if (body.scopes !== undefined) {
      const check = validateApiScopes(body.scopes as string[]);
      if (!check.ok) throw new BadRequestException(`Invalid API scopes: ${check.invalid.join(", ")}`);
      data.scopes = body.scopes;
    }
    const updated = await this.prisma.serviceAccount.update({ where: { id }, data });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId,
      action: data.status === "DISABLED" ? "SERVICE_ACCOUNT_DISABLED" : "SERVICE_ACCOUNT_UPDATED",
      resourceType: "ServiceAccount", resourceId: id,
    });
    return this.presentServiceAccount(updated);
  }

  async createServiceAccountCredential(user: RequestUser, id: string, body: Record<string, unknown>) {
    const account = await this.ownServiceAccount(user, id);
    if (account.status !== "ACTIVE") throw new BadRequestException("Service account is disabled");
    return this.mintApiKey(user, "SERVICE_ACCOUNT", id, (account.scopes as string[]) ?? [], body);
  }

  /* -------------------------------- API keys ------------------------------- */
  async createPersonalApiKey(user: RequestUser, body: Record<string, unknown>) {
    const policy = await this.prisma.organizationSecurityPolicy.findUnique({ where: { organizationId: user.organizationId } });
    if (policy && !(policy.patAllowed as boolean)) throw new ForbiddenException("Personal access tokens are disabled by organization policy (§84)");
    const scopes = (body.scopes as string[]) ?? [];
    return this.mintApiKey(user, "USER", user.id, scopes, body);
  }

  private async mintApiKey(user: RequestUser, ownerKind: "USER" | "SERVICE_ACCOUNT", ownerId: string, scopes: string[], body: Record<string, unknown>) {
    const check = validateApiScopes(scopes);
    if (!check.ok) throw new BadRequestException(`Invalid API scopes: ${check.invalid.join(", ") || "at least one scope is required"}`);
    const policy = await this.prisma.organizationSecurityPolicy.findUnique({ where: { organizationId: user.organizationId } });
    let expiresAt: Date | null = body.expiresAt ? new Date(body.expiresAt as string) : null;
    const maxDays = policy?.apiKeyMaxLifetimeDays as number | undefined;
    if (maxDays) {
      const cap = new Date(Date.now() + maxDays * 24 * 3600_000);
      if (!expiresAt || expiresAt > cap) expiresAt = cap;
    }
    const generated = generateApiKey();
    const key = await this.prisma.apiKey.create({
      data: {
        ownerKind, ownerId, organizationId: user.organizationId, name: String(body.name ?? "api-key"),
        prefix: generated.prefix, secretHash: generated.secretHash, scopes, expiresAt,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId,
      action: ownerKind === "SERVICE_ACCOUNT" ? "SERVICE_ACCOUNT_CREDENTIAL_CREATED" : "API_KEY_CREATED",
      resourceType: "ApiKey", resourceId: key.id as string, metadata: { prefix: generated.prefix },
    });
    // Plaintext is returned exactly once (§77) — it is never stored.
    return { id: key.id, name: key.name, prefix: generated.prefix, plaintext: generated.plaintext, shownOnce: true, scopes, expiresAt };
  }

  async listApiKeys(user: RequestUser) {
    const rows = await this.prisma.apiKey.findMany({ where: { organizationId: user.organizationId, ownerKind: "USER", ownerId: user.id }, orderBy: { createdAt: "desc" } });
    // Service-account keys are visible only to callers who may manage them.
    const canManageServiceAccounts = ["OWNER", "ADMIN", "SECURITY_ADMIN"].includes(user.role);
    const serviceKeys = canManageServiceAccounts ? await this.prisma.apiKey.findMany({ where: { organizationId: user.organizationId, ownerKind: "SERVICE_ACCOUNT" }, orderBy: { createdAt: "desc" } }) : [];
    return [...rows, ...serviceKeys].map((k) => this.presentApiKey(k));
  }

  async rotateApiKey(user: RequestUser, id: string) {
    const key = await this.ownApiKey(user, id);
    const generated = generateApiKey();
    // Create replacement first (overlap window §81), then revoke the old key.
    const replacement = await this.prisma.apiKey.create({
      data: {
        ownerKind: key.ownerKind, ownerId: key.ownerId, organizationId: user.organizationId,
        name: key.name, prefix: generated.prefix, secretHash: generated.secretHash, scopes: key.scopes as never, expiresAt: key.expiresAt,
      },
    });
    await this.prisma.apiKey.update({ where: { id }, data: { revokedAt: new Date() } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "API_KEY_ROTATED", resourceType: "ApiKey", resourceId: id as string, metadata: { replacementId: replacement.id, prefix: generated.prefix } });
    return { id: replacement.id, prefix: generated.prefix, plaintext: generated.plaintext, shownOnce: true };
  }

  async revokeApiKey(user: RequestUser, id: string) {
    await this.ownApiKey(user, id);
    await this.prisma.apiKey.update({ where: { id }, data: { revokedAt: new Date() } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "API_KEY_REVOKED", resourceType: "ApiKey", resourceId: id });
    return { revoked: true };
  }

  /** Authenticate an API-key request (§82/83): returns the principal or a
   *  rejection reason. Usage is recorded with the PREFIX only — the full
   *  credential is never logged. */
  async authenticateApiKey(plaintext: string, requiredScope: string) {
    const prefix = plaintext.slice(0, 16);
    const candidates = await this.prisma.apiKey.findMany({ where: { prefix } });
    for (const key of candidates) {
      const unusable = apiKeyUsable(
        { secretHash: key.secretHash as string, revokedAtMs: key.revokedAt ? new Date(key.revokedAt as Date).getTime() : null, expiresAtMs: key.expiresAt ? new Date(key.expiresAt as Date).getTime() : null },
        plaintext, Date.now(),
      );
      if (unusable) continue;
      const scopes = (key.scopes as string[]) ?? [];
      if (!scopes.includes(requiredScope)) return { ok: false as const, reason: "INSUFFICIENT_SCOPE" };
      if (key.ownerKind === "SERVICE_ACCOUNT") {
        const account = await this.prisma.serviceAccount.findUnique({ where: { id: key.ownerId } });
        if (!account || account.status !== "ACTIVE") return { ok: false as const, reason: "SERVICE_ACCOUNT_DISABLED" };
        await this.prisma.serviceAccount.update({ where: { id: account.id }, data: { lastUsedAt: new Date() } });
      }
      await this.prisma.apiKey.update({ where: { id: key.id }, data: { lastUsedAt: new Date() } });
      return {
        ok: true as const, keyId: key.id as string, prefix, organizationId: key.organizationId as string,
        ownerKind: key.ownerKind as string, ownerId: key.ownerId as string, scopes,
        workspaceId: key.ownerKind === "SERVICE_ACCOUNT" ? await this.serviceAccountWorkspace(key.ownerId as string) : null,
      };
    }
    return { ok: false as const, reason: "INVALID_KEY" };
  }

  private async serviceAccountWorkspace(id: string): Promise<string | null> {
    const account = await this.prisma.serviceAccount.findUnique({ where: { id } });
    return (account?.workspaceId as string) ?? null;
  }

  private async ownServiceAccount(user: RequestUser, id: string) {
    const account = await this.prisma.serviceAccount.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!account) throw new NotFoundException("Service account not found");
    return account;
  }

  private async ownApiKey(user: RequestUser, id: string) {
    const key = await this.prisma.apiKey.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!key) throw new NotFoundException("API key not found");
    const privileged = ["OWNER", "ADMIN", "SECURITY_ADMIN"].includes(user.role);
    if (key.ownerKind === "USER" && key.ownerId !== user.id && !privileged) {
      throw new NotFoundException("API key not found");
    }
    // Service-account keys are additionally gated in service (see
    // MANAGE_API_KEYS in permissions.ts): rotate/revoke — and the plaintext
    // a rotation returns — require MANAGE_SERVICE_ACCOUNTS privilege.
    if (key.ownerKind === "SERVICE_ACCOUNT" && !privileged) {
      throw new ForbiddenException("Missing identity permission MANAGE_SERVICE_ACCOUNTS");
    }
    return key;
  }

  private presentServiceAccount(a: Record<string, unknown>) {
    return { id: a.id, name: a.name, status: a.status, workspaceId: a.workspaceId, scopes: a.scopes, createdBy: a.createdBy, lastUsedAt: a.lastUsedAt, createdAt: a.createdAt };
  }

  private presentApiKey(k: Record<string, unknown>) {
    return { id: k.id, name: k.name, prefix: k.prefix, ownerKind: k.ownerKind, ownerId: k.ownerId, scopes: k.scopes, expiresAt: k.expiresAt, lastUsedAt: k.lastUsedAt, revokedAt: k.revokedAt, createdAt: k.createdAt };
  }
}
