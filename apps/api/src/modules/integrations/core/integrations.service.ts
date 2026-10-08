import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  ENTERPRISE_INTEGRATION_TYPES,
  createConnector,
  type EnterpriseIntegrationType,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireIntegrationPermission } from "../permissions";
import type { CreateIntegrationBody, RotateCredentialBody, UpdateIntegrationBody } from "../dto/schemas";
import { IntegrationTransportFactory } from "./transport";

type Row = Record<string, unknown>;

/**
 * Integration registry (Prompt 24 §3–§8, §95–§104). One Integration
 * row per (workspace, provider instance). Credentials exist ONLY as
 * secret references (§7): the API accepts, stores and returns
 * reference names, configured/rotated metadata — never values (§8).
 */
@Injectable()
export class IntegrationsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly transports: IntegrationTransportFactory,
  ) {}

  connectorFor(row: Row) {
    const kind = row.type as string;
    const config = ((row.configuration ?? row.config ?? {}) as Record<string, unknown>);
    if ((ENTERPRISE_INTEGRATION_TYPES as readonly string[]).includes(kind)) {
      return createConnector(kind as EnterpriseIntegrationType, config, this.transports.forIntegration(row as Row & { type: string }));
    }
    return null;
  }

  present(row: Row) {
    return {
      id: row.id,
      workspaceId: row.workspaceId,
      organizationId: row.organizationId ?? null,
      type: row.type,
      name: row.name,
      status: row.enabled === false && row.status === "PENDING" ? "DISABLED" : row.status ?? "PENDING",
      enabled: row.enabled !== false,
      config: row.config ?? null,
      configuration: row.configuration ?? row.config ?? null,
      // §8: the UI shows whether a credential is configured, its type
      // and when it was last rotated — never the value.
      secretConfigured: Boolean(row.secretReference),
      secretReference: row.secretReference ?? null,
      secretRotatedAt: row.secretRotatedAt ?? null,
      credentialType: row.credentialType ?? null,
      capabilities: row.capabilities ?? [],
      lastHealthCheckAt: row.lastHealthCheckAt ?? null,
      lastSyncAt: row.lastSyncAt ?? null,
      healthDetail: row.healthDetail ?? null,
      lastErrorCategory: row.lastErrorCategory ?? null,
      createdBy: row.createdBy ?? null,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  async list(user: RequestUser, workspaceId: string) {
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    const rows = await this.prisma.integration.findMany({
      where: { workspaceId },
      orderBy: { createdAt: "desc" },
    });
    return rows.map((r) => this.present(r as Row));
  }

  async get(user: RequestUser, workspaceId: string, id: string) {
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    return this.present(await this.own(user, workspaceId, id));
  }

  async create(user: RequestUser, workspaceId: string, body: CreateIntegrationBody) {
    requireIntegrationPermission(user, "CREATE_INTEGRATION");
    const config = (body.configuration ?? body.config ?? {}) as Record<string, unknown>;
    const connector = (ENTERPRISE_INTEGRATION_TYPES as readonly string[]).includes(body.type as string)
      ? createConnector(body.type as EnterpriseIntegrationType, config)
      : null;
    if (connector) {
      const validation = connector.validateConfiguration(config);
      if (!validation.ok) throw new BadRequestException(`Invalid integration configuration: ${validation.errors.join("; ")}`);
    }
    const row = await this.prisma.integration.create({
      data: {
        workspaceId,
        organizationId: user.organizationId,
        type: body.type,
        name: body.name,
        config: (body.config ?? undefined) as never,
        configuration: (body.configuration ?? body.config ?? undefined) as never,
        secretReference: body.secretReference ?? null,
        credentialType: body.credentialType ?? null,
        secretRotatedAt: body.secretReference ? new Date() : null,
        capabilities: connector ? connector.capabilities() : [],
        status: "PENDING",
        enabled: body.enabled ?? true,
        createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "INTEGRATION_CREATED", resourceType: "Integration", resourceId: row.id as string,
      metadata: { type: body.type, secretConfigured: Boolean(body.secretReference) },
    });
    return this.present(row as Row);
  }

  async update(user: RequestUser, workspaceId: string, id: string, body: UpdateIntegrationBody) {
    requireIntegrationPermission(user, "EDIT_INTEGRATION");
    const row = await this.own(user, workspaceId, id);
    const data: Row = {};
    if (body.name !== undefined) data.name = body.name;
    if (body.config !== undefined) data.config = body.config;
    if (body.configuration !== undefined) data.configuration = body.configuration;
    if (body.enabled !== undefined) data.enabled = body.enabled;
    if (body.status !== undefined) data.status = body.status;
    const updated = await this.prisma.integration.update({ where: { id: row.id as string }, data: data as never });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "INTEGRATION_UPDATED", resourceType: "Integration", resourceId: id,
      metadata: { fields: Object.keys(data) },
    });
    return this.present(updated as Row);
  }

  /** §103: deletion stops future sync/delivery and drops the stored
   *  secret reference with the row. Historical findings, tickets and
   *  audit records are separate records and are preserved. */
  async remove(user: RequestUser, workspaceId: string, id: string) {
    requireIntegrationPermission(user, "DELETE_INTEGRATION");
    const row = await this.own(user, workspaceId, id);
    await this.prisma.integration.delete({ where: { id: row.id as string } });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "INTEGRATION_DELETED", resourceType: "Integration", resourceId: id,
      metadata: { type: row.type },
    });
    return { deleted: true, historicalRecordsPreserved: true };
  }

  /** §8/§102: rotation swaps the secret REFERENCE. The platform never
   *  receives or stores the new value. */
  async rotateCredential(user: RequestUser, workspaceId: string, id: string, body: RotateCredentialBody) {
    requireIntegrationPermission(user, "MANAGE_INTEGRATION_SECRETS");
    const row = await this.own(user, workspaceId, id);
    const connector = this.connectorFor(row);
    connector?.rotateCredentialReference(body.secretReference as string);
    const updated = await this.prisma.integration.update({
      where: { id: row.id as string },
      data: {
        secretReference: body.secretReference,
        credentialType: body.credentialType ?? (row.credentialType as string | undefined),
        secretRotatedAt: new Date(),
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "INTEGRATION_UPDATED", resourceType: "Integration", resourceId: id,
      metadata: { credentialRotated: true },
    });
    return this.present(updated as Row);
  }

  /** POST /integrations/:id/test (§95): connector health probe. With
   *  no transport wired the result is honestly NOT_CONFIGURED and the
   *  integration stays PENDING — never CONNECTED (§104). */
  async test(user: RequestUser, workspaceId: string, id: string) {
    requireIntegrationPermission(user, "TEST_INTEGRATION");
    const row = await this.own(user, workspaceId, id);
    const connector = this.connectorFor(row);
    if (!connector) {
      return { id, status: row.status ?? "PENDING", detail: "Prompt 20 platform connector — health is reported by the vulnerability-management integrations surface" };
    }
    const health = await connector.testConnection();
    const now = new Date();
    const status = health.status === "NOT_CONFIGURED" ? (row.status as string) ?? "PENDING" : health.status;
    await this.prisma.integration.update({
      where: { id: row.id as string },
      data: {
        status,
        lastHealthCheckAt: now,
        healthDetail: {
          reachable: health.reachable, authenticated: health.authenticated,
          rateLimit: health.rateLimit ?? null, detail: health.detail,
        } as never,
        lastErrorCategory: health.errorCategory ?? null,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: health.status === "AUTHENTICATION_FAILED" ? "INTEGRATION_AUTH_FAILED" : "INTEGRATION_TESTED",
      resourceType: "Integration", resourceId: id,
      metadata: { healthStatus: health.status, errorCategory: health.errorCategory ?? null },
    });
    return { id, health, status };
  }

  async own(user: RequestUser, workspaceId: string, id: string): Promise<Row> {
    const row = await this.prisma.integration.findFirst({ where: { id, workspaceId } });
    if (!row) throw new NotFoundException("Integration not found");
    if (row.organizationId && row.organizationId !== user.organizationId) throw new NotFoundException("Integration not found");
    return row as Row;
  }
}
