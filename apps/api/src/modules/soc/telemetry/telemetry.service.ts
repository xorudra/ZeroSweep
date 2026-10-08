import { ForbiddenException, Inject, Injectable } from "@nestjs/common";
import {
  normalizeTelemetryEvent, verifyApiKey,
  type CanonicalTelemetryEvent,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireSocPermission } from "../permissions";
import type { Row } from "../helpers";

export interface IngestAuth { kind: string; reference: string }
export interface IngestedEvent {
  id: string; fingerprint: string; event: CanonicalTelemetryEvent; duplicate: boolean;
}

/**
 * Telemetry ingestion (Prompt 28 §8–§13). Pipeline per event:
 * authenticate (§9) → size/rate limits (§10) → normalize (§5) →
 * redact (§157, inside the normalizer) → tenant resolution (the
 * workspace is the caller's, never the payload's) → store →
 * idempotency by fingerprint (§11). Detection + indicator matching
 * run in the SOC module after storage (see SocIngestionCoordinator).
 * Unsigned/unscoped telemetry is never trusted (§161).
 */
@Injectable()
export class TelemetryService {
  private readonly windows = new Map<string, { minute: number; count: number }>();
  static readonly MAX_EVENTS_PER_MINUTE_PER_WORKSPACE = 5000;

  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async createSource(user: RequestUser, workspaceId: string, body: { name: string; sourceCategory: string; authReference?: string; expectedIntervalSeconds?: number }) {
    requireSocPermission(user, "MANAGE_DETECTIONS");
    const source = await this.prisma.socTelemetrySource.create({
      data: {
        organizationId: user.organizationId, workspaceId, name: body.name,
        sourceCategory: body.sourceCategory, authReference: body.authReference,
        expectedIntervalSeconds: body.expectedIntervalSeconds, enabled: true,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "TELEMETRY_SOURCE_CONNECTED", resourceType: "SocTelemetrySource", resourceId: source.id as string,
      metadata: { name: body.name, sourceCategory: body.sourceCategory },
    });
    return source;
  }

  async listSources(user: RequestUser, workspaceId: string) {
    requireSocPermission(user, "VIEW_SOC");
    const items = await this.prisma.socTelemetrySource.findMany({
      where: { workspaceId }, orderBy: { name: "asc" },
    });
    // authReference is a reference NAME — safe to show; values never exist here.
    return { items, total: items.length };
  }

  /** §9: verify the ingestion identity. Returns the verified mode. */
  async verifyIngestionAuth(user: RequestUser, workspaceId: string, auth: IngestAuth): Promise<string> {
    if (auth.kind === "USER_SESSION") {
      requireSocPermission(user, "MANAGE_DETECTIONS");
      return "USER_SESSION";
    }
    if (auth.kind === "API_KEY") {
      const prefix = auth.reference.slice(0, 16);
      const keys = await this.prisma.apiKey.findMany({ where: { prefix, organizationId: user.organizationId, revokedAt: null } });
      for (const key of keys as Row[]) {
        const scopes = (key.scopes as string[]) ?? [];
        if (!scopes.includes("telemetry:ingest")) continue;
        if (key.expiresAt && new Date(key.expiresAt as string).getTime() < Date.now()) continue;
        if (verifyApiKey(auth.reference, key.secretHash as string)) return "API_KEY";
      }
      throw new ForbiddenException("Ingestion API key is invalid, expired, revoked, or lacks the telemetry:ingest scope");
    }
    if (auth.kind === "SERVICE_ACCOUNT") {
      const account = await this.prisma.serviceAccount.findFirst({
        where: { id: auth.reference, organizationId: user.organizationId, status: "ACTIVE" },
      });
      const scopes = ((account?.scopes as string[]) ?? []);
      if (!account || !scopes.includes("telemetry:ingest")) {
        throw new ForbiddenException("Service account is missing, disabled, or lacks the telemetry:ingest scope");
      }
      return "SERVICE_ACCOUNT";
    }
    if (auth.kind === "SIGNED_WEBHOOK") {
      // Signature verification itself happens in the integrations
      // webhook layer (P24); SOC ingestion additionally requires the
      // named integration to exist, be enabled, and carry a secret
      // reference in THIS workspace.
      const integration = await this.prisma.integration.findFirst({
        where: { id: auth.reference, workspaceId, enabled: true },
      });
      if (!integration || !(integration as Row).secretReference) {
        throw new ForbiddenException("Signed-webhook ingestion requires an enabled integration with a secret reference in this workspace");
      }
      return "SIGNED_WEBHOOK";
    }
    throw new ForbiddenException(`Unsupported ingestion auth kind: ${auth.kind}`);
  }

  private rateLimit(workspaceId: string, count: number): boolean {
    const minute = Math.floor(Date.now() / 60000);
    const entry = this.windows.get(workspaceId);
    if (!entry || entry.minute !== minute) {
      this.windows.set(workspaceId, { minute, count });
      return count <= TelemetryService.MAX_EVENTS_PER_MINUTE_PER_WORKSPACE;
    }
    entry.count += count;
    return entry.count <= TelemetryService.MAX_EVENTS_PER_MINUTE_PER_WORKSPACE;
  }

  async ingest(user: RequestUser, workspaceId: string, auth: IngestAuth, rawEvents: unknown[]): Promise<{
    authMode: string; stored: IngestedEvent[]; duplicates: number; rejected: Array<{ index: number; errors: string[] }>;
  }> {
    const authMode = await this.verifyIngestionAuth(user, workspaceId, auth);
    if (!this.rateLimit(workspaceId, rawEvents.length)) {
      throw new ForbiddenException("Telemetry ingestion rate limit exceeded for this workspace (§10)");
    }
    const stored: IngestedEvent[] = [];
    const rejected: Array<{ index: number; errors: string[] }> = [];
    let duplicates = 0;
    for (let i = 0; i < rawEvents.length; i++) {
      const normalized = normalizeTelemetryEvent(rawEvents[i]);
      if (!normalized.ok || !normalized.event || !normalized.fingerprint) {
        rejected.push({ index: i, errors: normalized.errors });
        await this.audit.record({
          actorId: user.id, organizationId: user.organizationId, workspaceId,
          action: "TELEMETRY_EVENT_REJECTED", resourceType: "SecurityTelemetryEvent",
          metadata: { errors: normalized.errors, authMode },
        }).catch(() => undefined);
        continue;
      }
      const event = normalized.event;
      const existing = await this.prisma.securityTelemetryEvent.findFirst({
        where: { workspaceId, fingerprint: normalized.fingerprint },
      });
      if (existing) {
        duplicates++;
        stored.push({ id: existing.id as string, fingerprint: normalized.fingerprint, event, duplicate: true });
        continue;
      }
      const row = await this.prisma.securityTelemetryEvent.create({
        data: {
          organizationId: user.organizationId, workspaceId,
          eventTime: new Date(event.eventTime), source: event.source, sourceCategory: event.sourceCategory,
          eventCategory: event.eventCategory, eventAction: event.eventAction,
          assetId: event.assetId, identityReference: event.identityReference,
          severity: event.severity, classification: event.classification,
          attributes: event.attributes as never, rawReference: event.rawReference,
          schemaVersion: event.schemaVersion, fingerprint: normalized.fingerprint,
          contentHash: normalized.contentHash!,
        },
      });
      // Source bookkeeping for telemetry health (§115).
      const source = await this.prisma.socTelemetrySource.findFirst({ where: { workspaceId, name: event.source } });
      if (source) {
        await this.prisma.socTelemetrySource.update({
          where: { id: source.id as string },
          data: { lastEventAt: new Date(event.eventTime), lastIngestedAt: new Date(), eventsIngested: { increment: 1 } },
        }).catch(() => undefined);
      }
      stored.push({ id: row.id as string, fingerprint: normalized.fingerprint, event, duplicate: false });
    }
    return { authMode, stored, duplicates, rejected };
  }

  async listEvents(user: RequestUser, workspaceId: string, filters: { source?: string; eventCategory?: string; assetId?: string; identityReference?: string; limit?: number }) {
    requireSocPermission(user, "VIEW_SOC");
    const items = await this.prisma.securityTelemetryEvent.findMany({
      where: {
        workspaceId,
        ...(filters.source ? { source: filters.source } : {}),
        ...(filters.eventCategory ? { eventCategory: filters.eventCategory } : {}),
        ...(filters.assetId ? { assetId: filters.assetId } : {}),
        ...(filters.identityReference ? { identityReference: filters.identityReference } : {}),
      },
      orderBy: { eventTime: "desc" },
      take: Math.min(filters.limit ?? 100, 500),
    });
    return { items, total: items.length };
  }
}
