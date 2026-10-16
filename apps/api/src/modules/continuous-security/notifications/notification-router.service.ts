import { createHmac } from "node:crypto";
import { lookup } from "node:dns/promises";
import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  alertFingerprint, alertGroupKey, checkThrottle, escalationDue, isQuietHours, policyAdmitsEvent,
  validateWebhookDestination, type NotificationEventView, type NotificationPolicyView,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { requireContinuousPermission } from "../permissions";

/** Resolver seam: production DNS; tests inject a fake (no network). */
export type WebhookResolver = (hostname: string) => Promise<string[]>;

export const dnsResolver: WebhookResolver = async (hostname) => {
  const records = await lookup(hostname, { all: true });
  return records.map((r) => r.address);
};

const SEVERITY_ORDER = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

/**
 * Provider-neutral notification router (Prompt 22 §65–§75).
 *
 * Delivery honesty: IN_APP notifications are persisted delivery (the
 * /notifications page IS the inbox). EMAIL/SLACK/TEAMS/WEBHOOK
 * providers are configured by an administrator with credential
 * REFERENCES — none is configured in this deployment, so routed
 * records say RECORDED_NOT_DELIVERED / NOT_CONFIGURED. A record is
 * never marked SENT without a provider acceptance.
 *
 * Webhook destinations are validated with the SDK SSRF guard at
 * policy-save time AND again at every delivery attempt (§73/§74).
 */
@Injectable()
export class NotificationRouterService {
  /** Overridable in tests; production uses real DNS. */
  resolver: WebhookResolver = dnsResolver;

  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  private toPolicyView(row: {
    eventTypes: unknown; channels: unknown; minSeverity: string | null; minPriority: string | null;
    riskThreshold: number | null; recipients: unknown; dedupWindowMinutes: number; quietHours: unknown;
    emergencySeverities: unknown; throttlePerHour: number;
  }): NotificationPolicyView {
    return {
      eventTypes: (row.eventTypes as string[]) ?? [],
      channels: (row.channels as NotificationPolicyView["channels"]) ?? ["IN_APP"],
      ...(row.minSeverity ? { minSeverity: row.minSeverity } : {}),
      ...(row.minPriority ? { minPriority: row.minPriority } : {}),
      ...(row.riskThreshold != null ? { riskThreshold: row.riskThreshold } : {}),
            dedupWindowMinutes: row.dedupWindowMinutes,
      quietHours: (row.quietHours as NotificationPolicyView["quietHours"]) ?? null,
      emergencySeverities: (row.emergencySeverities as string[]) ?? ["CRITICAL"],
      throttlePerHour: row.throttlePerHour,
    };
  }

  async createPolicy(user: RequestUser, workspaceId: string, input: Record<string, unknown>) {
    requireContinuousPermission(user, "MANAGE_NOTIFICATION_POLICIES");
    const webhook = input.webhook as { url: string; allowlist?: string[]; signingSecretRef?: string } | undefined;
    if (webhook) {
      // §73: validate the destination BEFORE the policy can exist.
      const verdict = await validateWebhookDestination({
        url: webhook.url, allowlist: webhook.allowlist ?? [], resolver: this.resolver,
      });
      if (!verdict.ok) throw new BadRequestException(`webhook destination refused: ${verdict.message}`);
    }
    const { webhook: _webhook, ...rest } = input;
    void _webhook;
    const policy = await this.prisma.notificationPolicy.create({
      data: {
        workspaceId, name: rest.name as string,
        eventTypes: rest.eventTypes as never, minSeverity: rest.minSeverity as string | undefined,
        minPriority: rest.minPriority as string | undefined, riskThreshold: rest.riskThreshold as number | undefined,
        channels: rest.channels as never, recipients: (rest.recipients ?? []) as never,
        dedupWindowMinutes: (rest.dedupWindowMinutes as number) ?? 60,
        quietHours: (rest.quietHours ?? null) as never,
        emergencySeverities: (rest.emergencySeverities ?? ["CRITICAL"]) as never,
        throttlePerHour: (rest.throttlePerHour as number) ?? 60,
        // §73: destination + allowlist + signing-secret REFERENCE.
        webhookUrl: webhook?.url, webhookAllowlist: (webhook?.allowlist ?? []) as never,
        signingSecretRef: webhook?.signingSecretRef,
        enabled: (rest.enabled as boolean) ?? true, createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "NOTIFICATION_POLICY_UPDATED", resourceType: "NotificationPolicy", resourceId: policy.id,
      metadata: { created: true, channels: rest.channels as string[] },
    });
    return policy;
  }

  async listPolicies(user: RequestUser, workspaceId: string) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    return this.prisma.notificationPolicy.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 200 });
  }

  async updatePolicy(user: RequestUser, workspaceId: string, id: string, input: Record<string, unknown>) {
    requireContinuousPermission(user, "MANAGE_NOTIFICATION_POLICIES");
    const existing = await this.prisma.notificationPolicy.findFirst({ where: { id, workspaceId } });
    if (!existing) throw new NotFoundException("notification policy not found in this workspace");
    // Same discipline as createPolicy: a nested webhook is re-validated
    // through the SSRF guard, and the Prisma write is built from an
    // explicit allowlist — raw client keys (id, workspaceId, createdBy,
    // …) can never be mass-assigned into the row.
    const webhook = input.webhook as { url: string; allowlist?: string[]; signingSecretRef?: string } | undefined;
    if (webhook) {
      const verdict = await validateWebhookDestination({ url: webhook.url, allowlist: webhook.allowlist ?? [], resolver: this.resolver });
      if (!verdict.ok) throw new BadRequestException(`webhook destination refused: ${verdict.message}`);
    }
    const { webhook: _w, ...rest } = input;
    void _w;
    const data = {
      ...(rest.name !== undefined ? { name: rest.name as string } : {}),
      ...(rest.eventTypes !== undefined ? { eventTypes: rest.eventTypes as never } : {}),
      ...(rest.minSeverity !== undefined ? { minSeverity: rest.minSeverity as string } : {}),
      ...(rest.minPriority !== undefined ? { minPriority: rest.minPriority as string } : {}),
      ...(rest.riskThreshold !== undefined ? { riskThreshold: rest.riskThreshold as number } : {}),
      ...(rest.channels !== undefined ? { channels: rest.channels as never } : {}),
      ...(rest.recipients !== undefined ? { recipients: rest.recipients as never } : {}),
      ...(rest.dedupWindowMinutes !== undefined ? { dedupWindowMinutes: rest.dedupWindowMinutes as number } : {}),
      ...(rest.quietHours !== undefined ? { quietHours: rest.quietHours as never } : {}),
      ...(rest.emergencySeverities !== undefined ? { emergencySeverities: rest.emergencySeverities as never } : {}),
      ...(rest.throttlePerHour !== undefined ? { throttlePerHour: rest.throttlePerHour as number } : {}),
      ...(rest.enabled !== undefined ? { enabled: rest.enabled as boolean } : {}),
      ...(webhook ? { webhookUrl: webhook.url, webhookAllowlist: (webhook.allowlist ?? []) as never, signingSecretRef: webhook.signingSecretRef } : {}),
    };
    const updated = await this.prisma.notificationPolicy.update({ where: { id }, data: data as never });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "NOTIFICATION_POLICY_UPDATED", resourceType: "NotificationPolicy", resourceId: id,
    });
    return updated;
  }

  async createEscalationPolicy(user: RequestUser, workspaceId: string, input: { name: string; priorities?: string[]; escalateAfterMinutes?: number; escalateTo?: string[]; enabled?: boolean }) {
    requireContinuousPermission(user, "MANAGE_NOTIFICATION_POLICIES");
    return this.prisma.alertEscalationPolicy.create({
      data: {
        workspaceId, name: input.name, priorities: (input.priorities ?? ["P0", "P1"]) as never,
        escalateAfterMinutes: input.escalateAfterMinutes ?? 240, escalateTo: (input.escalateTo ?? []) as never,
        enabled: input.enabled ?? true, createdBy: user.id,
      },
    });
  }

  async listEscalationPolicies(user: RequestUser, workspaceId: string) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    return this.prisma.alertEscalationPolicy.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 200 });
  }

  /**
   * Route one event through every enabled policy of the workspace.
   * Dedup (§68): same fingerprint within the policy's window ⇒
   * suppressed. Throttle (§70) and quiet hours (§72) suppress too —
   * every outcome is a persisted record, never silent loss.
   */
  async routeEvent(workspaceId: string, event: NotificationEventView & { title: string; detail?: string; riskScore?: number }, now = new Date()): Promise<Array<{ channel: string; status: string; policyId: string }>> {
    const policies = await this.prisma.notificationPolicy.findMany({ where: { workspaceId, enabled: true }, take: 100 });
    const results: Array<{ channel: string; status: string; policyId: string }> = [];
    const fingerprint = alertFingerprint(event);
    for (const policy of policies) {
      const view = this.toPolicyView(policy);
      const admission = policyAdmitsEvent(view, event);
      if (!admission.admitted) continue;
      for (const channel of view.channels) {
        let status: string;
        let providerStatus: string | undefined;
        let deliveryDetail: string | undefined;
        if (channel !== "IN_APP") {
          if (channel === "WEBHOOK" && policy.webhookUrl) {
            // §73: destinations are re-validated at delivery time —
            // DNS may have moved since the policy was saved.
            const verdict = await validateWebhookDestination({
              url: policy.webhookUrl,
              allowlist: (policy.webhookAllowlist as string[]) ?? [],
              resolver: this.resolver,
            });
            if (!verdict.ok) {
              status = "FAILED";
              deliveryDetail = `webhook destination refused at delivery: ${verdict.message}`;
            } else {
              status = "RECORDED_NOT_DELIVERED";
              providerStatus = "NOT_CONFIGURED";
            }
          } else {
            // Provider delivery gate (§66): no provider transport is
            // configured in this deployment. The record is honest.
            status = "RECORDED_NOT_DELIVERED";
            providerStatus = "NOT_CONFIGURED";
          }
        } else if (isQuietHours(view, event, now)) {
          status = "SUPPRESSED_QUIET_HOURS";
        } else {
          const since = new Date(now.getTime() - Math.max(view.dedupWindowMinutes, 0) * 60_000);
          const dupe = await this.prisma.securityNotification.findFirst({
            where: { workspaceId, policyId: policy.id, fingerprint, channel, status: "SENT", createdAt: { gte: since } },
          });
          if (dupe) {
            status = "SUPPRESSED_DEDUP";
          } else {
            const hourAgo = new Date(now.getTime() - 3600_000);
            const recent = await this.prisma.securityNotification.findMany({
              where: { workspaceId, policyId: policy.id, channel, status: "SENT", createdAt: { gte: hourAgo } },
              select: { createdAt: true }, take: 10000,
            });
            const throttle = checkThrottle({ priorTimestamps: recent.map((r) => r.createdAt), now, limitPerHour: view.throttlePerHour ?? 60 });
            status = throttle.allowed ? "SENT" : "SUPPRESSED_THROTTLE";
          }
        }
        const record = await this.prisma.securityNotification.create({
          data: {
            workspaceId, policyId: policy.id, eventType: event.type, channel, status,
            ...(providerStatus ? { providerStatus } : {}),
            fingerprint, groupKey: alertGroupKey(event),
            findingId: event.findingId, assetKey: event.assetKey,
            title: event.title, detail: deliveryDetail ?? event.detail,
          },
        });
        results.push({ channel, status, policyId: policy.id });
        void record;
      }
    }
    return results;
  }

  /** §71: escalate unresolved P0/P1 notifications past their policy window. */
  async runEscalations(workspaceId: string, now = new Date()) {
    const policies = await this.prisma.alertEscalationPolicy.findMany({ where: { workspaceId, enabled: true }, take: 50 });
    let escalated = 0;
    for (const policy of policies) {
      const candidates = await this.prisma.securityNotification.findMany({
        where: { workspaceId, status: "SENT", escalated: false },
        orderBy: { createdAt: "asc" }, take: 200,
      });
      for (const n of candidates) {
        const finding = n.findingId ? await this.prisma.finding.findFirst({ where: { id: n.findingId, workspaceId } }) : null;
        const priority = finding?.priority ?? null;
        if (!priority || !(policy.priorities as string[]).includes(priority)) continue;
        const findingOpen = !!finding && !["RESOLVED", "CLOSED", "FIXED", "REMEDIATED", "FALSE_POSITIVE"].includes(finding.lifecycleStatus);
        if (!findingOpen) continue;
        const due = escalationDue({
          priority, unresolvedSince: n.createdAt, now,
          escalateAfterMinutes: policy.escalateAfterMinutes,
          priorities: policy.priorities as string[],
        });
        if (due) {
          await this.prisma.securityNotification.update({ where: { id: n.id }, data: { escalated: true } });
          escalated++;
        }
      }
    }
    return { escalated };
  }

  async listNotifications(user: RequestUser, workspaceId: string, filters: { channel?: string; status?: string } = {}) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    const where: Record<string, unknown> = { workspaceId };
    if (filters.channel) where.channel = filters.channel;
    if (filters.status) where.status = filters.status;
    return this.prisma.securityNotification.findMany({ where: where as never, orderBy: { createdAt: "desc" }, take: 300 });
  }

  /** Webhook signing (§73): HMAC over the payload with a secret the
   *  CALLER resolved from its reference — this function never sees or
   *  stores a secret value beyond the call frame. */
  signWebhookPayload(secretValue: string, payload: string): string {
    return createHmac("sha256", secretValue).update(payload).digest("hex");
  }

  severityRank(severity: string): number {
    return SEVERITY_ORDER.indexOf(severity);
  }
}
