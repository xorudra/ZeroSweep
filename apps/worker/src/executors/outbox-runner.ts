import {
  IntegrationNotConfiguredError,
  SiemConnector,
  SlackConnector,
  TeamsConnector,
  UnconfiguredIntegrationTransport,
  formatCef,
  formatLeef,
  nextRetryDelayMs,
  retryAfterDelayMs,
  shouldDeadLetter,
  signOutboundPayload,
  toSiemEvent,
  validateWebhookDestination,
  type HostResolver,
  type IntegrationTransport,
  type SanitizedFindingView,
  type SecurityEventEnvelope,
} from "@dsrclone/security-sdk";

/**
 * Integration outbox runner (Prompt 24 §79). The API's transactional
 * outbox (§78) records every integration delivery as an
 * IntegrationDelivery row; this worker runner claims due PENDING
 * deliveries and performs them with the SAME policy functions the
 * API-side processor uses (shared via @dsrclone/security-sdk):
 *
 * - webhook destinations are re-validated with fresh DNS before
 *   every hop, redirects are followed at most 3 times and every hop
 *   is re-validated (§70/§129); SSRF refusals dead-letter immediately
 *   because they are policy, not transience;
 * - retries are bounded with exponential backoff and Retry-After
 *   honoring, then dead-lettered (§72) — never infinite;
 * - a failing destination (including a full SIEM outage) never
 *   blocks the producing workflow (§66): the event waits here.
 *
 * Job payloads carry IDs only (§14 pattern): all state is loaded
 * through the store.
 */

export interface OutboxDeliveryRecord {
  id: string;
  workspaceId: string;
  outboxId: string | null;
  eventId: string;
  integrationId: string | null;
  subscriptionId: string | null;
  destinationKind: string;
  attempt: number;
  responseMetadata: Record<string, unknown>;
}

export interface OutboxSubscriptionRecord {
  id: string;
  endpoint: string;
  enabled: boolean;
  secretReference: string | null;
}

export interface OutboxIntegrationRecord {
  id: string;
  type: string;
  config: Record<string, unknown> | null;
  configuration: Record<string, unknown> | null;
}

export interface OutboxStore {
  claimDueDeliveries(now: Date, limit: number): Promise<OutboxDeliveryRecord[]>;
  getEnvelope(outboxId: string): Promise<SecurityEventEnvelope | null>;
  getSubscription(id: string): Promise<OutboxSubscriptionRecord | null>;
  getIntegration(id: string): Promise<OutboxIntegrationRecord | null>;
  updateDelivery(id: string, patch: { status: string; attempt?: number; responseMetadata: Record<string, unknown>; completedAt?: Date }): Promise<void>;
  recomputeOutbox(outboxId: string, now: Date): Promise<void>;
}

export interface OutboxHttpResponse {
  status: number;
  headers?: Record<string, string>;
  location?: string;
}
export type OutboxHttp = (req: { url: string; headers: Record<string, string>; body: string }) => Promise<OutboxHttpResponse>;

export interface OutboxRunnerDeps {
  store: OutboxStore;
  http: OutboxHttp;
  resolver: HostResolver;
  /** Secret REFERENCE resolution (env:VAR) — values never persist. */
  resolveSecret: (reference: string | null | undefined) => string | null;
  /** Provider transport factory; production wiring returns the
   *  deliberately unconfigured transport (NOT_CONFIGURED honestly). */
  transportFor?: (integration: OutboxIntegrationRecord) => IntegrationTransport;
}

const MAX_REDIRECTS = 3;

export class OutboxRunner {
  constructor(private readonly deps: OutboxRunnerDeps) {}

  /** Drain due deliveries once (bounded). Returns outcome counts. */
  async runOnce(now = new Date(), limit = 50): Promise<{ processed: number; delivered: number; failed: number; deadLettered: number; skipped: number }> {
    const due = await this.deps.store.claimDueDeliveries(now, limit);
    const summary = { processed: 0, delivered: 0, failed: 0, deadLettered: 0, skipped: 0 };
    for (const delivery of due) {
      const nextAt = delivery.responseMetadata?.nextAttemptAt
        ? new Date(delivery.responseMetadata.nextAttemptAt as string)
        : null;
      if (nextAt && nextAt.getTime() > now.getTime()) { summary.skipped += 1; continue; }
      summary.processed += 1;
      const outcome = await this.attempt(delivery, now);
      if (outcome === "DELIVERED") summary.delivered += 1;
      else if (outcome === "DEAD_LETTER") summary.deadLettered += 1;
      else if (outcome === "FAILED") summary.failed += 1;
      else summary.skipped += 1;
      if (delivery.outboxId) await this.deps.store.recomputeOutbox(delivery.outboxId, now);
    }
    return summary;
  }

  private async attempt(delivery: OutboxDeliveryRecord, now: Date): Promise<string> {
    try {
      switch (delivery.destinationKind) {
        case "WEBHOOK": return await this.attemptWebhook(delivery, now);
        case "SIEM": return await this.attemptSiem(delivery, now);
        case "SLACK": return await this.attemptMessaging(delivery, now, "SLACK");
        case "TEAMS": return await this.attemptMessaging(delivery, now, "TEAMS");
        default:
          await this.finish(delivery, "SKIPPED", { category: "UNKNOWN_DESTINATION" }, now);
          return "SKIPPED";
      }
    } catch (err) {
      if (err instanceof IntegrationNotConfiguredError) {
        await this.finish(delivery, "NOT_CONFIGURED", { category: "NOT_CONFIGURED" }, now);
        return "SKIPPED";
      }
      return this.retryOrDeadLetter(delivery, { category: "NETWORK" }, now);
    }
  }

  private async attemptWebhook(delivery: OutboxDeliveryRecord, now: Date): Promise<string> {
    const sub = delivery.subscriptionId ? await this.deps.store.getSubscription(delivery.subscriptionId) : null;
    if (!sub || !sub.enabled) {
      await this.finish(delivery, "SKIPPED", { category: "SUBSCRIPTION_DISABLED" }, now);
      return "SKIPPED";
    }
    const envelope = delivery.outboxId ? await this.deps.store.getEnvelope(delivery.outboxId) : null;
    if (!envelope) {
      await this.finish(delivery, "SKIPPED", { category: "ENVELOPE_MISSING" }, now);
      return "SKIPPED";
    }
    const body = JSON.stringify(envelope);
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "x-dsrclone-event": envelope.eventType,
      "x-dsrclone-delivery": delivery.id,
      "x-dsrclone-event-id": envelope.eventId,
    };
    if (sub.secretReference) {
      const secret = this.deps.resolveSecret(sub.secretReference);
      if (!secret) {
        await this.finish(delivery, "NOT_CONFIGURED", { category: "SIGNING_SECRET_UNRESOLVED" }, now);
        return "SKIPPED";
      }
      headers["x-dsrclone-signature"] = signOutboundPayload(secret, body);
    }
    let url = sub.endpoint;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
      const verdict = await validateWebhookDestination({ url, allowlist: [], resolver: this.deps.resolver });
      if (!verdict.ok) {
        await this.finish(delivery, "DEAD_LETTER", { category: "SSRF_BLOCKED", reasonCode: verdict.reasonCode, hop }, now);
        return "DEAD_LETTER";
      }
      const res = await this.deps.http({ url, headers, body });
      if (res.status >= 300 && res.status < 400) {
        if (!res.location) return this.retryOrDeadLetter(delivery, { category: "REDIRECT_WITHOUT_LOCATION", httpStatus: res.status }, now);
        if (hop === MAX_REDIRECTS) {
          await this.finish(delivery, "DEAD_LETTER", { category: "TOO_MANY_REDIRECTS" }, now);
          return "DEAD_LETTER";
        }
        url = new URL(res.location, url).toString();
        continue;
      }
      if (res.status >= 200 && res.status < 300) {
        await this.finish(delivery, "DELIVERED", { httpStatus: res.status, hops: hop }, now);
        return "DELIVERED";
      }
      const retryAfter = retryAfterDelayMs(res.headers, now.getTime());
      return this.retryOrDeadLetter(
        delivery,
        { category: res.status === 429 ? "RATE_LIMIT" : "HTTP_ERROR", httpStatus: res.status },
        now,
        retryAfter ?? undefined,
      );
    }
    await this.finish(delivery, "DEAD_LETTER", { category: "TOO_MANY_REDIRECTS" }, now);
    return "DEAD_LETTER";
  }

  private async attemptSiem(delivery: OutboxDeliveryRecord, now: Date): Promise<string> {
    const integration = delivery.integrationId ? await this.deps.store.getIntegration(delivery.integrationId) : null;
    const envelope = delivery.outboxId ? await this.deps.store.getEnvelope(delivery.outboxId) : null;
    if (!integration || !envelope) {
      await this.finish(delivery, "SKIPPED", { category: "INTEGRATION_OR_ENVELOPE_MISSING" }, now);
      return "SKIPPED";
    }
    const p = (envelope.payload ?? {}) as Record<string, unknown>;
    const event = toSiemEvent({
      eventId: envelope.eventId, timestamp: envelope.timestamp, workspaceId: envelope.workspaceId,
      eventType: (p.siemEventType as string) ?? envelope.eventType,
      severity: (p.severity as string) ?? "MEDIUM", status: (p.status as string) ?? "OPEN",
      findingId: p.findingId as string | undefined, assetReference: p.assetReference as string | undefined,
      riskScore: p.riskScore as number | undefined, cve: p.cve as string | undefined, cwe: p.cwe as string | undefined,
    });
    const config = integration.configuration ?? integration.config ?? {};
    const format = config.format as string | undefined;
    const serialized = format === "CEF" ? formatCef(event) : format === "LEEF" ? formatLeef(event) : JSON.stringify(event);
    const transport = this.deps.transportFor?.(integration) ?? new UnconfiguredIntegrationTransport(integration.type);
    const connector = new SiemConnector(config, transport);
    const result = await connector.sendEvent(serialized);
    if (result.delivered) {
      await this.finish(delivery, "DELIVERED", { format: format ?? "JSON" }, now);
      return "DELIVERED";
    }
    if (result.detail.includes("NOT_CONFIGURED")) {
      await this.finish(delivery, "NOT_CONFIGURED", { category: "NOT_CONFIGURED" }, now);
      return "SKIPPED";
    }
    return this.retryOrDeadLetter(delivery, { category: "PROVIDER_ERROR" }, now);
  }

  private async attemptMessaging(delivery: OutboxDeliveryRecord, now: Date, kind: "SLACK" | "TEAMS"): Promise<string> {
    const integration = delivery.integrationId ? await this.deps.store.getIntegration(delivery.integrationId) : null;
    const envelope = delivery.outboxId ? await this.deps.store.getEnvelope(delivery.outboxId) : null;
    if (!integration || !envelope) {
      await this.finish(delivery, "SKIPPED", { category: "INTEGRATION_OR_ENVELOPE_MISSING" }, now);
      return "SKIPPED";
    }
    const p = (envelope.payload ?? {}) as Record<string, unknown>;
    const config = integration.configuration ?? integration.config ?? {};
    const transport = this.deps.transportFor?.(integration) ?? new UnconfiguredIntegrationTransport(integration.type);
    const connector = kind === "SLACK" ? new SlackConnector(config, transport) : new TeamsConnector(config, transport);
    let result: { delivered: boolean; detail: string };
    if (p.finding) result = await connector.sendFindingAlert(p.finding as unknown as SanitizedFindingView);
    else if (p.reportTitle) result = await connector.sendReportReady({ title: p.reportTitle as string, reference: p.reference as string });
    else result = await connector.sendNotification({ text: (p.text as string) ?? envelope.eventType });
    if (result.delivered) {
      await this.finish(delivery, "DELIVERED", {}, now);
      return "DELIVERED";
    }
    if (result.detail.includes("NOT_CONFIGURED")) {
      await this.finish(delivery, "NOT_CONFIGURED", { category: "NOT_CONFIGURED" }, now);
      return "SKIPPED";
    }
    return this.retryOrDeadLetter(delivery, { category: "PROVIDER_ERROR" }, now);
  }

  private async finish(delivery: OutboxDeliveryRecord, status: string, metadata: Record<string, unknown>, now: Date): Promise<void> {
    await this.deps.store.updateDelivery(delivery.id, { status, responseMetadata: metadata, completedAt: now });
  }

  private async retryOrDeadLetter(delivery: OutboxDeliveryRecord, metadata: Record<string, unknown>, now: Date, delayOverrideMs?: number): Promise<string> {
    if (shouldDeadLetter(delivery.attempt)) {
      await this.finish(delivery, "DEAD_LETTER", { ...metadata, attempts: delivery.attempt }, now);
      return "DEAD_LETTER";
    }
    const delay = delayOverrideMs ?? nextRetryDelayMs(delivery.attempt);
    await this.deps.store.updateDelivery(delivery.id, {
      status: "PENDING",
      attempt: delivery.attempt + 1,
      responseMetadata: { ...metadata, nextAttemptAt: new Date(now.getTime() + delay).toISOString() },
    });
    return "FAILED";
  }
}

/** Job contract for the outbox queue (IDs only, §14 pattern). */
export interface IntegrationOutboxJobData {
  kind: "INTEGRATION_OUTBOX";
  workspaceId?: string;
}
