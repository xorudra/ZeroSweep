import { Inject, Injectable, Optional } from "@nestjs/common";
import {
  CircuitBreaker,
  IntegrationNotConfiguredError,
  SiemConnector,
  SlackConnector,
  TeamsConnector,
  createEventEnvelope,
  formatCef,
  formatLeef,
  nextRetryDelayMs,
  retryAfterDelayMs,
  shouldDeadLetter,
  signOutboundPayload,
  toSiemEvent,
  validateWebhookDestination,
  type HostResolver,
  type SanitizedFindingView,
  type SecurityEventEnvelope,
} from "@dsrclone/security-sdk";
import { request as httpsRequest } from "node:https";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import { IntegrationSecretResolver, IntegrationTransportFactory } from "../core/transport";
import { dnsResolver } from "../../continuous-security/notifications/notification-router.service";

type Row = Record<string, unknown>;

export interface OutboundHttpRequest {
  url: string;
  headers: Record<string, string>;
  body: string;
  /** Addresses returned by SSRF validation for THIS hop. The
   *  transport must connect only to one of these (connection
   *  pinning) — re-resolving the hostname at connect time reopens
   *  the DNS-rebinding TOCTOU the validation just closed. */
  pinnedIps?: string[];
}
export interface OutboundHttpResponse {
  status: number;
  headers?: Record<string, string>;
  location?: string;
}
/** Outbound HTTP seam. The production implementation NEVER follows
 *  redirects automatically (§72/§129): each hop is re-validated
 *  against the SSRF policy before it is requested. */
export type OutboundHttp = (req: OutboundHttpRequest) => Promise<OutboundHttpResponse>;

export const OUTBOUND_HTTP = "INTEGRATIONS_OUTBOUND_HTTP";

export class FetchOutboundHttp {
  async send(req: OutboundHttpRequest): Promise<OutboundHttpResponse> {
    // Pinned path (the only path the outbox processor uses): connect
    // to a validation-approved address with node:https directly —
    // no DNS lookup happens at connect time, while Host and TLS
    // servername (SNI + certificate verification) keep the ORIGINAL
    // hostname, so a rebound name can never steer the connection.
    // ponytail: tries pinned addresses in order; no Happy-Eyeballs
    // racing — validation already screened every address in the set.
    if (req.pinnedIps && req.pinnedIps.length > 0) return this.sendPinned(req, req.pinnedIps);
    const res = await fetch(req.url, {
      method: "POST",
      headers: req.headers,
      body: req.body,
      redirect: "manual",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { status: res.status, headers, location: res.headers.get("location") ?? undefined };
  }

  private async sendPinned(req: OutboundHttpRequest, pinnedIps: string[]): Promise<OutboundHttpResponse> {
    const url = new URL(req.url);
    if (url.protocol !== "https:") throw new Error("pinned outbound transport requires an https: URL");
    let lastError: unknown;
    for (const rawIp of pinnedIps) {
      try {
        return await this.sendPinnedOnce(req, url, rawIp.replace(/^\[|\]$/g, ""));
      } catch (err) { lastError = err; }
    }
    throw lastError instanceof Error ? lastError : new Error("pinned connection failed");
  }

  private sendPinnedOnce(req: OutboundHttpRequest, url: URL, ip: string): Promise<OutboundHttpResponse> {
    return new Promise((resolve, reject) => {
      const isIpLiteral = /^[0-9.]+$/.test(url.hostname) || url.hostname.includes(":");
      const headers: Record<string, string> = {
        ...req.headers,
        host: url.host,
        "content-length": String(Buffer.byteLength(req.body)),
      };
      const res = httpsRequest({
        protocol: "https:",
        hostname: ip,
        port: url.port ? Number(url.port) : 443,
        path: `${url.pathname}${url.search}`,
        method: "POST",
        headers,
        // TLS identity stays the original hostname (skipped when the
        // host already IS an IP literal — it then equals the address).
        ...(isIpLiteral ? {} : { servername: url.hostname }),
        rejectUnauthorized: true,
        timeout: 10_000,
      }, (incoming) => {
        const out: Record<string, string> = {};
        for (const [k, v] of Object.entries(incoming.headers)) {
          if (typeof v === "string") out[k.toLowerCase()] = v;
        }
        incoming.resume(); // body is never used — drain so the socket completes
        incoming.on("end", () => resolve({
          status: incoming.statusCode ?? 0,
          headers: out,
          location: out["location"],
        }));
        incoming.on("error", reject);
      });
      res.on("timeout", () => res.destroy(new Error("pinned outbound request timed out")));
      res.on("error", reject);
      res.end(req.body);
    });
  }
}

const MAX_REDIRECTS = 3;

/**
 * Outbox processor (Prompt 24 §79, §65–§67, §70–§72, §96, §104,
 * §128–§132). Delivers pending IntegrationDelivery rows with bounded
 * retries, exponential backoff, Retry-After honoring, circuit
 * breaking and dead-lettering. A failing destination — including a
 * full SIEM outage — never blocks the producing workflow (§66): the
 * scan/report completes and the event waits here.
 */
@Injectable()
export class OutboxProcessorService {
  private readonly breakers = new Map<string, CircuitBreaker>();
  private readonly http: OutboundHttp;
  private readonly resolver: HostResolver;

  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly transports: IntegrationTransportFactory,
    private readonly secrets: IntegrationSecretResolver,
    @Optional() @Inject(OUTBOUND_HTTP) http?: OutboundHttp | FetchOutboundHttp,
    @Optional() resolver?: HostResolver,
  ) {
    if (http && typeof (http as OutboundHttp) === "function") this.http = http as OutboundHttp;
    else if (http && typeof (http as FetchOutboundHttp).send === "function") this.http = (req) => (http as FetchOutboundHttp).send(req);
    else { const f = new FetchOutboundHttp(); this.http = (req) => f.send(req); }
    this.resolver = resolver ?? dnsResolver;
  }

  breakerFor(key: string): CircuitBreaker {
    let b = this.breakers.get(key);
    if (!b) { b = new CircuitBreaker(5, 60_000); this.breakers.set(key, b); }
    return b;
  }

  async processDue(now = new Date(), workspaceId?: string): Promise<{ processed: number; delivered: number; failed: number; deadLettered: number; skipped: number }> {
    // User-triggered runs are scoped to the caller's workspace (the
    // controller always passes one). A run WITHOUT a workspaceId is
    // global and reserved for trusted internal scheduler contexts —
    // never reachable from a tenant request.
    const pending = await this.prisma.integrationDelivery.findMany({
      where: { status: "PENDING", ...(workspaceId ? { workspaceId } : {}) },
      orderBy: { createdAt: "asc" },
      take: 100,
    });
    const summary = { processed: 0, delivered: 0, failed: 0, deadLettered: 0, skipped: 0 };
    for (const delivery of pending as Row[]) {
      const meta = (delivery.responseMetadata as Row) ?? {};
      const nextAt = meta.nextAttemptAt ? new Date(meta.nextAttemptAt as string) : null;
      if (nextAt && nextAt.getTime() > now.getTime()) { summary.skipped += 1; continue; }
      summary.processed += 1;
      const outcome = await this.attempt(delivery, now);
      if (outcome === "DELIVERED") summary.delivered += 1;
      else if (outcome === "DEAD_LETTER") summary.deadLettered += 1;
      else if (outcome === "FAILED") summary.failed += 1;
      else summary.skipped += 1;
      await this.recomputeOutbox(delivery.outboxId as string | null, now);
    }
    return summary;
  }

  private async attempt(delivery: Row, now: Date): Promise<"DELIVERED" | "FAILED" | "DEAD_LETTER" | "SKIPPED"> {
    const kind = delivery.destinationKind as string;
    try {
      if (kind === "WEBHOOK") return await this.attemptWebhook(delivery, now);
      if (kind === "SIEM") return await this.attemptSiem(delivery, now);
      if (kind === "SLACK" || kind === "TEAMS") return await this.attemptMessaging(delivery, now, kind);
      return this.finish(delivery, "SKIPPED", { category: "UNKNOWN_DESTINATION" }, now);
    } catch (err) {
      if (err instanceof IntegrationNotConfiguredError) {
        return this.finish(delivery, "NOT_CONFIGURED", { category: "NOT_CONFIGURED" }, now);
      }
      return this.retryOrDeadLetter(delivery, { category: "NETWORK", message: "transport error (details never stored with payloads)" }, now);
    }
  }

  /* ------------------------------ webhook ------------------------------ */

  private async attemptWebhook(delivery: Row, now: Date): Promise<"DELIVERED" | "FAILED" | "DEAD_LETTER" | "SKIPPED"> {
    const sub = await this.prisma.webhookSubscription.findUnique({ where: { id: delivery.subscriptionId as string } }) as Row | null;
    if (!sub || sub.enabled === false) return this.finish(delivery, "SKIPPED", { category: "SUBSCRIPTION_DISABLED" }, now);
    const outbox = await this.outboxFor(delivery);
    const envelope = outbox.payload as SecurityEventEnvelope;
    const body = JSON.stringify(envelope);
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "x-dsrclone-event": envelope.eventType,
      "x-dsrclone-delivery": delivery.id as string,
      "x-dsrclone-event-id": envelope.eventId,
    };
    if (sub.secretReference) {
      const secret = this.secrets.resolve(sub.secretReference as string);
      if (!secret) return this.finish(delivery, "NOT_CONFIGURED", { category: "SIGNING_SECRET_UNRESOLVED" }, now);
      headers["x-dsrclone-signature"] = signOutboundPayload(secret, body);
    }
    const breaker = this.breakerFor(`webhook:${sub.id}`);
    if (!breaker.canExecute(now.getTime())) {
      return this.retryOrDeadLetter(delivery, { category: "CIRCUIT_OPEN" }, now, 60_000);
    }
    // §70/§129: validate the destination, follow at most 3 redirects,
    // and re-validate EVERY hop with fresh DNS before requesting it.
    let url = sub.endpoint as string;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
      const verdict = await validateWebhookDestination({ url, allowlist: [], resolver: this.resolver });
      if (!verdict.ok) {
        breaker.recordFailure(now.getTime());
        // Policy refusals are permanent — never retried (§128/§129).
        return this.finish(delivery, "DEAD_LETTER", { category: "SSRF_BLOCKED", reasonCode: verdict.reasonCode, hop }, now);
      }
      const res = await this.http({ url, headers, body, pinnedIps: verdict.resolvedIps });
      if (res.status >= 300 && res.status < 400) {
        if (!res.location) return this.retryOrDeadLetter(delivery, { category: "REDIRECT_WITHOUT_LOCATION", httpStatus: res.status }, now);
        if (hop === MAX_REDIRECTS) return this.finish(delivery, "DEAD_LETTER", { category: "TOO_MANY_REDIRECTS" }, now);
        url = new URL(res.location, url).toString();
        continue;
      }
      if (res.status >= 200 && res.status < 300) {
        breaker.recordSuccess();
        await this.auditDelivery(delivery, "WEBHOOK_DELIVERED", { httpStatus: res.status });
        return this.finish(delivery, "DELIVERED", { httpStatus: res.status, hops: hop }, now);
      }
      breaker.recordFailure(now.getTime());
      const retryAfter = retryAfterDelayMs(res.headers, now.getTime());
      return this.retryOrDeadLetter(
        delivery,
        { category: res.status === 429 ? "RATE_LIMIT" : "HTTP_ERROR", httpStatus: res.status },
        now,
        retryAfter ?? undefined,
      );
    }
    return this.finish(delivery, "DEAD_LETTER", { category: "TOO_MANY_REDIRECTS" }, now);
  }

  /* -------------------------------- SIEM -------------------------------- */

  private async attemptSiem(delivery: Row, now: Date): Promise<"DELIVERED" | "FAILED" | "DEAD_LETTER" | "SKIPPED"> {
    const integration = await this.integrationFor(delivery);
    if (!integration) return this.finish(delivery, "SKIPPED", { category: "INTEGRATION_MISSING" }, now);
    const outbox = await this.outboxFor(delivery);
    const envelope = outbox.payload as SecurityEventEnvelope;
    const p = (envelope.payload ?? {}) as Record<string, unknown>;
    const event = toSiemEvent({
      eventId: envelope.eventId,
      timestamp: envelope.timestamp,
      workspaceId: envelope.workspaceId,
      eventType: (p.siemEventType as string) ?? envelope.eventType,
      severity: (p.severity as string) ?? "MEDIUM",
      status: (p.status as string) ?? "OPEN",
      findingId: p.findingId as string | undefined,
      assetReference: p.assetReference as string | undefined,
      riskScore: p.riskScore as number | undefined,
      cve: p.cve as string | undefined,
      cwe: p.cwe as string | undefined,
    });
    const format = ((integration.configuration ?? integration.config ?? {}) as Row).format as string | undefined;
    const serialized = format === "CEF" ? formatCef(event) : format === "LEEF" ? formatLeef(event) : JSON.stringify(event);
    const connector = new SiemConnector(
      (integration.configuration ?? integration.config ?? {}) as Record<string, unknown>,
      this.transports.forIntegration(integration as Row & { type: string }),
    );
    const breaker = this.breakerFor(`siem:${integration.id}`);
    if (!breaker.canExecute(now.getTime())) return this.retryOrDeadLetter(delivery, { category: "CIRCUIT_OPEN" }, now, 60_000);
    const result = await connector.sendEvent(serialized);
    if (result.delivered) {
      breaker.recordSuccess();
      await this.auditDelivery(delivery, "SIEM_EVENT_EXPORTED", { format: format ?? "JSON" });
      return this.finish(delivery, "DELIVERED", { format: format ?? "JSON" }, now);
    }
    if (result.detail.includes("NOT_CONFIGURED")) {
      return this.finish(delivery, "NOT_CONFIGURED", { category: "NOT_CONFIGURED" }, now);
    }
    breaker.recordFailure(now.getTime());
    return this.retryOrDeadLetter(delivery, { category: "PROVIDER_ERROR" }, now);
  }

  /* ------------------------------ messaging ------------------------------ */

  private async attemptMessaging(delivery: Row, now: Date, kind: "SLACK" | "TEAMS"): Promise<"DELIVERED" | "FAILED" | "DEAD_LETTER" | "SKIPPED"> {
    const integration = await this.integrationFor(delivery);
    if (!integration) return this.finish(delivery, "SKIPPED", { category: "INTEGRATION_MISSING" }, now);
    const outbox = await this.outboxFor(delivery);
    const envelope = outbox.payload as SecurityEventEnvelope;
    const p = (envelope.payload ?? {}) as Record<string, unknown>;
    const config = (integration.configuration ?? integration.config ?? {}) as Record<string, unknown>;
    const transport = this.transports.forIntegration(integration as Row & { type: string });
    const connector = kind === "SLACK" ? new SlackConnector(config, transport) : new TeamsConnector(config, transport);
    let result: { delivered: boolean; detail: string };
    if (p.finding) result = await connector.sendFindingAlert(p.finding as unknown as SanitizedFindingView);
    else if (p.reportTitle) result = await connector.sendReportReady({ title: p.reportTitle as string, reference: p.reference as string });
    else result = await connector.sendNotification({ text: (p.text as string) ?? envelope.eventType });
    if (result.delivered) return this.finish(delivery, "DELIVERED", {}, now);
    if (result.detail.includes("NOT_CONFIGURED")) return this.finish(delivery, "NOT_CONFIGURED", { category: "NOT_CONFIGURED" }, now);
    return this.retryOrDeadLetter(delivery, { category: "PROVIDER_ERROR" }, now);
  }

  /* ------------------------------ bookkeeping ------------------------------ */

  private async integrationFor(delivery: Row): Promise<Row | null> {
    if (!delivery.integrationId) return null;
    return (await this.prisma.integration.findUnique({ where: { id: delivery.integrationId as string } })) as Row | null;
  }

  private async outboxFor(delivery: Row): Promise<Row> {
    const row = await this.prisma.securityEventOutbox.findUnique({ where: { id: delivery.outboxId as string } });
    if (row) return row as Row;
    // Delivery without a stored envelope: rebuild a minimal envelope
    // from the delivery fields (defensive; should not occur).
    return {
      payload: createEventEnvelope({
        eventType: "unknown", workspaceId: delivery.workspaceId as string,
        resourceType: "Integration", resourceId: delivery.integrationId as string ?? "",
        payload: {}, eventId: delivery.eventId as string,
      }),
    } as Row;
  }

  private async finish(delivery: Row, status: string, metadata: Row, now: Date) {
    await this.prisma.integrationDelivery.update({
      where: { id: delivery.id as string },
      data: { status, responseMetadata: metadata as never, completedAt: now },
    });
    if (status === "DEAD_LETTER" && delivery.destinationKind === "WEBHOOK") {
      await this.auditDelivery(delivery, "WEBHOOK_DELIVERY_FAILED", metadata);
    }
    return status as "DELIVERED" | "DEAD_LETTER" | "SKIPPED";
  }

  private async retryOrDeadLetter(delivery: Row, metadata: Row, now: Date, delayOverrideMs?: number) {
    const attempt = (delivery.attempt as number) ?? 1;
    if (shouldDeadLetter(attempt)) {
      return this.finish(delivery, "DEAD_LETTER", { ...metadata, attempts: attempt }, now);
    }
    const delay = delayOverrideMs ?? nextRetryDelayMs(attempt);
    await this.prisma.integrationDelivery.update({
      where: { id: delivery.id as string },
      data: {
        attempt: attempt + 1,
        status: "PENDING",
        responseMetadata: { ...metadata, nextAttemptAt: new Date(now.getTime() + delay).toISOString() },
      },
    });
    return "FAILED" as const;
  }

  private async recomputeOutbox(outboxId: string | null, now: Date): Promise<void> {
    if (!outboxId) return;
    const deliveries = await this.prisma.integrationDelivery.findMany({ where: { outboxId } }) as Row[];
    if (deliveries.length === 0) return;
    const terminal = deliveries.every((d) => ["DELIVERED", "NOT_CONFIGURED", "SKIPPED", "DEAD_LETTER"].includes(d.status as string));
    if (!terminal) return;
    const anyDelivered = deliveries.some((d) => d.status === "DELIVERED");
    const allDead = deliveries.every((d) => d.status === "DEAD_LETTER");
    await this.prisma.securityEventOutbox.update({
      where: { id: outboxId },
      data: {
        status: allDead ? "DEAD_LETTER" : "DELIVERED",
        deliveredAt: anyDelivered ? now : null,
        attempts: Math.max(...deliveries.map((d) => (d.attempt as number) ?? 1)),
      },
    });
  }

  private async auditDelivery(delivery: Row, action: string, metadata: Row): Promise<void> {
    await this.audit.record({
      workspaceId: delivery.workspaceId as string,
      action,
      resourceType: "IntegrationDelivery",
      resourceId: delivery.id as string,
      metadata: { ...metadata, eventId: delivery.eventId, destinationKind: delivery.destinationKind, outboxId: delivery.outboxId ?? null },
    }).catch(() => undefined);
  }
}
