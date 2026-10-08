import { BadRequestException, Inject, Injectable, ServiceUnavailableException } from "@nestjs/common";
import { findPaymentDataViolations, verifyBillingWebhookSignature } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import { ProductConfigService } from "../product-config.service";
import { EntitlementService } from "../entitlements/entitlement.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Billing abstraction (Prompt 40 §19–§27).
 *
 * - No provider configured => billing is NOT_CONFIGURED and NOTHING is
 *   simulated: there is no code path that invents a successful payment
 *   (§21/§268).
 * - The TEST provider exists only when explicitly configured and is
 *   refused in production (SDK billingConfigurationStatus, §21).
 * - MANUAL_INVOICE records invoice/contract events through the same
 *   audited event pipeline; it never touches card data (§26).
 * - Webhooks: HMAC signature + timestamp replay window (§23), event-ID
 *   idempotency (§24/§219), payment-data refusal (§26). Processing is
 *   deliberately light — acknowledge fast, transition subscription
 *   state, record the event (§240). Billing events survive restarts in
 *   the database (§284).
 */
@Injectable()
export class BillingService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly config: ProductConfigService,
    private readonly entitlements: EntitlementService,
  ) {}

  status() {
    return this.config.billing();
  }

  async listEvents(organizationId: string): Promise<any[]> {
    return (this.prisma as any).billingEvent.findMany({ where: { organizationId }, orderBy: { receivedAt: "desc" }, take: 100 });
  }

  async listInvoices(organizationId: string): Promise<any[]> {
    return (this.prisma as any).billingInvoiceReference.findMany({ where: { organizationId }, orderBy: { createdAt: "desc" }, take: 100 });
  }

  /** Manual-invoice provider (§20): an operator records an issued invoice reference. */
  async recordManualInvoice(actorId: string, input: { organizationId: string; externalInvoiceId: string; status: string; currency?: string; amountCents?: number; hostedInvoiceRef?: string }): Promise<any> {
    const status = this.status();
    if (status.status !== "CONFIGURED" || status.provider !== "MANUAL_INVOICE") {
      throw new ServiceUnavailableException("Manual-invoice billing is not the configured provider; nothing was recorded (§21).");
    }
    const violations = findPaymentDataViolations(input);
    if (violations.length) throw new BadRequestException(`Invoice payload contains forbidden payment data (§26): ${violations.join(", ")}`);
    return (this.prisma as any).billingInvoiceReference.create({
      data: {
        organizationId: input.organizationId, provider: "MANUAL_INVOICE",
        externalInvoiceId: input.externalInvoiceId, status: input.status,
        currency: input.currency ?? null, amountCents: input.amountCents ?? null,
        hostedInvoiceRef: input.hostedInvoiceRef ?? null,
      },
    });
  }

  /**
   * Webhook entry (§23). Returns an acknowledgement object; rejects
   * (throws) on: unconfigured provider, bad signature, replay, or
   * payment-data contamination. Duplicate deliveries are acknowledged
   * WITHOUT a second state transition (§219).
   */
  async handleWebhook(input: { provider: string; rawBody: string; signature: string | null; timestamp: string | null }): Promise<{ received: boolean; duplicate: boolean; eventId?: string }> {
    const status = this.status();
    if (status.status === "NOT_CONFIGURED" || !status.provider) {
      await this.audit.record({ action: "BILLING_WEBHOOK_REJECTED", resourceType: "BillingEvent", metadata: { provider: input.provider, reason: "billing not configured" } }).catch(() => undefined);
      throw new ServiceUnavailableException("Billing is not configured; webhooks are not accepted (§21).");
    }
    const secret = this.config.billingWebhookSecret();
    if (!secret) {
      await this.audit.record({ action: "BILLING_WEBHOOK_REJECTED", resourceType: "BillingEvent", metadata: { provider: input.provider, reason: "webhook secret not configured" } }).catch(() => undefined);
      throw new ServiceUnavailableException("Billing webhook secret is not configured; webhooks are rejected (§22/§23).");
    }
    const verification = verifyBillingWebhookSignature({
      rawBody: input.rawBody, signatureHeader: input.signature, timestampHeader: input.timestamp, secret, now: new Date(),
    });
    if (!verification.ok) {
      await this.audit.record({ action: "BILLING_WEBHOOK_REJECTED", resourceType: "BillingEvent", metadata: { provider: input.provider, reason: verification.reason } }).catch(() => undefined);
      throw new BadRequestException(`Billing webhook rejected: ${verification.reason} (§23/§220).`);
    }

    let event: any;
    try { event = JSON.parse(input.rawBody); } catch { throw new BadRequestException("Billing webhook body is not valid JSON."); }
    const externalEventId = String(event.id ?? "");
    const type = String(event.type ?? "");
    const organizationId = event.data?.organizationId ? String(event.data.organizationId) : null;
    if (!externalEventId || !type) throw new BadRequestException("Billing webhook event lacks id/type.");

    const violations = findPaymentDataViolations(event);
    if (violations.length) {
      await this.audit.record({ action: "BILLING_WEBHOOK_REJECTED", resourceType: "BillingEvent", metadata: { provider: input.provider, externalEventId, reason: "payment data present" } }).catch(() => undefined);
      throw new BadRequestException(`Billing webhook refused: payload contains raw payment data (§26): ${violations.join(", ")}`);
    }

    const existing = await (this.prisma as any).billingEvent.findFirst({ where: { provider: input.provider, externalEventId } });
    if (existing) return { received: true, duplicate: true, eventId: existing.id };

    const row = await (this.prisma as any).billingEvent.create({
      data: { organizationId, provider: input.provider, externalEventId, type, status: "RECEIVED" },
    });
    await this.audit.record({ organizationId: organizationId ?? undefined, action: "BILLING_WEBHOOK_RECEIVED", resourceType: "BillingEvent", resourceId: row.id, metadata: { provider: input.provider, type } });

    try {
      await this.applyEvent(type, organizationId, event.data ?? {});
      await (this.prisma as any).billingEvent.update({ where: { id: row.id }, data: { status: "PROCESSED", processedAt: new Date() } });
    } catch (err) {
      await (this.prisma as any).billingEvent.update({ where: { id: row.id }, data: { status: "REJECTED", processedAt: new Date(), error: err instanceof Error ? err.message : "processing failed" } });
      throw err;
    }
    return { received: true, duplicate: false, eventId: row.id };
  }

  /** Subscription state transitions driven by verified provider events. */
  private async applyEvent(type: string, organizationId: string | null, data: any): Promise<void> {
    if (!organizationId) return;
    const sub = await (this.prisma as any).subscription.findFirst({ where: { organizationId }, orderBy: { createdAt: "desc" } });
    if (!sub) return;
    const transitions: Record<string, string> = {
      "subscription.activated": "ACTIVE",
      "subscription.updated": "ACTIVE",
      "subscription.past_due": "PAST_DUE",
      "invoice.payment_failed": "PAST_DUE",
      "subscription.cancelled": "CANCELLED",
      "subscription.suspended": "SUSPENDED",
    };
    const next = transitions[type];
    if (next) {
      await (this.prisma as any).subscription.update({
        where: { id: sub.id },
        data: { status: next, cancelledAt: next === "CANCELLED" ? new Date() : sub.cancelledAt, externalBillingReference: data.externalReference ?? sub.externalBillingReference },
      });
      this.entitlements.invalidate(organizationId);
    }
    if (type === "invoice.issued" && data.externalInvoiceId) {
      await (this.prisma as any).billingInvoiceReference.create({
        data: {
          organizationId, provider: String(data.provider ?? "STRIPE_COMPATIBLE"), externalInvoiceId: String(data.externalInvoiceId),
          status: String(data.status ?? "OPEN"), currency: data.currency ?? null, amountCents: data.amountCents ?? null,
          hostedInvoiceRef: data.hostedInvoiceRef ?? null,
        },
      }).catch(() => undefined);
    }
  }
}
