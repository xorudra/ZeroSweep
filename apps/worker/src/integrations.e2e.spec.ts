import { describe, expect, it } from "vitest";
import {
  createEventEnvelope,
  hmacSha256Hex,
  type SecurityEventEnvelope,
} from "@zerosweep/security-sdk";
import {
  OutboxRunner,
  type OutboxDeliveryRecord,
  type OutboxHttp,
  type OutboxIntegrationRecord,
  type OutboxStore,
  type OutboxSubscriptionRecord,
} from "./executors/outbox-runner";

/**
 * Prompt 24 worker e2e (§79, §128–§132): the outbox runner drains
 * due deliveries with the shared SDK policy — signed webhook
 * delivery, SSRF dead-lettering, redirect re-validation, bounded
 * retries and honest NOT_CONFIGURED for unwired provider transports.
 * All state is an in-memory store; the HTTP seam is a fake. No
 * network, no real providers.
 */

class MemOutboxStore implements OutboxStore {
  deliveries: Array<OutboxDeliveryRecord & { status: string }> = [];
  envelopes = new Map<string, SecurityEventEnvelope>();
  subscriptions = new Map<string, OutboxSubscriptionRecord>();
  integrations = new Map<string, OutboxIntegrationRecord>();
  outboxStatus = new Map<string, string>();

  async claimDueDeliveries(): Promise<OutboxDeliveryRecord[]> {
    return this.deliveries.filter((d) => d.status === "PENDING") as OutboxDeliveryRecord[];
  }
  async getEnvelope(outboxId: string) {
    return this.envelopes.get(outboxId) ?? null;
  }
  async getSubscription(id: string) {
    return this.subscriptions.get(id) ?? null;
  }
  async getIntegration(id: string) {
    return this.integrations.get(id) ?? null;
  }
  async updateDelivery(id: string, patch: { status: string; attempt?: number; responseMetadata: Record<string, unknown>; completedAt?: Date }) {
    const row = this.deliveries.find((d) => d.id === id)!;
    row.status = patch.status;
    if (patch.attempt) row.attempt = patch.attempt;
    row.responseMetadata = patch.responseMetadata;
  }
  async recomputeOutbox(outboxId: string) {
    const rows = this.deliveries.filter((d) => d.outboxId === outboxId);
    const terminal = rows.every((d) => ["DELIVERED", "NOT_CONFIGURED", "SKIPPED", "DEAD_LETTER"].includes(d.status));
    if (terminal) this.outboxStatus.set(outboxId, rows.every((d) => d.status === "DEAD_LETTER") ? "DEAD_LETTER" : "DELIVERED");
  }
}

const SECRET = "worker-fixture-secret";
const resolver = async (host: string): Promise<string[]> => {
  if (host === "hooks.example.com") return ["93.184.216.34"];
  if (host === "internal.example.com") return ["169.254.169.254"];
  return [];
};

function setup(http: OutboxHttp) {
  const store = new MemOutboxStore();
  const envelope = createEventEnvelope({
    eventType: "finding.created", workspaceId: "ws-1", resourceType: "Finding",
    resourceId: "f-1", payload: { severity: "CRITICAL" }, eventId: "evt-worker-1",
  });
  store.envelopes.set("outbox-1", envelope);
  store.subscriptions.set("sub-1", {
    id: "sub-1", endpoint: "https://hooks.example.com/zerosweep",
    enabled: true, secretReference: "env:TEST_HOOK_SECRET",
  });
  store.deliveries.push({
    id: "del-1", workspaceId: "ws-1", outboxId: "outbox-1", eventId: envelope.eventId,
    integrationId: null, subscriptionId: "sub-1", destinationKind: "WEBHOOK",
    attempt: 1, responseMetadata: {}, status: "PENDING",
  });
  const runner = new OutboxRunner({
    store, http, resolver,
    resolveSecret: (ref) => (ref === "env:TEST_HOOK_SECRET" ? SECRET : null),
  });
  return { store, runner, envelope };
}

describe("outbox runner (§79)", () => {
  it("delivers a signed webhook and marks the outbox DELIVERED (§71)", async () => {
    const seen: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
    const { store, runner, envelope } = setup(async (req) => {
      seen.push(req);
      return { status: 200 };
    });
    const summary = await runner.runOnce(new Date());
    expect(summary.delivered).toBe(1);
    expect(store.deliveries[0]!.status).toBe("DELIVERED");
    expect(store.outboxStatus.get("outbox-1")).toBe("DELIVERED");
    expect(seen[0]!.headers["x-zerosweep-signature"]).toBe(`sha256=${hmacSha256Hex(SECRET, seen[0]!.body)}`);
    expect(seen[0]!.headers["x-zerosweep-event-id"]).toBe(envelope.eventId);
  });

  it("dead-letters an SSRF destination without requesting it (§128)", async () => {
    let calls = 0;
    const { store, runner } = setup(async () => { calls += 1; return { status: 200 }; });
    store.subscriptions.get("sub-1")!.endpoint = "https://internal.example.com/hook";
    const summary = await runner.runOnce(new Date());
    expect(summary.deadLettered).toBe(1);
    expect(calls).toBe(0);
    expect(store.deliveries[0]!.status).toBe("DEAD_LETTER");
    expect(store.deliveries[0]!.responseMetadata.category).toBe("SSRF_BLOCKED");
  });

  it("blocks a redirect into a private address after re-validation (§129)", async () => {
    const urls: string[] = [];
    const { store, runner } = setup(async (req) => {
      urls.push(req.url);
      if (req.url.includes("hooks.example.com")) return { status: 302, location: "https://internal.example.com/hook" };
      return { status: 200 };
    });
    const summary = await runner.runOnce(new Date());
    expect(summary.deadLettered).toBe(1);
    expect(urls).toEqual(["https://hooks.example.com/zerosweep"]); // private hop never requested
    expect(store.deliveries[0]!.responseMetadata.reasonCode).toBe("SSRF_PROTECTED_DESTINATION");
  });

  it("retries transient failures with backoff and dead-letters at the bound (§72)", async () => {
    const { store, runner } = setup(async () => ({ status: 500 }));
    const t0 = new Date("2026-10-08T00:00:00Z");
    const first = await runner.runOnce(t0);
    expect(first.failed).toBe(1);
    expect(store.deliveries[0]!.status).toBe("PENDING");
    expect(store.deliveries[0]!.attempt).toBe(2);
    expect(store.deliveries[0]!.responseMetadata.nextAttemptAt).toBe("2026-10-08T00:00:30.000Z");
    // Exhaust the remaining attempts: attempts 2..5 fail → dead letter.
    store.deliveries[0]!.attempt = 5;
    store.deliveries[0]!.responseMetadata = {};
    const last = await runner.runOnce(t0);
    expect(last.deadLettered).toBe(1);
    expect(store.deliveries[0]!.status).toBe("DEAD_LETTER");
  });

  it("records SIEM deliveries NOT_CONFIGURED when no transport is wired (§66)", async () => {
    const { store, runner } = setup(async () => ({ status: 200 }));
    store.integrations.set("siem-1", { id: "siem-1", type: "SIEM", config: { collector: "https://siem.example.com/collect" }, configuration: null });
    store.deliveries.push({
      id: "del-2", workspaceId: "ws-1", outboxId: "outbox-1", eventId: "evt-worker-1",
      integrationId: "siem-1", subscriptionId: null, destinationKind: "SIEM",
      attempt: 1, responseMetadata: {}, status: "PENDING",
    });
    await runner.runOnce(new Date());
    const siem = store.deliveries.find((d) => d.id === "del-2")!;
    expect(siem.status).toBe("NOT_CONFIGURED");
  });

  it("skips deliveries whose backoff has not elapsed (§131: no duplicate send)", async () => {
    let calls = 0;
    const { store, runner } = setup(async () => { calls += 1; return { status: 200 }; });
    store.deliveries[0]!.responseMetadata = { nextAttemptAt: "2999-01-01T00:00:00.000Z" };
    const summary = await runner.runOnce(new Date());
    expect(summary.skipped).toBe(1);
    expect(calls).toBe(0);
    expect(store.deliveries[0]!.status).toBe("PENDING");
  });
});
