/**
 * Distributed scheduler lease (Prompt 22 §23/§24, §98/§119).
 *
 * Exactly one scheduler node may materialize runs at a time. The
 * lease is a database row with an owner, an expiry and a heartbeat;
 * acquisition is a single conditional write, so two racing nodes
 * cannot both win. A node that dies holding the lease blocks the
 * scheduler only until leaseUntil passes — then another node takes
 * over safely, and idempotency keys (§19) guarantee the takeover
 * cannot double-execute a run the dead node already materialized.
 */

export interface LeaseView {
  owner: string;
  leaseUntil: Date;
  heartbeatAt: Date;
}

export type LeaseDecision =
  | { action: "ACQUIRE"; reason: string }
  | { action: "HELD_BY_OTHER"; owner: string; reason: string }
  | { action: "RENEW"; reason: string };

export function decideLease(input: {
  existing: LeaseView | null;
  owner: string;
  now: Date;
  ttlSeconds: number;
}): LeaseDecision {
  const { existing, owner, now } = input;
  if (!existing) return { action: "ACQUIRE", reason: "no lease exists" };
  if (existing.owner === owner) return { action: "RENEW", reason: "own lease — heartbeat" };
  if (existing.leaseUntil.getTime() <= now.getTime()) {
    return {
      action: "ACQUIRE",
      reason: `lease held by ${existing.owner} expired at ${existing.leaseUntil.toISOString()} — safe takeover (§119)`,
    };
  }
  return {
    action: "HELD_BY_OTHER",
    owner: existing.owner,
    reason: `lease held by ${existing.owner} until ${existing.leaseUntil.toISOString()}`,
  };
}

export function nextLeaseUntil(now: Date, ttlSeconds: number): Date {
  return new Date(now.getTime() + ttlSeconds * 1000);
}

/** A lease is stale when its heartbeat is older than the TTL — the
 *  holder is presumed dead even if leaseUntil was written generously. */
export function isLeaseStale(lease: LeaseView, now: Date, ttlSeconds: number): boolean {
  return lease.heartbeatAt.getTime() + ttlSeconds * 1000 <= now.getTime()
    || lease.leaseUntil.getTime() <= now.getTime();
}
