# Integration Outbox (Prompt 24 §78–§80, §131)

Publishing an event writes a `SecurityEventOutbox` row and its
`IntegrationDelivery` rows. With a live database the publish runs in
the same transaction as the business change (§78), so an event can
never be lost between "the thing happened" and "integrations were
told".

The processor (`OutboxProcessorService` in the API,
`OutboxRunner` in the worker — one policy implementation in the SDK)
claims PENDING deliveries and attempts them with:

- bounded retries (max 5 attempts) and exponential backoff
  (30s → 2m → 10m → 30m → 2h);
- `Retry-After` honoring, capped at 1h (§97/§132);
- a per-destination circuit breaker (§96);
- dead-lettering at the bound — never infinite retry (§72).

A crash after commit but before delivery is the normal case, not an
edge: the row survives, a later processor run delivers it, and the
stable `eventId` + one delivery row per destination make the pair
logically exactly-once (§131). Delivery records store response
METADATA only (HTTP status, category, duration) — never response
bodies or secrets (§80).
