# Generic Webhooks (Prompt 24 §68–§74)

Outbound subscriptions are created per workspace with an event-type
allowlist. Delivery semantics:

- payload = canonical event envelope, JSON;
- `X-DSRclone-Signature: sha256=<hmac>` with the subscription's
  secret reference (§69) plus event-id / timestamp headers;
- destination validated at creation AND at every delivery, including
  every redirect hop (§70 — see
  `docs/security/integration-ssrf-protection.md`);
- bounded retries with backoff and dead-letter (§72);
- delivery history (status + metadata only) queryable at
  `GET /integrations/deliveries` (§74).

Inbound provider webhooks are documented per provider; the shared
verification pipeline is in `docs/security/webhook-verification.md`.
