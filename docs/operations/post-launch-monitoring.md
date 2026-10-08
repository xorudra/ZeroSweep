# Post-Launch Monitoring (Prompt 40 §280/§281/§283/§284)

Watch, from the platform-ops + product surfaces:

- Health + SLOs (measured only — INSUFFICIENT_DATA stays honest).
- Queue depths, worker availability, scan failure rates.
- Error rates incl. QUOTA_EXCEEDED volume (a product signal, not just
  an error).
- Metering pipeline: usage aggregate freshness; duplicate-event rate
  (idempotency hits are expected under retries).
- Billing webhook failures/signature rejections (when enabled).
- License status transitions (when enabled).
- Abuse signals volume + review queue.
- Support/incident communications follow
  `docs/product/incident-communication.md`.
