# High Availability (Prompt 38 §30–§37)

Deepens Prompt 25's HA treatment. Stateless services (API, web, AI)
scale horizontally behind health checks; availability claims are
limited to what the architecture can demonstrate — see
`docs/operations/production-readiness-checklist.md` for what is and
is not claimed.

- **PostgreSQL** is the single source of truth. HA is an operator
  choice (managed HA, Patroni, streaming replica); failover semantics
  and the resulting write-loss window are the provider's, recorded in
  the DR exercise log when exercised (§235).
- **Redis durability is classed (§38/§39).** Cache, rate limits and
  leases are reconstructable/ephemeral (AOF `everysec` at most);
  queues and scheduler leases are reconstructable from the database.
  Redis loss never loses findings — the database holds them.
- **Scheduler** runs lease-guarded: exactly one active tick planner;
  a stale lease is detected (§45/§46) and the standby takes over.
- **Object storage** availability follows the S3-compatible provider;
  the platform degrades honestly (health reports `down`) rather than
  buffering artifacts in the database.
- **Failure domains (§31).** AZ failure: stateless tiers re-schedule;
  region failure is a DR event (§180 — RPO/RTO are *measured* in DR
  exercises, never asserted).
