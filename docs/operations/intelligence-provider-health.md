# Intelligence Provider Health (Prompt 30 §68)

`VulnerabilityIntelProviderHealth` tracks per-provider: status (OK / DEGRADED / DOWN / NOT_CONFIGURED), last success/failure, latency, rate-limit state, freshness (CURRENT / STALE / NEVER_SYNCED) and a human-readable detail. Read it at `GET /api/v1/vulnerability-intelligence/providers` (also shows the Prompt 11 sync states and the honest live-fetch status).

Failure semantics (§67):

- A failed fetch/sync updates health + freshness and **retains** existing intelligence — dashboards keep serving the last good data, labelled with its freshness.
- Backoff delays are deterministic (`syncBackoffDelays`: 30s → 60s → 120s → 300s cap) so an outage never becomes a request storm.
- Fixture imports never touch provider health: health describes the live provider relationship only.
- Alerting: wire the existing notification policies to provider DOWN transitions when a transport is provisioned; in the current build the health view + audit trail are the operational surface.
