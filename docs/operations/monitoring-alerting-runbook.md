# Monitoring & Alerting Runbook — DSRclone

## Signals (§102–§111)

- **Metrics**: API `/api/v1/metrics` (request counters by method/status
  class — bounded labels; process + dependency-up gauges). Workers export
  queue depth/wait, stage durations, tool availability and heartbeat
  freshness. Prometheus rules: `deploy/monitoring/prometheus-rules.yaml`.
- **Logs**: structured JSON from `@dsrclone/logger`, secrets redacted at
  emission, correlation fields requestId/jobId/scanId/eventId/traceId
  (§105–§107). Log-injection safety: user-derived values are never
  interpolated into message strings, only structured fields.
- **Traces**: OpenTelemetry spans are emitted around queue jobs and stage
  executions by the worker telemetry module; exporters are configured per
  environment (OTLP endpoint via env) — sampling is head-based at 10%
  with 100% for errored scans.

## SLOs (example targets — tune per deployment, §112)

| SLI | Target | Window |
|---|---|---|
| API availability (ready endpoints) | 99.9% | 30d |
| API p95 latency (non-scan endpoints) | < 500ms | 30d |
| Scan start success (authorized scans accepted) | 99% | 30d |
| Verified backup freshness | < 25h, restore-verified | continuous |
| Scheduler lease heartbeat age | < 5m | continuous |

Error-budget burn alerts ride on the operational rule group; page on
fast burn (SEV1/SEV2 per the incident runbook), ticket on slow burn.

## Alert hygiene

Every alert in the rules file names its runbook. An alert without a
play is deleted or demoted to a dashboard. Security alerts (denial
spikes, scope violations, capability violations, privileged workloads,
break-glass, audit failures) route to the security channel, not the
general ops channel.

## Capacity & load (§172–§177)

- Baseline method: fixture load test against staging (register/login/
  target/scan-start mix + Mock-adapter scans) recording p50/p95/p99,
  queue wait, and DB pool saturation; rerun per release train.
- NO capacity number is published without a benchmark record behind it.
  Current verified baseline: the local-stack smoke (single-node dev
  profile) — functional only, NOT a production capacity claim.
- Watch growth drivers: concurrent scans per pool, artifact volume,
  findings table growth; review quotas quarterly.
