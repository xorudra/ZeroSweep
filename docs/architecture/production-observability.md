# Production Observability (Prompt 38 §95–§127)

Three signals, one discipline: **nothing sensitive is ever emitted.**

- **Metrics.** Prometheus exposition at `GET /api/v1/metrics`
  (loopback/monitoring-namespace only). The `dsrclone_` prefix is
  mandatory (§98); the SDK validates metric names and rejects
  forbidden labels (§107: no tenant/user ids, emails, URLs, IPs,
  findings, credentials). HTTP metrics carry method, status class and
  route *template* (§99) plus a latency histogram. Reference
  dashboards for all ten §118 boards live in
  `deploy/monitoring/dashboards/`; a series no exporter emits renders
  as "No data" — never as a fabricated value.
- **Logs (§108–§112).** Structured JSON via `@dsrclone/logger` with
  secret redaction on keys AND value patterns (authorization headers,
  cookies, bearer/JWT/API-key shapes). Correlation ids link API,
  worker and AI records (§96).
- **Traces (§113–§116).** W3C trace context propagation; span
  attributes are screened by the SDK (`screenSpanAttributes`) —
  sensitive keys are removed outright, long values dropped — and
  again at the reference OTel collector.
- **Health (§128–§138)** is layered (liveness/readiness/dependency/
  platform) and honest: a dependency that is down reports down.
- **SLOs (§124–§127)** are computed from persisted operational
  records (backups, restore tests, scans). Unmeasured services report
  `INSUFFICIENT_DATA` with a null ratio. **This product makes no
  uptime claim it has not measured.**

Alert rules (§120–§123) live in `deploy/monitoring/prometheus-rules.yaml`
(operational + security groups, grouped/inhibited in the reference
Alertmanager config so one root failure pages once).
