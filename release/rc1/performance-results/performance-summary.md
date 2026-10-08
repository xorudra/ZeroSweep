# RC1 Performance measurements (Prompt 39 §240–§254)

Rules (§240): measurements only — nothing here is an estimate.
Environment: the Docker-less reference stack on the build VM
(PostgreSQL 16.2, Redis 7.2.5, single node, loopback HTTP). Dataset:
a purpose-created workspace populated with **5,000 synthetic Finding
rows inserted directly via SQL** (to measure query/render cost at
scale — ingestion was bypassed by design and the rows were deleted
after measurement), alongside 67 pre-existing smoke organizations.
20 sequential requests per endpoint; numbers in `api-latency.json`.

| Endpoint | Mean | p95 | Max |
| --- | --- | --- | --- |
| GET /findings?pageSize=50 (5,000-row workspace) | 64.6 ms | 131.0 ms | 137.9 ms |
| GET /findings?severity=HIGH (filtered) | 25.7 ms | 31.1 ms | 41.7 ms |
| GET /vulnerabilities?pageSize=50 | 357.4 ms | 434.5 ms | 434.9 ms |
| GET /assets?pageSize=50 | 11.0 ms | 34.0 ms | 47.7 ms |
| GET /scans?pageSize=50 | 6.2 ms | 9.0 ms | 9.2 ms |

## Interpretation (honest)

- Pagination is bounded everywhere sampled (≤200 rows), so list cost
  does not grow with workspace size beyond per-page enrichment.
- `/vulnerabilities` is the slowest list (per-row intelligence
  enrichment) — recorded as finding **RC1-M2** with an optimization
  path; acceptable for RC1, not hidden.
- NOT measured in RC1 (§253): multi-tenant concurrent load, scanner
  worker throughput under parallel real scans, report generation at
  10k-finding scale, and the §154-style load test. These need a
  production-shaped environment; the RC1 numbers are single-node
  latency evidence, not a capacity claim (§252 — no capacity claim
  is made).
