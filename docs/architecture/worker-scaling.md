# Worker Scaling (Prompt 38 §40–§52, §76–§85)

- **Queue classes (§40)** separate interactive scans, batch scans,
  ingestion, reports, AI, integrations and maintenance. Priorities age
  (+1/minute, SDK `platformops`) so batch work cannot starve
  interactive scans.
- **Retries (§42/§43)** are bounded (5 attempts, exponential backoff
  with jitter) and end in the dead-letter store — never infinite, never
  silent. Operator retry is limited to IDs-only job kinds and re-runs
  every worker-side gate.
- **Leases (§45/§46).** A claimed job holds a lease; expired leases
  make jobs claimable again; operator cancel refuses ACTIVE jobs
  (the lease owner decides).
- **Worker classes (§47)** map to pools: general, recon, web, API,
  network, code, cloud, mobile/binary, reporting, AI, privileged-host.
  Scanner pools scale on queue depth + CPU/memory (§77), never on
  HTTP rate (§78), and never scale to zero mid-scan (§80).
- **Isolation (§50–§52).** Scanner workers cannot reach the API,
  database, Redis or metadata services; privileged tools exist only
  in the privileged pool behind approval; no worker is privileged.
