# Production Hardening — ZeroSweep (§134)

## Configuration & secrets

- Production mode (`NODE_ENV=production|staging`) FAILS FAST on
  placeholder secrets, wildcard CORS, or unmet TLS requirements
  (`packages/config` — `validateProductionConfig`, enforced at API, worker
  and scheduler boot).
- Secrets are references in manifests and values in the secret manager
  only. The platform's own credential model (secret references, never
  values in the database) extends to deployment: `zerosweep-secrets` is
  created out-of-band.
- Rotation tolerance: JWT secret — restart API (old tokens expire ≤ JWT
  TTL); database password — rolling restart after secret update; Redis
  password — rolling restart; object-storage keys — rolling restart;
  TLS certificates — ingress reload only. Full table: `deploy/README.md`.

## Transport & headers

- HTTPS-only ingress with HSTS; app-level helmet headers; CSP without
  `unsafe-inline`/`unsafe-eval` on the console (Next.js defaults tightened
  at the ingress + app layers); request bodies bounded (1MB API default,
  2MB ingress/webhook paths with their own governed caps).

## Data protection

- PostgreSQL TLS (`sslmode=require` minimum in production policy),
  bounded pools; Redis `rediss://` + AUTH where supported; object storage
  private buckets, TLS, server-side encryption, tenant-prefixed keys
  (`organization/workspace/resource`) and lifecycle retention.
- Backups are encrypted client-side (age) when leaving the platform
  boundary, with keys held separately from the backups themselves.

## Runtime posture

- All images: multi-stage, digest-pinned bases, non-root, no package
  managers or shells beyond runtime needs in the final layer.
- Containers: `readOnlyRootFilesystem`, `cap_drop: ALL`,
  `no-new-privileges`, seccomp RuntimeDefault (compose + Kubernetes).
- The platform refuses scans without verified targets + approved
  assessments at BOTH the API gate and the worker — deployment topology
  never weakens this (no "trusted network" bypass exists).
- Feature flags cannot bypass authorization, scope, approval, or adapter
  policy (§152).

## Logging & audit

- Structured JSON logs, redaction at emission (passwords/tokens/cookies/
  authorization headers), bounded retention at the aggregator.
- Audit records are database-persisted; audit write failure is a SEV1
  alert, not a log line.
