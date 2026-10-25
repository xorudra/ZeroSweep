# RC1 Operations Handoff (Prompt 39 §306/§307)

## Deployment

Two supported topologies ship in `deploy/`:

1. **Docker Compose (production profile)** —
   `deploy/compose/docker-compose.production.yml`. Services run
   read-only, `cap_drop: ["ALL"]`, `no-new-privileges`, non-root.
   Set `ZEROSWEEP_VERSION=1.0.0-rc.1` (immutable tag — never `latest`)
   and provide secrets via the environment/secret store, never in
   the compose file. The API refuses to boot on placeholder secrets
   (`assertProductionConfig`).
2. **Kubernetes** — Kustomize base in `deploy/kubernetes` (canonical)
   or the Helm chart in `deploy/helm/zerosweep` (renders an equivalent
   subset). NetworkPolicies in `deploy/policies` define the service
   communication matrix; scanner workers are the only components with
   target egress.

Local reference stack (development/verification):
`scripts/local-stack/start.sh` provisions the Docker-less stack
(PostgreSQL/Redis/MinIO/AI/API/worker) used for all RC1 live evidence.

## Configuration & secrets

- All configuration is environment-driven and validated by
  `@zerosweep/config` (zod) at boot; production violations are fatal.
- Platform data secrets are **references** (vault names), never
  values. Application-managed sensitive fields are AES-256-GCM
  encrypted (identity vault) or hashed (tokens, recovery codes).
- Rotate: JWT secret (invalidates access tokens), vault keys
  (rotation-safe design — P23), MinIO/S3 credentials, provider API
  keys by reference update. No rotation requires data re-encryption
  of findings/reports (they hold no credential material).

## Backup / restore / DR

- Machinery: P25 runbooks + P38 platform-ops backup service
  (checksum-gated, encrypted, isolated restore). RC1 exercise
  (measured): pg_dump of the reference database (1.48 MB) in ~1 s;
  isolated restore in ~89 s; user/org/workspace/finding/history/
  audit/report counts identical after restore, per-workspace finding
  distribution identical (§255–§259). Results:
  `release/rc1/dr-results/`.
- Restore **only** into an isolated database, verify counts and
  tenant distribution, then cut over. Never restore over a live
  primary as a first step.

## Monitoring & alerts

- `GET /api/v1/health` — honest per-dependency status (a down
  dependency degrades the report; it never fabricates "ok").
- `GET /api/v1/metrics` — Prometheus counters with bounded labels.
  **Restrict by network policy to the monitoring namespace** (RC1-L3);
  it is intentionally unauthenticated at the app layer.
- Platform-ops surface (P38): deployment records, worker fleet,
  kill switches (six levels), SLO views computed from measured data.
- Alert on: health degradation, queue backlog/dead-letter growth,
  backup failure, worker heartbeat loss, scheduler lease contention.

## Worker management & scanner troubleshooting

- Workers pull IDs-only jobs; a worker needs only the secrets of its
  current capability (§171). Tool health is reported honestly
  (UNAVAILABLE when a binary is absent) — install operator-provided
  binaries per `docs/tools/`; the platform never downloads tools.
- Poison jobs dead-letter with bounded retries; inspect via
  platform-ops. A stuck scan is cancellable; cancellation terminates
  the process tree (§85).

## Incident response

1. Use platform kill switches (assessment → workspace → platform)
   to stop activity first; switches are enforced in the scan-start
   path, not just the UI.
2. Preserve audit logs (immutable to tenant users) and report
   snapshots (immutable by construction).
3. Follow `SECURITY.md` for disclosure handling.

## Upgrade & rollback

- Upgrades: apply Prisma migrations (`prisma migrate deploy`,
  serialized), then roll images by immutable tag. RC1's migration
  set is verified from an empty database and as an upgrade on the
  reference stack.
- Rollback: redeploy the previous immutable tag; migrations in this
  project are additive — a code rollback does not require a schema
  rollback for RC1's set. Database rollback = restore from the
  pre-upgrade backup into an isolated instance and cut over.
