# Deployment Runbook — ZeroSweep

Canonical path: **Kustomize** (`deploy/kubernetes/base` + overlays). Helm
(`deploy/helm/zerosweep`) renders an equivalent subset. Compose production
profile: `deploy/compose/docker-compose.production.yml`.

## Release flow

1. **Build** images from `deploy/docker/*.Dockerfile`; tag immutably with
   the release version (never `latest`).
2. **Gate** (§18): scan images (Trivy/Grype), generate SBOMs (Syft), and
   sign (cosign). The release does not proceed on a failed gate.
3. **Manifest**: `node deploy/scripts/release-manifest.mjs` with
   `IMAGE_DIGEST_*` from the build; commit `release-manifest.json`
   alongside the overlay tag bump.
4. **Preflight**: `sh deploy/scripts/preflight.sh deploy/compose/.env.production`
   (Compose) or verify the cluster Secret exists and matches the rotation
   table (Kubernetes). Secrets come from the secret manager — never git.
5. **Migrate**: run the migration Job / compose `migrate` service FIRST.
   It preflights, takes Prisma's migration lock, applies, and verifies.
   Application pods never run DDL, so replicas cannot race (§36).
6. **Roll out**: `kubectl apply -k deploy/kubernetes/overlays/production`
   (RollingUpdate, maxUnavailable 0 for API/Web). Watch readiness at
   `/api/v1/health/ready`.
7. **Verify**: health (`ok` overall), scheduler lease heartbeat fresh,
   queue depth draining, smoke flow per `scripts/local-stack/smoke.mjs`
   adapted to staging fixtures.

## Migration discipline: expand / migrate / contract (§39)

- **Expand** releases only ADD nullable columns/tables; old and new code
  both work against the expanded schema.
- **Migrate** releases backfill/transform data with the new code running.
- **Contract** (drop/rename) happens only in a LATER release, after every
  running replica is on code that no longer reads the old shape.
- Destructive migrations are never blindly reversed (§151): rollback of a
  contract step is a restore-from-backup decision, not `migrate resolve`.

## Rollback (§149–§152)

1. Application rollback = re-apply the previous overlay tag set (images
   are immutable; the previous release manifest names exact digests).
2. If the release included an expand migration, old code runs safely
   against it — no DB action needed.
3. If a data migration misbehaved, STOP: freeze writes (scale API to 0),
   follow the backup-restore runbook, and only then resume. Never improvise
   reverse DDL against production.
4. Feature flags may disable FEATURES; they never bypass authorization,
   scope, approval, or adapter policy (§152).

## Canary (§148)

Production overlay supports a canary by deploying the new API tag to a
parallel Deployment (10% of Ingress weight via the ingress controller's
canary annotations) for one monitoring window (error rate, p95, denial
spikes), then promoting or rolling back per the thresholds in the
monitoring runbook.
