# Production Readiness Checklist — DSRclone (§185)

Do not promote to production until every item is verifiably true.

## Configuration & secrets
- [ ] `validateProductionConfig` passes in the target environment (API and
      worker logs show a clean boot in production mode).
- [ ] No placeholder values anywhere; secrets delivered by the secret
      manager; rotation owners named (deploy/README.md table).
- [ ] CORS origin is the exact production origin; no wildcards.
- [ ] `DATABASE_REQUIRE_TLS` / `REDIS_REQUIRE_TLS` set where the managed
      services support TLS, and URLs carry the matching scheme.

## Data layer
- [ ] Migration Job green; `_prisma_migrations` at the release head.
- [ ] Bounded pools: per-instance `DATABASE_CONNECTION_LIMIT` × max
      replicas < database `max_connections` with headroom.
- [ ] Backups: last `restore-verify.sh` = `RESTORE_VERIFIED`, age < 25h.
- [ ] PITR/WAL archiving confirmed on the managed database (or accepted
      risk recorded).

## Platform
- [ ] Kustomize production overlay builds; admission policies in Enforce.
- [ ] Probes hit `/health/live` + `/health/ready` (never the aggregate
      endpoint for liveness).
- [ ] PDBs, quotas, HPA bounds in place; scanner pool node taints live.
- [ ] NetworkPolicies applied; metadata endpoint unreachable from pods
      (resilience test log attached to the release record).
- [ ] `/metrics` reachable only from the monitoring namespace.

## Security
- [ ] Image scan gate passed; SBOMs attached; signatures verify.
- [ ] No privileged/host workloads in the namespaces (policy report clean).
- [ ] Break-glass procedure tested in staging within the last quarter.
- [ ] Scheduler lease: exactly one active control plane.

## Operations
- [ ] Alerts from `deploy/monitoring/prometheus-rules.yaml` loaded and
      routed; on-call knows the incident runbook location.
- [ ] Release manifest committed with real image digests.
- [ ] Rollback target (previous manifest) identified before rollout.
