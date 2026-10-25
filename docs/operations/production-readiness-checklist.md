# Production Readiness Checklist — ZeroSweep (§185)

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

## Prompt 38 V2 gates (§240–§242)

### Security
- [ ] No default credentials anywhere (§242 blocker); MFA on operator
      accounts; break-glass accounts exist and are sealed (§213).
- [ ] Secrets are references only (§23/§24); repo scan shows no secret
      material (§242 blocker: secrets in repo = NO-GO).
- [ ] Database not publicly exposed (§242 blocker); scanner egress
      governed; admission policies Enforce.
### Reliability
- [ ] Backup taken AND restore test passed within the last cycle
      (§242 blocker: untested backup = NO-GO).
- [ ] Kill switches + maintenance mode drilled once in staging
      (audited records exist).
- [ ] SLO table reviewed; unmeasured entries read INSUFFICIENT_DATA —
      nobody has typed an uptime figure into a slide (§127).
### Data protection
- [ ] Tenant-isolation tests green (§242 blocker); retention rules
      active; encryption-at-rest confirmed on DB + object storage.
### Operations
- [ ] On-call rota + alert receivers wired; Alertmanager inhibition
      on; dashboards load with live series (no silent "no data").
- [ ] DR exercise recorded with measured or NOT_MEASURED RPO/RTO
      (§235); runbooks linked from every alert (§120).
### Release
- [ ] Release promoted by digest from staging (§147/§148); deployment
      recorded in `/admin/platform`; rollback digests retained.
- [ ] Go-live approval recorded with the approver's name (§242).

**NO-GO blockers (§242):** default credentials · no TLS · backup
untested · tenant-isolation failure · critical migration pending ·
secrets in repo · database publicly exposed. Any one blocks launch.
