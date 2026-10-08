# Disaster Recovery Runbook — DSRclone

Scenarios and RPO/RTO targets: `deploy/disaster-recovery/README.md`.
Targets are configurable examples, not business commitments (§130).

## Failure scenarios & recovery sequences

### Cluster loss
1. Provision/repair the cluster; re-apply
   `deploy/kubernetes/overlays/production`.
2. Restore secrets from the secret manager (never from backups of the
   cluster itself).
3. Run the migration Job (no-op if the database survived).
4. Verify: health ready, scheduler lease held by exactly one instance,
   smoke flow green.

### Database loss / corruption
1. Freeze writes (scale API/Web to 0; workers paused).
2. Restore per the backup-restore runbook into a NEW database; run
   restore verification incl. tenant isolation.
3. Repoint `DATABASE_URL` (secret rotation), run migration Job, unfreeze.
4. Announce the data-loss window honestly (last verified backup time).

### Redis loss
Queues are durable-ish by design: job payloads carry IDs only, and scan
state lives in PostgreSQL. On Redis loss: restore Redis (AOF volume or
fresh), workers reconnect; the stale-execution recovery reconciles
in-flight work from the database. No findings data is lost — Redis never
holds long-lived evidence (§42).

### Object storage loss
Restore the artifact bucket from its mirror (backup-objects). Findings and
reports remain in PostgreSQL; affected artifact downloads report
unavailable until the mirror restore completes — never fabricate content.

### Region loss
Rebuild in the secondary region from git + secret manager + the
cross-region backup copies; DNS failover last, after the smoke flow
passes in the new region.

### Credential compromise (§132)
1. Rotate the affected credential in the secret manager FIRST (revoke,
   then issue).
2. Restart the affected workloads to pick up the new version (rotation is
   restart-tolerated per the table in `deploy/README.md`).
3. Audit: pull AuditLog + integration outbox records for the exposure
   window; force password/MFA resets if user credentials are implicated.

### Bad deployment / failed migration
Follow the deployment runbook's rollback section. A failed MIGRATION is
not rolled back by reverse DDL: restore is the path (§151).

## Control-plane invariant (§129)

During ANY failover, exactly one scheduler control plane may be active:
the Prompt 22 database lease decides. Before declaring recovery complete,
verify a single lease holder and a fresh heartbeat — if two schedulers
appear active, scale the scheduler Deployment to 0, wait for lease
expiry (120s TTL), then scale back to 1.

## Key & certificate rotation (§131/§133)

- Backup encryption keys are held SEPARATELY from backups (split
  knowledge); recovery requires the key custodian path in
  `deploy/disaster-recovery/README.md`.
- TLS certificates: rotate via the ingress secret; the platform tolerates
  rotation on restart of the ingress controller only — no app restart.

## Prompt 38 additions — measured recovery (§176–§184, §235)

- Every recovery (real or drill) is recorded via
  `POST /api/v1/platform/dr-exercises` with the **measured** RPO/RTO
  actually observed, or left null — NOT_MEASURED is the honest state
  until a drill measures it (§180).
- Restore path is the platform RestoreOrchestrator: integrity
  verified before any database is created (§234), isolated target
  first (§173), §174 validation recorded — see
  `docs/operations/restore-runbook.md`.
- Failure classes beyond P25's set: accidental deletion and
  ransomware follow the same sequence, with full credential rotation
  before services return (ransomware: assume compromise).
