# Disaster Recovery — design notes (Prompt 25 §128–§133)

Runbook: `docs/operations/disaster-recovery-runbook.md`.

## Example targets (configurable — NOT business commitments, §130)

| Scenario | Example RPO | Example RTO | Mechanism |
|---|---|---|---|
| Pod/node failure | 0 | < 5 min | Replicas, PDBs, topology spread |
| Database failure (managed HA) | ~0 | < 15 min | Provider failover |
| Database loss (restore) | ≤ 24h (daily) / ≤ 5 min (PITR) | ≤ 4h | Verified backups + WAL |
| Redis loss | 0 (state in PG) | < 30 min | Rebuild; workers reconcile |
| Object storage loss | ≤ 24h | ≤ 4h | Bucket mirror restore |
| Cluster loss | ≤ 24h | ≤ 8h | Git + secrets + backups rebuild |
| Region loss | ≤ 24h | ≤ 24h | Cross-region copies, DNS failover |
| Credential compromise | n/a | rotate < 1h | Secret manager rotation |

## Invariants

- Exactly ONE active scheduler control plane during any failover — the
  Prompt 22 database lease is the mechanism and the verification step.
- Backups are worthless until restore-verified; verification includes
  TENANT ISOLATION after restore (§172).
- Master/backup encryption keys are stored SEPARATELY from backups
  (§131): split-knowledge custody (two operators or an HSM/KMS with
  dual control). A backup without its key path is recorded as
  unrestorable, honestly.
- TLS and signing keys rotate on their own schedules (§133); rotation is
  rehearsed in staging quarterly (game-day list in the runbook).
