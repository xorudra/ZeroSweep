# Restore (Prompt 38 §172–§175)

Restores run through the platform admin plane (`/admin/platform/backups`,
API `POST /api/v1/platform/backups/:id/restore`) — there is no shell
path that restores over production.

Rules enforced by the RestoreOrchestrator (not by convention):

1. **OWNER only** (`RUN_RESTORE`) + the typed confirmation
   `RESTORE_INTO_ISOLATED_ENVIRONMENT` (§202).
2. **Integrity first (§234):** the artifact's SHA-256 is recomputed and
   compared with the checksum recorded at backup time. A mismatch —
   or a missing checksum — fails the restore record BEFORE any
   database is created. Production is never touched by a failed
   restore.
3. **Isolated target only (§173):** the target database name must end
   in `_restore`, `_recovery` or `_dr`, must not be the production
   database, and must not be a system database.
4. **Validation recorded verbatim (§174):** DB consistency, object
   references, report access, finding-history presence and tenant
   isolation are checked against the restored database and stored on
   the restore record. Any failed check marks the restore FAILED.
5. The isolated database is left in place for operator inspection;
   dropping it is a deliberate operator action.

Step-by-step procedure: `docs/operations/restore-runbook.md`.
Backup side: `docs/operations/backup-runbook.md`, scripts in
`deploy/backup/`.
