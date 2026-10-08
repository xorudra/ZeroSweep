# Backup & Restore Architecture (Prompt 38 §160–§184)

Implemented by the platform-ops `BackupOrchestrator` /
`RestoreOrchestrator` (`apps/api/src/modules/platform-ops`):

- **What is backed up (§162/§163).** PostgreSQL (logical `pg_dump`
  custom format by the platform orchestrator), object storage and
  configuration/exports via provider-native tooling (§164 — the API
  refuses those kinds rather than pretending to back them up).
  Secrets and encryption keys are NEVER inside backups (§165).
- **Protection (§166–§167).** Artifacts are checksummed (SHA-256)
  before and after optional AES-256 encryption (operator passphrase
  *file*, never a value in the repo or the database).
- **Retention (§168).** 30 days default with a keep-minimum of 3;
  expiry is recorded on the backup record.
- **Restore discipline (§172–§175).** OWNER-only + typed confirmation;
  integrity verified before any write (§234); isolated target
  databases only (never production); the §174 validation set is
  recorded verbatim on the restore record. **A backup counts as valid
  only after a successful restore test.**
- **DR honesty (§180).** RPO/RTO are measured in recorded DR
  exercises (`PlatformDrExercise`); until measured they are reported
  as NOT_MEASURED.

Procedures: `docs/operations/backup-runbook.md`,
`docs/operations/restore-runbook.md`, `deploy/backup/`, `deploy/restore/`.
