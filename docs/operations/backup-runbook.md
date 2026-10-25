# Backup Runbook (Prompt 38 §160–§171)

- Start a backup: `/admin/platform/backups` → "Start PostgreSQL
  backup" (or `POST /api/v1/platform/backups`). Operator roles:
  OWNER/ADMIN (`MANAGE_BACKUPS`).
- The run records status, size, duration, checksum and retention
  expiry on completion — failed runs are recorded FAILED with a
  sanitized reason (§171). Object storage / config backups are
  provider-native (§164); the API refuses those kinds rather than
  faking them.
- Encryption: set `PLATFORM_BACKUP_PASSPHRASE_FILE` to a
  secret-mounted file; artifacts are AES-256 encrypted before the
  checksum is taken (§166).
- Verify weekly: the `ZerosweepBackupStale` alert fires if no
  successful backup lands in 25h. A backup is valid only after a
  restore test — see the restore runbook.
