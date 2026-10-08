# Restore Runbook (Prompt 38 §172–§175)

1. `/admin/platform/backups` → pick a COMPLETED backup → "Restore
   tests". OWNER role required (`RUN_RESTORE`).
2. Target database: an isolated name ending `_restore` / `_recovery`
   / `_dr`. Production and system databases are refused by the
   orchestrator itself.
3. Type the confirmation `RESTORE_INTO_ISOLATED_ENVIRONMENT`.
4. The orchestrator verifies the artifact checksum **before** creating
   anything (§234); a corrupt backup fails the restore record and
   touches nothing.
5. Read the recorded validation (§174): DB consistency, object
   references, report access, finding history, tenant isolation. All
   must pass for the restore to count.
6. The restored database stays for inspection; drop it deliberately
   when done. Promoting a restore to production is a separate,
   planned operation (see the rollback runbook).
