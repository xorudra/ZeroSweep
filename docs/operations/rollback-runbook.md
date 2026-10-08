# Rollback Runbook (Prompt 38 §185–§196)

Triggers: elevated 5xx, failed migrations, data corruption signs,
runaway queues.

1. Enable the relevant kill switch / maintenance mode from
   `/admin/platform` (confirmation-gated, audited) to stop the
   bleeding first.
2. Redeploy the previous release digests (they are immutable and
   retained, §187). Code rollback is safe whenever migrations were
   expand-only (§189).
3. If the database must roll back: restore the pre-upgrade backup
   into an isolated database, validate (§174), then promote by
   operator decision — never restore over production directly (§173).
4. Record `PRODUCTION_ROLLBACK_STARTED` + the incident timeline in
   the admin plane; run the post-rollback checklist (§196): health
   green, queues draining, smoke passing, one test scan completing.
