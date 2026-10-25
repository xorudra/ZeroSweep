# Upgrade Runbook (Prompt 38 §150–§156)

1. Read the release notes + migration list for the target version.
2. Take a backup and complete a restore test (§175) — no upgrade
   starts on an unproven backup.
3. Deploy to staging with the exact release digests; run smoke +
   migration state check (`zerosweep_db_migration_current`).
4. Promote the same digests to production (CI `deploy-production`
   job is manually approved, §148). Migrations run via the migrate
   job only.
5. Record the deployment in `/admin/platform` (version, commit,
   environment) and watch error budget + queue health for one
   business cycle.
6. Breaking migrations follow expand → migrate → contract (§153);
   skip-version upgrades only along tested paths (§154).
