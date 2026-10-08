# Upgrade Guide (Prompt 40 §189–§196)

1. Read the target release notes + support matrix
   (`docs/product/support-matrix.md`).
2. Take a backup (P38) — an upgrade without a fresh backup is blocked
   by preflight policy (§192).
3. Run `GET /api/v1/product/upgrade/preflight?target=<version>`:
   blockers include missing backup, worker version mismatch, pending
   migrations and an active incident (§190/§191). Warnings never block
   silently — they are listed.
4. Apply migrations (`prisma migrate deploy`), deploy the new release
   train, run the seed.
5. Verify: health check (`scripts/product/health-check.mjs`), product
   smoke, one governed fixture scan.
6. Update execution is operator-driven; signed update metadata is
   informational — nothing auto-executes (§187/§188).
