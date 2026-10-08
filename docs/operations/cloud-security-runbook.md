# Cloud Security Runbook (Prompt 34)

## Daily flow

1. Register/verify accounts (Cloud Security page) — credential
   REFERENCE only; confirm environment + criticality are right.
2. Run a connection test (Cloud Security V2 page). Interpret results
   honestly: AUTH_FAILED → fix the reference/identity; EXPIRED →
   rotate in Secrets Management; PERMISSION_LIMITED → grant the
   missing read permissions or accept the limitation (it appears in
   coverage); UNREACHABLE + TRANSPORT_NOT_CONFIGURED → the live
   transport is not wired in this deployment — inventory-based
   assessment still works.
3. Run the posture assessment. COMPLETED_WITH_GAPS is the normal
   state when any pack/permission/transport is missing — read the
   gap list before the findings.
4. Review IAM signals and attack-path candidates; candidates are
   analysis, not incidents — confirm constituent findings first.
5. Check drift: snapshot diffs and baseline deviations; a
   PUBLIC_EXPOSURE drift to PUBLIC is the highest-priority review.

## Backup & restore (§164)

All V2 state (accounts metadata, snapshots, baselines, coverage,
runs, RBAC inventory, correlations) is ordinary PostgreSQL data —
covered by the platform backup/restore runbook
(`backup-restore-runbook.md`). Secrets are NOT in the database:
restoring the platform never restores credentials; references are
re-pointed at Secrets Management after restore. Snapshot hashes let
you verify restored snapshot integrity.

## Never do

- Never paste a credential value anywhere in the product.
- Never treat COMPLETED_WITH_GAPS as "secure" — read the gaps.
- Never act on an attack-path candidate as if it were an exploit
  result.
